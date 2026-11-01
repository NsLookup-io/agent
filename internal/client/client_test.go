package client

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nslookup-io/agent/internal/identity"
	"github.com/nslookup-io/agent/internal/protocol"
	"github.com/nslookup-io/agent/internal/version"
)

// The shared test vectors (the server tests against the same file): keys, bodies, a join and a seal.
type vectorFile struct {
	Keys struct {
		AgentSign      struct{ Seed string }       `json:"agentSign"`
		AgentSeal      struct{ PrivateKey string } `json:"agentSeal"`
		ServerSign     struct{ Seed string }       `json:"serverSign"`
		ServerSignNext struct{ Seed string }       `json:"serverSignNext"`
	} `json:"keys"`
	Requests []struct {
		AgentID string `json:"agentId"`
		Body    string `json:"body"`
	} `json:"requests"`
	Answers []struct {
		Body string `json:"body"`
	} `json:"answers"`
	Joins []struct {
		JoinCode     string `json:"joinCode"`
		JoinCodeID   string `json:"joinCodeId"`
		Secret       string `json:"secret"`
		RequestBody  string `json:"requestBody"`
		Proof        string `json:"proof"`
		ResponseBody string `json:"responseBody"`
		MAC          string `json:"mac"`
	} `json:"joins"`
	JoinCodes struct {
		Invalid []string `json:"invalid"`
	} `json:"joinCodes"`
	Seals []struct {
		AssignmentID string `json:"assignmentId"`
		SHA256       string `json:"sha256"`
		Plaintext    string `json:"plaintext"`
	} `json:"seals"`
}

type fixture struct {
	v         vectorFile
	agentID   string
	agentSign ed25519.PrivateKey
	agentSeal *ecdh.PrivateKey
	server    ed25519.PrivateKey
	// next is the server's next key of a key rollover.
	next ed25519.PrivateKey
}

func load(t *testing.T) *fixture {
	t.Helper()
	data, err := os.ReadFile("../protocol/testdata/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{}
	if err := json.Unmarshal(data, &f.v); err != nil {
		t.Fatal(err)
	}
	raw := func(text string) []byte {
		b, err := base64.RawURLEncoding.DecodeString(text)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	f.agentID = f.v.Requests[0].AgentID
	f.agentSign = ed25519.NewKeyFromSeed(raw(f.v.Keys.AgentSign.Seed))
	f.server = ed25519.NewKeyFromSeed(raw(f.v.Keys.ServerSign.Seed))
	f.next = ed25519.NewKeyFromSeed(raw(f.v.Keys.ServerSignNext.Seed))
	if f.agentSeal, err = ecdh.X25519().NewPrivateKey(raw(f.v.Keys.AgentSeal.PrivateKey)); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *fixture) joined() *identity.Identity {
	return &identity.Identity{AgentID: f.agentID, SignKey: f.agentSign, SealKey: f.agentSeal, ServerSignPublicKey: f.server.Public().(ed25519.PublicKey)}
}

// What the fake engine received.
type seen struct {
	method, uri string
	header      http.Header
	body        []byte
	// signed: the request's signature verified the engine's way.
	signed bool
}

// How the fake engine answers one request.
type reply struct {
	status int
	body   string
	header map[string]string
	// unsigned sends no x-nsa-server-signature (of a 2xx answer); sign signs any other answer (a 403 agent_removed).
	unsigned bool
	sign     bool
	// signWith signs with another key than the engine's.
	signWith ed25519.PrivateKey
	// cover changes what the signature covers: an answer meant for another request.
	cover func(a *answerLine)
	// sent replaces the body after signing: changed on the way.
	sent *string
}

type answerLine struct {
	status                      int
	agentID, method, uri, nonce string
	body                        []byte
}

type engine struct {
	t     *testing.T
	f     *fixture
	srv   *httptest.Server
	reply func(seen) reply

	mu   sync.Mutex
	seen []seen
}

func newEngine(t *testing.T, f *fixture, answer func(seen) reply) *engine {
	e := &engine{t: t, f: f, reply: answer}
	e.srv = httptest.NewServer(http.HandlerFunc(e.serve))
	t.Cleanup(e.srv.Close)
	return e
}

func (e *engine) requests() []seen {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]seen(nil), e.seen...)
}

func hexSHA256(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

var timestampText = regexp.MustCompile(`^(0|[1-9][0-9]{0,11})$`)

// verifies a signed request exactly as the engine's guard does, with its own canonical string.
func (e *engine) verify(r *http.Request, body []byte) bool {
	h := func(name string) string { return r.Header.Get(name) }
	nonce, err := base64.RawURLEncoding.Strict().DecodeString(h("x-nsa-nonce"))
	if err != nil || len(nonce) != 16 || !timestampText.MatchString(h("x-nsa-timestamp")) || h("x-nsa-agent") == "" {
		return false
	}
	sig, err := base64.RawURLEncoding.Strict().DecodeString(h("x-nsa-signature"))
	if err != nil {
		return false
	}
	canonical := strings.Join([]string{"NSA1", r.Method, r.RequestURI, h("x-nsa-timestamp"), h("x-nsa-nonce"), h("x-nsa-agent"), hexSHA256(body)}, "\n")
	return ed25519.Verify(e.f.agentSign.Public().(ed25519.PublicKey), []byte(canonical), sig)
}

func (e *engine) serve(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		e.t.Errorf("reading the request: %v", err)
	}
	s := seen{method: r.Method, uri: r.RequestURI, header: r.Header.Clone(), body: body}
	if r.URL.Path != "/agent/v1/join" {
		s.signed = e.verify(r, body)
	}
	e.mu.Lock()
	e.seen = append(e.seen, s)
	e.mu.Unlock()

	rep := e.reply(s)
	for k, v := range rep.header {
		w.Header().Set(k, v)
	}
	if (rep.status >= 200 && rep.status < 300 && !rep.unsigned || rep.sign) && r.URL.Path != "/agent/v1/join" {
		line := answerLine{status: rep.status, agentID: r.Header.Get("x-nsa-agent"), method: r.Method, uri: r.RequestURI, nonce: r.Header.Get("x-nsa-nonce"), body: []byte(rep.body)}
		if rep.cover != nil {
			rep.cover(&line)
		}
		key := e.f.server
		if rep.signWith != nil {
			key = rep.signWith
		}
		canonical := strings.Join([]string{"NSA1-RESP", strconv.Itoa(line.status), line.agentID, line.method, line.uri, line.nonce, hexSHA256(line.body)}, "\n")
		w.Header().Set("x-nsa-server-signature", base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, []byte(canonical))))
	}
	out := rep.body
	if rep.sent != nil {
		out = *rep.sent
	}
	if out != "" {
		w.Header().Set("Content-Type", "application/json")
	}
	w.WriteHeader(rep.status)
	_, _ = io.WriteString(w, out)
}

var fixedNow = time.Unix(1793275200, 0)

func newClient(server string, id *identity.Identity) *Client {
	c := New(server, id)
	c.now = func() time.Time { return fixedNow }
	return c
}

func heartbeatRequest(t *testing.T, f *fixture) protocol.HeartbeatRequest {
	t.Helper()
	var req protocol.HeartbeatRequest
	if err := json.Unmarshal([]byte(f.v.Requests[0].Body), &req); err != nil {
		t.Fatal(err)
	}
	return req
}

func TestHeartbeatIsSignedTheEngineWayAndItsAnswerChecked(t *testing.T) {
	f := load(t)
	e := newEngine(t, f, func(seen) reply { return reply{status: 200, body: f.v.Answers[0].Body} })
	c := newClient(e.srv.URL, f.joined())

	resp, err := c.Heartbeat(context.Background(), heartbeatRequest(t, f))
	if err != nil {
		t.Fatal(err)
	}
	if resp.Now != 1793275200 || resp.PollSeconds != 60 || len(resp.Work) != 1 || resp.Work[0].AssignmentID != f.v.Seals[0].AssignmentID ||
		resp.Work[0].Action != protocol.ActionInstall || resp.Work[0].Certbot != nil {
		t.Errorf("answer = %+v", resp)
	}
	if _, err := c.Heartbeat(context.Background(), heartbeatRequest(t, f)); err != nil {
		t.Fatal(err)
	}

	got := e.requests()
	if len(got) != 2 {
		t.Fatalf("%d requests, want 2", len(got))
	}
	r := got[0]
	if r.method != "POST" || r.uri != "/agent/v1/heartbeat" || !r.signed {
		t.Errorf("request = %s %s, signed %v", r.method, r.uri, r.signed)
	}
	if string(r.body) != f.v.Requests[0].Body {
		t.Errorf("body =\n%s\nwant\n%s", r.body, f.v.Requests[0].Body)
	}
	for name, want := range map[string]string{
		"Content-Type":     "application/json",
		"Content-Encoding": "",
		"User-Agent":       "nslookup-agent/" + version.Version,
		"X-Nsa-Agent":      f.agentID,
		"X-Nsa-Timestamp":  "1793275200",
	} {
		if v := r.header.Get(name); v != want {
			t.Errorf("%s = %q, want %q", name, v, want)
		}
	}
	if got[1].header.Get("x-nsa-nonce") == r.header.Get("x-nsa-nonce") {
		t.Error("two requests carried the same nonce")
	}
}

func TestBundleOpensTheKeySealedToTheAgent(t *testing.T) {
	f := load(t)
	seal := f.v.Seals[0]
	e := newEngine(t, f, func(seen) reply { return reply{status: 200, body: f.v.Answers[1].Body} })
	c := newClient(e.srv.URL, f.joined())

	b, err := c.Bundle(context.Background(), seal.AssignmentID)
	if err != nil {
		t.Fatal(err)
	}
	want := &protocol.Bundle{
		AssignmentID: seal.AssignmentID,
		SHA256:       seal.SHA256,
		CertPEM:      []byte("-----BEGIN CERTIFICATE-----\nTEST-VECTOR-ONLY\n-----END CERTIFICATE-----\n"),
		ChainPEM:     []byte("-----BEGIN CERTIFICATE-----\nTEST-VECTOR-ONLY-CHAIN\n-----END CERTIFICATE-----\n"),
		KeyPEM:       []byte(seal.Plaintext),
	}
	if !reflect.DeepEqual(b, want) {
		t.Errorf("bundle = %+v\nwant %+v", b, want)
	}
	r := e.requests()[0]
	if r.method != "GET" || r.uri != "/agent/v1/assignments/"+seal.AssignmentID+"/bundle" || !r.signed || len(r.body) != 0 || r.header.Get("Content-Type") != "" {
		t.Errorf("request = %s %s, signed %v, body %q, Content-Type %q", r.method, r.uri, r.signed, r.body, r.header.Get("Content-Type"))
	}
}

func TestBundleRefusesAnotherAssignmentsBundle(t *testing.T) {
	f := load(t)
	e := newEngine(t, f, func(seen) reply { return reply{status: 200, body: f.v.Answers[1].Body} })
	c := newClient(e.srv.URL, f.joined())
	if b, err := c.Bundle(context.Background(), "e4a7b2c9-6d1f-4e3a-8b5c-7f9d0e1a2b3c"); err == nil {
		t.Fatalf("got %+v for another assignment", b)
	}
}

func TestAssignmentIDsAreCheckedBeforeAnyRequest(t *testing.T) {
	f := load(t)
	e := newEngine(t, f, func(seen) reply { return reply{status: 204} })
	c := newClient(e.srv.URL, f.joined())
	for _, id := range []string{"", "../join", "9c1d4e7a-2b3f-4a8c-9d6e-0f1a2b3c4d5e/../../join", "9c1d4e7a-2b3f-4a8c-9d6e-0f1a2b3c4d5e?x=1", "not-an-id"} {
		if _, err := c.Bundle(context.Background(), id); !errors.Is(err, ErrNotAnAssignmentID) {
			t.Errorf("Bundle(%q): %v, want ErrNotAnAssignmentID", id, err)
		}
		if err := c.Result(context.Background(), id, protocol.InstallResult{}); !errors.Is(err, ErrNotAnAssignmentID) {
			t.Errorf("Result(%q): %v, want ErrNotAnAssignmentID", id, err)
		}
	}
	if n := len(e.requests()); n != 0 {
		t.Errorf("%d requests sent", n)
	}
}

func TestResultIsSignedAndItsEmptyAnswerChecked(t *testing.T) {
	f := load(t)
	e := newEngine(t, f, func(seen) reply { return reply{status: 204} })
	c := newClient(e.srv.URL, f.joined())
	var result protocol.InstallResult
	if err := json.Unmarshal([]byte(f.v.Requests[2].Body), &result); err != nil {
		t.Fatal(err)
	}

	if err := c.Result(context.Background(), f.v.Seals[0].AssignmentID, result); err != nil {
		t.Fatal(err)
	}
	r := e.requests()[0]
	if r.method != "POST" || r.uri != "/agent/v1/assignments/"+f.v.Seals[0].AssignmentID+"/result" || !r.signed || string(r.body) != f.v.Requests[2].Body ||
		r.header.Get("Content-Type") != "application/json" {
		t.Errorf("request = %s %s, signed %v, body %s", r.method, r.uri, r.signed, r.body)
	}
}

func TestAnswersWithoutAValidServerSignatureAreRefused(t *testing.T) {
	f := load(t)
	_, otherKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	body := f.v.Answers[0].Body
	changed := strings.Replace(body, `"action":"install"`, `"action":"release"`, 1)
	cases := map[string]reply{
		"no signature":                   {status: 200, body: body, unsigned: true},
		"signed with another key":        {status: 200, body: body, signWith: otherKey},
		"a garbage signature":            {status: 200, body: body, unsigned: true, header: map[string]string{"x-nsa-server-signature": "not-a-signature"}},
		"changed on the way":             {status: 200, body: body, sent: &changed},
		"meant for another nonce":        {status: 200, body: body, cover: func(a *answerLine) { a.nonce = "AAAAAAAAAAAAAAAAAAAAAA" }},
		"meant for another agent":        {status: 200, body: body, cover: func(a *answerLine) { a.agentID = "0d6f1e2a-3b4c-4d5e-8f60-718293a4b5c6" }},
		"meant for another path":         {status: 200, body: body, cover: func(a *answerLine) { a.uri = "/agent/v1/assignments/x/bundle" }},
		"meant for another method":       {status: 200, body: body, cover: func(a *answerLine) { a.method = "GET" }},
		"signed for another status code": {status: 200, body: body, cover: func(a *answerLine) { a.status = 201 }},
	}
	for name, rep := range cases {
		t.Run(name, func(t *testing.T) {
			e := newEngine(t, f, func(seen) reply { return rep })
			resp, err := newClient(e.srv.URL, f.joined()).Heartbeat(context.Background(), heartbeatRequest(t, f))
			if !errors.Is(err, ErrBadServerSignature) || resp != nil {
				t.Errorf("got %+v, %v; want ErrBadServerSignature", resp, err)
			}
		})
	}
	t.Run("an unsigned bundle", func(t *testing.T) {
		e := newEngine(t, f, func(seen) reply { return reply{status: 200, body: f.v.Answers[1].Body, unsigned: true} })
		b, err := newClient(e.srv.URL, f.joined()).Bundle(context.Background(), f.v.Seals[0].AssignmentID)
		if !errors.Is(err, ErrBadServerSignature) || b != nil {
			t.Errorf("got %+v, %v; want ErrBadServerSignature", b, err)
		}
	})
	t.Run("an unsigned 204", func(t *testing.T) {
		e := newEngine(t, f, func(seen) reply { return reply{status: 204, unsigned: true} })
		err := newClient(e.srv.URL, f.joined()).Result(context.Background(), f.v.Seals[0].AssignmentID, protocol.InstallResult{})
		if !errors.Is(err, ErrBadServerSignature) {
			t.Errorf("got %v; want ErrBadServerSignature", err)
		}
	})
}

func TestARemovedAgentGetsErrRemoved(t *testing.T) {
	f := load(t)
	e := newEngine(t, f, func(seen) reply { return reply{status: 403, body: `{"code":"agent_removed"}`, sign: true} })
	c := newClient(e.srv.URL, f.joined())
	if _, err := c.Heartbeat(context.Background(), heartbeatRequest(t, f)); !errors.Is(err, ErrRemoved) {
		t.Errorf("heartbeat: %v, want ErrRemoved", err)
	}
	if _, err := c.Bundle(context.Background(), f.v.Seals[0].AssignmentID); !errors.Is(err, ErrRemoved) {
		t.Errorf("bundle: %v, want ErrRemoved", err)
	}
	if err := c.Result(context.Background(), f.v.Seals[0].AssignmentID, protocol.InstallResult{}); !errors.Is(err, ErrRemoved) {
		t.Errorf("result: %v, want ErrRemoved", err)
	}
}

func TestClockSkewCarriesTheOffsetFromTheServersTime(t *testing.T) {
	f := load(t)
	for _, offset := range []int64{400, -250} {
		serverTime := fixedNow.Unix() + offset
		e := newEngine(t, f, func(seen) reply {
			return reply{status: 401, body: `{"statusCode":401,"code":"clock_skew","serverTime":` + strconv.FormatInt(serverTime, 10) + `}`}
		})
		_, err := newClient(e.srv.URL, f.joined()).Heartbeat(context.Background(), heartbeatRequest(t, f))
		var skew *ErrClockSkew
		if !errors.As(err, &skew) {
			t.Fatalf("offset %d: %v, want *ErrClockSkew", offset, err)
		}
		if skew.Offset != time.Duration(offset)*time.Second {
			t.Errorf("Offset = %v, want %d s", skew.Offset, offset)
		}
		abs := offset
		if abs < 0 {
			abs = -abs
		}
		if !strings.Contains(err.Error(), "your clock is off by "+strconv.FormatInt(abs, 10)+" s") {
			t.Errorf("message %q", err.Error())
		}
	}
}

func TestOtherRefusalsAreAPIErrors(t *testing.T) {
	f := load(t)
	cases := []struct {
		name string
		rep  reply
		want APIError
	}{
		{"a bad signature", reply{status: 401, body: `{"code":"unauthorized"}`}, APIError{Status: 401, Code: "unauthorized"}},
		{"clock_skew without the server's time", reply{status: 401, body: `{"code":"clock_skew"}`}, APIError{Status: 401, Code: "clock_skew"}},
		{"a 403 that is not a removal", reply{status: 403, body: `{"code":"forbidden"}`}, APIError{Status: 403, Code: "forbidden"}},
		{"a refused body", reply{status: 422, body: `{"code":"invalid_request","message":"facts.os must be at most 64 characters"}`},
			APIError{Status: 422, Code: "invalid_request", Message: "facts.os must be at most 64 characters"}},
		{"a rate limit", reply{status: 429, body: `{"code":"rate_limited"}`}, APIError{Status: 429, Code: "rate_limited"}},
		{"a proxy's error page", reply{status: 502, body: "<html>Bad Gateway</html>"}, APIError{Status: 502}},
		{"a redirect (never followed)", reply{status: 302, header: map[string]string{"Location": "/elsewhere"}}, APIError{Status: 302}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newEngine(t, f, func(seen) reply { return c.rep })
			_, err := newClient(e.srv.URL, f.joined()).Heartbeat(context.Background(), heartbeatRequest(t, f))
			var apiErr *APIError
			if !errors.As(err, &apiErr) || *apiErr != c.want {
				t.Errorf("got %v (%#v), want %#v", err, apiErr, c.want)
			}
			if n := len(e.requests()); n != 1 {
				t.Errorf("%d requests, want 1", n)
			}
		})
	}
}

// A refusal's code (and the server's time) count even when another field has a type the agent does not expect,
// such as a framework's list of messages.
func TestARefusalsCodeIsReadWhateverItsOtherFields(t *testing.T) {
	f := load(t)
	serverTime := fixedNow.Unix() + 400
	cases := []struct {
		name string
		rep  reply
		want func(error) bool
	}{
		// Not the server's removal (its body is exactly {"code":"agent_removed"}, signed): a refusal whose fields are read.
		{"agent_removed with a list of messages", reply{status: 403, body: `{"statusCode":403,"message":["gone"],"code":"agent_removed"}`},
			func(err error) bool {
				var apiErr *APIError
				return errors.As(err, &apiErr) && *apiErr == APIError{Status: 403, Code: "agent_removed", Message: "gone"}
			}},
		{"agent_removed with an object for statusCode", reply{status: 403, body: `{"statusCode":{"x":1},"code":"agent_removed"}`},
			func(err error) bool {
				var apiErr *APIError
				return errors.As(err, &apiErr) && *apiErr == APIError{Status: 403, Code: "agent_removed"}
			}},
		{"clock_skew with a number for message", reply{status: 401, body: `{"message":5,"code":"clock_skew","serverTime":` + strconv.FormatInt(serverTime, 10) + `}`},
			func(err error) bool {
				var skew *ErrClockSkew
				return errors.As(err, &skew) && skew.Offset == 400*time.Second
			}},
		{"clock_skew whose serverTime is text", reply{status: 401, body: `{"code":"clock_skew","serverTime":"soon"}`},
			func(err error) bool {
				var apiErr *APIError
				return errors.As(err, &apiErr) && *apiErr == APIError{Status: 401, Code: "clock_skew"}
			}},
		{"clock_skew whose serverTime is null", reply{status: 401, body: `{"code":"clock_skew","serverTime":null}`},
			func(err error) bool {
				var apiErr *APIError
				return errors.As(err, &apiErr) && *apiErr == APIError{Status: 401, Code: "clock_skew"}
			}},
		{"a list of messages is joined", reply{status: 422, body: `{"statusCode":422,"message":["facts.os is too long","version is empty"],"error":"Unprocessable Entity","code":"invalid_request"}`},
			func(err error) bool {
				var apiErr *APIError
				return errors.As(err, &apiErr) && *apiErr == APIError{Status: 422, Code: "invalid_request", Message: "facts.os is too long; version is empty"}
			}},
		{"a code that is not text", reply{status: 403, body: `{"code":["agent_removed"]}`},
			func(err error) bool {
				var apiErr *APIError
				return errors.As(err, &apiErr) && *apiErr == APIError{Status: 403}
			}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newEngine(t, f, func(seen) reply { return c.rep })
			_, err := newClient(e.srv.URL, f.joined()).Heartbeat(context.Background(), heartbeatRequest(t, f))
			if !c.want(err) {
				t.Errorf("got %v (%#v)", err, err)
			}
		})
	}
}

func TestAnOversizedAnswerIsNotRead(t *testing.T) {
	f := load(t)
	huge := `{"now":1,"work":[],"pad":"` + strings.Repeat("x", 2<<20) + `"}`
	e := newEngine(t, f, func(seen) reply { return reply{status: 200, body: huge} })
	if resp, err := newClient(e.srv.URL, f.joined()).Heartbeat(context.Background(), heartbeatRequest(t, f)); err == nil {
		t.Fatalf("got %+v", resp)
	}
}

func TestSignedCallsNeedAJoinedIdentity(t *testing.T) {
	f := load(t)
	e := newEngine(t, f, func(seen) reply { return reply{status: 204} })
	noAgent := f.joined()
	noAgent.AgentID = ""
	noServerKey := f.joined()
	noServerKey.ServerSignPublicKey = nil
	noSignKey := f.joined()
	noSignKey.SignKey = nil
	for name, id := range map[string]*identity.Identity{"nil": nil, "no agent id": noAgent, "no server key": noServerKey, "no signing key": noSignKey} {
		if _, err := newClient(e.srv.URL, id).Heartbeat(context.Background(), protocol.HeartbeatRequest{}); !errors.Is(err, ErrNotJoined) {
			t.Errorf("%s: %v, want ErrNotJoined", name, err)
		}
	}
	if n := len(e.requests()); n != 0 {
		t.Errorf("%d requests sent", n)
	}
}

func ptr[T any](v T) *T { return &v }

func joinFacts() protocol.AgentFacts {
	return protocol.AgentFacts{
		OS: "linux", OSVersion: "Ubuntu 24.04", Arch: "amd64", Hostname: "web-1.example.test",
		WebServers: []protocol.WebServer{{Kind: protocol.WebServerNginx, Version: "1.24.0"}}, AgentVersion: "1.0.0",
	}
}

// A fresh agent: its keys, no id and no server key yet.
func (f *fixture) unjoined() *identity.Identity {
	return &identity.Identity{SignKey: f.agentSign, SealKey: f.agentSeal}
}

func labelledMAC(label, secret, body string) string {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte(label + body))
	return hex.EncodeToString(m.Sum(nil))
}

func TestJoinSendsTheCodeIDAndAProofButNeverTheSecret(t *testing.T) {
	f := load(t)
	j := f.v.Joins[0]
	e := newEngine(t, f, func(seen) reply {
		return reply{status: 201, body: j.ResponseBody, header: map[string]string{"x-nsa-join-mac": j.MAC}}
	})
	c := newClient(e.srv.URL, f.unjoined())

	resp, err := c.Join(context.Background(), j.JoinCode, protocol.KindHost, ptr("web-1 — front"), joinFacts())
	if err != nil {
		t.Fatal(err)
	}
	want := &protocol.JoinResponse{AgentID: f.agentID, ServerSignPublicKey: "1VSN2LzbUEa0lyYDWYTaeAwwAbIeqKOnyl5PPJ-mRMw", PollSeconds: 60, MinVersion: "1.0.0", LatestVersion: "1.0.0"}
	if !reflect.DeepEqual(resp, want) {
		t.Errorf("answer = %+v, want %+v", resp, want)
	}

	r := e.requests()[0]
	if r.method != "POST" || r.uri != "/agent/v1/join" || r.header.Get("Content-Type") != "application/json" || r.header.Get("Content-Encoding") != "" {
		t.Errorf("request = %s %s, Content-Type %q", r.method, r.uri, r.header.Get("Content-Type"))
	}
	if string(r.body) != j.RequestBody {
		t.Errorf("body =\n%s\nwant\n%s", r.body, j.RequestBody)
	}
	if got := r.header.Get("x-nsa-join-proof"); got != j.Proof {
		t.Errorf("x-nsa-join-proof = %s, want %s", got, j.Proof)
	}
	everything := r.uri + string(r.body)
	for name, values := range r.header {
		everything += name + strings.Join(values, ",")
	}
	if strings.Contains(everything, j.Secret) {
		t.Error("the join code's secret was sent")
	}
	if r.header.Get("x-nsa-signature") != "" {
		t.Error("a join is not signed")
	}
}

func TestJoinRefusesAnAnswerWithoutTheRightMAC(t *testing.T) {
	f := load(t)
	j := f.v.Joins[0]
	for name, mac := range map[string]string{
		"no MAC":                         "",
		"a wrong MAC":                    strings.Repeat("0", 64),
		"a MAC without the label":        labelledMAC("", j.Secret, j.ResponseBody),
		"a MAC with the request's label": labelledMAC("NSA1-JOIN-REQ\n", j.Secret, j.ResponseBody),
		"another code's MAC":             labelledMAC("NSA1-JOIN-ANS\n", strings.Repeat("A", 36), j.ResponseBody),
		"the request's proof, sent back": j.Proof,
	} {
		t.Run(name, func(t *testing.T) {
			e := newEngine(t, f, func(seen) reply {
				return reply{status: 201, body: j.ResponseBody, header: map[string]string{"x-nsa-join-mac": mac}}
			})
			resp, err := newClient(e.srv.URL, f.unjoined()).Join(context.Background(), j.JoinCode, protocol.KindHost, nil, joinFacts())
			if !errors.Is(err, ErrBadServerSignature) || resp != nil {
				t.Errorf("got %+v, %v; want ErrBadServerSignature", resp, err)
			}
		})
	}
}

func TestJoinRefusesAnIncompleteAnswer(t *testing.T) {
	f := load(t)
	j := f.v.Joins[0]
	for name, body := range map[string]string{
		"no agentId":                    `{"serverSignPublicKey":"1VSN2LzbUEa0lyYDWYTaeAwwAbIeqKOnyl5PPJ-mRMw","pollSeconds":60,"minVersion":"1.0.0","latestVersion":"1.0.0"}`,
		"no serverSignPublicKey":        `{"agentId":"3f2b8c1e-7a4d-4e9b-b1c6-5d8e2f0a7c93","pollSeconds":60,"minVersion":"1.0.0","latestVersion":"1.0.0"}`,
		"a server key of 31 bytes":      `{"agentId":"3f2b8c1e-7a4d-4e9b-b1c6-5d8e2f0a7c93","serverSignPublicKey":"1VSN2LzbUEa0lyYDWYTaeAwwAbIeqKOnyl5PPJ-mRA","pollSeconds":60}`,
		"an agent id with a line break": `{"agentId":"3f2b8c1e\nx","serverSignPublicKey":"1VSN2LzbUEa0lyYDWYTaeAwwAbIeqKOnyl5PPJ-mRMw","pollSeconds":60}`,
		"not JSON":                      `agentId=1`,
	} {
		t.Run(name, func(t *testing.T) {
			e := newEngine(t, f, func(seen) reply {
				return reply{status: 201, body: body, header: map[string]string{"x-nsa-join-mac": labelledMAC("NSA1-JOIN-ANS\n", j.Secret, body)}}
			})
			resp, err := newClient(e.srv.URL, f.unjoined()).Join(context.Background(), j.JoinCode, protocol.KindHost, nil, joinFacts())
			if err == nil || resp != nil {
				t.Errorf("got %+v, %v; want an error", resp, err)
			}
		})
	}
}

func TestJoinRefusals(t *testing.T) {
	f := load(t)
	j := f.v.Joins[0]
	t.Run("410 join_code_invalid", func(t *testing.T) {
		e := newEngine(t, f, func(seen) reply {
			return reply{status: 410, body: `{"code":"join_code_invalid","message":"This join code was already used or has expired. Create a new one in the portal."}`}
		})
		if _, err := newClient(e.srv.URL, f.unjoined()).Join(context.Background(), j.JoinCode, protocol.KindHost, nil, joinFacts()); !errors.Is(err, ErrJoinCodeInvalid) {
			t.Errorf("%v, want ErrJoinCodeInvalid", err)
		}
	})
	t.Run("409 agent_limit_reached", func(t *testing.T) {
		e := newEngine(t, f, func(seen) reply { return reply{status: 409, body: `{"code":"agent_limit_reached"}`} })
		_, err := newClient(e.srv.URL, f.unjoined()).Join(context.Background(), j.JoinCode, protocol.KindHost, nil, joinFacts())
		var apiErr *APIError
		if !errors.As(err, &apiErr) || *apiErr != (APIError{Status: 409, Code: "agent_limit_reached"}) {
			t.Errorf("%v, want APIError 409 agent_limit_reached", err)
		}
	})
	t.Run("a malformed code is refused before any request", func(t *testing.T) {
		e := newEngine(t, f, func(seen) reply { return reply{status: 500} })
		c := newClient(e.srv.URL, f.unjoined())
		for _, code := range f.v.JoinCodes.Invalid {
			if _, err := c.Join(context.Background(), code, protocol.KindHost, nil, joinFacts()); !errors.Is(err, ErrMalformedJoinCode) {
				t.Errorf("%q: %v, want ErrMalformedJoinCode", code, err)
			}
		}
		if n := len(e.requests()); n != 0 {
			t.Errorf("%d requests sent", n)
		}
	})
	t.Run("no keys", func(t *testing.T) {
		e := newEngine(t, f, func(seen) reply { return reply{status: 500} })
		if _, err := newClient(e.srv.URL, &identity.Identity{}).Join(context.Background(), j.JoinCode, protocol.KindHost, nil, joinFacts()); err == nil {
			t.Error("joined without keys")
		}
		if n := len(e.requests()); n != 0 {
			t.Errorf("%d requests sent", n)
		}
	})
}

func TestHTTPSettings(t *testing.T) {
	c := New("https://agents.example.test/", nil)
	if c.http.Timeout != 30*time.Second {
		t.Errorf("timeout = %v, want 30 s", c.http.Timeout)
	}
	transport, ok := c.http.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport is %T", c.http.Transport)
	}
	if transport.Proxy == nil || reflect.ValueOf(transport.Proxy).Pointer() != reflect.ValueOf(http.ProxyFromEnvironment).Pointer() {
		t.Error("the proxy does not come from the environment")
	}
	if transport.TLSClientConfig != nil && transport.TLSClientConfig.InsecureSkipVerify {
		t.Error("TLS verification is off")
	}
	if c.http.CheckRedirect == nil {
		t.Error("redirects are followed")
	}
	if c.server != "https://agents.example.test" {
		t.Errorf("server = %q", c.server)
	}
}

func TestTLSCertificatesAreVerified(t *testing.T) {
	f := load(t)
	var reached atomic.Bool
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached.Store(true) }))
	srv.Config.ErrorLog = log.New(io.Discard, "", 0) // the refused handshake is the point, not news
	srv.StartTLS()
	defer srv.Close()
	_, err := newClient(srv.URL, f.joined()).Heartbeat(context.Background(), heartbeatRequest(t, f))
	var verifyErr *tls.CertificateVerificationError
	if !errors.As(err, &verifyErr) {
		t.Errorf("%v, want a certificate verification error", err)
	}
	if reached.Load() {
		t.Error("the request reached a server whose certificate is not trusted")
	}
}

// HTTPS_PROXY is read once per process, so the request runs in a child process with the proxy set; the proxy here
// records the tunnel it is asked for and refuses it.
func TestRequestsGoThroughTheHTTPSProxyOfTheEnvironment(t *testing.T) {
	if os.Getenv("NSA_TEST_PROXY_CHILD") == "1" {
		f := load(t)
		_, err := New("https://agents.example.test", f.joined()).Heartbeat(context.Background(), heartbeatRequest(t, f))
		if err == nil {
			t.Fatal("the proxy refuses every tunnel, yet the heartbeat succeeded")
		}
		return
	}
	var mu sync.Mutex
	var asked []string
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		asked = append(asked, r.Method+" "+r.Host)
		mu.Unlock()
		http.Error(w, "no tunnels", http.StatusForbidden)
	}))
	defer proxy.Close()

	var env []string
	for _, kv := range os.Environ() {
		name := strings.ToUpper(strings.SplitN(kv, "=", 2)[0])
		if name != "HTTPS_PROXY" && name != "HTTP_PROXY" && name != "NO_PROXY" && name != "ALL_PROXY" && name != "REQUEST_METHOD" {
			env = append(env, kv)
		}
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestRequestsGoThroughTheHTTPSProxyOfTheEnvironment$", "-test.count=1")
	cmd.Env = append(env, "NSA_TEST_PROXY_CHILD=1", "HTTPS_PROXY="+proxy.URL)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("child: %v\n%s", err, out)
	}
	mu.Lock()
	defer mu.Unlock()
	if !reflect.DeepEqual(asked, []string{"CONNECT agents.example.test:443"}) {
		t.Errorf("the proxy was asked %q, want one CONNECT agents.example.test:443", asked)
	}
}

// Only a removal the server signed counts: a 403 unsigned, signed by another key, signed for another request or with
// another body is a refusal like any other, temporary (a proxy could have sent it); the agent never stops on it.
func TestAnUnsignedRemovalIsATemporaryRefusal(t *testing.T) {
	f := load(t)
	stranger := ed25519.NewKeyFromSeed(make([]byte, 32))
	for name, rep := range map[string]reply{
		"unsigned":             {status: 403, body: `{"code":"agent_removed"}`},
		"signed by a stranger": {status: 403, body: `{"code":"agent_removed"}`, sign: true, signWith: stranger},
		"signed for another request": {status: 403, body: `{"code":"agent_removed"}`, sign: true,
			cover: func(a *answerLine) { a.uri = "/agent/v1/assignments/9c1d4e7a-2b3f-4a8c-9d6e-0f1a2b3c4d5e/bundle" }},
		"another body, signed":  {status: 403, body: `{"code":"agent_removed","message":"gone"}`, sign: true},
		"changed after signing": {status: 403, body: `{"code":"agent_removed"}`, sign: true, sent: ptr(`{"code": "agent_removed"}`)},
		"a 401 saying removed":  {status: 401, body: `{"code":"agent_removed"}`, sign: true},
	} {
		t.Run(name, func(t *testing.T) {
			e := newEngine(t, f, func(seen) reply { return rep })
			_, err := newClient(e.srv.URL, f.joined()).Heartbeat(context.Background(), heartbeatRequest(t, f))
			var refused *APIError
			if errors.Is(err, ErrRemoved) || !errors.As(err, &refused) || RetryOf(err) == Removed || RetryOf(err) == Never {
				t.Errorf("%v (%v)", err, RetryOf(err))
			}
		})
	}
}

// heartbeatAnswer is a heartbeat answer listing keys as serverSignPublicKeys (none: no list).
func heartbeatAnswer(keys ...string) string {
	body := `{"now":1793275200,"pollSeconds":60,"wantInventory":false,"minVersion":"1.0.0","latestVersion":"1.0.0",`
	if keys != nil {
		quoted := make([]string, len(keys))
		for i, k := range keys {
			quoted[i] = strconv.Quote(k)
		}
		body += `"serverSignPublicKeys":[` + strings.Join(quoted, ",") + `],`
	}
	return body + `"work":[]}`
}

// savedKeys records the trusted key sets the client saved.
type savedKeys struct {
	sets [][]ed25519.PublicKey
	fail error
}

func (s *savedKeys) save(id *identity.Identity) error {
	if s.fail != nil {
		return s.fail
	}
	s.sets = append(s.sets, slices.Clone(id.ServerSignPublicKeys))
	return nil
}

// The server rolls its signing key over: a heartbeat answer signed with a trusted key lists the active and the next
// key, the agent trusts both and saves them; once the server signs with the next key, an answer listing only that one
// leaves it trusted alone.
func TestServerKeyRollover(t *testing.T) {
	f := load(t)
	active := protocol.EncodeB64URL(f.server.Public().(ed25519.PublicKey))
	next := protocol.EncodeB64URL(f.next.Public().(ed25519.PublicKey))
	var rep reply
	e := newEngine(t, f, func(seen) reply { return rep })
	id := f.joined()
	c := newClient(e.srv.URL, id)
	saved := &savedKeys{}
	var logs bytes.Buffer
	c.SaveKeys = saved.save
	c.Log = slog.New(slog.NewTextHandler(&logs, nil))
	beat := func() error {
		_, err := c.Heartbeat(context.Background(), heartbeatRequest(t, f))
		return err
	}

	// Signed with the next key before the agent knows it: refused.
	rep = reply{status: 200, body: heartbeatAnswer(next), signWith: f.next}
	if err := beat(); !errors.Is(err, ErrBadServerSignature) {
		t.Fatalf("before the rollover: %v", err)
	}
	// Announced: both trusted, and saved.
	rep = reply{status: 200, body: heartbeatAnswer(active, next)}
	if err := beat(); err != nil {
		t.Fatal(err)
	}
	if len(saved.sets) != 1 || len(saved.sets[0]) != 2 || len(id.TrustedServerKeys()) != 2 {
		t.Fatalf("saved %x", saved.sets)
	}
	// The same list again: nothing saved again.
	if err := beat(); err != nil || len(saved.sets) != 1 {
		t.Errorf("again: %v, saved %d times", err, len(saved.sets))
	}
	// Swapped: answers signed with the next key verify, every route.
	rep = reply{status: 200, body: heartbeatAnswer(next), signWith: f.next}
	if err := beat(); err != nil {
		t.Fatal(err)
	}
	if keys := id.TrustedServerKeys(); len(keys) != 1 || !keys[0].Equal(f.next.Public().(ed25519.PublicKey)) || len(saved.sets) != 2 {
		t.Errorf("after the rollover, trusts %x, saved %d times", keys, len(saved.sets))
	}
	rep = reply{status: 204, signWith: f.next}
	if err := c.Result(context.Background(), f.v.Seals[0].AssignmentID, protocol.InstallResult{}); err != nil {
		t.Errorf("a result answer signed with the next key: %v", err)
	}
	// The former key is no longer trusted.
	rep = reply{status: 200, body: heartbeatAnswer(next)}
	if err := beat(); !errors.Is(err, ErrBadServerSignature) {
		t.Errorf("signed with the former key: %v", err)
	}
	if !id.ServerSignPublicKey.Equal(f.server.Public().(ed25519.PublicKey)) {
		t.Error("the key pinned at join changed")
	}
}

// A list that is not valid (empty, more than two keys, a malformed key, one of small order, or without the key that
// signed the answer) is ignored, said once, and the trusted set kept; an answer that lists none keeps it too.
func TestAnInvalidKeyListIsIgnored(t *testing.T) {
	f := load(t)
	active := protocol.EncodeB64URL(f.server.Public().(ed25519.PublicKey))
	next := protocol.EncodeB64URL(f.next.Public().(ed25519.PublicKey))
	for name, list := range map[string][]string{
		"empty":                       {},
		"three keys":                  {active, next, active},
		"a malformed key":             {active, "not-a-key"},
		"a key of small order":        {active, "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
		"without the key that signed": {next},
	} {
		t.Run(name, func(t *testing.T) {
			e := newEngine(t, f, func(seen) reply { return reply{status: 200, body: heartbeatAnswer(list...)} })
			id := f.joined()
			c := newClient(e.srv.URL, id)
			saved := &savedKeys{}
			var logs bytes.Buffer
			c.SaveKeys = saved.save
			c.Log = slog.New(slog.NewTextHandler(&logs, nil))
			for range 3 {
				if _, err := c.Heartbeat(context.Background(), heartbeatRequest(t, f)); err != nil {
					t.Fatal(err)
				}
			}
			if keys := id.TrustedServerKeys(); len(keys) != 1 || !keys[0].Equal(f.server.Public().(ed25519.PublicKey)) || len(saved.sets) != 0 {
				t.Errorf("trusts %x, saved %d times", keys, len(saved.sets))
			}
			if n := strings.Count(logs.String(), "is not valid"); n != 1 {
				t.Errorf("said %d times:\n%s", n, logs.String())
			}
		})
	}
	t.Run("no list", func(t *testing.T) {
		e := newEngine(t, f, func(seen) reply { return reply{status: 200, body: heartbeatAnswer()} })
		id := f.joined()
		c := newClient(e.srv.URL, id)
		var logs bytes.Buffer
		c.Log = slog.New(slog.NewTextHandler(&logs, nil))
		if _, err := c.Heartbeat(context.Background(), heartbeatRequest(t, f)); err != nil || len(id.TrustedServerKeys()) != 1 || logs.Len() != 0 {
			t.Errorf("%v, trusts %x, logs %s", err, id.TrustedServerKeys(), logs.String())
		}
	})
}

// A key set that cannot be saved is used all the same, and saving is tried again with the next heartbeat.
func TestAKeySetThatCannotBeSavedIsSavedLater(t *testing.T) {
	f := load(t)
	active := protocol.EncodeB64URL(f.server.Public().(ed25519.PublicKey))
	next := protocol.EncodeB64URL(f.next.Public().(ed25519.PublicKey))
	e := newEngine(t, f, func(seen) reply { return reply{status: 200, body: heartbeatAnswer(active, next)} })
	id := f.joined()
	c := newClient(e.srv.URL, id)
	saved := &savedKeys{fail: errors.New("read-only file system")}
	var logs bytes.Buffer
	c.SaveKeys = saved.save
	c.Log = slog.New(slog.NewTextHandler(&logs, nil))
	if _, err := c.Heartbeat(context.Background(), heartbeatRequest(t, f)); err != nil {
		t.Fatal(err)
	}
	if len(id.TrustedServerKeys()) != 2 || !strings.Contains(logs.String(), "read-only file system") {
		t.Errorf("trusts %x; logs %s", id.TrustedServerKeys(), logs.String())
	}
	// Said once while it cannot be stored, not with every heartbeat.
	for range 3 {
		if _, err := c.Heartbeat(context.Background(), heartbeatRequest(t, f)); err != nil {
			t.Fatal(err)
		}
	}
	if n := strings.Count(logs.String(), "could not be stored"); n != 1 {
		t.Errorf("said %d times:\n%s", n, logs.String())
	}
	saved.fail = nil
	if _, err := c.Heartbeat(context.Background(), heartbeatRequest(t, f)); err != nil || len(saved.sets) != 1 {
		t.Errorf("%v, saved %d times", err, len(saved.sets))
	}
}
