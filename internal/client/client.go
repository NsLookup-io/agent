// Package client talks to the server's /agent/v1 API: the join, then signed heartbeats, bundles and results.
//
// Every request after the join is signed with the agent's key, and every 2xx answer (and the 403 that removes the
// agent) is checked against the server keys the agent trusts before anything in it is used: the key pinned at join,
// then the keys the server lists in its heartbeat answers when it rolls its key over. The join itself is proven with
// the join code's secret, which never leaves the machine, and its answer is checked with a MAC keyed with the same
// secret.
package client

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/nslookup-io/agent/internal/identity"
	"github.com/nslookup-io/agent/internal/protocol"
	"github.com/nslookup-io/agent/internal/version"
)

const (
	// requestTimeout covers one whole request, answer included.
	requestTimeout = 30 * time.Second
	// maxAnswerBytes: a heartbeat answer with 200 work items, or a bundle with its chain, is far smaller.
	maxAnswerBytes = 1 << 20
	nonceBytes     = 16
)

var (
	// ErrRemoved: the agent was removed in the portal: a 403 agent_removed signed by the server. It never works again.
	ErrRemoved = errors.New("this agent was removed in the portal")
	// ErrJoinCodeInvalid: the join code was already used, has expired or does not exist (410 join_code_invalid).
	ErrJoinCodeInvalid = errors.New("this join code was already used or has expired; create a new one in the portal")
	// ErrMalformedJoinCode: what was given is not a join code (nsj_<12 letters or digits>_<36 letters or digits>).
	// Nothing was sent.
	ErrMalformedJoinCode = errors.New("this is not a join code: copy the whole code from the portal")
	// ErrBadServerSignature: a 2xx answer whose server signature (or, at join, MAC) is missing or does not verify. Its
	// body was not used.
	ErrBadServerSignature = errors.New("the answer is not signed by the server this agent joined")
	// ErrNotJoined: a signed call before the agent joined (no agent id, signing key or pinned server key).
	ErrNotJoined = errors.New("this agent has not joined yet")
	// ErrNotAnAssignmentID: a bundle or result was asked for with an id that is not an assignment id (a UUID).
	// Nothing was sent, and asking again cannot succeed.
	ErrNotAnAssignmentID = errors.New("not an assignment id")
)

// ErrClockSkew: the server refused the request because this machine's clock is too far from its own (401
// clock_skew). Offset = the server's time minus ours, in whole seconds.
type ErrClockSkew struct {
	Offset time.Duration
}

func (e *ErrClockSkew) Error() string {
	seconds := int64(e.Offset / time.Second)
	direction := "behind"
	if seconds < 0 {
		seconds, direction = -seconds, "ahead of"
	}
	return fmt.Sprintf("the server refused the request: your clock is off by %d s (%s the server's)", seconds, direction)
}

// APIError is any other refusal: its HTTP status and, when the body was a JSON error, its code and message.
type APIError struct {
	Status  int
	Code    string
	Message string
}

func (e *APIError) Error() string {
	text := fmt.Sprintf("the server answered %d", e.Status)
	if e.Code != "" {
		text += " " + e.Code
	}
	if e.Message != "" {
		text += ": " + e.Message
	}
	return text
}

// An agent id goes into a header and both canonical strings.
var agentID = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)

// Client is one agent's connection to the server. Not for concurrent use.
type Client struct {
	// SaveKeys stores the identity's new set of trusted server keys (identity.Store.SaveServerKeys); nil: kept in
	// memory only.
	SaveKeys func(*identity.Identity) error
	// Log: nil = slog.Default().
	Log *slog.Logger

	server string
	id     *identity.Identity
	http   *http.Client
	now    func() time.Time
	// saved is the trusted key set as last stored; warned: an invalid key list was said already; unsaved: a failure to
	// store the set was said already (said again only after a store worked).
	saved   []ed25519.PublicKey
	warned  bool
	unsaved bool
}

// New returns a client of server (its origin, such as https://agents.example.test) for the agent id. Requests go
// through the proxy of the environment (HTTPS_PROXY, NO_PROXY), verify TLS certificates, never follow a redirect and
// give up after 30 s.
func New(server string, id *identity.Identity) *Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = http.ProxyFromEnvironment
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	return &Client{
		server: strings.TrimRight(server, "/"),
		id:     id,
		http: &http.Client{
			Transport: transport,
			Timeout:   requestTimeout,
			// A signed request is valid for one path only, and a join's proof belongs to this server only.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		now:   time.Now,
		saved: slices.Clone(id.TrustedServerKeys()),
	}
}

// Join spends a join code: it sends the code's id, the agent's two public keys, its kind, name and facts, proven
// with the code's secret (which is never sent). The answer is returned only when its MAC verifies and it names the
// agent and the server's signing key; the caller then pins that key and stores the identity. Nothing else changes.
func (c *Client) Join(ctx context.Context, joinCode string, kind protocol.AgentKind, name *string, facts protocol.AgentFacts) (*protocol.JoinResponse, error) {
	codeID, secret, ok := protocol.SplitJoinCode(joinCode)
	if !ok {
		return nil, ErrMalformedJoinCode
	}
	if c.id == nil || len(c.id.SignKey) != ed25519.PrivateKeySize || c.id.SealKey == nil {
		return nil, errors.New("joining needs the agent's signing and sealing keys")
	}
	body, err := protocol.MarshalBody(protocol.JoinRequest{
		JoinCodeID:    codeID,
		SignPublicKey: protocol.EncodeB64URL(c.id.SignKey.Public().(ed25519.PublicKey)),
		SealPublicKey: protocol.EncodeB64URL(c.id.SealKey.PublicKey().Bytes()),
		Kind:          kind,
		Name:          name,
		Facts:         facts,
	})
	if err != nil {
		return nil, err
	}
	req, err := c.newRequest(ctx, http.MethodPost, protocol.APIBase+"/join", body)
	if err != nil {
		return nil, err
	}
	req.Header.Set(protocol.HeaderJoinProof, protocol.JoinProof(secret, body))

	status, header, answer, err := c.send(req)
	if err != nil {
		return nil, err
	}
	if status < 200 || status > 299 {
		return nil, c.refusal(status, answer)
	}
	if !protocol.JoinMACMatches(secret, answer, header.Get(protocol.HeaderJoinMAC)) {
		return nil, ErrBadServerSignature
	}
	var joined protocol.JoinResponse
	if err := json.Unmarshal(answer, &joined); err != nil {
		return nil, fmt.Errorf("the join answer is not JSON: %w", err)
	}
	if !agentID.MatchString(joined.AgentID) {
		return nil, errors.New("the join answer names no agent")
	}
	if _, err := protocol.ParseSignPublicKey(joined.ServerSignPublicKey); err != nil {
		return nil, errors.New("the join answer carries no usable server key")
	}
	return &joined, nil
}

// Heartbeat says the agent is alive, sends its facts (and its inventory when it changed or was asked for) and gets
// its work. The answer's list of server keys, when it is valid, becomes the set of keys the agent trusts.
func (c *Client) Heartbeat(ctx context.Context, beat protocol.HeartbeatRequest) (*protocol.HeartbeatResponse, error) {
	answer, signer, err := c.signed(ctx, http.MethodPost, protocol.APIBase+"/heartbeat", beat)
	if err != nil {
		return nil, err
	}
	var resp protocol.HeartbeatResponse
	if err := json.Unmarshal(answer, &resp); err != nil {
		return nil, fmt.Errorf("the heartbeat answer is not JSON: %w", err)
	}
	c.learnKeys(resp.ServerSignPublicKeys, signer)
	return &resp, nil
}

// learnKeys makes list (an answer's serverSignPublicKeys, verified with signer) the set of trusted server keys when
// it is valid: 1 or 2 well-formed keys of no small order, signer among them. An invalid list is said once and
// ignored; no list (a server that lists none) keeps the set. A new set is used at once and stored (SaveKeys); one that
// could not be stored is stored again with the next heartbeat.
func (c *Client) learnKeys(list []string, signer ed25519.PublicKey) {
	if list == nil {
		return
	}
	keys, err := protocol.ParseServerKeys(list)
	if err == nil && !slices.ContainsFunc(keys, func(k ed25519.PublicKey) bool { return k.Equal(signer) }) {
		err = errors.New("the list does not hold the key that signed the answer")
	}
	if err != nil {
		if !c.warned {
			c.warned = true
			c.log().Warn("the server's list of its signing keys is not valid; the keys trusted now are kept", "error", err)
		}
		return
	}
	if !sameKeys(keys, c.id.TrustedServerKeys()) {
		c.id.ServerSignPublicKeys = keys
		c.log().Info("the server's signing keys changed; this agent trusts the keys it lists now", "keys", len(keys))
	}
	if sameKeys(keys, c.saved) || c.SaveKeys == nil {
		return
	}
	if err := c.SaveKeys(c.id); err != nil {
		if !c.unsaved {
			c.unsaved = true
			c.log().Warn("the server's new signing keys could not be stored; they are used, and stored again with each heartbeat", "error", err)
		}
		return
	}
	c.saved, c.unsaved = slices.Clone(keys), false
}

func sameKeys(a, b []ed25519.PublicKey) bool {
	return slices.EqualFunc(a, b, func(x, y ed25519.PublicKey) bool { return x.Equal(y) })
}

func (c *Client) log() *slog.Logger {
	if c.Log == nil {
		return slog.Default()
	}
	return c.Log
}

// Bundle fetches an assignment's certificate and opens its private key, which the server sealed to this agent.
func (c *Client) Bundle(ctx context.Context, assignment string) (*protocol.Bundle, error) {
	if !protocol.IsAssignmentID(assignment) {
		return nil, fmt.Errorf("%q is %w", assignment, ErrNotAnAssignmentID)
	}
	answer, _, err := c.signed(ctx, http.MethodGet, protocol.APIBase+"/assignments/"+assignment+"/bundle", nil)
	if err != nil {
		return nil, err
	}
	var sealed protocol.SealedBundle
	if err := json.Unmarshal(answer, &sealed); err != nil {
		return nil, fmt.Errorf("the bundle is not JSON: %w", err)
	}
	if sealed.AssignmentID != assignment {
		return nil, fmt.Errorf("the server sent the bundle of assignment %q instead of %q", sealed.AssignmentID, assignment)
	}
	key, err := protocol.OpenSealedKey(c.id.SealKey, sealed.AssignmentID, sealed.SHA256, sealed.SealedKey)
	if err != nil {
		return nil, err
	}
	return &protocol.Bundle{
		AssignmentID: sealed.AssignmentID,
		SHA256:       sealed.SHA256,
		CertPEM:      []byte(sealed.CertPEM),
		ChainPEM:     []byte(sealed.ChainPEM),
		KeyPEM:       key,
	}, nil
}

// Result reports what the agent did with an assignment's work.
func (c *Client) Result(ctx context.Context, assignment string, result protocol.InstallResult) error {
	if !protocol.IsAssignmentID(assignment) {
		return fmt.Errorf("%q is %w", assignment, ErrNotAnAssignmentID)
	}
	_, _, err := c.signed(ctx, http.MethodPost, protocol.APIBase+"/assignments/"+assignment+"/result", result)
	return err
}

// signed sends a signed request (payload marshalled once; nil = no body) and returns the body of a 2xx answer whose
// server signature verifies with a trusted key, and that key. A 403 removing the agent counts only when its signature
// verifies (ErrRemoved); unsigned, it is a refusal like the others.
func (c *Client) signed(ctx context.Context, method, path string, payload any) ([]byte, ed25519.PublicKey, error) {
	id := c.id
	if id == nil || !agentID.MatchString(id.AgentID) || len(id.SignKey) != ed25519.PrivateKeySize || len(id.TrustedServerKeys()) == 0 {
		return nil, nil, ErrNotJoined
	}
	var body []byte
	if payload != nil {
		var err error
		if body, err = protocol.MarshalBody(payload); err != nil {
			return nil, nil, err
		}
	}
	req, err := c.newRequest(ctx, method, path, body)
	if err != nil {
		return nil, nil, err
	}
	nonce := make([]byte, nonceBytes)
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	nonceText := protocol.EncodeB64URL(nonce)
	// The path and query exactly as they go on the wire.
	pathWithQuery := req.URL.RequestURI()
	timestamp := c.now().Unix()
	canonical, err := protocol.CanonicalRequest(method, pathWithQuery, timestamp, nonceText, id.AgentID, body)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set(protocol.HeaderAgent, id.AgentID)
	req.Header.Set(protocol.HeaderTimestamp, strconv.FormatInt(timestamp, 10))
	req.Header.Set(protocol.HeaderNonce, nonceText)
	req.Header.Set(protocol.HeaderSignature, protocol.SignRequest(id.SignKey, canonical))

	status, header, answer, err := c.send(req)
	if err != nil {
		return nil, nil, err
	}
	parts := protocol.AnswerParts{Status: status, AgentID: id.AgentID, Method: method, PathWithQuery: pathWithQuery, RequestNonce: nonceText, Body: answer}
	signer, verified := protocol.VerifyAnswerWithAny(id.TrustedServerKeys(), parts, header.Get(protocol.HeaderServerSignature))
	switch {
	case protocol.IsRemoval(status, answer) && verified:
		return nil, nil, ErrRemoved
	case status < 200 || status > 299:
		return nil, nil, c.refusal(status, answer)
	case !verified:
		return nil, nil, ErrBadServerSignature
	}
	return answer, signer, nil
}

// newRequest builds a request to the server: a POST carries body as JSON (never compressed), a GET nothing.
func (c *Client) newRequest(ctx context.Context, method, path string, body []byte) (*http.Request, error) {
	var reader io.Reader
	if method != http.MethodGet {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.server+path, reader)
	if err != nil {
		return nil, err
	}
	if method != http.MethodGet {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "nslookup-agent/"+version.Version)
	return req, nil
}

// send makes the request and reads at most maxAnswerBytes of the answer.
func (c *Client) send(req *http.Request) (int, http.Header, []byte, error) {
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, nil, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxAnswerBytes+1))
	if err != nil {
		return 0, nil, nil, err
	}
	if len(body) > maxAnswerBytes {
		return 0, nil, nil, fmt.Errorf("the answer to %s %s is larger than %d bytes", req.Method, req.URL.Path, maxAnswerBytes)
	}
	return resp.StatusCode, resp.Header, body, nil
}

// refusal turns a non-2xx answer into its error.
func (c *Client) refusal(status int, body []byte) error {
	e, ok := decodeRefusal(body)
	if !ok {
		return &APIError{Status: status}
	}
	switch {
	case status == http.StatusUnauthorized && e.Code == "clock_skew" && e.ServerTime != nil:
		return &ErrClockSkew{Offset: time.Duration(*e.ServerTime-c.now().Unix()) * time.Second}
	case status == http.StatusGone && e.Code == "join_code_invalid":
		return ErrJoinCodeInvalid
	}
	return &APIError{Status: status, Code: e.Code, Message: e.Message}
}

// decodeRefusal reads a refusal's fields one by one, so a field of a type the agent does not expect (a framework's
// list of messages, say) never hides the code or the server's time. ok is false when the body is not a JSON object.
func decodeRefusal(body []byte) (e protocol.ErrorBody, ok bool) {
	var fields map[string]json.RawMessage
	if json.Unmarshal(body, &fields) != nil || fields == nil {
		return e, false
	}
	_ = json.Unmarshal(fields["code"], &e.Code)
	var serverTime int64
	if raw := fields["serverTime"]; raw != nil && string(raw) != "null" && json.Unmarshal(raw, &serverTime) == nil {
		e.ServerTime = &serverTime
	}
	if json.Unmarshal(fields["message"], &e.Message) != nil {
		var messages []string
		if json.Unmarshal(fields["message"], &messages) == nil {
			e.Message = strings.Join(messages, "; ")
		}
	}
	return e, true
}
