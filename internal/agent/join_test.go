package agent

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/nslookup-io/agent/internal/client"
	"github.com/nslookup-io/agent/internal/identity"
	"github.com/nslookup-io/agent/internal/protocol"
)

const (
	testCodeID  = "nsj_A1b2C3d4E5f6"
	testSecret  = "Q9w8E7r6T5y4U3i2O1p0A9s8D7f6G5h4J3k2"
	testCode    = testCodeID + "_" + testSecret
	testAgentID = "3f2b8c1e-7a4d-4e9b-b1c6-5d8e2f0a7c93"
)

// joinEngine answers POST /agent/v1/join like the server: it checks the proof and signs its answer with the code's
// secret (or, with macSecret set, another one).
type joinEngine struct {
	srv       *httptest.Server
	serverKey ed25519.PrivateKey
	status    int
	macSecret string

	mu       sync.Mutex
	requests []protocol.JoinRequest
	proofsOK []bool
}

func newJoinEngine(t *testing.T) *joinEngine {
	t.Helper()
	_, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	e := &joinEngine{serverKey: key, status: http.StatusCreated, macSecret: testSecret}
	e.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req protocol.JoinRequest
		if err := json.Unmarshal(body, &req); err != nil {
			t.Errorf("join body: %v", err)
		}
		e.mu.Lock()
		e.requests = append(e.requests, req)
		e.proofsOK = append(e.proofsOK, r.Header.Get(protocol.HeaderJoinProof) == protocol.JoinProof(testSecret, body))
		e.mu.Unlock()
		if e.status != http.StatusCreated {
			w.WriteHeader(e.status)
			_, _ = io.WriteString(w, `{"code":"join_code_invalid","message":"This join code was already used or has expired. Create a new one in the portal."}`)
			return
		}
		answer, _ := protocol.MarshalBody(protocol.JoinResponse{
			AgentID:             testAgentID,
			ServerSignPublicKey: protocol.EncodeB64URL(e.serverKey.Public().(ed25519.PublicKey)),
			PollSeconds:         60,
			MinVersion:          "1.0.0",
			LatestVersion:       "1.0.0",
		})
		w.Header().Set(protocol.HeaderJoinMAC, protocol.JoinMAC(e.macSecret, answer))
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write(answer)
	}))
	t.Cleanup(e.srv.Close)
	return e
}

func (e *joinEngine) sent() []protocol.JoinRequest {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]protocol.JoinRequest(nil), e.requests...)
}

func joinFacts() protocol.AgentFacts {
	return protocol.AgentFacts{OS: "linux", OSVersion: "Ubuntu 24.04", Arch: "amd64", Hostname: "web-1.example.test", AgentVersion: "1.0.0"}
}

func storeDir(t *testing.T) identity.FileStore {
	return identity.FileStore{Dir: filepath.Join(t.TempDir(), "state", "identity")}
}

func TestJoinStoresTheIdentityAfterTheMACVerifies(t *testing.T) {
	e := newJoinEngine(t)
	store := storeDir(t)
	name := "web-1"

	id, err := Join(context.Background(), store, e.srv.URL, testCode, protocol.KindHost, &name, joinFacts())
	if err != nil {
		t.Fatal(err)
	}
	stored, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if stored.AgentID != testAgentID || stored.Server != e.srv.URL || !stored.ServerSignPublicKey.Equal(e.serverKey.Public()) {
		t.Errorf("stored %+v", stored)
	}
	if !stored.SignKey.Equal(id.SignKey) || !stored.SealKey.Equal(id.SealKey) {
		t.Error("the stored keys are not the ones returned")
	}

	sent := e.sent()
	if len(sent) != 1 || !e.proofsOK[0] {
		t.Fatalf("%d requests, proofs %v", len(sent), e.proofsOK)
	}
	r := sent[0]
	if r.JoinCodeID != testCodeID || r.Kind != protocol.KindHost || r.Name == nil || *r.Name != "web-1" || r.Facts.Hostname != "web-1.example.test" {
		t.Errorf("request %+v", r)
	}
	if r.SignPublicKey != protocol.EncodeB64URL(stored.SignKey.Public().(ed25519.PublicKey)) || r.SealPublicKey != protocol.EncodeB64URL(stored.SealKey.PublicKey().Bytes()) {
		t.Error("the public keys sent are not the stored keys' halves")
	}
}

func TestAJoinAnswerWithAWrongMACStoresNothing(t *testing.T) {
	e := newJoinEngine(t)
	e.macSecret = strings.Repeat("Z", 36)
	store := storeDir(t)

	id, err := Join(context.Background(), store, e.srv.URL, testCode, protocol.KindDocker, nil, joinFacts())
	if !errors.Is(err, client.ErrBadServerSignature) || id != nil {
		t.Fatalf("got %+v, %v; want ErrBadServerSignature", id, err)
	}
	if _, err := os.Stat(store.Dir); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the identity directory exists: %v", err)
	}
	if _, err := store.Load(); !errors.Is(err, identity.ErrNotFound) {
		t.Errorf("load: %v, want ErrNotFound", err)
	}
}

func TestARefusedJoinStoresNothing(t *testing.T) {
	e := newJoinEngine(t)
	e.status = http.StatusGone
	store := storeDir(t)
	if _, err := Join(context.Background(), store, e.srv.URL, testCode, protocol.KindHost, nil, joinFacts()); !errors.Is(err, client.ErrJoinCodeInvalid) {
		t.Fatalf("%v, want ErrJoinCodeInvalid", err)
	}
	if _, err := store.Load(); !errors.Is(err, identity.ErrNotFound) {
		t.Errorf("load: %v, want ErrNotFound", err)
	}
}

func TestJoinNeverReplacesAStoredIdentity(t *testing.T) {
	e := newJoinEngine(t)
	store := storeDir(t)
	if _, err := Join(context.Background(), store, e.srv.URL, testCode, protocol.KindHost, nil, joinFacts()); err != nil {
		t.Fatal(err)
	}
	before, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}

	_, err = Join(context.Background(), store, e.srv.URL, testCode, protocol.KindHost, nil, joinFacts())
	var already *AlreadyJoinedError
	if !errors.As(err, &already) || already.AgentID != testAgentID || err.Error() != "already joined as "+testAgentID {
		t.Fatalf("%v, want AlreadyJoinedError", err)
	}
	if n := len(e.sent()); n != 1 {
		t.Errorf("%d join requests, want only the first", n)
	}
	after, err := store.Load()
	if err != nil || !after.SignKey.Equal(before.SignKey) {
		t.Errorf("the stored identity changed: %v", err)
	}
}

func TestJoinLeavesAnUnreadableIdentityAlone(t *testing.T) {
	e := newJoinEngine(t)
	store := storeDir(t)
	if err := os.MkdirAll(store.Dir, 0o700); err != nil {
		t.Fatal(err)
	}
	broken := filepath.Join(store.Dir, "agent.json")
	if err := os.WriteFile(broken, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Join(context.Background(), store, e.srv.URL, testCode, protocol.KindHost, nil, joinFacts())
	var already *AlreadyJoinedError
	if err == nil || errors.As(err, &already) {
		t.Fatalf("%v, want an error about the stored identity", err)
	}
	if n := len(e.sent()); n != 0 {
		t.Errorf("%d join requests sent", n)
	}
	if data, _ := os.ReadFile(broken); string(data) != "{" {
		t.Errorf("agent.json was replaced: %q", data)
	}
}

func TestAPastedJoinCodeIsTrimmed(t *testing.T) {
	e := newJoinEngine(t)
	if _, err := Join(context.Background(), storeDir(t), e.srv.URL, " \t"+testCode+"\r\n", protocol.KindHost, nil, joinFacts()); err != nil {
		t.Fatal(err)
	}
	if sent := e.sent(); len(sent) != 1 || sent[0].JoinCodeID != testCodeID || !e.proofsOK[0] {
		t.Errorf("sent %+v, proofs %v", sent, e.proofsOK)
	}
}

func TestAMalformedJoinCodeSendsNothing(t *testing.T) {
	e := newJoinEngine(t)
	store := storeDir(t)
	for _, code := range []string{"", testCodeID, testCode + "x", "nsj_A1b2C3d4E5f6 " + testSecret} {
		if _, err := Join(context.Background(), store, e.srv.URL, code, protocol.KindHost, nil, joinFacts()); !errors.Is(err, client.ErrMalformedJoinCode) {
			t.Errorf("%q: %v, want ErrMalformedJoinCode", code, err)
		}
	}
	if n := len(e.sent()); n != 0 {
		t.Errorf("%d join requests sent", n)
	}
}

type failingStore struct{ saves int }

func (s *failingStore) Load() (*identity.Identity, error) { return nil, identity.ErrNotFound }
func (s *failingStore) Save(*identity.Identity) error {
	s.saves++
	return errors.New("read-only file system")
}
func (s *failingStore) SaveServerKeys(*identity.Identity) error {
	return errors.New("read-only file system")
}

func TestASaveThatFailsSaysTheCodeIsSpent(t *testing.T) {
	e := newJoinEngine(t)
	store := &failingStore{}
	_, err := Join(context.Background(), store, e.srv.URL, testCode, protocol.KindHost, nil, joinFacts())
	if err == nil || !strings.Contains(err.Error(), "read-only file system") || !strings.Contains(err.Error(), "join code is spent") || store.saves != 1 {
		t.Errorf("%v (saves %d)", err, store.saves)
	}
}
