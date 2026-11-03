package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"k8s.io/client-go/kubernetes"

	"github.com/nslookup-io/agent/internal/agent"
	"github.com/nslookup-io/agent/internal/identity"
	"github.com/nslookup-io/agent/internal/install"
	"github.com/nslookup-io/agent/internal/inventory"
	"github.com/nslookup-io/agent/internal/protocol"
	"github.com/nslookup-io/agent/internal/state"
	"github.com/nslookup-io/agent/internal/version"
)

const (
	testSecret  = "Q9w8E7r6T5y4U3i2O1p0A9s8D7f6G5h4J3k2"
	testCode    = "nsj_A1b2C3d4E5f6_" + testSecret
	testAgentID = "3f2b8c1e-7a4d-4e9b-b1c6-5d8e2f0a7c93"
)

type harness struct {
	t      *testing.T
	env    map[string]string
	stdout syncBuffer
	stderr syncBuffer
	cli    *cli
}

// syncBuffer is a bytes.Buffer the test may read while the command writes to it.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func (b *syncBuffer) Bytes() []byte { return []byte(b.String()) }

func (b *syncBuffer) Reset() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.buf.Reset()
}

func newCLI(t *testing.T) *harness {
	h := &harness{t: t, env: map[string]string{}}
	dir := t.TempDir()
	h.cli = &cli{
		getenv:     func(k string) string { return h.env[k] },
		stdout:     &h.stdout,
		stderr:     &h.stderr,
		stateDir:   filepath.Join(dir, "root", "var", "lib", "nslookup-agent"),
		configPath: filepath.Join(dir, "agent.yaml"),
		// No web server installed, an empty machine.
		runner:  fakeRunner{},
		root:    fstest.MapFS{},
		rootDir: filepath.Join(dir, "root"),
		// The test's own user stands for root, who owns the agent's directories.
		dirOwner: os.Getuid(),
		// Never the machine's own Docker socket, nor its cluster.
		dockerSocket: filepath.Join(dir, "docker.sock"),
		kube:         func() (kubernetes.Interface, string, error) { return nil, "", errors.New("no cluster in this test") },
	}
	return h
}

// fakeRunner answers the commands it knows (by their text); every other program is not installed.
type fakeRunner map[string]string

func (f fakeRunner) Run(_ context.Context, c inventory.Command) ([]byte, error) {
	out, ok := f[c.String()]
	if !ok {
		return nil, inventory.ErrNotInstalled
	}
	if strings.HasPrefix(out, "fail:") {
		return nil, errors.New(strings.TrimPrefix(out, "fail:"))
	}
	return []byte(out), nil
}

// parts are the parts of the agent s describes; the test fails when they cannot be made.
func (h *harness) parts(s settings) parts {
	h.t.Helper()
	p, err := h.cli.parts(s)
	if err != nil {
		h.t.Fatal(err)
	}
	return p
}

func (h *harness) run(args ...string) int {
	h.stdout.Reset()
	h.stderr.Reset()
	return h.cli.main(context.Background(), args)
}

// runBriefly runs a command that should exit by itself, stopping it (as SIGTERM does) after 5 seconds if it does not:
// the test then fails.
func (h *harness) runBriefly(args ...string) int {
	h.t.Helper()
	h.stdout.Reset()
	h.stderr.Reset()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	code := h.cli.main(ctx, args)
	if ctx.Err() != nil {
		h.t.Errorf("%v did not exit by itself: %s", args, h.stderr.String())
	}
	return code
}

// runUntil runs a command that waits (run) and stops it, as SIGTERM does, once stderr says stop.
func (h *harness) runUntil(stop string, args ...string) int {
	h.t.Helper()
	h.stdout.Reset()
	h.stderr.Reset()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan int, 1)
	go func() { done <- h.cli.main(ctx, args) }()
	deadline := time.After(10 * time.Second)
	for !strings.Contains(h.stderr.String(), stop) {
		select {
		case code := <-done:
			h.t.Fatalf("exit %d before %q; stderr %s", code, stop, h.stderr.String())
		case <-deadline:
			h.t.Fatalf("no %q; stderr %s", stop, h.stderr.String())
		case <-time.After(5 * time.Millisecond):
		}
	}
	cancel()
	select {
	case code := <-done:
		return code
	case <-deadline:
		h.t.Fatal("the command did not stop")
		return -1
	}
}

func (h *harness) writeConfig(text string) {
	h.t.Helper()
	if err := os.WriteFile(h.cli.configPath, []byte(text), 0o644); err != nil {
		h.t.Fatal(err)
	}
}

// settingsOf parses args for cmd the way the command does and resolves them.
func (h *harness) settingsOf(cmd string, args ...string) (settings, []string, error) {
	o, positional, err := parseFlags(cmd, args)
	if err != nil {
		return settings{}, nil, err
	}
	s, err := h.cli.resolve(o)
	return s, positional, err
}

func TestFlagsTakeTheirValueAfterAnEqualsSignOrAsTheNextArgument(t *testing.T) {
	h := newCLI(t)
	for _, args := range [][]string{
		{"--name=-rf", "--server=https://agents.example.test", "--mode=docker", testCode},
		{"--name", "-rf", "--server", "https://agents.example.test", "--mode", "docker", testCode},
		{testCode, "--name", "-rf", "--server=https://agents.example.test", "-mode", "docker"},
		{"--name=-rf", testCode, "--server", "https://agents.example.test/", "--mode=docker"},
		{"--name=-rf", "--server", "https://agents.example.test", "--mode=docker", "--", testCode},
	} {
		s, positional, err := h.settingsOf("join", args...)
		if err != nil {
			t.Errorf("%q: %v", args, err)
			continue
		}
		if s.name == nil || *s.name != "-rf" || s.server != "https://agents.example.test" || s.kind != protocol.KindDocker || !reflect.DeepEqual(positional, []string{testCode}) {
			t.Errorf("%q: name %v, server %q, kind %q, arguments %q", args, s.name, s.server, s.kind, positional)
		}
	}
}

func TestEveryFlagOfRun(t *testing.T) {
	h := newCLI(t)
	s, positional, err := h.settingsOf("run", "--join", "  "+testCode+"\n", "--mode=kubernetes", "--namespaces", "web, shop", "--name=edge 1")
	if err != nil || len(positional) != 0 {
		t.Fatalf("%v, %q", err, positional)
	}
	if s.join != testCode || s.kind != protocol.KindKubernetes || !reflect.DeepEqual(s.namespaces, []string{"web", "shop"}) || *s.name != "edge 1" || s.server != "" {
		t.Errorf("settings %+v", s)
	}
}

func TestTheEnvironmentCountsWhenAFlagIsNotGivenAndAgentYAMLWhenNeitherIs(t *testing.T) {
	h := newCLI(t)
	h.writeConfig("server: https://config.example.test\nname: from-config\n")
	s, _, err := h.settingsOf("run")
	if err != nil || s.server != "https://config.example.test" || *s.name != "from-config" || s.join != "" {
		t.Fatalf("agent.yaml: %+v, %v", s, err)
	}

	h.env = map[string]string{"NSL_SERVER": "https://env.example.test", "NSL_NAME": "from-env", "NSL_JOIN": " " + testCode + " ", "NSL_NAMESPACES": "web"}
	s, _, err = h.settingsOf("run", "--mode", "kubernetes")
	if err != nil || s.server != "https://env.example.test" || *s.name != "from-env" || s.join != testCode || !reflect.DeepEqual(s.namespaces, []string{"web"}) {
		t.Fatalf("environment: %+v, %v", s, err)
	}

	s, _, err = h.settingsOf("run", "--mode", "kubernetes", "--server=https://flag.example.test", "--name=from-flag", "--join="+testCode, "--namespaces=shop")
	if err != nil || s.server != "https://flag.example.test" || *s.name != "from-flag" || !reflect.DeepEqual(s.namespaces, []string{"shop"}) {
		t.Fatalf("flags: %+v, %v", s, err)
	}
}

func TestAnnotationsComeFromTheFlagOrTheEnvironmentInKubernetesMode(t *testing.T) {
	h := newCLI(t)
	if s, _, err := h.settingsOf("run", "--mode=kubernetes"); err != nil || s.annotations {
		t.Fatalf("default: %+v, %v", s, err)
	}
	h.env = map[string]string{"NSL_ANNOTATIONS": "true"}
	if s, _, err := h.settingsOf("run", "--mode=kubernetes"); err != nil || !s.annotations {
		t.Fatalf("environment: %+v, %v", s, err)
	}
	if s, _, err := h.settingsOf("run", "--mode=kubernetes", "--annotations=false"); err != nil || s.annotations {
		t.Fatalf("a flag counts first: %+v, %v", s, err)
	}
	h.env = nil
	if s, _, err := h.settingsOf("run", "--mode=kubernetes", "--annotations=true"); err != nil || !s.annotations {
		t.Fatalf("flag: %+v, %v", s, err)
	}
	// Off is allowed anywhere: the chart-less default needs no mode.
	if s, _, err := h.settingsOf("run", "--annotations=false"); err != nil || s.annotations {
		t.Fatalf("off in host mode: %+v, %v", s, err)
	}
}

// The image sets NSL_MODE=docker; the Helm chart runs it with --mode=kubernetes.
func TestTheModeComesFromNSL_MODEWhenNoFlagGivesIt(t *testing.T) {
	h := newCLI(t)
	h.env = map[string]string{"NSL_MODE": " docker\n"}
	if s, _, err := h.settingsOf("run"); err != nil || s.kind != protocol.KindDocker {
		t.Fatalf("NSL_MODE: %+v, %v", s, err)
	}
	if s, _, err := h.settingsOf("run", "--mode=kubernetes"); err != nil || s.kind != protocol.KindKubernetes {
		t.Fatalf("--mode over NSL_MODE: %+v, %v", s, err)
	}
	h.env = map[string]string{"NSL_MODE": "  "}
	if s, _, err := h.settingsOf("run"); err != nil || s.kind != protocol.KindHost {
		t.Fatalf("a blank NSL_MODE: %+v, %v", s, err)
	}
}

func TestDefaults(t *testing.T) {
	h := newCLI(t)
	s, _, err := h.settingsOf("run")
	if err != nil || s.server != "" || s.name != nil || s.kind != protocol.KindHost || s.namespaces != nil || s.cfg.Docker.Signal != "HUP" {
		t.Errorf("%+v, %v", s, err)
	}
}

func TestBadValuesAreRefusedNamingWhereTheyCameFrom(t *testing.T) {
	cases := []struct {
		name string
		env  map[string]string
		yaml string
		args []string
		want string
	}{
		{"an http server", nil, "", []string{"run", "--server=http://agents.example.test"}, "--server must use https://"},
		{"a server with a path", nil, "", []string{"run", "--server", "https://agents.example.test/agent/v1"}, "--server must be an origin"},
		{"a server with a password", nil, "", []string{"run", "--server=https://u:p@agents.example.test"}, "--server must be an origin"},
		{"an empty server", nil, "", []string{"run", "--server="}, "--server is empty"},
		{"NSL_SERVER", map[string]string{"NSL_SERVER": "http://agents.example.test"}, "", []string{"run"}, "NSL_SERVER must use https://"},
		{"agent.yaml's server", nil, "server: http://agents.example.test\n", []string{"run"}, "agent.yaml: line 1: server: must use https://"},
		{"a long name", nil, "", []string{"run", "--name=" + strings.Repeat("a", 101)}, "--name must be at most 100 characters"},
		{"NSL_NAME", map[string]string{"NSL_NAME": "a\nb"}, "", []string{"run"}, "NSL_NAME must not hold control characters"},
		{"a mode", nil, "", []string{"run", "--mode=vm"}, "--mode must be host, docker or kubernetes"},
		{"an empty mode", nil, "", []string{"run", "--mode="}, "--mode must be host, docker or kubernetes"},
		{"NSL_MODE", map[string]string{"NSL_MODE": "vm"}, "", []string{"run"}, "NSL_MODE must be host, docker or kubernetes"},
		{"namespaces outside kubernetes", nil, "", []string{"run", "--namespaces=web"}, "--namespaces is for --mode kubernetes only"},
		{"NSL_NAMESPACES outside kubernetes", map[string]string{"NSL_NAMESPACES": "web"}, "", []string{"run", "--mode=docker"}, "NSL_NAMESPACES is for --mode kubernetes only"},
		{"annotations outside kubernetes", nil, "", []string{"run", "--annotations=true"}, "--annotations is for --mode kubernetes only"},
		{"NSL_ANNOTATIONS outside kubernetes", map[string]string{"NSL_ANNOTATIONS": "true"}, "", []string{"run", "--mode=host"}, "NSL_ANNOTATIONS is for --mode kubernetes only"},
		{"a bad NSL_ANNOTATIONS", map[string]string{"NSL_ANNOTATIONS": "yes"}, "", []string{"run", "--mode=kubernetes"}, "NSL_ANNOTATIONS: yes is not true or false"},
		{"a bad namespace", nil, "", []string{"run", "--mode=kubernetes", "--namespaces=Web"}, `--namespaces: "Web" is not a Kubernetes namespace name`},
		{"NSL_FOLDER_ROOT outside docker", map[string]string{"NSL_FOLDER_ROOT": "/srv/certs"}, "", []string{"run"}, "NSL_FOLDER_ROOT is for --mode docker only"},
		{"NSL_RELOAD_CONTAINER outside docker", map[string]string{"NSL_RELOAD_CONTAINER": "nginx"}, "", []string{"run", "--mode=kubernetes"}, "NSL_RELOAD_CONTAINER is for --mode docker only"},
		{"NSL_RELOAD_SIGNAL outside docker", map[string]string{"NSL_RELOAD_SIGNAL": "HUP"}, "", []string{"run"}, "NSL_RELOAD_SIGNAL is for --mode docker only"},
		{"a relative NSL_FOLDER_ROOT", map[string]string{"NSL_FOLDER_ROOT": "certs"}, "", []string{"run", "--mode=docker"}, "NSL_FOLDER_ROOT must be an absolute path"},
		{"a bad NSL_RELOAD_CONTAINER", map[string]string{"NSL_RELOAD_CONTAINER": "nginx,../x"}, "", []string{"run", "--mode=docker"}, `NSL_RELOAD_CONTAINER: "../x" is not a container name`},
		{"a killing NSL_RELOAD_SIGNAL", map[string]string{"NSL_RELOAD_SIGNAL": "KILL"}, "", []string{"run", "--mode=docker"}, "NSL_RELOAD_SIGNAL: KILL is not a signal the agent sends"},
		{"agent.yaml's signal", nil, "docker:\n  signal: TERM\n", []string{"run", "--mode=docker"}, "agent.yaml: line 2: docker.signal: TERM is not a signal the agent sends"},
		{"an unknown flag", nil, "", []string{"run", "--sever=https://agents.example.test"}, "flag provided but not defined: -sever"},
		{"a flag without its value", nil, "", []string{"run", "--name"}, "flag needs an argument: -name"},
		{"an argument to run", nil, "", []string{"run", testCode}, "run takes no arguments"},
		{"join without a code", nil, "", []string{"join"}, "join needs a join code"},
		{"join with two codes", nil, "", []string{"join", testCode, testCode}, "join takes one join code"},
		{"--join on join", nil, "", []string{"join", "--join=" + testCode}, "flag provided but not defined: -join"},
		{"a missing --config", nil, "", []string{"run", "--config=/nonexistent/agent.yaml"}, "/nonexistent/agent.yaml"},
		{"an unknown command", nil, "", []string{"start"}, `unknown command "start"`},
		{"no command", nil, "", nil, "Usage:"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newCLI(t)
			if c.env != nil {
				h.env = c.env
			}
			if c.yaml != "" {
				h.writeConfig(c.yaml)
			}
			if code := h.run(c.args...); code != 2 {
				t.Errorf("exit %d, want 2; stderr %s", code, h.stderr.String())
			}
			if !strings.Contains(h.stderr.String(), c.want) {
				t.Errorf("stderr %q does not contain %q", h.stderr.String(), c.want)
			}
			if _, err := os.Stat(h.cli.stateDir); !errors.Is(err, os.ErrNotExist) {
				t.Error("something was written")
			}
		})
	}
}

func TestHelpAndVersion(t *testing.T) {
	h := newCLI(t)
	for _, args := range [][]string{{"help"}, {"--help"}, {"-h"}, {"run", "--help"}} {
		if code := h.run(args...); code != 0 || !strings.Contains(h.stdout.String()+h.stderr.String(), "--flag=value") {
			t.Errorf("%q: exit %d, out %q", args, code, h.stdout.String()+h.stderr.String())
		}
	}
	if code := h.run("version"); code != 0 || h.stdout.String() != "nslookup-agent "+version.Version+"\n" {
		t.Errorf("version: exit %d, %q", code, h.stdout.String())
	}
}

// engine is the server for the commands: it joins with the test code and answers heartbeats with heartbeat() (by
// default the agent's removal, signed as the server signs it).
type engine struct {
	srv       *httptest.Server
	serverKey ed25519.PrivateKey
	heartbeat func(w http.ResponseWriter, r *http.Request)

	mu    sync.Mutex
	joins []protocol.JoinRequest
	beats int
}

func newEngine(t *testing.T) *engine {
	_, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	e := &engine{serverKey: key}
	e.heartbeat = func(w http.ResponseWriter, r *http.Request) {
		e.answer(w, r, http.StatusForbidden, protocol.RemovedBody)
	}
	e.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		e.mu.Lock()
		defer e.mu.Unlock()
		switch r.URL.Path {
		case "/agent/v1/join":
			var req protocol.JoinRequest
			_ = json.Unmarshal(body, &req)
			e.joins = append(e.joins, req)
			answer, _ := protocol.MarshalBody(protocol.JoinResponse{
				AgentID: testAgentID, ServerSignPublicKey: protocol.EncodeB64URL(key.Public().(ed25519.PublicKey)),
				PollSeconds: 60, MinVersion: "1.0.0", LatestVersion: "1.0.0",
			})
			w.Header().Set(protocol.HeaderJoinMAC, protocol.JoinMAC(testSecret, answer))
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write(answer)
		case "/agent/v1/heartbeat":
			e.beats++
			e.heartbeat(w, r)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(e.srv.Close)
	return e
}

// answer answers the signed request r with status and body, signed with the engine's key.
func (e *engine) answer(w http.ResponseWriter, r *http.Request, status int, body string) {
	sig, err := protocol.SignAnswer(e.serverKey, protocol.AnswerParts{Status: status, AgentID: r.Header.Get(protocol.HeaderAgent), Method: r.Method,
		PathWithQuery: r.URL.RequestURI(), RequestNonce: r.Header.Get(protocol.HeaderNonce), Body: []byte(body)})
	if err == nil {
		w.Header().Set(protocol.HeaderServerSignature, sig)
	}
	w.WriteHeader(status)
	_, _ = io.WriteString(w, body)
}

// The server rolls its signing key over: the agent trusts the keys a heartbeat answer lists, keeps them in its identity,
// and goes on trusting them after a restart.
func TestTheServersNewKeysAreKeptInTheIdentity(t *testing.T) {
	h := newCLI(t)
	e := newEngine(t)
	_, next, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	keys := []string{protocol.EncodeB64URL(e.serverKey.Public().(ed25519.PublicKey)), protocol.EncodeB64URL(next.Public().(ed25519.PublicKey))}
	e.heartbeat = func(w http.ResponseWriter, r *http.Request) {
		body, _ := protocol.MarshalBody(protocol.HeartbeatResponse{Now: time.Now().Unix(), PollSeconds: 60, ServerSignPublicKeys: keys})
		e.answer(w, r, http.StatusOK, string(body))
	}
	h.env["NSL_JOIN"] = testCode
	h.env["NSL_SERVER"] = e.srv.URL
	if code := h.runUntil("the server's signing keys changed", "run", "--mode=docker"); code != 0 {
		t.Fatalf("exit %d: %s", code, h.stderr.String())
	}
	id, err := (identity.FileStore{Dir: filepath.Join(h.cli.stateDir, "identity")}).Load()
	if err != nil {
		t.Fatal(err)
	}
	if got := id.TrustedServerKeys(); len(got) != 2 || !got[1].Equal(next.Public()) {
		t.Fatalf("trusts %x", got)
	}

	// Started again after the rollover: answers signed with the next key are the server's.
	e.mu.Lock()
	e.serverKey = next
	e.heartbeat = func(w http.ResponseWriter, r *http.Request) {
		e.answer(w, r, http.StatusForbidden, protocol.RemovedBody)
	}
	e.mu.Unlock()
	if code := h.runUntil("removed this agent", "run", "--mode=docker"); code != 0 {
		t.Fatalf("exit %d: %s", code, h.stderr.String())
	}
}

// A removal the server did not sign (a proxy could send it) never stops the agent: it backs off and heartbeats again.
func TestAnUnsignedRemovalNeverStopsTheAgent(t *testing.T) {
	h := newCLI(t)
	e := newEngine(t)
	e.heartbeat = func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, protocol.RemovedBody)
	}
	h.env["NSL_JOIN"] = testCode
	h.env["NSL_SERVER"] = e.srv.URL
	if code := h.runUntil("the heartbeat failed", "run", "--mode=docker"); code != 0 {
		t.Fatalf("exit %d: %s", code, h.stderr.String())
	}
	if strings.Contains(h.stderr.String(), "removed this agent") || !strings.Contains(h.stderr.String(), "403 agent_removed") {
		t.Errorf("stderr %s", h.stderr.String())
	}
}

func TestJoinStoresTheIdentityAndNeverJoinsTwice(t *testing.T) {
	h := newCLI(t)
	e := newEngine(t)
	if code := h.run("join", "--server="+e.srv.URL, "--name", "-web", "--mode=docker", "  "+testCode+"\n"); code != 0 {
		t.Fatalf("exit %d: %s", code, h.stderr.String())
	}
	if !strings.Contains(h.stdout.String(), testAgentID) {
		t.Errorf("stdout %q", h.stdout.String())
	}
	if len(e.joins) != 1 || *e.joins[0].Name != "-web" || e.joins[0].Kind != protocol.KindDocker || e.joins[0].Facts.AgentVersion != version.Version {
		t.Errorf("join requests %+v", e.joins)
	}
	identityDir := filepath.Join(h.cli.stateDir, "identity")
	id, err := identity.FileStore{Dir: identityDir}.Load()
	if err != nil || id.AgentID != testAgentID || id.Server != e.srv.URL {
		t.Fatalf("stored %+v, %v", id, err)
	}
	if strings.Contains(h.stdout.String()+h.stderr.String(), testSecret) {
		t.Error("the join code's secret was printed")
	}

	if code := h.run("join", "--server="+e.srv.URL, testCode); code != 1 {
		t.Errorf("a second join: exit %d", code)
	}
	if want := "already joined as " + testAgentID + "; remove " + identityDir + " to join again"; !strings.Contains(h.stderr.String(), want) {
		t.Errorf("stderr %q, want %q", h.stderr.String(), want)
	}
	if len(e.joins) != 1 {
		t.Errorf("%d join requests", len(e.joins))
	}
}

func TestJoinTakesTheCodeFromNSL_JOIN(t *testing.T) {
	h := newCLI(t)
	e := newEngine(t)
	h.env["NSL_JOIN"] = testCode + "\n"
	h.env["NSL_SERVER"] = e.srv.URL
	if code := h.run("join"); code != 0 {
		t.Fatalf("exit %d: %s", code, h.stderr.String())
	}
}

func TestRunJoinsFirstAndARemovedAgentWaitsKeepingItsIdentity(t *testing.T) {
	h := newCLI(t)
	e := newEngine(t)
	h.env["NSL_JOIN"] = testCode
	h.env["NSL_SERVER"] = e.srv.URL
	removed := "nslookup.io removed this agent; it stops now. Remove it with: docker rm -f nslookup-agent, then delete " +
		filepath.Join(h.cli.stateDir, "identity") + " only"
	// A removed agent waits for its stop signal instead of exiting (Docker and Kubernetes would restart it in a loop).
	if code := h.runUntil(removed, "run", "--mode=docker"); code != 0 {
		t.Fatalf("exit %d: %s", code, h.stderr.String())
	}
	if len(e.joins) != 1 || e.beats != 1 {
		t.Errorf("%d joins, %d heartbeats", len(e.joins), e.beats)
	}
	if _, err := (identity.FileStore{Dir: filepath.Join(h.cli.stateDir, "identity")}).Load(); err != nil {
		t.Errorf("the identity is gone: %v", err)
	}

	// Started again: the code is not used again.
	if code := h.runUntil(removed, "run", "--mode=docker"); code != 0 {
		t.Fatalf("exit %d: %s", code, h.stderr.String())
	}
	if len(e.joins) != 1 || e.beats != 2 {
		t.Errorf("%d joins, %d heartbeats", len(e.joins), e.beats)
	}
}

// The hints never remove the whole state directory: certbot/ and previous/ give sites back to certbot and roll back.
func TestRemovalHintsKeepWhatGivesSitesBack(t *testing.T) {
	h := newCLI(t)
	state := h.cli.stateDir
	for kind, uninstall := range map[protocol.AgentKind]string{
		protocol.KindHost:   "systemctl disable --now nslookup-agent",
		protocol.KindDocker: "docker rm -f nslookup-agent",
	} {
		hint := h.parts(settings{kind: kind}).removeHint
		want := uninstall + ", then delete " + filepath.Join(state, "identity") + " only"
		if !strings.HasPrefix(hint, want) {
			t.Errorf("%s: %q, want it to start with %q", kind, hint, want)
		}
		if !strings.Contains(hint, "keep "+filepath.Join(state, "certbot")+" and "+filepath.Join(state, "previous")) {
			t.Errorf("%s: %q does not say to keep certbot/ and previous/", kind, hint)
		}
		if strings.Contains(hint, "rm -rf") || strings.Contains(hint, "delete "+state+" ") || strings.Contains(hint, "volume that holds") {
			t.Errorf("%s: %q removes the whole state directory", kind, hint)
		}
	}
}

// On a server and in Docker the agent starts only when its own directories, and every directory above them, can be
// changed by root (or its own user) only: what it keeps there drives what it writes as root. Kubernetes keeps its state
// on an emptyDir only the agent's pod uses, and is not checked.
func TestTheAgentsOwnDirectoriesAreCheckedBeforeItStarts(t *testing.T) {
	for _, mode := range []string{"host", "docker"} {
		for _, dir := range []string{"", "identity", "../..", "previous", "certbot", "blocked", "reload-owed"} {
			t.Run(mode+" "+dir, func(t *testing.T) {
				h := newCLI(t)
				e := newEngine(t)
				target := filepath.Join(h.cli.stateDir, dir)
				for _, d := range []string{"identity", "previous", "certbot", "blocked", "reload-owed"} {
					if err := os.MkdirAll(filepath.Join(h.cli.stateDir, d), 0o700); err != nil {
						t.Fatal(err)
					}
				}
				if err := os.Chmod(target, 0o770); err != nil {
					t.Fatal(err)
				}
				for _, args := range [][]string{{"join", "--server=" + e.srv.URL, testCode}, {"run", "--server=" + e.srv.URL, "--join=" + testCode}} {
					code := h.runBriefly(append(args, "--mode="+mode)...)
					if code != 1 || !strings.Contains(h.stderr.String(), "can be changed by a user other than") || !strings.Contains(h.stderr.String(), "so it does not start") {
						t.Errorf("%s: exit %d, stderr %s", args[0], code, h.stderr.String())
					}
				}
				if len(e.joins) != 0 || e.beats != 0 {
					t.Errorf("%d joins, %d heartbeats", len(e.joins), e.beats)
				}
			})
		}
	}
	t.Run("kubernetes", func(t *testing.T) {
		h := newCLI(t)
		h.inCluster()
		e := newEngine(t)
		if err := os.MkdirAll(h.cli.stateDir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(h.cli.stateDir, 0o777); err != nil {
			t.Fatal(err)
		}
		if code := h.run("join", "--mode=kubernetes", "--server="+e.srv.URL, testCode); code != 0 {
			t.Fatalf("exit %d: %s", code, h.stderr.String())
		}
	})
}

// Only one agent runs with a state directory: a second copy (a run by hand beside the service, say) exits at once,
// naming the one that runs.
func TestASecondCopyOfTheAgentExitsAtOnce(t *testing.T) {
	h := newCLI(t)
	e := newEngine(t)
	if err := os.MkdirAll(h.cli.stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	lock, err := state.Lock(h.cli.stateDir)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	want := "another nslookup-agent (pid " + strconv.Itoa(os.Getpid()) + ") is running with " + h.cli.stateDir
	if code := h.runBriefly("run", "--server="+e.srv.URL, "--join="+testCode); code != 1 || !strings.Contains(h.stderr.String(), want) ||
		!strings.Contains(h.stderr.String(), "systemctl status nslookup-agent") {
		t.Errorf("exit %d, stderr %s", code, h.stderr.String())
	}
	// In Docker, no word of systemd.
	if code := h.runBriefly("run", "--mode=docker", "--server="+e.srv.URL, "--join="+testCode); code != 1 || !strings.Contains(h.stderr.String(), want) ||
		strings.Contains(h.stderr.String(), "systemctl") {
		t.Errorf("docker: exit %d, stderr %s", code, h.stderr.String())
	}
	if len(e.joins) != 0 || e.beats != 0 {
		t.Errorf("%d joins, %d heartbeats", len(e.joins), e.beats)
	}
}

func TestRunWithoutAnIdentityOrACode(t *testing.T) {
	h := newCLI(t)
	if code := h.run("run"); code != 1 || !strings.Contains(h.stderr.String(), "this agent has not joined yet") {
		t.Errorf("exit %d, stderr %s", code, h.stderr.String())
	}
}

func TestRunRefusesAServerOtherThanTheOneItJoined(t *testing.T) {
	h := newCLI(t)
	e := newEngine(t)
	if code := h.run("join", "--server="+e.srv.URL, testCode); code != 0 {
		t.Fatalf("exit %d: %s", code, h.stderr.String())
	}
	if code := h.run("run", "--server=https://agents.example.test"); code != 1 || !strings.Contains(h.stderr.String(), "this agent joined "+e.srv.URL) {
		t.Errorf("exit %d, stderr %s", code, h.stderr.String())
	}
	if e.beats != 0 {
		t.Errorf("%d heartbeats", e.beats)
	}
}

func TestInventoryPrintsWhatTheAgentReports(t *testing.T) {
	h := newCLI(t)
	if code := h.run("inventory", "--mode=docker"); code != 0 {
		t.Fatalf("exit %d: %s", code, h.stderr.String())
	}
	var out struct {
		Facts     protocol.AgentFacts `json:"facts"`
		Inventory protocol.Inventory  `json:"inventory"`
	}
	if err := json.Unmarshal(h.stdout.Bytes(), &out); err != nil {
		t.Fatalf("%v: %s", err, h.stdout.String())
	}
	if out.Facts.AgentVersion != version.Version || out.Facts.OS == "" || out.Inventory.Sites == nil || len(out.Inventory.Sites) != 0 {
		t.Errorf("printed %s", h.stdout.String())
	}
}

const nginxDump = `# configuration file /etc/nginx/nginx.conf:
http { server { listen 443 ssl; server_name shop.example; ssl_certificate /etc/ssl/shop.pem; ssl_certificate_key /etc/ssl/shop.key; } }
`

func TestInventoryPrintsTheSitesOfThisMachine(t *testing.T) {
	h := newCLI(t)
	h.cli.runner = fakeRunner{"nginx -v": "nginx version: nginx/1.24.0 (Ubuntu)\n", "nginx -T": nginxDump}
	if code := h.run("inventory"); code != 0 {
		t.Fatalf("exit %d: %s", code, h.stderr.String())
	}
	var out struct {
		Facts     protocol.AgentFacts `json:"facts"`
		Inventory protocol.Inventory  `json:"inventory"`
	}
	if err := json.Unmarshal(h.stdout.Bytes(), &out); err != nil {
		t.Fatalf("%v: %s", err, h.stdout.String())
	}
	if !reflect.DeepEqual(out.Facts.WebServers, []protocol.WebServer{{Kind: protocol.WebServerNginx, Version: "1.24.0"}}) {
		t.Errorf("web servers %+v", out.Facts.WebServers)
	}
	// The certificate file is not on this (empty) machine: the site is reported as unreadable, and the log says why.
	sites := out.Inventory.Sites
	if len(sites) != 1 || *sites[0].CertPath != "/etc/ssl/shop.pem" || sites[0].Blocked == nil || *sites[0].Blocked != protocol.BlockedUnreadable {
		t.Errorf("sites %s", h.stdout.String())
	}
	if !strings.Contains(h.stderr.String(), "/etc/ssl/shop.pem cannot be read") {
		t.Errorf("stderr %q", h.stderr.String())
	}

	// Read again (the run loop reads every 5 minutes): the same problems are not logged again.
	h.stderr.Reset()
	read := h.parts(settings{kind: protocol.KindHost}).inventory
	for range 3 {
		if _, err := read(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if n := strings.Count(h.stderr.String(), "cannot be read"); n != 1 {
		t.Errorf("logged %d times: %s", n, h.stderr.String())
	}
}

func TestInventoryFailsWhenAWebServerCannotBeRead(t *testing.T) {
	h := newCLI(t)
	h.cli.runner = fakeRunner{"nginx -T": "fail:nginx -T failed (exit status 1): nginx: [emerg] unknown directive"}
	if code := h.run("inventory"); code != 1 || !strings.Contains(h.stderr.String(), "nginx could not be read") || !strings.Contains(h.stderr.String(), "unknown directive") {
		t.Errorf("exit %d, stderr %s", code, h.stderr.String())
	}
}

// The run loop reads with one reader: a web server failing a later read keeps the sites it had.
func TestAWebServerFailingALaterReadKeepsItsSites(t *testing.T) {
	h := newCLI(t)
	runner := fakeRunner{"nginx -T": nginxDump}
	h.cli.runner = runner
	read := h.parts(settings{kind: protocol.KindHost}).inventory
	if inv, err := read(context.Background()); err != nil || len(inv.Sites) != 1 {
		t.Fatalf("%+v, %v", inv, err)
	}
	runner["nginx -T"] = "fail:nginx -T did not finish within 30s"
	inv, err := read(context.Background())
	if err != nil || len(inv.Sites) != 1 || *inv.Sites[0].CertPath != "/etc/ssl/shop.pem" {
		t.Errorf("%+v, %v", inv, err)
	}
	if !strings.Contains(h.stderr.String(), "its sites are reported as at its last read") {
		t.Errorf("stderr %s", h.stderr.String())
	}
}

func TestAgentYAMLNamesHAProxyConfigurations(t *testing.T) {
	h := newCLI(t)
	h.writeConfig("haproxy:\n  configs: [/etc/haproxy/edge.cfg]\n")
	h.cli.runner = fakeRunner{"haproxy -v": "HAProxy version 2.8.5 2024/04/01\n"}
	h.cli.root = fstest.MapFS{"etc/haproxy/edge.cfg": {Data: []byte("frontend edge\n\tbind :9443 ssl crt /etc/ssl/edge.pem\n")}}
	if code := h.run("inventory"); code != 0 || !strings.Contains(h.stdout.String(), `"certPath": "/etc/ssl/edge.pem"`) {
		t.Errorf("exit %d, stdout %s, stderr %s", code, h.stdout.String(), h.stderr.String())
	}
}

func TestOSVersionFromOSRelease(t *testing.T) {
	for text, want := range map[string]string{
		"NAME=\"Ubuntu\"\nVERSION_ID=\"24.04\"\nPRETTY_NAME=\"Ubuntu 24.04.1 LTS\"\n": "Ubuntu 24.04.1 LTS",
		"NAME=Alpine Linux\nVERSION_ID=3.20.3\n":                                      "Alpine Linux 3.20.3",
		"NAME='Debian GNU/Linux'\n":                                                   "Debian GNU/Linux",
		"PRETTY_NAME=\"a\\tb\x01c\"\n":                                                "abc",
		"":                                                                            "",
	} {
		read := func(string) ([]byte, error) { return []byte(text), nil }
		if got := osVersion(read); got != want {
			t.Errorf("os-release %q: %q, want %q", text, got, want)
		}
	}
	if got := osVersion(func(string) ([]byte, error) { return nil, os.ErrNotExist }); got != "" {
		t.Errorf("no os-release: %q", got)
	}
}

func TestFactsFitTheServersLimits(t *testing.T) {
	long := strings.Repeat("h", 300)
	f := machineFacts(func(string) ([]byte, error) { return []byte("PRETTY_NAME=" + strings.Repeat("v", 300)), nil }, func() (string, error) { return long + "\n", nil })
	if len(f.Hostname) != 253 || len(f.OSVersion) != 128 || f.AgentVersion != version.Version || f.WebServers != nil || f.Kubernetes != nil {
		t.Errorf("facts %+v", f)
	}
}

// selfSigned is a certificate for names with its key, as PEM, and its SHA-256.
func selfSigned(t *testing.T, names ...string) (certPEM, keyPEM []byte, sha string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: names[0]},
		DNSNames:     names,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(der)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), hex.EncodeToString(sum[:])
}

// A host agent installs on the sites it read: the paths are its own inventory's, the work names only the site's key.
func TestAHostAgentInstallsOnTheSitesItRead(t *testing.T) {
	h := newCLI(t)
	oldCert, oldKey, _ := selfSigned(t, "shop.example")
	for _, dir := range []string{"", "/etc", "/etc/ssl"} {
		if err := os.MkdirAll(filepath.Join(h.cli.rootDir, dir), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(filepath.Join(h.cli.rootDir, dir), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for p, data := range map[string][]byte{"/etc/ssl/shop.pem": oldCert, "/etc/ssl/shop.key": oldKey} {
		if err := os.WriteFile(filepath.Join(h.cli.rootDir, p), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	h.cli.root = os.DirFS(h.cli.rootDir)
	h.cli.runner = fakeRunner{"nginx -T": nginxDump, "nginx -t": "", "nginx -s reload": ""}
	cert, key, sha := selfSigned(t, "shop.example")
	apply := func() protocol.InstallResult {
		p := h.parts(settings{kind: protocol.KindHost})
		inv, err := p.inventory(context.Background())
		if err != nil || len(inv.Sites) != 1 {
			t.Fatalf("%+v, %v", inv, err)
		}
		site := inv.Sites[0]
		if disk, err := p.installer.DiskSHA(site); err != nil || disk == "" {
			t.Fatalf("on disk %q, %v", disk, err)
		}
		work := protocol.Work{AssignmentID: "6a1f0c2e-3b4d-4e5f-8a9b-0c1d2e3f4a5b", SiteKey: site.SiteKey, SHA256: sha, Action: protocol.ActionInstall}
		return p.installer.Apply(context.Background(), site, protocol.Bundle{AssignmentID: work.AssignmentID, SHA256: sha, CertPEM: cert, KeyPEM: key}, work)
	}
	// The agent writes only in directories root owns: the test's own are not, unless it runs as root.
	if os.Getuid() != 0 {
		h.cli.dirOwner = 0
		if r := apply(); r.OK || r.Message == nil || !strings.Contains(*r.Message, "which a user other than root can change") {
			t.Fatalf("%+v", r)
		}
	}
	h.cli.dirOwner = os.Getuid()
	r := apply()
	if !r.OK {
		t.Fatalf("%+v", r)
	}
	site := protocol.Site{SiteKey: inventory.SiteKey(protocol.SiteNginx, "/etc/nginx/nginx.conf", "/etc/ssl/shop.pem")}
	if got, _ := os.ReadFile(filepath.Join(h.cli.rootDir, "/etc/ssl/shop.key")); !bytes.Equal(got, key) {
		t.Error("the key was not installed")
	}
	if sets, _ := os.ReadDir(filepath.Join(h.cli.stateDir, "previous", site.SiteKey)); len(sets) != 1 {
		t.Errorf("%d previous sets in the state directory", len(sets))
	}
}

// rootDirs makes the directories of the test machine (each 0755) and lets the agent write in them: the test's own user
// stands for root.
func (h *harness) rootDirs(dirs ...string) {
	h.t.Helper()
	for _, dir := range append([]string{""}, dirs...) {
		if err := os.MkdirAll(filepath.Join(h.cli.rootDir, dir), 0o755); err != nil {
			h.t.Fatal(err)
		}
		if err := os.Chmod(filepath.Join(h.cli.rootDir, dir), 0o755); err != nil {
			h.t.Fatal(err)
		}
	}
	h.cli.dirOwner = os.Getuid()
}

func folderWork(name, sha string) protocol.Work {
	return protocol.Work{AssignmentID: "6a1f0c2e-3b4d-4e5f-8a9b-0c1d2e3f4a5b", SHA256: sha, Action: protocol.ActionInstall, FolderName: &name}
}

// A Docker agent writes folder certificates into /certs (or NSL_FOLDER_ROOT), then signals the containers
// NSL_RELOAD_CONTAINER names with NSL_RELOAD_SIGNAL through the Docker socket, when one is mounted.
func TestADockerAgentWritesFolderCertificates(t *testing.T) {
	h := newCLI(t)
	h.rootDirs("/certs", "/srv/certs")
	h.writeConfig("docker:\n  reloadContainers: [web]\n")
	s, _, err := h.settingsOf("run", "--mode=docker")
	if err != nil || s.folderRoot != "/certs" || !reflect.DeepEqual(s.reloadContainers, []string{"web"}) || s.reloadSignal != "HUP" {
		t.Fatalf("defaults: %+v, %v", s, err)
	}
	h.env = map[string]string{"NSL_FOLDER_ROOT": "/srv/certs/", "NSL_RELOAD_CONTAINER": "nginx, mail", "NSL_RELOAD_SIGNAL": "usr1"}
	s, _, err = h.settingsOf("run", "--mode=docker")
	if err != nil || s.folderRoot != "/srv/certs" || !reflect.DeepEqual(s.reloadContainers, []string{"nginx", "mail"}) || s.reloadSignal != "USR1" {
		t.Fatalf("environment: %+v, %v", s, err)
	}
	p := h.parts(s)
	if p.folder == nil || p.recover == nil || p.installer != nil {
		t.Fatalf("parts %+v", p)
	}
	cert, key, sha := selfSigned(t, "shop.example")
	w := folderWork("shop.example", sha)
	r := p.folder.Apply(context.Background(), w, protocol.Bundle{AssignmentID: w.AssignmentID, SHA256: sha, CertPEM: cert, KeyPEM: key})
	if !r.OK || len(r.Steps) != 3 || r.Steps[2].Name != protocol.StepHookRan || *r.Steps[2].Detail != "no Docker socket mounted; reload nginx, mail yourself" {
		t.Fatalf("%+v", r)
	}
	if got, _ := os.ReadFile(filepath.Join(h.cli.rootDir, "/srv/certs/shop.example/privkey.pem")); !bytes.Equal(got, key) {
		t.Error("the key was not written")
	}
	if disk, err := p.folder.DiskSHA(w); disk != sha || err != nil {
		t.Errorf("on disk %q, %v", disk, err)
	}
	if rec, err := p.recover(context.Background()); rec != nil || err != nil {
		t.Errorf("recover %+v, %v", rec, err)
	}
}

// A Linux server agent has folder mode when agent.yaml sets folder.root, and runs its folder.hook after writing.
func TestAHostAgentWritesFolderCertificatesWhenAgentYAMLSetsARoot(t *testing.T) {
	h := newCLI(t)
	h.rootDirs("/etc/ssl/nslookup")
	h.cli.runner = fakeRunner{"the folder hook": ""}
	cert, key, sha := selfSigned(t, "mail.example")
	w := folderWork("mail.example", sha)
	b := protocol.Bundle{AssignmentID: w.AssignmentID, SHA256: sha, CertPEM: cert, KeyPEM: key}

	p := h.parts(settings{kind: protocol.KindHost})
	if r := p.folder.Apply(context.Background(), w, b); r.OK || r.Message == nil ||
		*r.Message != "folder mode isn't set up on this server: set folder.root in /etc/nslookup-agent/agent.yaml" {
		t.Errorf("no folder.root: %+v", r)
	}

	h.writeConfig("folder:\n  root: /etc/ssl/nslookup\n  hook: systemctl reload postfix\n")
	s, _, err := h.settingsOf("run")
	if err != nil {
		t.Fatal(err)
	}
	p = h.parts(s)
	r := p.folder.Apply(context.Background(), w, b)
	if !r.OK || len(r.Steps) != 3 || r.Steps[2].Name != protocol.StepHookRan || !r.Steps[2].OK {
		t.Fatalf("%+v", r)
	}
	if got, _ := os.ReadFile(filepath.Join(h.cli.rootDir, "/etc/ssl/nslookup/mail.example/fullchain.pem")); !bytes.Equal(got, cert) {
		t.Error("the certificate was not written")
	}
}

// An install the agent was stopped in is finished or undone before the first heartbeat, and its result goes with it.
func TestAnInterruptedInstallIsReportedWithTheFirstHeartbeat(t *testing.T) {
	h := newCLI(t)
	var logs bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logs, nil))
	ledger := agent.FileLedger{Path: filepath.Join(h.cli.stateDir, "installed.json")}
	sha := strings.Repeat("b", 64)
	recovered := &install.Recovered{AssignmentID: "6a1f0c2e-3b4d-4e5f-8a9b-0c1d2e3f4a5b", Installed: true,
		Result: protocol.InstallResult{SHA256: sha, OK: true}}
	recoverInstall(context.Background(), func(context.Context) (*install.Recovered, error) { return recovered, nil }, ledger, log)
	m, err := ledger.Load()
	if err != nil || len(m.Pending) != 1 || m.Pending[0].AssignmentID != recovered.AssignmentID || m.Installed[recovered.AssignmentID] != sha {
		t.Errorf("ledger %+v, %v", m, err)
	}
	if !strings.Contains(logs.String(), "finished an install the agent was stopped in") {
		t.Errorf("log %s", logs.String())
	}

	// A folder certificate whose files are in place but whose reload failed: reported, never remembered as installed.
	logs.Reset()
	owedID, owedSHA := "e4a7b2c9-6d1f-4e3a-8b5c-7f9d0e1a2b3c", strings.Repeat("c", 64)
	failed := "the folder hook failed (exit status 1): postfix: not running"
	recoverInstall(context.Background(), func(context.Context) (*install.Recovered, error) {
		return &install.Recovered{AssignmentID: owedID, ReloadOwed: true,
			Result: protocol.InstallResult{SHA256: owedSHA, Message: &failed}}, nil
	}, ledger, log)
	if m, err := ledger.Load(); err != nil || len(m.Pending) != 2 || m.Installed[owedID] != "" {
		t.Errorf("ledger %+v, %v", m, err)
	}
	if !strings.Contains(logs.String(), "the new files of an install the agent was stopped in are in place, but reloading what uses them failed") ||
		!strings.Contains(logs.String(), "postfix: not running") || strings.Contains(logs.String(), "undid") {
		t.Errorf("log %s", logs.String())
	}

	logs.Reset()
	recoverInstall(context.Background(), func(context.Context) (*install.Recovered, error) {
		return nil, errors.New("pending.json is not valid JSON")
	}, ledger, log)
	if !strings.Contains(logs.String(), "pending.json is not valid JSON") {
		t.Errorf("log %s", logs.String())
	}
}
