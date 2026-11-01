package install

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nslookup-io/agent/internal/inventory"
	"github.com/nslookup-io/agent/internal/protocol"
)

const testAssignment = "6a1f0c2e-3b4d-4e5f-8a9b-0c1d2e3f4a5b"

// fakeRunner answers the commands it knows (by their text) with their error, nil for success; every other program is
// not installed. hooks run before a command answers; a command run with an ended context fails as a real one would.
type fakeRunner struct {
	mu      sync.Mutex
	answers map[string]error
	hooks   map[string]func()
	ran     []string
}

func newRunner(answers map[string]error) *fakeRunner {
	return &fakeRunner{answers: answers, hooks: map[string]func(){}}
}

func (f *fakeRunner) Run(ctx context.Context, c inventory.Command) ([]byte, error) {
	f.mu.Lock()
	f.ran = append(f.ran, c.String())
	hook := f.hooks[c.String()]
	f.mu.Unlock()
	if hook != nil {
		hook()
	}
	f.mu.Lock()
	err, ok := f.answers[c.String()]
	f.mu.Unlock()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if !ok {
		return nil, fmt.Errorf("%s: %w", strings.Fields(c.String())[0], inventory.ErrNotInstalled)
	}
	return nil, err
}

func (f *fakeRunner) set(command string, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.answers[command] = err
}

// commands are what ran, in order.
func (f *fakeRunner) commands() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.ran)
}

func (f *fakeRunner) count(command string) int {
	n := 0
	for _, c := range f.commands() {
		if c == command {
			n++
		}
	}
	return n
}

// nginxOnItsOwn is a machine with nginx and no systemd.
func nginxOnItsOwn() map[string]error {
	return map[string]error{"nginx -t": nil, "nginx -s reload": nil}
}

// testCA issues the test certificates.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

func newCA(t *testing.T) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(48 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &testCA{cert: cert, key: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

// issued is a certificate with its key and chain.
type issued struct {
	leafPEM, keyPEM, chainPEM []byte
	sha                       string
}

var serials struct {
	sync.Mutex
	n int64
}

func (ca *testCA) issue(t *testing.T, names ...string) issued {
	return ca.issueUntil(t, time.Now().Add(24*time.Hour), names...)
}

func (ca *testCA) issueUntil(t *testing.T, notAfter time.Time, names ...string) issued {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serials.Lock()
	serials.n++
	serial := serials.n + 100
	serials.Unlock()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: names[0]},
		DNSNames:     names,
		NotBefore:    time.Now().Add(-48 * time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(der)
	return issued{
		leafPEM:  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		keyPEM:   pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
		chainPEM: ca.pem,
		sha:      hex.EncodeToString(sum[:]),
	}
}

// bundle is what the loop hands the installer for c (its key opened).
func (c issued) bundle() protocol.Bundle {
	return protocol.Bundle{AssignmentID: testAssignment, SHA256: c.sha, CertPEM: c.leafPEM, ChainPEM: c.chainPEM, KeyPEM: bytes.Clone(c.keyPEM)}
}

// machine is a file system root in a temporary directory, the agent's state directory and a Host installing on them.
type machine struct {
	t      *testing.T
	root   string
	state  string
	runner *fakeRunner
	host   *Host
	// chowned are the owner changes asked for: "<path> <uid>:<gid>", path as configured.
	chowned []string
	ca      *testCA
}

func newMachine(t *testing.T, answers map[string]error) *machine {
	t.Helper()
	dir := t.TempDir()
	m := &machine{t: t, root: filepath.Join(dir, "root"), state: filepath.Join(dir, "state"), runner: newRunner(answers), ca: newCA(t)}
	if err := os.Mkdir(m.root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(m.root, 0o755); err != nil {
		t.Fatal(err)
	}
	// The test's own user stands for root: it owns every directory of the machine.
	m.host = &Host{Root: m.root, StateDir: m.state, Runner: m.runner, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), DirOwner: os.Getuid(), localWait: fakeWait(new(fakeClock))}
	m.host.chown = func(path string, uid, gid int) error {
		m.chowned = append(m.chowned, fmt.Sprintf("%s %d:%d", path, uid, gid))
		return nil
	}
	return m
}

func (m *machine) path(p string) string { return filepath.Join(m.root, p) }

// changeableBy is how a refusal names who may change a directory the agent writes in: root, and the agent's own
// user when that is not root (the test's user stands for the agent's).
func (m *machine) changeableBy() string {
	if m.host.DirOwner == 0 {
		return "which a user other than root can change"
	}
	return fmt.Sprintf("which a user other than root or the agent's user (uid %d) can change", m.host.DirOwner)
}

// mkdirs makes the directory p (as configured) and those above it, each 0755 whatever the umask.
func (m *machine) mkdirs(p string) {
	m.t.Helper()
	d := m.root
	for _, part := range strings.Split(strings.Trim(filepath.ToSlash(p), "/"), "/") {
		if part == "" {
			continue
		}
		d = filepath.Join(d, part)
		if err := os.Mkdir(d, 0o755); err != nil && !errors.Is(err, fs.ErrExist) {
			m.t.Fatal(err)
		}
		if err := os.Chmod(d, 0o755); err != nil {
			m.t.Fatal(err)
		}
	}
}

func (m *machine) write(p string, data []byte, mode fs.FileMode) {
	m.t.Helper()
	full := m.path(p)
	m.mkdirs(filepath.Dir(p))
	if err := os.WriteFile(full, data, mode); err != nil {
		m.t.Fatal(err)
	}
	if err := os.Chmod(full, mode); err != nil {
		m.t.Fatal(err)
	}
}

func (m *machine) link(p, target string) {
	m.t.Helper()
	full := m.path(p)
	m.mkdirs(filepath.Dir(p))
	if err := os.Symlink(target, full); err != nil {
		m.t.Fatal(err)
	}
}

func (m *machine) read(p string) []byte {
	m.t.Helper()
	data, err := os.ReadFile(m.path(p))
	if err != nil {
		m.t.Fatal(err)
	}
	return data
}

func (m *machine) mode(p string) fs.FileMode {
	m.t.Helper()
	info, err := os.Lstat(m.path(p))
	if err != nil {
		m.t.Fatal(err)
	}
	return info.Mode()
}

func (m *machine) exists(p string) bool {
	_, err := os.Lstat(m.path(p))
	return err == nil
}

// site makes the site of uses (sharing one certificate file), as the inventory reports it, and gives the host the
// inventory with it and the HAProxy configuration files.
func (m *machine) site(uses ...inventory.Use) protocol.Site {
	m.t.Helper()
	first := uses[0]
	config := first.ConfigPath
	var names []string
	for _, u := range uses {
		config = min(config, u.ConfigPath)
		names = append(names, u.Names...)
	}
	slices.Sort(names)
	kind := protocol.SiteKind(first.Kind)
	cert, key, chain := first.CertPath, first.KeyPath, first.ChainPath
	s := protocol.Site{
		SiteKey:    inventory.SiteKey(kind, config, cert),
		Kind:       kind,
		Names:      slices.Compact(names),
		ConfigPath: &config,
		CertPath:   &cert,
		KeyPath:    &key,
	}
	if chain != "" {
		s.ChainPath = &chain
	}
	m.add(s, uses)
	return s
}

// add gives the host one more site of the inventory.
func (m *machine) add(s protocol.Site, uses []inventory.Use) {
	m.host.mu.Lock()
	inv := inventory.Inventory{Uses: map[string][]inventory.Use{}, HAProxyFiles: []string{"/etc/haproxy/haproxy.cfg"}}
	for k, v := range m.host.uses {
		inv.Uses[k] = v
	}
	m.host.mu.Unlock()
	inv.Uses[s.SiteKey] = uses
	m.host.SetInventory(inv)
}

func installWork(s protocol.Site, sha string) protocol.Work {
	return protocol.Work{AssignmentID: testAssignment, SiteKey: s.SiteKey, SHA256: sha, Action: protocol.ActionInstall}
}

// closedPort is a TCP port of 127.0.0.1 nothing listens on.
func closedPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return port
}

// steps are the result's steps as "name" (ok) or "name!" (failed).
func steps(r protocol.InstallResult) string {
	var out []string
	for _, s := range r.Steps {
		if s.OK {
			out = append(out, string(s.Name))
		} else {
			out = append(out, string(s.Name)+"!")
		}
	}
	return strings.Join(out, " ")
}

func detail(r protocol.InstallResult, name protocol.StepName) string {
	for _, s := range r.Steps {
		if s.Name == name && s.Detail != nil {
			return *s.Detail
		}
	}
	return ""
}

func message(r protocol.InstallResult) string {
	if r.Message == nil {
		return ""
	}
	return *r.Message
}

// leftovers are the files in dir (a configured path) that are not names: temporary files left behind.
func (m *machine) leftovers(dir string, names ...string) []string {
	m.t.Helper()
	entries, err := os.ReadDir(m.path(dir))
	if err != nil {
		m.t.Fatal(err)
	}
	var extra []string
	for _, e := range entries {
		if !slices.Contains(names, e.Name()) {
			extra = append(extra, e.Name())
		}
	}
	return extra
}

// fakeClock is time that only moves when the check sleeps.
type fakeClock struct {
	mu     sync.Mutex
	t      time.Time
	sleeps int
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func fakeWait(c *fakeClock) localWait {
	return localWait{now: c.now, sleep: func(_ context.Context, d time.Duration) {
		c.mu.Lock()
		defer c.mu.Unlock()
		c.t = c.t.Add(d)
		c.sleeps++
	}}
}
