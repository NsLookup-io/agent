package inventory

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/fs"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/nslookup-io/agent/internal/protocol"
)

// fakeRunner answers the commands it knows (by their text) and says every other program is not installed.
type fakeRunner map[string]fakeRun

type fakeRun struct {
	out string
	err error
}

func (f fakeRunner) Run(_ context.Context, c Command) ([]byte, error) {
	r, ok := f[c.String()]
	if !ok {
		return nil, fmt.Errorf("%s: %w", c.argv[0], ErrNotInstalled)
	}
	return []byte(r.out), r.err
}

// testCA issues the test certificates.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newCA(t *testing.T, org string) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{Organization: []string{org}, CommonName: org + " Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
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
	return &testCA{cert: cert, key: key}
}

// issue signs a leaf for names (the first is also its common name) and returns it with its key's PEM.
func (ca *testCA) issue(t *testing.T, names ...string) (*x509.Certificate, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: names[0]},
		DNSNames:     names,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour).Truncate(time.Second),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return leaf, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}

func certPEM(c *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
}

// machine is a file system to read, built from fixture trees and the certificates a test writes into it.
type machine struct {
	t     *testing.T
	fs    fstest.MapFS
	ca    *testCA
	leafs map[string]*x509.Certificate
	keys  [][]byte
}

// newMachine copies testdata/<tree>/root of each tree into a new file system.
func newMachine(t *testing.T, trees ...string) *machine {
	t.Helper()
	m := &machine{t: t, fs: fstest.MapFS{}, ca: newCA(t, "Example Trust"), leafs: map[string]*x509.Certificate{}}
	for _, tree := range trees {
		root := filepath.Join("testdata", tree, "root")
		err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			data, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			rel, err := filepath.Rel(root, p)
			if err != nil {
				return err
			}
			m.fs[filepath.ToSlash(rel)] = &fstest.MapFile{Data: data, Mode: 0o644}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return m
}

// file writes text at the absolute path p.
func (m *machine) file(p string, data []byte) {
	m.fs[strings.TrimPrefix(p, "/")] = &fstest.MapFile{Data: data, Mode: 0o644}
}

// cert writes a certificate for names at p (leaf, then the issuer) and its key at keyPath ("" = none).
func (m *machine) cert(p, keyPath string, names ...string) *x509.Certificate {
	leaf, key := m.ca.issue(m.t, names...)
	m.leafs[p] = leaf
	m.keys = append(m.keys, key)
	m.file(p, append(certPEM(leaf), certPEM(m.ca.cert)...))
	if keyPath != "" {
		m.file(keyPath, key)
	}
	return leaf
}

// combined writes HAProxy's combined file at p: the key, the leaf, then the issuer.
func (m *machine) combined(p string, names ...string) *x509.Certificate {
	leaf, key := m.ca.issue(m.t, names...)
	m.leafs[p] = leaf
	m.keys = append(m.keys, key)
	m.file(p, slices.Concat(key, certPEM(leaf), certPEM(m.ca.cert)))
	return leaf
}

// facts is what the inventory should say about the certificate written at p.
func (m *machine) facts(p string) *protocol.CertFacts {
	leaf := m.leafs[p]
	if leaf == nil {
		m.t.Fatalf("no certificate written at %s", p)
	}
	sum := sha256.Sum256(leaf.Raw)
	return &protocol.CertFacts{
		SHA256:   hex.EncodeToString(sum[:]),
		Issuer:   "Example Trust",
		Names:    leaf.DNSNames,
		Serial:   leaf.SerialNumber.Text(16),
		NotAfter: leaf.NotAfter.UTC().Format(time.RFC3339),
	}
}

func str(s string) *string { return &s }

func blocked(b protocol.SiteBlocked) *protocol.SiteBlocked { return &b }

func certbot() *protocol.SiteOwner { o := protocol.OwnerCertbot; return &o }

// tlsSite is the site the inventory should report for a certificate file.
func tlsSite(kind protocol.SiteKind, config string, names []string, cert, key, chain string) protocol.Site {
	s := protocol.Site{
		SiteKey:    SiteKey(kind, config, cert),
		Kind:       kind,
		Names:      names,
		ConfigPath: str(config),
		CertPath:   str(cert),
	}
	if key != "" {
		s.KeyPath = str(key)
	}
	if chain != "" {
		s.ChainPath = str(chain)
	}
	return s
}

// plainSite is the site the inventory should report for names served without HTTPS.
func plainSite(kind protocol.SiteKind, config string, names ...string) protocol.Site {
	return protocol.Site{
		SiteKey:    SiteKey(kind, config, ""),
		Kind:       kind,
		Names:      names,
		ConfigPath: str(config),
		Blocked:    blocked(protocol.BlockedNoHTTPS),
	}
}

// checkSites compares the sites read with the sites wanted (both in site key order), one by one.
func checkSites(t *testing.T, got, want []protocol.Site) {
	t.Helper()
	slices.SortFunc(want, func(a, b protocol.Site) int { return strings.Compare(a.SiteKey, b.SiteKey) })
	if len(got) != len(want) {
		t.Errorf("%d sites, want %d:\n got %s\nwant %s", len(got), len(want), dump(got), dump(want))
		return
	}
	for i := range want {
		g, w := dump(got[i]), dump(want[i])
		if g != w {
			t.Errorf("site %d:\n got %s\nwant %s", i, g, w)
		}
	}
}

func dump(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return err.Error()
	}
	return string(b)
}

var sslDirective = regexp.MustCompile(`(^|[^$])ssl_`)

// noConfigOrKeys fails when the inventory as sent holds configuration text or key material.
func noConfigOrKeys(t *testing.T, m *machine, inv Inventory) {
	t.Helper()
	body, err := protocol.MarshalBody(inv.Wire())
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"BEGIN", "SSLCertificate", "PRIVATE", "proxy_pass", "Rewrite"} {
		if strings.Contains(string(body), s) {
			t.Errorf("the inventory holds %q: %s", s, body)
		}
	}
	// An ssl_ directive; a path reported may name the variable $ssl_server_name.
	if m := sslDirective.FindString(string(body)); m != "" {
		t.Errorf("the inventory holds %q: %s", m, body)
	}
	for _, key := range m.keys {
		// The first line of the key's base64.
		if line := strings.Split(string(key), "\n")[1]; strings.Contains(string(body), line) {
			t.Error("the inventory holds key material")
		}
	}
}

// selfSigned writes at p a certificate for names signed by its own key (issuer = subject: a snakeoil certificate), and
// its key at keyPath.
func (m *machine) selfSigned(p, keyPath string, names ...string) {
	m.t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		m.t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(7),
		Subject:      pkix.Name{CommonName: names[0]},
		DNSNames:     names,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		m.t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		m.t.Fatal(err)
	}
	m.file(p, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	m.file(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
}

// expired writes at p a certificate for names the test CA issued that expired yesterday, and its key at keyPath.
func (m *machine) expired(p, keyPath string, names ...string) {
	m.t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		m.t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(8),
		Subject:      pkix.Name{CommonName: names[0]},
		DNSNames:     names,
		NotBefore:    time.Now().Add(-90 * 24 * time.Hour),
		NotAfter:     time.Now().Add(-24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, m.ca.cert, &key.PublicKey, m.ca.key)
	if err != nil {
		m.t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		m.t.Fatal(err)
	}
	m.file(p, append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), certPEM(m.ca.cert)...))
	m.file(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
}
