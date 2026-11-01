package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"io/fs"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/nslookup-io/agent/internal/agent"
	"github.com/nslookup-io/agent/internal/config"
	"github.com/nslookup-io/agent/internal/protocol"
	"github.com/nslookup-io/agent/internal/version"
)

// The wire samples (testdata/wire/ at the top of the repository) are request bodies exactly as the agent sends them:
// heartbeats carrying the inventories of the nginx, Apache, HAProxy and Kubernetes fixtures, and install results. The
// server's tests parse them, so a change on either side that the other does not take shows. Write them again with
//
//	go test ./cmd/nslookup-agent -run TestWireSamples -update
var update = flag.Bool("update", false, "write the wire samples in testdata/wire")

const (
	wireDir      = "../../testdata/wire"
	fixturesDir  = "../../internal/inventory/testdata"
	wireAssignID = "9c1d4e7a-2b3f-4a8c-9d6e-0f1a2b3c4d5e"
)

// The samples' certificates are made the same every time: Ed25519 keys from fixed seeds, fixed serials and dates.
var (
	wireNotBefore = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	wireNotAfter  = time.Date(2036, 1, 1, 0, 0, 0, 0, time.UTC)
)

func wireSeed(label string) []byte {
	sum := sha256.Sum256([]byte("nslookup-agent wire sample " + label))
	return sum[:]
}

type wireCA struct {
	key  ed25519.PrivateKey
	cert *x509.Certificate
	pem  []byte
}

func newWireCA(t *testing.T) *wireCA {
	t.Helper()
	key := ed25519.NewKeyFromSeed(wireSeed("ca"))
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{Organization: []string{"Example Trust"}, CommonName: "Example Trust Root"},
		NotBefore:             wireNotBefore,
		NotAfter:              wireNotAfter,
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(nil, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &wireCA{key: key, cert: cert, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

// issue makes the certificate of label for names (the first is its common name) and its key, as PEM.
func (ca *wireCA) issue(t *testing.T, label string, names ...string) (leaf, key []byte, sha string) {
	t.Helper()
	priv := ed25519.NewKeyFromSeed(wireSeed(label))
	tmpl := &x509.Certificate{
		SerialNumber: new(big.Int).SetBytes(wireSeed("serial " + label)[:16]),
		Subject:      pkix.Name{CommonName: names[0]},
		DNSNames:     names,
		NotBefore:    wireNotBefore,
		NotAfter:     wireNotAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(nil, tmpl, ca.cert, priv.Public(), ca.key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(der)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
		hex.EncodeToString(sum[:])
}

// wireMachine is a file system of fixture trees (testdata/<tree>/root of package inventory) and certificates.
type wireMachine struct {
	t  *testing.T
	fs fstest.MapFS
	ca *wireCA
}

func newWireMachine(t *testing.T, trees ...string) *wireMachine {
	t.Helper()
	m := &wireMachine{t: t, fs: fstest.MapFS{}, ca: newWireCA(t)}
	for _, tree := range trees {
		root := filepath.Join(fixturesDir, tree, "root")
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

func (m *wireMachine) file(p string, data []byte) {
	m.fs[strings.TrimPrefix(p, "/")] = &fstest.MapFile{Data: data, Mode: 0o644}
}

// cert writes the certificate of names at p (the leaf, then the issuer) and its key at keyPath ("" = none).
func (m *wireMachine) cert(p, keyPath string, names ...string) {
	leaf, key, _ := m.ca.issue(m.t, p, names...)
	m.file(p, append(leaf, m.ca.pem...))
	if keyPath != "" {
		m.file(keyPath, key)
	}
}

// combined writes HAProxy's combined file at p: the key, the leaf, then the issuer.
func (m *wireMachine) combined(p string, names ...string) {
	leaf, key, _ := m.ca.issue(m.t, p, names...)
	m.file(p, bytes.Join([][]byte{key, leaf, m.ca.pem}, nil))
}

func fixture(t *testing.T, p string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(fixturesDir, p))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// wireFacts are the facts every sample carries (the machine's own would differ from one test run to the next).
func wireFacts(kind protocol.AgentKind) func(context.Context) protocol.AgentFacts {
	return func(context.Context) protocol.AgentFacts {
		f := protocol.AgentFacts{OS: "linux", OSVersion: "Debian GNU/Linux 12 (bookworm)", Arch: "amd64", Hostname: "web-1", AgentVersion: "1.0.0"}
		switch kind {
		case protocol.KindHost:
			f.WebServers = []protocol.WebServer{{Kind: protocol.WebServerNginx, Version: "1.22.1"}, {Kind: protocol.WebServerApache, Version: "2.4.62"},
				{Kind: protocol.WebServerHAProxy, Version: "2.6.12"}}
		case protocol.KindKubernetes:
			class := "nginx"
			f.Kubernetes = &protocol.KubernetesFacts{Version: "1.31.2", IngressController: &class}
		}
		return f
	}
}

// wireServer stands for the server in a run of the loop: it answers heartbeats with work, hands out bundles, takes
// results, and ends the run at the loop's first wait (or its waits-th).
type wireServer struct {
	cancel  context.CancelFunc
	waits   int
	work    []protocol.Work
	bundles map[string]protocol.Bundle
	beats   []protocol.HeartbeatRequest
	results []protocol.InstallResult
}

func (s *wireServer) Heartbeat(_ context.Context, beat protocol.HeartbeatRequest) (*protocol.HeartbeatResponse, error) {
	s.beats = append(s.beats, beat)
	return &protocol.HeartbeatResponse{Now: wireNotBefore.Unix(), PollSeconds: 60, MinVersion: "1.0.0", LatestVersion: "1.0.0", Work: s.work}, nil
}

func (s *wireServer) Bundle(_ context.Context, id string) (*protocol.Bundle, error) {
	b := s.bundles[id]
	b.KeyPEM = bytes.Clone(b.KeyPEM)
	return &b, nil
}

func (s *wireServer) Result(_ context.Context, _ string, r protocol.InstallResult) error {
	s.results = append(s.results, r)
	return nil
}

func (s *wireServer) Now() time.Time { return wireNotBefore }

func (s *wireServer) Sleep(ctx context.Context, _ time.Duration) error {
	if s.waits--; s.waits <= 0 {
		s.cancel()
	}
	return ctx.Err()
}

// runLoop runs the agent's loop with parts p (facts fixed) for one heartbeat and its work.
func runLoop(t *testing.T, p parts, kind protocol.AgentKind, s *wireServer) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s.cancel = cancel
	loop := &agent.Loop{Client: s, Inventory: p.inventory, Facts: wireFacts(kind), Installer: p.installer, Folder: p.folder, Clock: s}
	if err := loop.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if len(s.beats) == 0 {
		t.Fatal("no heartbeat")
	}
}

// sample writes (with -update) or checks the sample name: body exactly as the agent sends it.
func sample(t *testing.T, name string, payload any) {
	t.Helper()
	body, err := protocol.MarshalBody(payload)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(wireDir, name)
	if *update {
		if err := os.MkdirAll(wireDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, body, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("%v (write the samples with -update)", err)
	}
	if !bytes.Equal(body, want) {
		t.Errorf("%s is not what the agent sends now (write the samples again with -update, and give them to the server's tests):\n got %s\nwant %s", name, body, want)
	}
}

func TestWireSamples(t *testing.T) {
	saved := version.Version
	version.Version = "1.0.0"
	defer func() { version.Version = saved }()

	t.Run("heartbeat nginx", func(t *testing.T) {
		m := newWireMachine(t, "certbot")
		m.cert("/etc/ssl/fallback/fallback.pem", "/etc/ssl/fallback/fallback.key", "fallback.example")
		m.cert("/etc/ssl/acme/fullchain.pem", "/etc/ssl/acme/privkey.pem", "shop.example", "www.shop.example", "api.shop.example")
		m.cert("/etc/letsencrypt/live/blog.example/fullchain.pem", "/etc/letsencrypt/live/blog.example/privkey.pem", "blog.example")
		m.cert("/etc/letsencrypt/live/old.example/fullchain.pem", "/etc/letsencrypt/live/old.example/privkey.pem", "old.example", "www.old.example")
		// The server whose server_name holds a regular expression: the site also has its certificate's names.
		m.cert("/etc/ssl/app/fullchain.pem", "/etc/ssl/app/privkey.pem", "app.example.test", "*.app.example.test")
		h := newCLI(t)
		h.cli.root, h.cli.runner = m.fs, fakeRunner{"nginx -T": fixture(t, "nginx/nginx-T.txt")}
		s := &wireServer{}
		runLoop(t, h.parts(settings{kind: protocol.KindHost}), protocol.KindHost, s)
		sample(t, "heartbeat-nginx.json", s.beats[0])
	})

	t.Run("heartbeat apache", func(t *testing.T) {
		m := newWireMachine(t, "apache", "certbot")
		m.cert("/etc/ssl/shop/cert.pem", "/etc/ssl/shop/privkey.pem", "shop.example", "www.shop.example", "api.shop.example")
		m.file("/etc/ssl/shop/chain.pem", m.ca.pem)
		m.cert("/etc/letsencrypt/live/blog.example/fullchain.pem", "/etc/letsencrypt/live/blog.example/privkey.pem", "blog.example")
		m.combined("/etc/apache2/ssl/intranet.pem", "intranet.example")
		h := newCLI(t)
		h.cli.root, h.cli.runner = m.fs, fakeRunner{"apachectl -t -D DUMP_VHOSTS -D DUMP_RUN_CFG": fixture(t, "apache/dump-vhosts.txt")}
		s := &wireServer{}
		runLoop(t, h.parts(settings{kind: protocol.KindHost}), protocol.KindHost, s)
		sample(t, "heartbeat-apache.json", s.beats[0])
	})

	t.Run("heartbeat haproxy", func(t *testing.T) {
		m := newWireMachine(t, "haproxy")
		m.combined("/etc/haproxy/certs/shop.pem", "shop.example", "www.shop.example")
		m.combined("/etc/haproxy/tenants/a.pem", "a.tenants.example")
		m.cert("/etc/haproxy/tenants/b.pem", "/etc/haproxy/tenants/b.pem.key", "b.tenants.example")
		m.file("/etc/haproxy/tenants/b.pem.ocsp", []byte("not a certificate"))
		m.combined("/etc/ssl/haproxy/api.pem", "api.shop.example")
		m.combined("/etc/haproxy/certs/mail.pem", "mail.example")
		m.combined("/etc/ssl/edge/edge.pem", "edge.example")
		h := newCLI(t)
		h.cli.root, h.cli.runner = m.fs, fakeRunner{"haproxy -v": "HAProxy version 2.6.12-1+deb12u1 2023/12/16 - https://haproxy.org/\n"}
		cfg := config.Default()
		cfg.HAProxy.Configs = []string{"/etc/haproxy/extra"}
		s := &wireServer{}
		runLoop(t, h.parts(settings{kind: protocol.KindHost, cfg: cfg}), protocol.KindHost, s)
		sample(t, "heartbeat-haproxy.json", s.beats[0])
	})

	t.Run("heartbeat kubernetes", func(t *testing.T) {
		ca := newWireCA(t)
		leaf, key, _ := ca.issue(t, "shop-tls", "shop.example.test", "www.shop.example.test")
		class := "nginx"
		ingress := func(ns, name string, tls []networkingv1.IngressTLS, hosts ...string) *networkingv1.Ingress {
			ing := &networkingv1.Ingress{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name}, Spec: networkingv1.IngressSpec{IngressClassName: &class, TLS: tls}}
			for _, h := range hosts {
				ing.Spec.Rules = append(ing.Spec.Rules, networkingv1.IngressRule{Host: h})
			}
			return ing
		}
		cs := fake.NewClientset(
			ingress("shop", "storefront", []networkingv1.IngressTLS{{Hosts: []string{"shop.example.test", "www.shop.example.test"}, SecretName: "shop-tls"}},
				"shop.example.test", "www.shop.example.test"),
			&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "shop-tls"}, Type: corev1.SecretTypeTLS,
				Data: map[string][]byte{corev1.TLSCertKey: append(leaf, ca.pem...), corev1.TLSPrivateKeyKey: key}},
			// Served without TLS: a site whose secret the agent makes when it is taken over.
			ingress("web", "status", nil, "status.example.test"),
			// A tls entry whose secret is not there yet.
			ingress("web", "docs", []networkingv1.IngressTLS{{Hosts: []string{"docs.example.test"}, SecretName: "docs-tls"}}, "docs.example.test"),
		)
		h := newCLI(t)
		h.cli.kube = func() (kubernetes.Interface, string, error) { return cs, "agents", nil }
		s := &wireServer{}
		runLoop(t, h.parts(settings{kind: protocol.KindKubernetes}), protocol.KindKubernetes, s)
		sample(t, "heartbeat-kubernetes.json", s.beats[0])
	})

	// The results: of an install on a server (its configuration test failing: the previous files go back), of a folder
	// certificate written in Docker, and the report of a certificate already in place.
	ca := newWireCA(t)
	oldCert, oldKey, oldSHA := ca.issue(t, "result old", "shop.example")
	newCert, newKey, newSHA := ca.issue(t, "result new", "shop.example")
	host := func(t *testing.T) *harness {
		h := newCLI(t)
		h.rootDirs("/etc", "/etc/ssl")
		for p, data := range map[string][]byte{"/etc/ssl/shop.pem": append(bytes.Clone(oldCert), ca.pem...), "/etc/ssl/shop.key": oldKey} {
			if err := os.WriteFile(filepath.Join(h.cli.rootDir, p), data, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		h.cli.root = os.DirFS(h.cli.rootDir)
		return h
	}
	siteKey := func(t *testing.T, p parts) string {
		inv, err := p.inventory(context.Background())
		if err != nil || len(inv.Sites) != 1 {
			t.Fatalf("%+v, %v", inv, err)
		}
		return inv.Sites[0].SiteKey
	}
	t.Run("result failed", func(t *testing.T) {
		h := host(t)
		h.cli.runner = fakeRunner{"nginx -T": nginxDump, "nginx -t": "fail:nginx: [emerg] cannot load certificate \"/etc/ssl/shop.pem\"", "nginx -s reload": ""}
		p := h.parts(settings{kind: protocol.KindHost})
		s := &wireServer{
			work:    []protocol.Work{{AssignmentID: wireAssignID, SiteKey: siteKey(t, p), SHA256: newSHA, Action: protocol.ActionInstall}},
			bundles: map[string]protocol.Bundle{wireAssignID: {AssignmentID: wireAssignID, SHA256: newSHA, CertPEM: newCert, ChainPEM: ca.pem, KeyPEM: newKey}},
		}
		runLoop(t, p, protocol.KindHost, s)
		if len(s.results) != 1 || s.results[0].OK {
			t.Fatalf("results %+v", s.results)
		}
		sample(t, "result-failed.json", s.results[0])
	})
	t.Run("result already installed", func(t *testing.T) {
		h := host(t)
		h.cli.runner = fakeRunner{"nginx -T": nginxDump}
		p := h.parts(settings{kind: protocol.KindHost})
		s := &wireServer{work: []protocol.Work{{AssignmentID: wireAssignID, SiteKey: siteKey(t, p), SHA256: oldSHA, Action: protocol.ActionInstall}}, waits: 2}
		runLoop(t, p, protocol.KindHost, s)
		if len(s.results) != 1 || !s.results[0].OK || len(s.beats) != 2 {
			t.Fatalf("results %+v, %d heartbeats", s.results, len(s.beats))
		}
		sample(t, "result-already-installed.json", s.results[0])
		// The next heartbeat says what is on disk for the assignment, and carries only the inventory's hash.
		sample(t, "heartbeat-installed.json", s.beats[1])
	})
	t.Run("result ok", func(t *testing.T) {
		h := newCLI(t)
		h.rootDirs("/certs")
		h.env["NSL_RELOAD_CONTAINER"] = "nginx"
		st, _, err := h.settingsOf("run", "--mode=docker")
		if err != nil {
			t.Fatal(err)
		}
		folder := "shop.example"
		s := &wireServer{
			work:    []protocol.Work{{AssignmentID: wireAssignID, SHA256: newSHA, Action: protocol.ActionInstall, FolderName: &folder}},
			bundles: map[string]protocol.Bundle{wireAssignID: {AssignmentID: wireAssignID, SHA256: newSHA, CertPEM: newCert, ChainPEM: ca.pem, KeyPEM: newKey}},
		}
		runLoop(t, h.parts(st), protocol.KindDocker, s)
		if len(s.results) != 1 || !s.results[0].OK {
			t.Fatalf("results %+v", s.results)
		}
		sample(t, "result-ok.json", s.results[0])
	})
}
