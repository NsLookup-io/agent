package inventory

import (
	"cmp"
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/nslookup-io/agent/internal/protocol"
)

var haproxyInstalled = fakeRunner{"haproxy -v": {out: "HAProxy version 2.8.5-1ubuntu3 2024/04/01 - https://haproxy.org/\n"}}

func haproxyMachine(t *testing.T) *machine {
	m := newMachine(t, "haproxy")
	m.combined("/etc/haproxy/certs/shop.pem", "shop.example", "www.shop.example")
	// A crt directory: every file but the reserved extensions is a certificate; b's key is beside it.
	m.combined("/etc/haproxy/tenants/a.pem", "a.tenants.example")
	m.cert("/etc/haproxy/tenants/b.pem", "/etc/haproxy/tenants/b.pem.key", "b.tenants.example")
	m.file("/etc/haproxy/tenants/b.pem.ocsp", []byte("not a certificate"))
	m.file("/etc/haproxy/tenants/b.pem.issuer", []byte("not a certificate either"))
	m.combined("/etc/ssl/haproxy/api.pem", "api.shop.example")
	m.combined("/etc/haproxy/certs/mail.pem", "mail.example")
	m.combined("/etc/ssl/edge/edge.pem", "edge.example")
	return m
}

func TestHAProxySites(t *testing.T) {
	m := haproxyMachine(t)
	inv, err := Read(context.Background(), haproxyInstalled, m.fs, Options{HAProxyConfigs: []string{"/etc/haproxy/extra/"}})
	if err != nil {
		t.Fatal(err)
	}
	const cfg = "/etc/haproxy/haproxy.cfg"
	// key "": the key is in the certificate's file.
	site := func(config, cert, key string, names ...string) protocol.Site {
		s := tlsSite(protocol.SiteHAProxy, config, names, cert, cmp.Or(key, cert), "")
		s.Served = m.facts(cert)
		return s
	}
	checkSites(t, inv.Sites, []protocol.Site{
		// crt relative to crt-base; the names are the certificate's own.
		site(cfg, "/etc/haproxy/certs/shop.pem", "", "shop.example", "www.shop.example"),
		site(cfg, "/etc/haproxy/tenants/a.pem", "", "a.tenants.example"),
		site(cfg, "/etc/haproxy/tenants/b.pem", "/etc/haproxy/tenants/b.pem.key", "b.tenants.example"),
		// crt-list lines, the second relative to crt-base.
		site(cfg, "/etc/ssl/haproxy/api.pem", "", "api.shop.example"),
		site(cfg, "/etc/haproxy/certs/mail.pem", "", "mail.example"),
		// A configuration file from agent.yaml (a directory of *.cfg files).
		site("/etc/haproxy/extra/edge.cfg", "/etc/ssl/edge/edge.pem", "", "edge.example"),
	})
	if len(inv.Problems) != 0 {
		t.Errorf("problems %q", inv.Problems)
	}
	ports := map[string][]int{}
	for _, uses := range inv.Uses {
		ports[uses[0].CertPath] = uses[0].Ports
		if len(uses[0].Names) == 0 {
			t.Errorf("%s has no names", uses[0].CertPath)
		}
	}
	want := map[string][]int{
		"/etc/haproxy/certs/shop.pem": {443}, "/etc/haproxy/tenants/a.pem": {8443}, "/etc/haproxy/tenants/b.pem": {8443},
		"/etc/ssl/haproxy/api.pem": {8443}, "/etc/haproxy/certs/mail.pem": {8443}, "/etc/ssl/edge/edge.pem": {9443},
	}
	if !reflect.DeepEqual(ports, want) {
		t.Errorf("ports %v, want %v", ports, want)
	}
	noConfigOrKeys(t, m, inv)
}

func TestHAProxyIsReadOnlyWhenInstalled(t *testing.T) {
	m := haproxyMachine(t)
	inv, err := Read(context.Background(), fakeRunner{}, m.fs, Options{HAProxyConfigs: []string{"/etc/haproxy/extra/edge.cfg"}})
	if err != nil || len(inv.Sites) != 0 {
		t.Fatalf("%d sites, %v", len(inv.Sites), err)
	}
	if len(inv.Problems) != 1 || !strings.Contains(inv.Problems[0], "haproxy.configs") {
		t.Errorf("problems %q", inv.Problems)
	}
	// Installed without /etc/haproxy/haproxy.cfg: nothing to read, no error.
	inv, err = Read(context.Background(), haproxyInstalled, newMachine(t).fs, Options{})
	if err != nil || len(inv.Sites) != 0 || len(inv.Problems) != 0 {
		t.Errorf("%d sites, %q, %v", len(inv.Sites), inv.Problems, err)
	}
	// A configuration agent.yaml names that is not there fails.
	if _, err := Read(context.Background(), haproxyInstalled, m.fs, Options{HAProxyConfigs: []string{"/etc/haproxy/missing.cfg"}}); err == nil {
		t.Error("a missing configuration: read")
	}
}

// The configuration files read are what HAProxy's configuration test is given: kept from the last read that worked,
// gone once HAProxy is.
func TestHAProxyConfigurationFilesAreKeptForItsTest(t *testing.T) {
	m := haproxyMachine(t)
	runner := fakeRunner{}
	for k, v := range haproxyInstalled {
		runner[k] = v
	}
	r := &Reader{Runner: runner, FS: m.fs, Options: Options{HAProxyConfigs: []string{"/etc/haproxy/extra/"}}}
	want := []string{"/etc/haproxy/haproxy.cfg", "/etc/haproxy/extra/edge.cfg"}
	inv, err := r.Read(context.Background())
	if err != nil || !reflect.DeepEqual(inv.HAProxyFiles, want) {
		t.Fatalf("%q, %v", inv.HAProxyFiles, err)
	}
	m.file("/etc/haproxy/haproxy.cfg", []byte("frontend tls\n\tbind :443 ssl crt \"/etc/ssl/unclosed\n"))
	if inv, err = r.Read(context.Background()); err != nil || !reflect.DeepEqual(inv.HAProxyFiles, want) || len(inv.Problems) != 1 {
		t.Errorf("a failed read: %q, %q, %v", inv.HAProxyFiles, inv.Problems, err)
	}
	delete(runner, "haproxy -v")
	if inv, err = r.Read(context.Background()); err != nil || inv.HAProxyFiles != nil {
		t.Errorf("not installed: %q, %v", inv.HAProxyFiles, err)
	}
}

func TestHAProxyBindLines(t *testing.T) {
	m := newMachine(t)
	m.combined("/etc/ssl/a.pem", "a.example")
	m.file("/etc/haproxy/haproxy.cfg", []byte(`
frontend plain
	bind :80 crt /etc/ssl/a.pem     # no ssl: the certificate is not served
listen tls
	bind ipv4@:443,ipv6@:::8443-8445,unix@/run/haproxy.sock ssl crt "/etc/ssl/a.pem" # a comment
	bind :9443 ssl crt "/etc/ssl/${SITE}.pem" crt @store/site
backend tls
	bind :10443 ssl crt /etc/ssl/a.pem
`))
	inv, err := Read(context.Background(), haproxyInstalled, m.fs, Options{})
	if err != nil {
		t.Fatal(err)
	}
	a := tlsSite(protocol.SiteHAProxy, "/etc/haproxy/haproxy.cfg", []string{"a.example"}, "/etc/ssl/a.pem", "/etc/ssl/a.pem", "")
	a.Served = m.facts("/etc/ssl/a.pem")
	variable := tlsSite(protocol.SiteHAProxy, "/etc/haproxy/haproxy.cfg", nil, "/etc/ssl/${SITE}.pem", "/etc/ssl/${SITE}.pem", "")
	variable.Blocked = blocked(protocol.BlockedPathVariable)
	checkSites(t, inv.Sites, []protocol.Site{a, variable})
	if uses := inv.Uses[a.SiteKey]; len(uses) != 1 || !reflect.DeepEqual(uses[0].Ports, []int{443, 8443}) {
		t.Errorf("uses %+v", uses)
	}
	// The crt-store reference is not a file.
	if len(inv.Problems) != 1 {
		t.Errorf("problems %q", inv.Problems)
	}
}

func TestHAProxyWords(t *testing.T) {
	for line, want := range map[string][]string{
		"\tbind :443 ssl crt /etc/ssl/a.pem":   {"bind", ":443", "ssl", "crt", "/etc/ssl/a.pem"},
		`bind :443 ssl crt "/etc/ssl/a b.pem"`: {"bind", ":443", "ssl", "crt", "/etc/ssl/a b.pem"},
		`bind :443 ssl crt '/etc/ssl/$a.pem'`:  {"bind", ":443", "ssl", "crt", "/etc/ssl/$a.pem"},
		`bind :443 ssl crt /etc/ssl/a\ b.pem`:  {"bind", ":443", "ssl", "crt", "/etc/ssl/a b.pem"},
		`bind :443 ssl crt /etc/ssl/a.pem#x`:   {"bind", ":443", "ssl", "crt", "/etc/ssl/a.pem"},
		"   # only a comment":                  nil,
	} {
		got, err := haproxyWords(line)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Errorf("%q: %q, %v; want %q", line, got, err, want)
		}
	}
	if _, err := haproxyWords(`bind :443 ssl crt "/etc/ssl/a.pem`); err == nil {
		t.Error("an unclosed quote: no error")
	}
}

// As HAProxy 2.8 and 3.0 read them: a crt-list named by a relative path is found from HAProxy's working directory
// (/ under systemd), not from crt-base; the certificates a crt-list names by relative paths are found from crt-base;
// a crt directory's files whose names start with a dot are skipped.
func TestHAProxyPathsAsHAProxyResolvesThem(t *testing.T) {
	m := newMachine(t)
	m.combined("/etc/haproxy/certs/a.pem", "a.example")
	m.combined("/etc/haproxy/certs/dir/b.pem", "b.example")
	m.file("/etc/haproxy/certs/dir/.hidden.pem", []byte("not a certificate\n"))
	m.file("/etc/haproxy/certs/dir/.b.pem.nslookup-agent-0123456789abcdef", []byte("a temporary file\n"))
	m.file("/lists/list.txt", []byte("a.pem a.example\n"))
	// Under crt-base, but HAProxy does not look there for the list.
	m.file("/etc/haproxy/certs/lists/list.txt", []byte("dir/b.pem b.example\n"))
	m.file("/etc/haproxy/haproxy.cfg", []byte(`
global
	crt-base /etc/haproxy/certs
frontend f
	bind :8443 ssl crt-list lists/list.txt
	bind :9443 ssl crt dir/
`))
	inv, err := Read(context.Background(), haproxyInstalled, m.fs, Options{})
	if err != nil {
		t.Fatal(err)
	}
	const cfg = "/etc/haproxy/haproxy.cfg"
	a := tlsSite(protocol.SiteHAProxy, cfg, []string{"a.example"}, "/etc/haproxy/certs/a.pem", "/etc/haproxy/certs/a.pem", "")
	a.Served = m.facts("/etc/haproxy/certs/a.pem")
	b := tlsSite(protocol.SiteHAProxy, cfg, []string{"b.example"}, "/etc/haproxy/certs/dir/b.pem", "/etc/haproxy/certs/dir/b.pem", "")
	b.Served = m.facts("/etc/haproxy/certs/dir/b.pem")
	checkSites(t, inv.Sites, []protocol.Site{a, b})
	if len(inv.Problems) != 0 {
		t.Errorf("problems %q", inv.Problems)
	}
}
