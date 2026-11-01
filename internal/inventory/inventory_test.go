package inventory

import (
	"context"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"unicode"

	"github.com/nslookup-io/agent/internal/protocol"
)

// sharedMachine has one certificate file used by nginx, Apache and HAProxy.
func sharedMachine(t *testing.T, apacheKey, apacheChain string) (*machine, fakeRunner) {
	m := newMachine(t)
	m.combined("/etc/ssl/acme/site.pem", "acme.example", "www.acme.example")
	vhost := "<VirtualHost *:443>\n\tServerName www.acme.example\n\tServerAlias shop.acme.example\n\tSSLEngine on\n\tSSLCertificateFile /etc/ssl/acme/site.pem\n"
	if apacheKey != "" {
		vhost += "\tSSLCertificateKeyFile " + apacheKey + "\n"
	}
	if apacheChain != "" {
		vhost += "\tSSLCertificateChainFile " + apacheChain + "\n"
	}
	m.file("/etc/apache2/sites-enabled/acme.conf", []byte(vhost+"</VirtualHost>\n"))
	m.file("/etc/haproxy/haproxy.cfg", []byte("frontend tls\n\tbind :8443 ssl crt /etc/ssl/acme/site.pem\n"))
	return m, fakeRunner{
		"nginx -T": {out: "# configuration file /etc/nginx/nginx.conf:\nhttp { server { listen 443 ssl; server_name acme.example;\n" +
			"ssl_certificate /etc/ssl/acme/site.pem; ssl_certificate_key /etc/ssl/acme/site.pem; } }\n"},
		apacheDumpCommand: {out: "VirtualHost configuration:\n*:443                  www.acme.example (/etc/apache2/sites-enabled/acme.conf:1)\nServerRoot: \"/etc/apache2\"\n"},
		"haproxy -v":      {out: "HAProxy version 2.8.5 2024/04/01\n"},
	}
}

// One file used by three web servers is one site: nginx's kind, the first configuration file, every name; installing
// on it tests and reloads all three.
func TestAFileUsedByEveryWebServerIsOneSite(t *testing.T) {
	m, runner := sharedMachine(t, "/etc/ssl/acme/site.pem", "")
	inv, err := Read(context.Background(), runner, m.fs, Options{})
	if err != nil {
		t.Fatal(err)
	}
	site := tlsSite(protocol.SiteNginx, "/etc/apache2/sites-enabled/acme.conf", []string{"acme.example", "shop.acme.example", "www.acme.example"},
		"/etc/ssl/acme/site.pem", "/etc/ssl/acme/site.pem", "")
	site.Served = m.facts("/etc/ssl/acme/site.pem")
	checkSites(t, inv.Sites, []protocol.Site{site})

	want := []Use{
		// The first (and only) nginx server on *:443 catches every name: the certificate's names too.
		{Kind: protocol.WebServerNginx, ConfigPath: "/etc/nginx/nginx.conf", Names: []string{"acme.example", "www.acme.example"},
			CertPath: "/etc/ssl/acme/site.pem", KeyPath: "/etc/ssl/acme/site.pem", Ports: []int{443}},
		// The only virtual host of its address catches every name: the certificate's names too.
		{Kind: protocol.WebServerApache, ConfigPath: "/etc/apache2/sites-enabled/acme.conf", Names: []string{"acme.example", "shop.acme.example", "www.acme.example"},
			CertPath: "/etc/ssl/acme/site.pem", KeyPath: "/etc/ssl/acme/site.pem", Ports: []int{443}},
		// HAProxy names no key file: the key is in the certificate's file, as nginx and Apache say.
		{Kind: protocol.WebServerHAProxy, ConfigPath: "/etc/haproxy/haproxy.cfg", Names: []string{"acme.example", "www.acme.example"},
			CertPath: "/etc/ssl/acme/site.pem", KeyPath: "/etc/ssl/acme/site.pem", Ports: []int{8443}},
	}
	if got := inv.Uses[site.SiteKey]; !reflect.DeepEqual(got, want) {
		t.Errorf("uses:\n got %+v\nwant %+v", got, want)
	}
	noConfigOrKeys(t, m, inv)
}

func TestConfigurationsThatDisagreeOnTheKeyOrChainBlockTheSite(t *testing.T) {
	for name, c := range map[string]struct{ key, chain string }{
		"another key":  {"/etc/ssl/acme/other.key", ""},
		"a chain file": {"/etc/ssl/acme/site.pem", "/etc/ssl/acme/chain.pem"},
	} {
		m, runner := sharedMachine(t, c.key, c.chain)
		delete(runner, "haproxy -v")
		inv, err := Read(context.Background(), runner, m.fs, Options{})
		if err != nil {
			t.Fatal(err)
		}
		if len(inv.Sites) != 1 || inv.Sites[0].Blocked == nil || *inv.Sites[0].Blocked != protocol.BlockedUnreadable || len(inv.Uses[inv.Sites[0].SiteKey]) != 2 {
			t.Errorf("%s: %s", name, dump(inv.Sites))
			continue
		}
		// The first configuration's paths are reported.
		if s := inv.Sites[0]; *s.KeyPath != "/etc/ssl/acme/site.pem" || s.ChainPath != nil {
			t.Errorf("%s: %s", name, dump(s))
		}
		if len(inv.Problems) != 1 {
			t.Errorf("%s: problems %q", name, inv.Problems)
		}
	}
	// Apache naming no key file: the key is in the certificate's file, the one nginx names.
	m, runner := sharedMachine(t, "", "")
	delete(runner, "haproxy -v")
	inv, _ := Read(context.Background(), runner, m.fs, Options{})
	if len(inv.Sites) != 1 || inv.Sites[0].Blocked != nil || len(inv.Problems) != 0 {
		t.Errorf("agreeing: %s, %q", dump(inv.Sites), inv.Problems)
	}
}

// twoServers is a machine where nginx serves one file and Apache another.
func twoServers(t *testing.T) (*machine, fakeRunner) {
	m := newMachine(t)
	m.cert("/etc/ssl/n.pem", "/etc/ssl/n.key", "n.example")
	m.cert("/etc/ssl/a.pem", "/etc/ssl/a.key", "a.example", "www.a.example")
	m.file("/etc/apache2/sites-enabled/a.conf", []byte("<VirtualHost *:443>\n\tServerName a.example\n\tSSLEngine on\n"+
		"\tSSLCertificateFile /etc/ssl/a.pem\n\tSSLCertificateKeyFile /etc/ssl/a.key\n</VirtualHost>\n"))
	return m, fakeRunner{
		"nginx -T": {out: "# configuration file /etc/nginx/nginx.conf:\nhttp { server { listen 443 ssl; server_name n.example;\n" +
			"ssl_certificate /etc/ssl/n.pem; ssl_certificate_key /etc/ssl/n.key; } }\n"},
		apacheDumpCommand: {out: "VirtualHost configuration:\n*:443                  a.example (/etc/apache2/sites-enabled/a.conf:1)\nServerRoot: \"/etc/apache2\"\n"},
	}
}

// names are the names of every site, by certificate file.
func names(inv Inventory) map[string][]string {
	out := map[string][]string{}
	for _, s := range inv.Sites {
		out[*s.CertPath] = s.Names
	}
	return out
}

// A web server that fails a read (a configuration being edited, an nginx -T that timed out) is reported as it was at
// its last read: its sites do not disappear, and the other web servers' are read fresh.
func TestAWebServerThatFailsKeepsItsLastSites(t *testing.T) {
	m, runner := twoServers(t)
	r := &Reader{Runner: runner, FS: m.fs}
	inv, err := r.Read(context.Background())
	if err != nil || len(inv.Problems) != 0 {
		t.Fatalf("%v, %q", err, inv.Problems)
	}
	nginxUses := inv.Uses[SiteKey(protocol.SiteNginx, "/etc/nginx/nginx.conf", "/etc/ssl/n.pem")]

	runner["nginx -T"] = fakeRun{err: errors.New("nginx -T did not finish within 30s")}
	m.file("/etc/apache2/sites-enabled/a.conf", []byte("<VirtualHost *:443>\n\tServerName a.example\n\tServerAlias www.a.example\n"+
		"\tSSLEngine on\n\tSSLCertificateFile /etc/ssl/a.pem\n\tSSLCertificateKeyFile /etc/ssl/a.key\n</VirtualHost>\n"))
	inv, err = r.Read(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][]string{"/etc/ssl/n.pem": {"n.example"}, "/etc/ssl/a.pem": {"a.example", "www.a.example"}}
	if got := names(inv); !reflect.DeepEqual(got, want) {
		t.Errorf("names %v, want %v", got, want)
	}
	if got := inv.Uses[SiteKey(protocol.SiteNginx, "/etc/nginx/nginx.conf", "/etc/ssl/n.pem")]; !reflect.DeepEqual(got, nginxUses) {
		t.Errorf("nginx's uses %+v, want %+v", got, nginxUses)
	}
	if len(inv.Problems) != 1 || !strings.Contains(inv.Problems[0], "nginx: nginx -T did not finish within 30s; its sites are reported as at its last read") {
		t.Errorf("problems %q", inv.Problems)
	}

	// Fails again: still its last sites. Back: read fresh.
	if inv, err = r.Read(context.Background()); err != nil || len(names(inv)) != 2 {
		t.Errorf("failing again: %v, %v", names(inv), err)
	}
	runner["nginx -T"] = fakeRun{out: "# configuration file /etc/nginx/nginx.conf:\nhttp { }\n"}
	if inv, err = r.Read(context.Background()); err != nil || !reflect.DeepEqual(names(inv), map[string][]string{"/etc/ssl/a.pem": {"a.example", "www.a.example"}}) {
		t.Errorf("read again: %v, %v", names(inv), err)
	}

	// A web server no longer installed has no sites, whatever it read before.
	r = &Reader{Runner: runner, FS: m.fs}
	if _, err = r.Read(context.Background()); err != nil {
		t.Fatal(err)
	}
	delete(runner, apacheDumpCommand)
	if inv, err = r.Read(context.Background()); err != nil || len(inv.Sites) != 0 {
		t.Errorf("uninstalled: %v, %v", names(inv), err)
	}
}

// A web server that fails its first read has no sites to fall back on: the read fails, and the agent sends no list
// without them (the server would take their sites as gone).
func TestAWebServerThatFailsItsFirstReadFailsTheRead(t *testing.T) {
	m, runner := twoServers(t)
	runner["nginx -T"] = fakeRun{err: errors.New("nginx -T failed (exit status 1): nginx: [emerg] unknown directive")}
	r := &Reader{Runner: runner, FS: m.fs}
	inv, err := r.Read(context.Background())
	if err == nil || !strings.Contains(err.Error(), "nginx could not be read") || len(inv.Sites) != 0 {
		t.Fatalf("%v, %s", err, dump(inv.Sites))
	}
	if len(inv.Problems) != 1 || !strings.Contains(inv.Problems[0], "unknown directive") {
		t.Errorf("problems %q", inv.Problems)
	}

	// Its first read that works counts; a failure after it keeps it.
	runner["nginx -T"] = fakeRun{out: "# configuration file /etc/nginx/nginx.conf:\nhttp { server { listen 443 ssl; server_name n.example; ssl_certificate /etc/ssl/n.pem; ssl_certificate_key /etc/ssl/n.key; } }\n"}
	if _, err := r.Read(context.Background()); err != nil {
		t.Fatal(err)
	}
	runner[apacheDumpCommand] = fakeRun{err: errors.New("exit status 1")}
	runner["nginx -T"] = fakeRun{err: errors.New("exit status 1")}
	if inv, err = r.Read(context.Background()); err != nil || len(inv.Sites) != 2 || len(inv.Problems) != 2 {
		t.Errorf("%v, %v, %q", names(inv), err, inv.Problems)
	}

	// None installed: nothing to read, no error.
	inv, err = Read(context.Background(), fakeRunner{}, m.fs, Options{})
	if err != nil || len(inv.Sites) != 0 {
		t.Errorf("%s, %v", dump(inv.Sites), err)
	}
}

// A certificate name the server would refuse (any kind of space, a byte order mark) is left out and said: one odd
// certificate must not make the server refuse the whole inventory.
func TestCertificateNamesTheServerWouldRefuseAreLeftOut(t *testing.T) {
	m := newMachine(t)
	for i, cn := range []string{"odd\u00a0name.example", "odd\u3000name.example", "odd\u2003name.example", "\ufeffodd.example", "odd\u0085.example"} {
		m.file(fmt.Sprintf("/etc/ssl/odd%d.pem", i), selfSigned(t, pkix.Name{CommonName: cn}, nil, int64(i+1)))
	}
	var servers strings.Builder
	for i := range 5 {
		fmt.Fprintf(&servers, "server { listen 443 ssl; server_name odd%d.example; ssl_certificate /etc/ssl/odd%d.pem; ssl_certificate_key /etc/ssl/odd%d.pem; }\n", i, i, i)
	}
	inv := nginxSites(t, m, "/etc/nginx/nginx.conf", "http {\n"+servers.String()+"}")
	if len(inv.Sites) != 5 || len(inv.Problems) != 5 {
		t.Fatalf("sites %s, problems %q", dump(inv.Sites), inv.Problems)
	}
	for _, s := range inv.Sites {
		if s.Served == nil || len(s.Served.Names) != 0 || s.Blocked != nil {
			t.Errorf("site %s", dump(s))
		}
		for _, n := range s.Names {
			if strings.ContainsFunc(n, func(r rune) bool { return unicode.IsSpace(r) || r == '\ufeff' }) {
				t.Errorf("name %q", n)
			}
		}
	}
	if !strings.Contains(inv.Problems[0], "no host name") {
		t.Errorf("problem %q", inv.Problems[0])
	}
}

func TestASiteReportsAtMost100Names(t *testing.T) {
	m := newMachine(t)
	m.cert("/etc/ssl/many.pem", "/etc/ssl/many.key", "many.example")
	var names []string
	for i := range 120 {
		names = append(names, fmt.Sprintf("n%03d.many.example", i))
	}
	// The first server on *:443 says default_server and serves no certificate: the site is no catch-all.
	inv := nginxSites(t, m, "/etc/nginx/nginx.conf", "http { server { listen 443 ssl default_server; ssl_reject_handshake on; } server { listen 443 ssl; server_name "+strings.Join(names, " ")+
		"; ssl_certificate /etc/ssl/many.pem; ssl_certificate_key /etc/ssl/many.key; } server { listen 80; server_name "+strings.Join(names, " ")+" plain.many.example; } }")
	if len(inv.Sites) != 2 {
		t.Fatalf("sites %s", dump(inv.Sites))
	}
	for _, s := range inv.Sites {
		if s.CertPath != nil && (len(s.Names) != 100 || s.Names[0] != "n000.many.example" || s.Names[99] != "n099.many.example") {
			t.Errorf("names %q", s.Names)
		}
		// Names served with HTTPS are left out of the site without, even beyond the first 100.
		if s.CertPath == nil && !reflect.DeepEqual(s.Names, []string{"plain.many.example"}) {
			t.Errorf("names without HTTPS %q", s.Names)
		}
	}
	if len(inv.Problems) != 1 {
		t.Errorf("problems %q", inv.Problems)
	}
}

func TestWebServers(t *testing.T) {
	got := WebServers(context.Background(), fakeRunner{
		"nginx -v":      {out: "nginx version: nginx/1.24.0 (Ubuntu)\n"},
		"apache2ctl -v": {out: "Server version: Apache/2.4.58 (Ubuntu)\nServer built:   2024-10-02T12:40:51\n"},
		"haproxy -v":    {out: "HAProxy version 2.8.5-1ubuntu3 2024/04/01 - https://haproxy.org/\nStatus: long-term supported branch\n"},
		// The first that prints a version counts.
		"apachectl -v": {err: errors.New("exit status 2")},
	})
	want := []protocol.WebServer{
		{Kind: protocol.WebServerNginx, Version: "1.24.0"},
		{Kind: protocol.WebServerApache, Version: "2.4.58"},
		{Kind: protocol.WebServerHAProxy, Version: "2.8.5-1ubuntu3"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v\nwant %+v", got, want)
	}

	got = WebServers(context.Background(), fakeRunner{
		"nginx -v":   {out: "nginx version: openresty/1.21.4.1\n"},
		"httpd -v":   {out: "Server version: Apache/2.4.62 (Red Hat Enterprise Linux)\n"},
		"haproxy -v": {out: "HA-Proxy version 1.8.27 2020/11/06\n"},
	})
	want = []protocol.WebServer{
		{Kind: protocol.WebServerNginx, Version: "openresty/1.21.4.1"},
		{Kind: protocol.WebServerApache, Version: "2.4.62"},
		{Kind: protocol.WebServerHAProxy, Version: "1.8.27"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v\nwant %+v", got, want)
	}
	if got := WebServers(context.Background(), fakeRunner{}); len(got) != 0 {
		t.Errorf("nothing installed: %+v", got)
	}
	// Installed, but it printed no version.
	got = WebServers(context.Background(), fakeRunner{"apachectl -v": {err: errors.New("exit status 2")}})
	if !reflect.DeepEqual(got, []protocol.WebServer{{Kind: protocol.WebServerApache}}) {
		t.Errorf("no version: %+v", got)
	}
}

// Every fixture together: what is sent never holds configuration text or key material.
func TestTheInventoryHoldsNoConfigurationOrKeys(t *testing.T) {
	m := nginxMachine(t)
	a := apacheMachine(t)
	h := haproxyMachine(t)
	for p, f := range a.fs {
		m.fs[p] = f
	}
	for p, f := range h.fs {
		m.fs[p] = f
	}
	m.keys = append(append(m.keys, a.keys...), h.keys...)
	runner := fakeRunner{"nginx -T": {out: nginxFixture(t)}, apacheDumpCommand: {out: apacheFixture(t)}}
	for k, v := range haproxyInstalled {
		runner[k] = v
	}
	inv, err := Read(context.Background(), runner, m.fs, Options{HAProxyConfigs: []string{"/etc/haproxy/extra"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(inv.Sites) < 15 {
		t.Errorf("%d sites", len(inv.Sites))
	}
	noConfigOrKeys(t, m, inv)
}
