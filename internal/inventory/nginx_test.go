package inventory

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/nslookup-io/agent/internal/protocol"
)

func nginxFixture(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "nginx", "nginx-T.txt"))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// nginxMachine is the machine of testdata/nginx/nginx-T.txt, with every certificate it names except the tenants'.
func nginxMachine(t *testing.T) *machine {
	m := newMachine(t, "certbot")
	m.cert("/etc/ssl/fallback/fallback.pem", "/etc/ssl/fallback/fallback.key", "fallback.example")
	m.cert("/etc/ssl/acme/fullchain.pem", "/etc/ssl/acme/privkey.pem", "shop.example", "www.shop.example", "api.shop.example")
	m.cert("/etc/letsencrypt/live/blog.example/fullchain.pem", "/etc/letsencrypt/live/blog.example/privkey.pem", "blog.example")
	m.cert("/etc/letsencrypt/live/old.example/fullchain.pem", "/etc/letsencrypt/live/old.example/privkey.pem", "old.example", "www.old.example")
	m.cert("/etc/ssl/mqtt/mqtt.pem", "/etc/ssl/mqtt/mqtt.key", "mqtt.example")
	m.cert("/etc/ssl/app/fullchain.pem", "/etc/ssl/app/privkey.pem", "app.example.test", "*.app.example.test")
	return m
}

func TestNginxSites(t *testing.T) {
	m := nginxMachine(t)
	inv, err := Read(context.Background(), fakeRunner{"nginx -T": {out: nginxFixture(t)}}, m.fs, Options{})
	if err != nil {
		t.Fatal(err)
	}

	fallback := tlsSite(protocol.SiteNginx, "/etc/nginx/conf.d/default-tls.conf", []string{"fallback.example"},
		"/etc/ssl/fallback/fallback.pem", "/etc/ssl/fallback/fallback.key", "")
	fallback.Served = m.facts("/etc/ssl/fallback/fallback.pem")

	// Two server blocks in two files share the snippet's certificate: one site with both blocks' names, named after
	// the first configuration file.
	acme := tlsSite(protocol.SiteNginx, "/etc/nginx/sites-enabled/api.example", []string{"api.shop.example", "shop.example", "www.shop.example"},
		"/etc/ssl/acme/fullchain.pem", "/etc/ssl/acme/privkey.pem", "")
	acme.Served = m.facts("/etc/ssl/acme/fullchain.pem")

	blog := tlsSite(protocol.SiteNginx, "/etc/nginx/sites-enabled/blog.example", []string{"blog.example"},
		"/etc/letsencrypt/live/blog.example/fullchain.pem", "/etc/letsencrypt/live/blog.example/privkey.pem", "")
	blog.Served = m.facts("/etc/letsencrypt/live/blog.example/fullchain.pem")
	blog.Owner, blog.CertbotName = certbot(), str("blog.example")

	// Under live/ but with no renewal configuration: certbot does not renew it.
	old := tlsSite(protocol.SiteNginx, "/etc/nginx/sites-enabled/old.example", []string{"old.example", "www.old.example"},
		"/etc/letsencrypt/live/old.example/fullchain.pem", "/etc/letsencrypt/live/old.example/privkey.pem", "")
	old.Served = m.facts("/etc/letsencrypt/live/old.example/fullchain.pem")

	// Its regular expression is no name a certificate can be checked against: the site also has the names of the
	// certificate it serves today, so a certificate replacing it must cover what the regular expression matches.
	app := tlsSite(protocol.SiteNginx, "/etc/nginx/sites-enabled/app.example.test", []string{"*.app.example.test", "app.example.test"},
		"/etc/ssl/app/fullchain.pem", "/etc/ssl/app/privkey.pem", "")
	app.Served = m.facts("/etc/ssl/app/fullchain.pem")

	tenants := tlsSite(protocol.SiteNginx, "/etc/nginx/sites-enabled/tenants.example", []string{"*.tenants.example", "tenants.example"},
		"/etc/ssl/tenants/$ssl_server_name.crt", "/etc/ssl/tenants/$ssl_server_name.key", "")
	tenants.Blocked = blocked(protocol.BlockedPathVariable)

	checkSites(t, inv.Sites, []protocol.Site{
		fallback, acme, app, blog, old, tenants,
		// Port 80 only; the regular expression is no name. The port-80 servers of shop and blog are left out: their
		// names are served with HTTPS.
		plainSite(protocol.SiteNginx, "/etc/nginx/sites-enabled/legacy.example", "legacy.example"),
	})
	if len(inv.Problems) != 0 {
		t.Errorf("problems %q", inv.Problems)
	}

	wantUses := []Use{
		// The first (and only) server on *:8443 catches every name there: the certificate's names too.
		{Kind: protocol.WebServerNginx, ConfigPath: "/etc/nginx/sites-enabled/api.example", Names: []string{"api.shop.example", "shop.example", "www.shop.example"},
			CertPath: "/etc/ssl/acme/fullchain.pem", KeyPath: "/etc/ssl/acme/privkey.pem", Ports: []int{8443}},
		{Kind: protocol.WebServerNginx, ConfigPath: "/etc/nginx/sites-enabled/shop.example", Names: []string{"shop.example", "www.shop.example"},
			CertPath: "/etc/ssl/acme/fullchain.pem", KeyPath: "/etc/ssl/acme/privkey.pem", Ports: []int{443}},
	}
	if got := inv.Uses[acme.SiteKey]; !reflect.DeepEqual(got, wantUses) {
		t.Errorf("uses of the shared certificate:\n got %+v\nwant %+v", got, wantUses)
	}
	// A server without a name of its own is known by its certificate's names.
	wantFallback := []Use{{Kind: protocol.WebServerNginx, ConfigPath: "/etc/nginx/conf.d/default-tls.conf", Names: []string{"fallback.example"},
		CertPath: "/etc/ssl/fallback/fallback.pem", KeyPath: "/etc/ssl/fallback/fallback.key", Ports: []int{443}}}
	if got := inv.Uses[fallback.SiteKey]; !reflect.DeepEqual(got, wantFallback) {
		t.Errorf("uses of the fallback certificate:\n got %+v\nwant %+v", got, wantFallback)
	}
	wantApp := []Use{{Kind: protocol.WebServerNginx, ConfigPath: "/etc/nginx/sites-enabled/app.example.test", Names: []string{"*.app.example.test", "app.example.test"},
		CertPath: "/etc/ssl/app/fullchain.pem", KeyPath: "/etc/ssl/app/privkey.pem", Ports: []int{443}}}
	if got := inv.Uses[app.SiteKey]; !reflect.DeepEqual(got, wantApp) {
		t.Errorf("uses of the certificate of a server with a regular expression:\n got %+v\nwant %+v", got, wantApp)
	}
	if _, ok := inv.Uses[plainSite(protocol.SiteNginx, "/etc/nginx/sites-enabled/legacy.example").SiteKey]; ok {
		t.Error("a site without HTTPS has uses")
	}
	noConfigOrKeys(t, m, inv)
}

func TestSiteKey(t *testing.T) {
	if got := SiteKey(protocol.SiteNginx, "/etc/nginx/sites-enabled/api.example", "/etc/ssl/acme/fullchain.pem"); got != "2c81e2474c76b140e9a21be2c8400a05" {
		t.Errorf("site key %s", got)
	}
}

// nginxSites reads a configuration given as nginx -T prints it, from the files named "# configuration file".
func nginxSites(t *testing.T, m *machine, files ...string) Inventory {
	t.Helper()
	var dump strings.Builder
	for i := 0; i+1 < len(files); i += 2 {
		dump.WriteString("# configuration file " + files[i] + ":\n" + files[i+1] + "\n")
	}
	inv, err := Read(context.Background(), fakeRunner{"nginx -T": {out: dump.String()}}, m.fs, Options{})
	if err != nil {
		t.Fatal(err)
	}
	return inv
}

func TestNginxInheritsTheCertificateOfHTTP(t *testing.T) {
	m := newMachine(t)
	m.cert("/etc/nginx/certs/site.pem", "/etc/nginx/certs/site.key", "site.example")
	m.cert("/etc/ssl/own.pem", "", "own.example")
	inv := nginxSites(t, m, "/etc/nginx/nginx.conf", `
http {
	ssl_certificate certs/site.pem;      # relative to the main file's directory
	ssl_certificate_key certs/site.key;
	server { listen 443 ssl; server_name site.example; }
	server { listen 80; server_name plain.example; }
	server { listen 443 ssl; server_name own.example; ssl_certificate /etc/ssl/own.pem; ssl_certificate_key /etc/ssl/own.pem; }
}`)
	site := tlsSite(protocol.SiteNginx, "/etc/nginx/nginx.conf", []string{"site.example"}, "/etc/nginx/certs/site.pem", "/etc/nginx/certs/site.key", "")
	site.Served = m.facts("/etc/nginx/certs/site.pem")
	own := tlsSite(protocol.SiteNginx, "/etc/nginx/nginx.conf", []string{"own.example"}, "/etc/ssl/own.pem", "/etc/ssl/own.pem", "")
	own.Served = m.facts("/etc/ssl/own.pem")
	checkSites(t, inv.Sites, []protocol.Site{site, own, plainSite(protocol.SiteNginx, "/etc/nginx/nginx.conf", "plain.example")})
}

func TestNginxListeners(t *testing.T) {
	m := newMachine(t)
	for _, name := range []string{"a", "b", "c", "d", "e"} {
		m.cert("/etc/ssl/"+name+".pem", "/etc/ssl/"+name+".key", name+".example")
	}
	inv := nginxSites(t, m, "/etc/nginx/nginx.conf", `
http {
	# Port 443 with a certificate counts even without "ssl".
	server { listen 443; server_name a.example; ssl_certificate /etc/ssl/a.pem; ssl_certificate_key /etc/ssl/a.key; }
	# The old "ssl on" makes every listener HTTPS.
	server { listen 8443; ssl on; server_name b.example; ssl_certificate /etc/ssl/b.pem; ssl_certificate_key /etc/ssl/b.key; }
	# HTTP/3 is HTTPS too; its UDP port is no port for a TLS check.
	server { listen 443 quic reuseport; listen 127.0.0.1:9443 ssl; server_name c.example; ssl_certificate /etc/ssl/c.pem; ssl_certificate_key /etc/ssl/c.key; }
	# A certificate on a server that listens without HTTPS is not served.
	server { listen 8080; server_name d.example; ssl_certificate /etc/ssl/d.pem; ssl_certificate_key /etc/ssl/d.key; }
	# A unix socket has no TCP port.
	server { listen unix:/run/e.sock ssl; listen [::1]:10443 ssl; server_name e.example; ssl_certificate "/etc/ssl/e.pem"; ssl_certificate_key '/etc/ssl/e.key'; }
}`)
	ports := map[string][]int{}
	for key, uses := range inv.Uses {
		for _, s := range inv.Sites {
			if s.SiteKey == key {
				ports[s.Names[0]] = uses[0].Ports
			}
		}
	}
	want := map[string][]int{"a.example": {443}, "b.example": {8443}, "c.example": {9443}, "e.example": {10443}}
	if !reflect.DeepEqual(ports, want) {
		t.Errorf("ports %v, want %v", ports, want)
	}
	if len(inv.Sites) != 5 || len(inv.Uses) != 4 {
		t.Errorf("sites %s", dump(inv.Sites))
	}
	for _, s := range inv.Sites {
		if s.Names[0] == "d.example" && (s.Blocked == nil || *s.Blocked != protocol.BlockedNoHTTPS || s.CertPath != nil) {
			t.Errorf("d.example: %s", dump(s))
		}
	}
}

func TestNginxServerNames(t *testing.T) {
	m := newMachine(t)
	inv := nginxSites(t, m, "/etc/nginx/nginx.conf", `
http {
	server {
		listen 80;
		server_name Shop.Example. .wild.example www.example.* ~^api\d+\.example$ "" _ localhost 192.0.2.10 *.*.example $hostname;
		server_name second.example;
	}
	server { listen 80 default_server; server_name _; return 444; }
}`)
	checkSites(t, inv.Sites, []protocol.Site{plainSite(protocol.SiteNginx, "/etc/nginx/nginx.conf",
		"*.wild.example", "second.example", "shop.example", "wild.example")})
}

// A server with HTTPS that names anything the agent cannot express as a host name (a regular expression, a wildcard
// that is not the whole first label, a variable) also gets the names of the certificate it serves: the agent cannot
// tell which hosts those names stand for, so a certificate replacing it must cover at least what it covers today.
func TestNginxNamesTheAgentCannotExpressAddTheServedNames(t *testing.T) {
	for _, names := range []string{
		`app.example.test ~^(?<t>.+)\.app\.example\.test$`,
		`app.example.test www.app.example.*`,
		`app.example.test $hostname`,
		`app.example.test w*.app.example.test`,
		`app.example.test *.*.example.test`,
	} {
		t.Run(names, func(t *testing.T) {
			m := newMachine(t)
			m.cert("/etc/ssl/app.pem", "/etc/ssl/app.key", "app.example.test", "*.app.example.test")
			inv := nginxSites(t, m, "/etc/nginx/nginx.conf", `
http {
	server {
		listen 443 ssl;
		server_name `+names+`;
		ssl_certificate /etc/ssl/app.pem;
		ssl_certificate_key /etc/ssl/app.key;
	}
}`)
			if len(inv.Sites) != 1 || !reflect.DeepEqual(inv.Sites[0].Names, []string{"*.app.example.test", "app.example.test"}) {
				t.Fatalf("sites %s", dump(inv.Sites))
			}
			if u := inv.Uses[inv.Sites[0].SiteKey]; len(u) != 1 || !reflect.DeepEqual(u[0].Names, []string{"*.app.example.test", "app.example.test"}) {
				t.Errorf("uses %+v", u)
			}
		})
	}
	// Names the agent can express keep the site to them (another server is the default one): a certificate for more is
	// not asked for.
	m := newMachine(t)
	m.cert("/etc/ssl/app.pem", "/etc/ssl/app.key", "app.example.test", "*.app.example.test", "other.example.test")
	inv := nginxSites(t, m, "/etc/nginx/nginx.conf", `
http {
	server { listen 443 ssl default_server; ssl_reject_handshake on; }
	server {
		listen 443 ssl;
		server_name app.example.test .shop.example.test _ "" localhost;
		ssl_certificate /etc/ssl/app.pem;
		ssl_certificate_key /etc/ssl/app.key;
	}
}`)
	if len(inv.Sites) != 1 || !reflect.DeepEqual(inv.Sites[0].Names, []string{"*.shop.example.test", "app.example.test", "shop.example.test"}) {
		t.Errorf("sites %s", dump(inv.Sites))
	}
}

// A catch-all server (default_server on its listen, or the old "default") answers names no other server serves: it
// also gets the names of the certificate it serves, so a certificate replacing it covers at least what it covers today.
func TestNginxCatchAllServersAddTheServedNames(t *testing.T) {
	for _, listen := range []string{"listen 443 ssl default_server;", "listen [::]:443 ssl default_server;", "listen 443 default ssl;"} {
		t.Run(listen, func(t *testing.T) {
			m := newMachine(t)
			m.cert("/etc/ssl/main.pem", "/etc/ssl/main.key", "www.example.test", "example.test", "old.example.test")
			inv := nginxSites(t, m, "/etc/nginx/nginx.conf", `
http {
	server {
		`+listen+`
		server_name www.example.test;
		ssl_certificate /etc/ssl/main.pem;
		ssl_certificate_key /etc/ssl/main.key;
	}
}`)
			if len(inv.Sites) != 1 || !reflect.DeepEqual(inv.Sites[0].Names, []string{"example.test", "old.example.test", "www.example.test"}) {
				t.Errorf("sites %s", dump(inv.Sites))
			}
		})
	}
	// Not a catch-all (another server is the default one): its own names only.
	m := newMachine(t)
	m.cert("/etc/ssl/main.pem", "/etc/ssl/main.key", "www.example.test", "example.test", "old.example.test")
	inv := nginxSites(t, m, "/etc/nginx/nginx.conf", `
http {
	server { listen 443 ssl default_server; ssl_reject_handshake on; }
	server {
		listen 443 ssl;
		server_name www.example.test;
		ssl_certificate /etc/ssl/main.pem;
		ssl_certificate_key /etc/ssl/main.key;
	}
}`)
	if len(inv.Sites) != 1 || !reflect.DeepEqual(inv.Sites[0].Names, []string{"www.example.test"}) {
		t.Errorf("sites %s", dump(inv.Sites))
	}
}

// Without a default_server on an address and port, nginx's default there is the first server listening on it: that
// one also catches every name no other server there serves, and gets its certificate's names too.
func TestNginxImplicitDefaultServersAddTheServedNames(t *testing.T) {
	m := newMachine(t)
	for _, c := range []string{"first", "second", "ports", "default"} {
		m.cert("/etc/ssl/"+c+".pem", "/etc/ssl/"+c+".key", c+".example.test", "extra-"+c+".example.test")
	}
	inv, err := Read(context.Background(), fakeRunner{"nginx -T": {out: nginxFixtureFile(t, "implicit-default-T.txt")}}, m.fs, Options{})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string][]string{}
	for _, s := range inv.Sites {
		got[*s.CertPath] = s.Names
	}
	want := map[string][]string{
		// First on *:443.
		"/etc/ssl/first.pem": {"extra-first.example.test", "first.example.test"},
		// First on [::]:443.
		"/etc/ssl/second.pem": {"extra-second.example.test", "second.example.test"},
		// First on 8443, but another says default_server there.
		"/etc/ssl/ports.pem":   {"ports.example.test"},
		"/etc/ssl/default.pem": {"default.example.test", "extra-default.example.test"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("names %v\nwant %v", got, want)
	}
}

// The served certificate's names are added only when that certificate is one a host could rely on today: not
// self-signed (a snakeoil certificate naming the machine) and not expired. A host given such a certificate had no valid
// one to lose, and its names (ip-10-0-0-5, localhost) are none an Autopilot certificate could cover.
func TestOnlyAValidServedCertificateLendsItsNames(t *testing.T) {
	only := func(listen, names, cert string) string {
		return `
http {
	server {
		` + listen + `
		server_name ` + names + `;
		ssl_certificate ` + cert + `;
		ssl_certificate_key /etc/ssl/site.key;
	}
}`
	}
	for name, c := range map[string]struct {
		write  func(m *machine)
		config string
		want   []string
	}{
		"implicit default, self-signed": {
			func(m *machine) {
				m.selfSigned("/etc/ssl/site.pem", "/etc/ssl/site.key", "ip-10-0-0-5.eu-west-1.compute.internal", "localhost")
			},
			only("listen 443 ssl;", "shop.example.test", "/etc/ssl/site.pem"), []string{"shop.example.test"}},
		"implicit default, issued by a CA": {
			func(m *machine) {
				m.cert("/etc/ssl/site.pem", "/etc/ssl/site.key", "shop.example.test", "old.example.test")
			},
			only("listen 443 ssl;", "shop.example.test", "/etc/ssl/site.pem"), []string{"old.example.test", "shop.example.test"}},
		"default_server, self-signed": {
			func(m *machine) {
				m.selfSigned("/etc/ssl/site.pem", "/etc/ssl/site.key", "web-1.internal.example.test")
			},
			only("listen 443 ssl default_server;", "shop.example.test", "/etc/ssl/site.pem"), []string{"shop.example.test"}},
		"a regular expression, expired": {
			func(m *machine) {
				m.expired("/etc/ssl/site.pem", "/etc/ssl/site.key", "app.example.test", "*.app.example.test")
			},
			only("listen 443 ssl default_server;", `app.example.test ~^(?<t>.+)\.app\.example\.test$`, "/etc/ssl/site.pem"),
			[]string{"app.example.test"}},
		"a regular expression, issued by a CA": {
			func(m *machine) {
				m.cert("/etc/ssl/site.pem", "/etc/ssl/site.key", "app.example.test", "*.app.example.test")
			},
			only("listen 443 ssl default_server;", `app.example.test ~^(?<t>.+)\.app\.example\.test$`, "/etc/ssl/site.pem"),
			[]string{"*.app.example.test", "app.example.test"}},
	} {
		t.Run(name, func(t *testing.T) {
			m := newMachine(t)
			c.write(m)
			inv := nginxSites(t, m, "/etc/nginx/nginx.conf", c.config)
			if len(inv.Sites) != 1 || !reflect.DeepEqual(inv.Sites[0].Names, c.want) {
				t.Fatalf("sites %s, want names %v", dump(inv.Sites), c.want)
			}
			if u := inv.Uses[inv.Sites[0].SiteKey]; len(u) != 1 || !reflect.DeepEqual(u[0].Names, c.want) {
				t.Errorf("uses %+v", u)
			}
		})
	}
}

func nginxFixtureFile(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "nginx", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestNginxIncludesFollowNginxsOrder(t *testing.T) {
	m := newMachine(t)
	m.cert("/etc/ssl/site.pem", "/etc/ssl/site.key", "site.example")
	inv := nginxSites(t, m,
		"/etc/nginx/nginx.conf", "http { include sites/*.conf; }",
		"/etc/nginx/sites/b.conf", "server { listen 443 ssl; server_name b.example; include /etc/nginx/tls/*.conf; }",
		"/etc/nginx/sites/a.conf", "server { listen 443 ssl; server_name a.example; include ../nginx/tls/site.conf; }",
		"/etc/nginx/tls/site.conf", "ssl_certificate /etc/ssl/site.pem; ssl_certificate_key /etc/ssl/site.key;",
		"/etc/nginx/other/c.conf", "server { listen 443 ssl; server_name not-included.example; ssl_certificate /etc/ssl/site.pem; }",
	)
	// a.conf, included first, is the first server on *:443: it catches every name, so the certificate's names too.
	site := tlsSite(protocol.SiteNginx, "/etc/nginx/sites/a.conf", []string{"a.example", "b.example", "site.example"}, "/etc/ssl/site.pem", "/etc/ssl/site.key", "")
	site.Served = m.facts("/etc/ssl/site.pem")
	checkSites(t, inv.Sites, []protocol.Site{site})
	if uses := inv.Uses[site.SiteKey]; len(uses) != 2 || uses[0].ConfigPath != "/etc/nginx/sites/a.conf" || uses[1].ConfigPath != "/etc/nginx/sites/b.conf" {
		t.Errorf("uses %+v", uses)
	}
}

func TestNginxCertificatesThatAreNotFiles(t *testing.T) {
	m := newMachine(t)
	m.cert("/etc/ssl/hsm.pem", "", "hsm.example")
	inv := nginxSites(t, m, "/etc/nginx/nginx.conf", `
http {
	server { listen 443 ssl; server_name inline.example; ssl_certificate "data:-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----"; ssl_certificate_key data:$key; }
	server { listen 443 ssl; server_name hsm.example; ssl_certificate /etc/ssl/hsm.pem; ssl_certificate_key engine:pkcs11:id_42; }
	server { listen 443 ssl; server_name missing.example; ssl_certificate /etc/ssl/missing.pem; ssl_certificate_key /etc/ssl/missing.key; }
}`)
	// A key in an engine cannot be written; a certificate written into the configuration is no file at all (left out,
	// and never sent); a file that cannot be read cannot be checked.
	hsm := tlsSite(protocol.SiteNginx, "/etc/nginx/nginx.conf", []string{"hsm.example"}, "/etc/ssl/hsm.pem", "", "")
	hsm.Served = m.facts("/etc/ssl/hsm.pem")
	hsm.Blocked = blocked(protocol.BlockedUnreadable)
	missing := tlsSite(protocol.SiteNginx, "/etc/nginx/nginx.conf", []string{"missing.example"}, "/etc/ssl/missing.pem", "/etc/ssl/missing.key", "")
	missing.Blocked = blocked(protocol.BlockedUnreadable)
	checkSites(t, inv.Sites, []protocol.Site{hsm, missing})
	if len(inv.Problems) != 3 {
		t.Errorf("problems %q", inv.Problems)
	}
	if strings.Contains(strings.Join(inv.Problems, "\n"), "MIIB") {
		t.Errorf("a problem quotes the configuration: %q", inv.Problems)
	}
	noConfigOrKeys(t, m, inv)
}

func TestAPathThatCannotBeReportedIsLeftOut(t *testing.T) {
	m := newMachine(t)
	// nginx reads \t in quotes as a tab; the server refuses control characters (in the whole inventory).
	inv := nginxSites(t, m, "/etc/nginx/nginx.conf", `http {
	server { listen 443 ssl; server_name tab.example; ssl_certificate "/etc/ssl/a\tb.pem"; ssl_certificate_key /etc/ssl/a.key; }
	server { listen 80; server_name plain.example; }
}`)
	checkSites(t, inv.Sites, []protocol.Site{plainSite(protocol.SiteNginx, "/etc/nginx/nginx.conf", "plain.example")})
	if len(inv.Problems) != 1 || !strings.Contains(inv.Problems[0], "cannot be reported") {
		t.Errorf("problems %q", inv.Problems)
	}
}

func TestNginxMultipleCertificatesOfOneServer(t *testing.T) {
	m := newMachine(t)
	m.cert("/etc/ssl/rsa.pem", "/etc/ssl/rsa.key", "dual.example")
	m.cert("/etc/ssl/ecdsa.pem", "/etc/ssl/ecdsa.key", "dual.example")
	inv := nginxSites(t, m, "/etc/nginx/nginx.conf", `
http { server {
	listen 443 ssl; server_name dual.example;
	ssl_certificate /etc/ssl/rsa.pem; ssl_certificate_key /etc/ssl/rsa.key;
	ssl_certificate /etc/ssl/ecdsa.pem; ssl_certificate_key /etc/ssl/ecdsa.key;
} }`)
	rsa := tlsSite(protocol.SiteNginx, "/etc/nginx/nginx.conf", []string{"dual.example"}, "/etc/ssl/rsa.pem", "/etc/ssl/rsa.key", "")
	rsa.Served = m.facts("/etc/ssl/rsa.pem")
	ecdsa := tlsSite(protocol.SiteNginx, "/etc/nginx/nginx.conf", []string{"dual.example"}, "/etc/ssl/ecdsa.pem", "/etc/ssl/ecdsa.key", "")
	ecdsa.Served = m.facts("/etc/ssl/ecdsa.pem")
	checkSites(t, inv.Sites, []protocol.Site{rsa, ecdsa})
}

func TestNginxConfigurationErrors(t *testing.T) {
	for name, dump := range map[string]string{
		"no configuration":    "nginx: [emerg] something\n",
		"an unclosed block":   "# configuration file /etc/nginx/nginx.conf:\nhttp { server { listen 80;\n",
		"an extra brace":      "# configuration file /etc/nginx/nginx.conf:\nhttp { }\n}\n",
		"an unclosed quote":   "# configuration file /etc/nginx/nginx.conf:\nhttp { server_name \"a; }\n",
		"a missing semicolon": "# configuration file /etc/nginx/nginx.conf:\nhttp { server { listen 80 } }\n",
		"includes in a loop": "# configuration file /etc/nginx/nginx.conf:\nhttp { include /etc/nginx/a.conf; }\n" +
			"# configuration file /etc/nginx/a.conf:\ninclude /etc/nginx/a.conf;\n",
	} {
		_, err := Read(context.Background(), fakeRunner{"nginx -T": {out: dump}}, newMachine(t).fs, Options{})
		if err == nil {
			t.Errorf("%s: read", name)
		}
	}
	// nginx -T fails on a configuration nginx refuses.
	_, err := Read(context.Background(), fakeRunner{"nginx -T": {err: errors.New("nginx -T failed: [emerg] unknown directive")}}, newMachine(t).fs, Options{})
	if err == nil || !strings.Contains(err.Error(), "nginx could not be read") {
		t.Errorf("a failing nginx -T: %v", err)
	}
}
