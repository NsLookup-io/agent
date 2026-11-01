package inventory

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/nslookup-io/agent/internal/protocol"
)

const apacheDumpCommand = "apachectl -t -D DUMP_VHOSTS -D DUMP_RUN_CFG"

func apacheFixture(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "apache", "dump-vhosts.txt"))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func apacheMachine(t *testing.T) *machine {
	m := newMachine(t, "apache", "certbot")
	m.cert("/etc/ssl/shop/cert.pem", "/etc/ssl/shop/privkey.pem", "shop.example", "www.shop.example", "api.shop.example")
	m.file("/etc/ssl/shop/chain.pem", certPEM(m.ca.cert))
	m.cert("/etc/letsencrypt/live/blog.example/fullchain.pem", "/etc/letsencrypt/live/blog.example/privkey.pem", "blog.example")
	m.combined("/etc/apache2/ssl/intranet.pem", "intranet.example")
	return m
}

func TestApacheSites(t *testing.T) {
	m := apacheMachine(t)
	inv, err := Read(context.Background(), fakeRunner{apacheDumpCommand: {out: apacheFixture(t)}}, m.fs, Options{})
	if err != nil {
		t.Fatal(err)
	}

	// Two virtual hosts use the shop's files, one through an Include relative to ServerRoot.
	shop := tlsSite(protocol.SiteApache, "/etc/apache2/sites-enabled/api-ssl.conf", []string{"api.shop.example", "shop.example", "www.shop.example"},
		"/etc/ssl/shop/cert.pem", "/etc/ssl/shop/privkey.pem", "/etc/ssl/shop/chain.pem")
	shop.Served = m.facts("/etc/ssl/shop/cert.pem")

	// certbot's virtual host: SSLEngine comes from certbot's included options file.
	blog := tlsSite(protocol.SiteApache, "/etc/apache2/sites-enabled/blog-le-ssl.conf", []string{"blog.example"},
		"/etc/letsencrypt/live/blog.example/fullchain.pem", "/etc/letsencrypt/live/blog.example/privkey.pem", "")
	blog.Served = m.facts("/etc/letsencrypt/live/blog.example/fullchain.pem")
	blog.Owner, blog.CertbotName = certbot(), str("blog.example")

	// A relative path is relative to ServerRoot; no key file named: the key is in the certificate's file.
	intranet := tlsSite(protocol.SiteApache, "/etc/apache2/sites-enabled/intranet.conf", []string{"intranet.example"},
		"/etc/apache2/ssl/intranet.pem", "/etc/apache2/ssl/intranet.pem", "")
	intranet.Served = m.facts("/etc/apache2/ssl/intranet.pem")

	checkSites(t, inv.Sites, []protocol.Site{
		shop, blog, intranet,
		// The port-80 hosts of shop and blog are left out: their names are served with HTTPS.
		plainSite(protocol.SiteApache, "/etc/apache2/sites-enabled/legacy.conf", "*.legacy.example", "legacy.example", "www.legacy.example"),
	})
	if len(inv.Problems) != 0 {
		t.Errorf("problems %q", inv.Problems)
	}
	want := []Use{
		{Kind: protocol.WebServerApache, ConfigPath: "/etc/apache2/sites-enabled/api-ssl.conf", Names: []string{"api.shop.example"},
			CertPath: "/etc/ssl/shop/cert.pem", KeyPath: "/etc/ssl/shop/privkey.pem", ChainPath: "/etc/ssl/shop/chain.pem", Ports: []int{443}},
		// The default server of *:443 catches every name: the certificate's names too.
		{Kind: protocol.WebServerApache, ConfigPath: "/etc/apache2/sites-enabled/shop-ssl.conf", Names: []string{"api.shop.example", "shop.example", "www.shop.example"},
			CertPath: "/etc/ssl/shop/cert.pem", KeyPath: "/etc/ssl/shop/privkey.pem", ChainPath: "/etc/ssl/shop/chain.pem", Ports: []int{443}},
	}
	if got := inv.Uses[shop.SiteKey]; !reflect.DeepEqual(got, want) {
		t.Errorf("uses:\n got %+v\nwant %+v", got, want)
	}
	if got := inv.Uses[intranet.SiteKey]; len(got) != 1 || !reflect.DeepEqual(got[0].Ports, []int{8443}) {
		t.Errorf("intranet uses %+v", got)
	}
	noConfigOrKeys(t, m, inv)
}

func TestApacheTriesApache2ctlThenHttpd(t *testing.T) {
	m := apacheMachine(t)
	for name, runner := range map[string]fakeRunner{
		// Debian: apachectl may be missing.
		"apache2ctl": {"apache2ctl -t -D DUMP_VHOSTS -D DUMP_RUN_CFG": {out: apacheFixture(t)}},
		// An apachectl that does not pass the flags on prints no virtual hosts.
		"httpd": {
			apacheDumpCommand: {out: "Syntax OK\n"},
			"httpd -S":        {out: apacheFixture(t)},
		},
	} {
		inv, err := Read(context.Background(), runner, m.fs, Options{})
		if err != nil || len(inv.Sites) != 4 {
			t.Errorf("%s: %d sites, %v", name, len(inv.Sites), err)
		}
	}
	_, err := Read(context.Background(), fakeRunner{apacheDumpCommand: {out: "AH00526: Syntax error on line 3\n", err: errors.New("exit status 1")}}, m.fs, Options{})
	if err == nil {
		t.Error("a failing apachectl: read")
	}
}

// What Apache's configuration says that the agent cannot use is left out, the same on every read, and said.
func TestApacheVirtualHostsLeftOut(t *testing.T) {
	m := newMachine(t)
	m.file("/etc/httpd/conf.d/a.conf", []byte(`<VirtualHost *:443>
	ServerName a.example
	SSLEngine on
</VirtualHost>
`))
	m.cert("/etc/pki/tls/certs/c.crt", "", "c.example")
	m.file("/etc/httpd/conf.d/c.conf", []byte(`<VirtualHost 192.0.2.10:443>
	ServerName c.example
	SSLEngine on
	SSLCertificateFile /etc/pki/tls/certs/c.crt
	SSLCertificateKeyFile pkcs11:token=hsm;object=c
	Include conf.d/${MISSING}.conf
	IncludeOptional conf.d/missing/*.conf
</VirtualHost>
`))
	dump := `VirtualHost configuration:
*:443                  is a NameVirtualHost
         default server a.example (/etc/httpd/conf.d/a.conf:1)
         port 443 namevhost a.example (/etc/httpd/conf.d/a.conf:1)
         port 443 namevhost m.example (macro 'TLSHost' (defined on line 1 of "/etc/httpd/conf.d/macros.conf") used on line 3 of "/etc/httpd/conf.d/sites.conf":2)
192.0.2.10:443         c.example (/etc/httpd/conf.d/c.conf:1)
ServerRoot: "/etc/httpd"
`
	inv, err := Read(context.Background(), fakeRunner{"httpd -S": {out: dump}}, m.fs, Options{})
	if err != nil {
		t.Fatal(err)
	}
	// a.example takes its certificate from outside its virtual host, m.example is made by a macro, c.example's
	// Include names a variable and its key is no file: each said, c reported as unreadable.
	c := tlsSite(protocol.SiteApache, "/etc/httpd/conf.d/c.conf", []string{"c.example"}, "/etc/pki/tls/certs/c.crt", "", "")
	c.Served = m.facts("/etc/pki/tls/certs/c.crt")
	c.Blocked = blocked(protocol.BlockedUnreadable)
	checkSites(t, inv.Sites, []protocol.Site{c})
	if len(inv.Problems) != 4 {
		t.Errorf("%d problems: %s", len(inv.Problems), strings.Join(inv.Problems, "\n"))
	}
}

// A virtual host that cannot be read this time (a file being edited, gone, unreadable) fails Apache's read: reported
// without it, its sites would look gone.
func TestApacheFailsOnAVirtualHostThatCannotBeRead(t *testing.T) {
	m := newMachine(t)
	m.file("/etc/httpd/conf.d/a.conf", []byte(`# the dump's line is not a <VirtualHost> any more
<VirtualHost *:443>
	ServerName a.example
</VirtualHost>
<VirtualHost *:443>
	ServerName b.example
	SSLEngine on
	SSLCertificateFile /etc/pki/tls/certs/b.crt
`))
	for line, why := range map[string]string{
		"/etc/httpd/conf.d/a.conf:1":    "no <VirtualHost> starts on that line",
		"/etc/httpd/conf.d/a.conf:5":    "its </VirtualHost> is missing",
		"/etc/httpd/conf.d/gone.conf:1": "gone.conf",
	} {
		dump := "VirtualHost configuration:\n*:443                  x.example (" + line + ")\nServerRoot: \"/etc/httpd\"\n"
		inv, err := Read(context.Background(), fakeRunner{"httpd -S": {out: dump}}, m.fs, Options{})
		if err == nil || len(inv.Problems) != 1 || !strings.Contains(inv.Problems[0], why) {
			t.Errorf("%s: %v, %q", line, err, inv.Problems)
		}
	}
}

// A virtual host with HTTPS whose names the agent cannot express as host names (a wildcard that is not the whole first
// label, a "?" wildcard, a variable) also gets the names of the certificate it serves.
func TestApacheNamesTheAgentCannotExpressAddTheServedNames(t *testing.T) {
	for alias, want := range map[string][]string{
		"www.app.example.*":    {"*.app.example.test", "app.example.test"},
		"w?w.app.example.test": {"*.app.example.test", "app.example.test"},
		"${APP_HOST}":          {"*.app.example.test", "app.example.test"},
		"*.app.example.test":   {"*.app.example.test", "app.example.test"},
		"www.app.example.test": {"app.example.test", "www.app.example.test"},
	} {
		t.Run(alias, func(t *testing.T) {
			m := newMachine(t)
			m.cert("/etc/pki/tls/certs/app.crt", "/etc/pki/tls/private/app.key", "app.example.test", "*.app.example.test")
			m.file("/etc/httpd/conf.d/app.conf", []byte(`<VirtualHost *:443>
	ServerName app.example.test
	ServerAlias `+alias+`
	SSLEngine on
	SSLCertificateFile /etc/pki/tls/certs/app.crt
	SSLCertificateKeyFile /etc/pki/tls/private/app.key
</VirtualHost>
`))
			// Another virtual host is the default server of *:443: app is no catch-all.
			m.file("/etc/httpd/conf.d/0-default.conf", []byte("<VirtualHost *:443>\n\tServerName default.example.test\n</VirtualHost>\n"))
			dump := `VirtualHost configuration:
*:443                  is a NameVirtualHost
         default server default.example.test (/etc/httpd/conf.d/0-default.conf:1)
         port 443 namevhost default.example.test (/etc/httpd/conf.d/0-default.conf:1)
         port 443 namevhost app.example.test (/etc/httpd/conf.d/app.conf:1)
ServerRoot: "/etc/httpd"
`
			inv, err := Read(context.Background(), fakeRunner{"httpd -S": {out: dump}}, m.fs, Options{})
			if err != nil {
				t.Fatal(err)
			}
			i := slices.IndexFunc(inv.Sites, func(s protocol.Site) bool { return s.CertPath != nil && *s.CertPath == "/etc/pki/tls/certs/app.crt" })
			if i < 0 || !reflect.DeepEqual(inv.Sites[i].Names, want) {
				t.Errorf("sites %+v, want names %v", inv.Sites, want)
			}
		})
	}
}

// The first virtual host of an address and port answers the names no other one there serves (Apache's default server,
// or the only one): it also gets the names of the certificate it serves; the others keep their own names.
func TestApacheCatchAllVirtualHostsAddTheServedNames(t *testing.T) {
	m := newMachine(t)
	m.cert("/etc/pki/tls/certs/first.crt", "/etc/pki/tls/private/first.key", "first.example.test", "legacy.example.test")
	m.cert("/etc/pki/tls/certs/second.crt", "/etc/pki/tls/private/second.key", "second.example.test", "other.example.test")
	m.cert("/etc/pki/tls/certs/alone.crt", "/etc/pki/tls/private/alone.key", "alone.example.test", "spare.example.test")
	vhost := func(name, cert string) string {
		return `<VirtualHost *:443>
	ServerName ` + name + `
	SSLEngine on
	SSLCertificateFile /etc/pki/tls/certs/` + cert + `.crt
	SSLCertificateKeyFile /etc/pki/tls/private/` + cert + `.key
</VirtualHost>
`
	}
	m.file("/etc/httpd/conf.d/sites.conf", []byte(vhost("first.example.test", "first")+vhost("second.example.test", "second")))
	m.file("/etc/httpd/conf.d/alone.conf", []byte(strings.Replace(vhost("alone.example.test", "alone"), "*:443", "192.0.2.10:8443", 1)))
	dump := `VirtualHost configuration:
*:443                  is a NameVirtualHost
         default server first.example.test (/etc/httpd/conf.d/sites.conf:1)
         port 443 namevhost first.example.test (/etc/httpd/conf.d/sites.conf:1)
         port 443 namevhost second.example.test (/etc/httpd/conf.d/sites.conf:7)
192.0.2.10:8443        alone.example.test (/etc/httpd/conf.d/alone.conf:1)
ServerRoot: "/etc/httpd"
`
	inv, err := Read(context.Background(), fakeRunner{"httpd -S": {out: dump}}, m.fs, Options{})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string][]string{}
	for _, s := range inv.Sites {
		got[*s.CertPath] = s.Names
	}
	want := map[string][]string{
		"/etc/pki/tls/certs/first.crt":  {"first.example.test", "legacy.example.test"},
		"/etc/pki/tls/certs/second.crt": {"second.example.test"},
		"/etc/pki/tls/certs/alone.crt":  {"alone.example.test", "spare.example.test"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("names %v\nwant %v", got, want)
	}
}

// The first virtual host of an address serving a self-signed certificate (Debian's snakeoil, say) adds nothing.
func TestApacheCatchAllWithASelfSignedCertificateAddsNothing(t *testing.T) {
	m := newMachine(t)
	m.selfSigned("/etc/ssl/certs/ssl-cert-snakeoil.pem", "/etc/ssl/private/ssl-cert-snakeoil.key", "ip-10-0-0-5.eu-west-1.compute.internal")
	m.file("/etc/apache2/sites-enabled/default-ssl.conf", []byte(`<VirtualHost *:443>
	ServerName shop.example.test
	SSLEngine on
	SSLCertificateFile /etc/ssl/certs/ssl-cert-snakeoil.pem
	SSLCertificateKeyFile /etc/ssl/private/ssl-cert-snakeoil.key
</VirtualHost>
`))
	dump := "VirtualHost configuration:\n*:443                  shop.example.test (/etc/apache2/sites-enabled/default-ssl.conf:1)\nServerRoot: \"/etc/apache2\"\n"
	inv, err := Read(context.Background(), fakeRunner{"apache2ctl -t -D DUMP_VHOSTS -D DUMP_RUN_CFG": {out: dump}}, m.fs, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(inv.Sites) != 1 || !reflect.DeepEqual(inv.Sites[0].Names, []string{"shop.example.test"}) {
		t.Errorf("sites %+v", inv.Sites)
	}
}

func TestApacheArgs(t *testing.T) {
	for line, want := range map[string][]string{
		`SSLCertificateFile /etc/ssl/a.pem`:            {"SSLCertificateFile", "/etc/ssl/a.pem"},
		"ServerAlias\ta.example   b.example":           {"ServerAlias", "a.example", "b.example"},
		`SSLCertificateFile "/etc/ssl/with space.pem"`: {"SSLCertificateFile", "/etc/ssl/with space.pem"},
		`Header set X "a \"quoted\" word"`:             {"Header", "set", "X", `a "quoted" word`},
		`SSLCertificateKeyFile '/etc/ssl/k.pem'`:       {"SSLCertificateKeyFile", "/etc/ssl/k.pem"},
	} {
		if got := apacheArgs(line); !reflect.DeepEqual(got, want) {
			t.Errorf("%s: %q, want %q", line, got, want)
		}
	}
}
