package install

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nslookup-io/agent/internal/inventory"
	"github.com/nslookup-io/agent/internal/protocol"
)

// Each web server gets the files its directives expect; the rest of the file system is left alone.
func TestEachWebServerGetsTheFilesItsDirectivesExpect(t *testing.T) {
	type files map[string][]byte
	for name, c := range map[string]struct {
		use  func(port int) inventory.Use
		want func(c issued) files
		test string
	}{
		"nginx: the certificate with its chain, the key on its own": {
			use: func(port int) inventory.Use {
				return inventory.Use{Kind: protocol.WebServerNginx, ConfigPath: "/etc/nginx/sites-enabled/shop", Names: []string{"shop.example"},
					CertPath: "/etc/ssl/shop.pem", KeyPath: "/etc/ssl/shop.key", Ports: []int{port}}
			},
			want: func(c issued) files {
				return files{"/etc/ssl/shop.pem": cat(c.leafPEM, c.chainPEM), "/etc/ssl/shop.key": c.keyPEM}
			},
			test: "nginx -t",
		},
		"Apache with SSLCertificateChainFile: the chain in its own file": {
			use: func(port int) inventory.Use {
				return inventory.Use{Kind: protocol.WebServerApache, ConfigPath: "/etc/apache2/sites-enabled/shop.conf", Names: []string{"shop.example"},
					CertPath: "/etc/ssl/shop.pem", KeyPath: "/etc/ssl/shop.key", ChainPath: "/etc/ssl/chain.pem", Ports: []int{port}}
			},
			want: func(c issued) files {
				return files{"/etc/ssl/shop.pem": c.leafPEM, "/etc/ssl/shop.key": c.keyPEM, "/etc/ssl/chain.pem": c.chainPEM}
			},
			test: "apachectl -t",
		},
		"Apache without a chain file: the certificate with its chain": {
			use: func(port int) inventory.Use {
				return inventory.Use{Kind: protocol.WebServerApache, ConfigPath: "/etc/apache2/sites-enabled/shop.conf", Names: []string{"shop.example"},
					CertPath: "/etc/ssl/shop.pem", KeyPath: "/etc/ssl/shop.key", Ports: []int{port}}
			},
			want: func(c issued) files {
				return files{"/etc/ssl/shop.pem": cat(c.leafPEM, c.chainPEM), "/etc/ssl/shop.key": c.keyPEM}
			},
			test: "apachectl -t",
		},
		"Apache without a key file: the key in the certificate's file": {
			use: func(port int) inventory.Use {
				return inventory.Use{Kind: protocol.WebServerApache, ConfigPath: "/etc/apache2/sites-enabled/shop.conf", Names: []string{"shop.example"},
					CertPath: "/etc/ssl/shop.pem", KeyPath: "/etc/ssl/shop.pem", Ports: []int{port}}
			},
			want: func(c issued) files { return files{"/etc/ssl/shop.pem": cat(c.keyPEM, c.leafPEM, c.chainPEM)} },
			test: "apachectl -t",
		},
		"HAProxy with one file: key, certificate and chain": {
			use: func(port int) inventory.Use {
				return inventory.Use{Kind: protocol.WebServerHAProxy, ConfigPath: "/etc/haproxy/haproxy.cfg", Names: []string{"shop.example"},
					CertPath: "/etc/haproxy/certs/shop.pem", KeyPath: "/etc/haproxy/certs/shop.pem", Ports: []int{port}}
			},
			want: func(c issued) files {
				return files{"/etc/haproxy/certs/shop.pem": cat(c.keyPEM, c.leafPEM, c.chainPEM)}
			},
			test: "haproxy -c -f /etc/haproxy/haproxy.cfg",
		},
		"HAProxy with the key beside it": {
			use: func(port int) inventory.Use {
				return inventory.Use{Kind: protocol.WebServerHAProxy, ConfigPath: "/etc/haproxy/haproxy.cfg", Names: []string{"shop.example"},
					CertPath: "/etc/haproxy/certs/shop.pem", KeyPath: "/etc/haproxy/certs/shop.pem.key", Ports: []int{port}}
			},
			want: func(c issued) files {
				return files{"/etc/haproxy/certs/shop.pem": cat(c.leafPEM, c.chainPEM), "/etc/haproxy/certs/shop.pem.key": c.keyPEM}
			},
			test: "haproxy -c -f /etc/haproxy/haproxy.cfg",
		},
	} {
		t.Run(name, func(t *testing.T) {
			m := newMachine(t, map[string]error{
				"nginx -t": nil, "nginx -s reload": nil, "apachectl -t": nil, "apachectl -k graceful": nil,
				"haproxy -c -f /etc/haproxy/haproxy.cfg": nil, "systemctl is-active haproxy": nil, "systemctl reload haproxy": nil,
			})
			use := c.use(closedPort(t))
			old := m.ca.issue(t, "shop.example")
			for p := range c.want(old) {
				m.write(p, []byte("old "+p+"\n"), 0o644)
			}
			m.write("/etc/ssl/unrelated.pem", []byte("unrelated\n"), 0o644)
			site := m.site(use)
			next := m.ca.issue(t, "shop.example")

			r := m.host.Apply(context.Background(), site, next.bundle(), installWork(site, next.sha))
			if !r.OK || steps(r) != "checked written tested reloaded checked_locally!" || r.Drift {
				t.Fatalf("%+v: %s, %s", r, steps(r), message(r))
			}
			for p, want := range c.want(next) {
				if got := m.read(p); !bytes.Equal(got, want) {
					t.Errorf("%s:\n%s\nwant\n%s", p, got, want)
				}
			}
			if got := m.read("/etc/ssl/unrelated.pem"); string(got) != "unrelated\n" {
				t.Errorf("an unrelated file changed: %q", got)
			}
			if m.runner.count(c.test) != 1 {
				t.Errorf("ran %q", m.runner.commands())
			}
			if sha, err := m.host.DiskSHA(site); err != nil || sha != next.sha {
				t.Errorf("on disk %q, %v", sha, err)
			}
			if r.ServedLocally == nil || *r.ServedLocally {
				t.Errorf("served locally %v", r.ServedLocally)
			}
			if fileExists(filepath.Join(m.state, "pending.json")) {
				t.Error("pending.json is left")
			}
			for _, dir := range []string{"/etc/ssl", "/etc/haproxy/certs"} {
				if !m.exists(dir) {
					continue
				}
				var keep []string
				for p := range c.want(next) {
					keep = append(keep, filepath.Base(p))
				}
				if extra := m.leftovers(dir, append(keep, "unrelated.pem")...); len(extra) > 0 {
					t.Errorf("left in %s: %q", dir, extra)
				}
			}
		})
	}
}

func fileExists(p string) bool {
	_, err := os.Lstat(p)
	return err == nil
}

// nginxSite is an nginx site with its certificate and key files on disk, holding old.
func nginxSite(m *machine, old issued, certMode, keyMode fs.FileMode) protocol.Site {
	m.write("/etc/ssl/shop.pem", cat(old.leafPEM, old.chainPEM), certMode)
	m.write("/etc/ssl/shop.key", old.keyPEM, keyMode)
	return m.site(inventory.Use{Kind: protocol.WebServerNginx, ConfigPath: "/etc/nginx/sites-enabled/shop", Names: []string{"shop.example", "www.shop.example"},
		CertPath: "/etc/ssl/shop.pem", KeyPath: "/etc/ssl/shop.key", Ports: []int{closedPort(m.t)}})
}

// The files keep their owner, group and mode; a key is never written wider than it was, nor than 0640.
func TestOwnerGroupAndModeAreKeptAndAKeyIsNeverWiderThan0640(t *testing.T) {
	for _, c := range []struct{ cert, key, wantCert, wantKey fs.FileMode }{
		{0o644, 0o600, 0o644, 0o600},
		{0o664, 0o640, 0o664, 0o640},
		{0o644, 0o644, 0o644, 0o640},
		{0o600, 0o604, 0o600, 0o600},
		{0o644, 0o666, 0o644, 0o640},
		{0o644, 0o400, 0o644, 0o400},
	} {
		m := newMachine(t, nginxOnItsOwn())
		site := nginxSite(m, m.ca.issue(t, "shop.example", "www.shop.example"), c.cert, c.key)
		next := m.ca.issue(t, "shop.example", "www.shop.example")
		r := m.host.Apply(context.Background(), site, next.bundle(), installWork(site, next.sha))
		if !r.OK {
			t.Fatalf("%s: %s", steps(r), message(r))
		}
		if got := m.mode("/etc/ssl/shop.pem").Perm(); got != c.wantCert {
			t.Errorf("certificate %04o: now %04o, want %04o", c.cert, got, c.wantCert)
		}
		if got := m.mode("/etc/ssl/shop.key").Perm(); got != c.wantKey {
			t.Errorf("key %04o: now %04o, want %04o", c.key, got, c.wantKey)
		}
		uid, gid := os.Getuid(), os.Getgid()
		want := []string{
			"/etc/ssl/shop.key " + strconv.Itoa(uid) + ":" + strconv.Itoa(gid),
			"/etc/ssl/shop.pem " + strconv.Itoa(uid) + ":" + strconv.Itoa(gid),
		}
		if got := slices.Sorted(slices.Values(m.chowned)); !slices.Equal(got, want) {
			t.Errorf("owners %q, want %q", got, want)
		}
	}
}

func TestATestFailurePutsTheOldFilesBackWithoutAReload(t *testing.T) {
	m := newMachine(t, nginxOnItsOwn())
	old := m.ca.issue(t, "shop.example", "www.shop.example")
	site := nginxSite(m, old, 0o644, 0o600)
	m.runner.set("nginx -t", errors.New(`nginx -t failed (exit status 1): nginx: [emerg] SSL_CTX_use_PrivateKey("/etc/ssl/shop.key") failed`))
	next := m.ca.issue(t, "shop.example", "www.shop.example")

	r := m.host.Apply(context.Background(), site, next.bundle(), installWork(site, next.sha))
	if r.OK || steps(r) != "checked written tested! restored" || !strings.Contains(message(r), "SSL_CTX_use_PrivateKey") {
		t.Fatalf("%s: %s", steps(r), message(r))
	}
	if r.ServedLocally != nil {
		t.Errorf("served locally %v", *r.ServedLocally)
	}
	if !bytes.Equal(m.read("/etc/ssl/shop.pem"), cat(old.leafPEM, old.chainPEM)) || !bytes.Equal(m.read("/etc/ssl/shop.key"), old.keyPEM) {
		t.Error("the old files are not back")
	}
	if m.mode("/etc/ssl/shop.key").Perm() != 0o600 {
		t.Errorf("key mode %v", m.mode("/etc/ssl/shop.key"))
	}
	if slices.ContainsFunc(m.runner.commands(), func(c string) bool { return strings.Contains(c, "reload") }) {
		t.Errorf("reloaded: %q", m.runner.commands())
	}
	if fileExists(filepath.Join(m.state, "pending.json")) {
		t.Error("pending.json is left")
	}
	if extra := m.leftovers("/etc/ssl", "shop.pem", "shop.key"); len(extra) > 0 {
		t.Errorf("left %q", extra)
	}
}

func TestAReloadFailurePutsTheOldFilesBackAndReloadsAgain(t *testing.T) {
	m := newMachine(t, nginxOnItsOwn())
	old := m.ca.issue(t, "shop.example", "www.shop.example")
	site := nginxSite(m, old, 0o644, 0o600)
	m.runner.set("nginx -s reload", errors.New("nginx -s reload failed (exit status 1): nginx: [error] invalid PID number"))
	// The second reload, with the old files back, works.
	m.runner.hooks["nginx -s reload"] = func() {
		if m.runner.count("nginx -s reload") == 2 {
			m.runner.set("nginx -s reload", nil)
		}
	}
	next := m.ca.issue(t, "shop.example", "www.shop.example")

	r := m.host.Apply(context.Background(), site, next.bundle(), installWork(site, next.sha))
	if r.OK || steps(r) != "checked written tested reloaded! restored reloaded" || !strings.Contains(message(r), "invalid PID number") {
		t.Fatalf("%s: %s", steps(r), message(r))
	}
	if !bytes.Equal(m.read("/etc/ssl/shop.pem"), cat(old.leafPEM, old.chainPEM)) || !bytes.Equal(m.read("/etc/ssl/shop.key"), old.keyPEM) {
		t.Error("the old files are not back")
	}
	if got := m.runner.commands(); !slices.Equal(got, []string{"nginx -t", "systemctl is-active nginx", "nginx -s reload", "systemctl is-active nginx", "nginx -s reload"}) {
		t.Errorf("ran %q", got)
	}
}

// A file used by several web servers is tested by every one of them (all must pass) and reloaded by every one.
func TestEveryWebServerUsingTheFileIsTestedAndReloaded(t *testing.T) {
	answers := map[string]error{
		"nginx -t": nil, "systemctl is-active nginx": nil, "systemctl reload nginx": nil,
		"apachectl -t": nil, "systemctl is-active apache2": errors.New("exit status 3"), "systemctl is-active httpd": errors.New("exit status 3"),
		"apachectl -k graceful":                  nil,
		"haproxy -c -f /etc/haproxy/haproxy.cfg": nil, "systemctl is-active haproxy": nil, "systemctl reload haproxy": nil,
	}
	shared := func(m *machine, old issued) protocol.Site {
		m.write("/etc/ssl/acme/site.pem", cat(old.keyPEM, old.leafPEM, old.chainPEM), 0o600)
		port := closedPort(t)
		return m.site(
			inventory.Use{Kind: protocol.WebServerNginx, ConfigPath: "/etc/nginx/nginx.conf", Names: []string{"acme.example"},
				CertPath: "/etc/ssl/acme/site.pem", KeyPath: "/etc/ssl/acme/site.pem", Ports: []int{port}},
			inventory.Use{Kind: protocol.WebServerApache, ConfigPath: "/etc/apache2/sites-enabled/acme.conf", Names: []string{"www.acme.example"},
				CertPath: "/etc/ssl/acme/site.pem", KeyPath: "/etc/ssl/acme/site.pem", Ports: []int{port}},
			inventory.Use{Kind: protocol.WebServerHAProxy, ConfigPath: "/etc/haproxy/haproxy.cfg", Names: []string{"acme.example", "www.acme.example"},
				CertPath: "/etc/ssl/acme/site.pem", KeyPath: "/etc/ssl/acme/site.pem", Ports: []int{port}},
		)
	}

	m := newMachine(t, answers)
	site := shared(m, m.ca.issue(t, "acme.example", "www.acme.example"))
	next := m.ca.issue(t, "acme.example", "www.acme.example")
	r := m.host.Apply(context.Background(), site, next.bundle(), installWork(site, next.sha))
	if !r.OK || !bytes.Equal(m.read("/etc/ssl/acme/site.pem"), cat(next.keyPEM, next.leafPEM, next.chainPEM)) {
		t.Fatalf("%s: %s", steps(r), message(r))
	}
	want := []string{
		"nginx -t", "apachectl -t", "haproxy -c -f /etc/haproxy/haproxy.cfg",
		"systemctl is-active nginx", "systemctl reload nginx",
		"systemctl is-active apache2", "systemctl is-active httpd", "apachectl -k graceful",
		"systemctl is-active haproxy", "systemctl reload haproxy",
	}
	if got := m.runner.commands(); !slices.Equal(got, want) {
		t.Errorf("ran %q\nwant %q", got, want)
	}

	// One of them fails its test: the old file is back and none is reloaded.
	m = newMachine(t, answers)
	old := m.ca.issue(t, "acme.example", "www.acme.example")
	site = shared(m, old)
	m.runner.set("apachectl -t", errors.New("apachectl -t failed (exit status 1): AH00526: Syntax error"))
	next = m.ca.issue(t, "acme.example", "www.acme.example")
	r = m.host.Apply(context.Background(), site, next.bundle(), installWork(site, next.sha))
	if r.OK || steps(r) != "checked written tested! restored" || !strings.Contains(message(r), "AH00526") {
		t.Fatalf("%s: %s", steps(r), message(r))
	}
	if !bytes.Equal(m.read("/etc/ssl/acme/site.pem"), cat(old.keyPEM, old.leafPEM, old.chainPEM)) {
		t.Error("the old file is not back")
	}
	if got := m.runner.commands(); !slices.Equal(got, []string{"nginx -t", "apachectl -t"}) {
		t.Errorf("ran %q", got)
	}
}

// Configurations sharing a file but expecting different files: nothing is written.
func TestConfigurationsExpectingDifferentFilesGetNothing(t *testing.T) {
	m := newMachine(t, map[string]error{"nginx -t": nil, "haproxy -c -f /etc/haproxy/haproxy.cfg": nil})
	old := m.ca.issue(t, "acme.example")
	m.write("/etc/ssl/acme/site.pem", cat(old.leafPEM, old.chainPEM), 0o644)
	m.write("/etc/ssl/acme/site.key", old.keyPEM, 0o600)
	site := m.site(
		inventory.Use{Kind: protocol.WebServerNginx, ConfigPath: "/etc/nginx/nginx.conf", Names: []string{"acme.example"},
			CertPath: "/etc/ssl/acme/site.pem", KeyPath: "/etc/ssl/acme/site.key"},
		// HAProxy expects the key inside the certificate's file.
		inventory.Use{Kind: protocol.WebServerHAProxy, ConfigPath: "/etc/haproxy/haproxy.cfg", Names: []string{"acme.example"},
			CertPath: "/etc/ssl/acme/site.pem", KeyPath: "/etc/ssl/acme/site.pem"},
	)
	next := m.ca.issue(t, "acme.example")
	r := m.host.Apply(context.Background(), site, next.bundle(), installWork(site, next.sha))
	if r.OK || steps(r) != "checked written!" || !strings.Contains(message(r), "expect different files") {
		t.Fatalf("%s: %s", steps(r), message(r))
	}
	if !bytes.Equal(m.read("/etc/ssl/acme/site.pem"), cat(old.leafPEM, old.chainPEM)) || !bytes.Equal(m.read("/etc/ssl/acme/site.key"), old.keyPEM) {
		t.Error("a file was written")
	}
	if len(m.runner.commands()) != 0 {
		t.Errorf("ran %q", m.runner.commands())
	}
}

// A key or chain file another site uses too is not written: the other site's certificate would no longer match it.
func TestAFileAnotherSiteUsesIsNotWritten(t *testing.T) {
	m := newMachine(t, nginxOnItsOwn())
	old := m.ca.issue(t, "a.example")
	m.write("/etc/ssl/a.pem", old.leafPEM, 0o644)
	m.write("/etc/ssl/b.pem", old.leafPEM, 0o644)
	m.write("/etc/ssl/shared.key", old.keyPEM, 0o600)
	a := m.site(inventory.Use{Kind: protocol.WebServerNginx, ConfigPath: "/etc/nginx/nginx.conf", Names: []string{"a.example"},
		CertPath: "/etc/ssl/a.pem", KeyPath: "/etc/ssl/shared.key"})
	m.site(inventory.Use{Kind: protocol.WebServerNginx, ConfigPath: "/etc/nginx/nginx.conf", Names: []string{"b.example"},
		CertPath: "/etc/ssl/b.pem", KeyPath: "/etc/ssl/shared.key"})
	next := m.ca.issue(t, "a.example")
	r := m.host.Apply(context.Background(), a, next.bundle(), installWork(a, next.sha))
	if r.OK || steps(r) != "checked written!" || !strings.Contains(message(r), "/etc/ssl/shared.key is also used by another site") {
		t.Fatalf("%s: %s", steps(r), message(r))
	}
	if !bytes.Equal(m.read("/etc/ssl/a.pem"), old.leafPEM) {
		t.Error("written")
	}
}

func TestTheBundleIsCheckedBeforeAnythingIsWritten(t *testing.T) {
	m := newMachine(t, nginxOnItsOwn())
	old := m.ca.issue(t, "shop.example", "www.shop.example")
	site := nginxSite(m, old, 0o644, 0o600)
	good := m.ca.issue(t, "shop.example", "www.shop.example")
	other := m.ca.issue(t, "shop.example", "www.shop.example")
	for name, c := range map[string]struct {
		bundle protocol.Bundle
		sha    string
		want   string
	}{
		"another certificate than the work names": {good.bundle(), other.sha, "not the certificate"},
		"a key that is not the certificate's": {func() protocol.Bundle {
			b := good.bundle()
			b.KeyPEM = other.keyPEM
			return b
		}(), good.sha, "does not match"},
		"a name the certificate does not cover": {m.ca.issue(t, "shop.example").bundle(), "", "does not cover www.shop.example"},
		"expired":                               {m.ca.issueUntil(t, time.Now().Add(-time.Hour), "shop.example", "www.shop.example").bundle(), "", "expired"},
		"no certificate": {func() protocol.Bundle {
			b := good.bundle()
			b.CertPEM = []byte("nothing")
			return b
		}(), good.sha, "no certificate"},
		"something other than certificates in the chain": {func() protocol.Bundle {
			b := good.bundle()
			b.ChainPEM = cat(good.chainPEM, good.keyPEM)
			return b
		}(), good.sha, "chain"},
	} {
		sha := c.sha
		if sha == "" {
			sha = c.bundle.SHA256
		}
		r := m.host.Apply(context.Background(), site, c.bundle, installWork(site, sha))
		if r.OK || steps(r) != "checked!" || !strings.Contains(message(r), c.want) {
			t.Errorf("%s: %s: %s", name, steps(r), message(r))
		}
	}
	if !bytes.Equal(m.read("/etc/ssl/shop.pem"), cat(old.leafPEM, old.chainPEM)) || len(m.runner.commands()) != 0 {
		t.Errorf("something was done: %q", m.runner.commands())
	}
}

// A wildcard covers one label: a.example.com and *.example.com, never a.b.example.com.
func TestAWildcardCoversOneLabel(t *testing.T) {
	m := newMachine(t, nginxOnItsOwn())
	old := m.ca.issue(t, "a.example.com")
	m.write("/etc/ssl/w.pem", old.leafPEM, 0o644)
	m.write("/etc/ssl/w.key", old.keyPEM, 0o600)
	use := inventory.Use{Kind: protocol.WebServerNginx, ConfigPath: "/etc/nginx/nginx.conf", Names: []string{"*.example.com", "a.example.com"},
		CertPath: "/etc/ssl/w.pem", KeyPath: "/etc/ssl/w.key", Ports: []int{closedPort(t)}}
	site := m.site(use)
	next := m.ca.issue(t, "*.example.com")
	if r := m.host.Apply(context.Background(), site, next.bundle(), installWork(site, next.sha)); !r.OK {
		t.Errorf("%s: %s", steps(r), message(r))
	}
	use.Names = []string{"a.b.example.com"}
	site = m.site(use)
	next = m.ca.issue(t, "*.example.com")
	if r := m.host.Apply(context.Background(), site, next.bundle(), installWork(site, next.sha)); r.OK || !strings.Contains(message(r), "does not cover a.b.example.com") {
		t.Errorf("%s: %s", steps(r), message(r))
	}
}

func TestASymbolicLinkIsNeverWrittenThrough(t *testing.T) {
	m := newMachine(t, nginxOnItsOwn())
	old := m.ca.issue(t, "shop.example")
	m.write("/srv/certs/shop.pem", old.leafPEM, 0o644)
	m.link("/etc/ssl/shop.pem", "../../srv/certs/shop.pem")
	m.write("/etc/ssl/shop.key", old.keyPEM, 0o600)
	site := m.site(inventory.Use{Kind: protocol.WebServerNginx, ConfigPath: "/etc/nginx/nginx.conf", Names: []string{"shop.example"},
		CertPath: "/etc/ssl/shop.pem", KeyPath: "/etc/ssl/shop.key"})
	next := m.ca.issue(t, "shop.example")
	r := m.host.Apply(context.Background(), site, next.bundle(), installWork(site, next.sha))
	if r.OK || steps(r) != "checked written!" || !strings.Contains(message(r), "symbolic link") {
		t.Fatalf("%s: %s", steps(r), message(r))
	}
	if m.mode("/etc/ssl/shop.pem")&fs.ModeSymlink == 0 || !bytes.Equal(m.read("/srv/certs/shop.pem"), old.leafPEM) {
		t.Error("the link or its target changed")
	}
}

// A write that fails half way leaves the original files untouched and no temporary file behind.
func TestAReadOnlyDirectoryLeavesTheOriginalsUntouched(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root writes into a read-only directory")
	}
	m := newMachine(t, nginxOnItsOwn())
	old := m.ca.issue(t, "shop.example", "www.shop.example")
	m.write("/etc/ssl/shop.pem", cat(old.leafPEM, old.chainPEM), 0o644)
	m.write("/etc/ssl/keys/shop.key", old.keyPEM, 0o600)
	site := m.site(inventory.Use{Kind: protocol.WebServerNginx, ConfigPath: "/etc/nginx/nginx.conf", Names: []string{"shop.example", "www.shop.example"},
		CertPath: "/etc/ssl/shop.pem", KeyPath: "/etc/ssl/keys/shop.key"})
	// The certificate's directory is writable, the key's is not: the certificate is staged first, then the key fails.
	if err := os.Chmod(m.path("/etc/ssl/keys"), 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(m.path("/etc/ssl/keys"), 0o755) })
	next := m.ca.issue(t, "shop.example", "www.shop.example")

	r := m.host.Apply(context.Background(), site, next.bundle(), installWork(site, next.sha))
	if r.OK || steps(r) != "checked written!" || !strings.Contains(detail(r, protocol.StepWritten), "nothing was written") {
		t.Fatalf("%s: %s", steps(r), message(r))
	}
	if !bytes.Equal(m.read("/etc/ssl/shop.pem"), cat(old.leafPEM, old.chainPEM)) || !bytes.Equal(m.read("/etc/ssl/keys/shop.key"), old.keyPEM) {
		t.Error("an original changed")
	}
	if extra := m.leftovers("/etc/ssl", "shop.pem", "keys"); len(extra) > 0 {
		t.Errorf("left in /etc/ssl: %q", extra)
	}
	if extra := m.leftovers("/etc/ssl/keys", "shop.key"); len(extra) > 0 {
		t.Errorf("left in /etc/ssl/keys: %q", extra)
	}
	if fileExists(filepath.Join(m.state, "pending.json")) || len(m.runner.commands()) != 0 {
		t.Errorf("pending.json or commands %q", m.runner.commands())
	}
	// Nothing was replaced, so no previous set was kept for it.
	if sets, _ := os.ReadDir(filepath.Join(m.state, "previous", site.SiteKey)); len(sets) != 0 {
		t.Errorf("%d previous sets", len(sets))
	}
}

func TestTheLastTwoPreviousSetsAreKept(t *testing.T) {
	m := newMachine(t, nginxOnItsOwn())
	site := nginxSite(m, m.ca.issue(t, "shop.example", "www.shop.example"), 0o644, 0o600)
	var installed []issued
	for range 3 {
		next := m.ca.issue(t, "shop.example", "www.shop.example")
		if r := m.host.Apply(context.Background(), site, next.bundle(), installWork(site, next.sha)); !r.OK {
			t.Fatalf("%s: %s", steps(r), message(r))
		}
		installed = append(installed, next)
	}
	dir := filepath.Join(m.state, "previous", site.SiteKey)
	sets, err := os.ReadDir(dir)
	if err != nil || len(sets) != 2 {
		t.Fatalf("%d sets, %v", len(sets), err)
	}
	// The newest set holds the files the last install replaced: the second certificate.
	newest := filepath.Join(dir, sets[1].Name())
	set, err := readSet(newest)
	if err != nil {
		t.Fatal(err)
	}
	var cert []byte
	for _, f := range set.Files {
		if f.Path == "/etc/ssl/shop.pem" {
			cert, _ = os.ReadFile(filepath.Join(newest, f.Data))
		}
	}
	if !bytes.Equal(cert, cat(installed[1].leafPEM, installed[1].chainPEM)) {
		t.Errorf("the newest set holds %q", cert)
	}
	if info, err := os.Stat(dir); err != nil || info.Mode().Perm() != 0o700 {
		t.Errorf("previous/<site> %v, %v", info.Mode(), err)
	}
}

// The agent killed between writing the files and testing them. On the next start the pending marker
// makes it test again: a failing test puts the previous files back, a passing one finishes the install.
func TestAnInstallKilledAfterWritingIsFinishedOrUndoneOnStart(t *testing.T) {
	for _, passes := range []bool{false, true} {
		m := newMachine(t, nginxOnItsOwn())
		old := m.ca.issue(t, "shop.example", "www.shop.example")
		site := nginxSite(m, old, 0o644, 0o600)
		next := m.ca.issue(t, "shop.example", "www.shop.example")
		killAt(m, "nginx -t", func() { m.host.Apply(context.Background(), site, next.bundle(), installWork(site, next.sha)) })
		if !fileExists(filepath.Join(m.state, "pending.json")) || !bytes.Equal(m.read("/etc/ssl/shop.key"), next.keyPEM) {
			t.Fatal("not killed after writing")
		}

		// Started again.
		m.runner = newRunner(nginxOnItsOwn())
		m.host.Runner = m.runner
		if !passes {
			m.runner.set("nginx -t", errors.New("nginx -t failed (exit status 1): nginx: [emerg] cannot load certificate"))
		}
		rec, err := m.host.RecoverPending(context.Background())
		if err != nil || rec == nil {
			t.Fatalf("%+v, %v", rec, err)
		}
		r := rec.Result
		if rec.AssignmentID != testAssignment || r.SHA256 != next.sha {
			t.Errorf("%+v", rec)
		}
		if fileExists(filepath.Join(m.state, "pending.json")) {
			t.Error("pending.json is left")
		}
		if passes {
			if !r.OK || !rec.Installed || steps(r) != "written tested reloaded" || !bytes.Equal(m.read("/etc/ssl/shop.key"), next.keyPEM) {
				t.Errorf("passing: %s: %s", steps(r), message(r))
			}
		} else {
			if r.OK || rec.Installed || steps(r) != "written tested! restored reloaded" || !strings.Contains(message(r), "cannot load certificate") {
				t.Errorf("failing: %s: %s", steps(r), message(r))
			}
			if !bytes.Equal(m.read("/etc/ssl/shop.pem"), cat(old.leafPEM, old.chainPEM)) || !bytes.Equal(m.read("/etc/ssl/shop.key"), old.keyPEM) {
				t.Error("the old files are not back")
			}
		}
		if m.runner.count("nginx -s reload") != 1 {
			t.Errorf("ran %q", m.runner.commands())
		}
		// Nothing left to recover.
		if rec, err := m.host.RecoverPending(context.Background()); rec != nil || err != nil {
			t.Errorf("again: %+v, %v", rec, err)
		}
	}
}

// killAt runs install and stops it as a kill would when it runs command: nothing after that runs.
func killAt(m *machine, command string, install func()) {
	m.runner.hooks[command] = runtime.Goexit
	done := make(chan struct{})
	go func() {
		defer close(done)
		install()
	}()
	<-done
	delete(m.runner.hooks, command)
}

// Killed before every file was in place (a file changed meanwhile, and a temporary file left beside one, stand for
// that): the temporary files go, the previous files go back.
func TestAnInstallKilledBeforeItsFilesWereInPlaceIsUndoneOnStart(t *testing.T) {
	m := newMachine(t, nginxOnItsOwn())
	old := m.ca.issue(t, "shop.example", "www.shop.example")
	site := nginxSite(m, old, 0o644, 0o600)
	next := m.ca.issue(t, "shop.example", "www.shop.example")
	killAt(m, "nginx -t", func() { m.host.Apply(context.Background(), site, next.bundle(), installWork(site, next.sha)) })
	m.write("/etc/ssl/shop.key", old.keyPEM, 0o600)
	m.write("/etc/ssl/.shop.key.nslookup-agent-123456", next.keyPEM, 0o600)
	m.write("/etc/ssl/.shop.key.backup", []byte("the customer's own\n"), 0o600)

	rec, err := m.host.RecoverPending(context.Background())
	if err != nil || rec == nil || rec.Result.OK || steps(rec.Result) != "written! restored reloaded" {
		t.Fatalf("%+v, %v", rec, err)
	}
	if !bytes.Equal(m.read("/etc/ssl/shop.pem"), cat(old.leafPEM, old.chainPEM)) {
		t.Error("the old certificate is not back")
	}
	if extra := m.leftovers("/etc/ssl", "shop.pem", "shop.key", ".shop.key.backup"); len(extra) > 0 {
		t.Errorf("left %q", extra)
	}
}

// A pending.json that cannot be used is set aside, so installs go on.
func TestAnUnusablePendingFileIsSetAside(t *testing.T) {
	m := newMachine(t, nginxOnItsOwn())
	site := nginxSite(m, m.ca.issue(t, "shop.example", "www.shop.example"), 0o644, 0o600)
	if err := writeStateFile(filepath.Join(m.state, "pending.json"), []byte("{not json")); err != nil {
		t.Fatal(err)
	}
	if rec, err := m.host.RecoverPending(context.Background()); rec != nil || err == nil || !strings.Contains(err.Error(), "set aside as") {
		t.Fatalf("%+v, %v", rec, err)
	}
	next := m.ca.issue(t, "shop.example", "www.shop.example")
	if r := m.host.Apply(context.Background(), site, next.bundle(), installWork(site, next.sha)); !r.OK {
		t.Errorf("%s: %s", steps(r), message(r))
	}
}

// While an interrupted install waits to be finished, no other starts.
func TestAnInstallWaitsForAnInterruptedOne(t *testing.T) {
	m := newMachine(t, nginxOnItsOwn())
	site := nginxSite(m, m.ca.issue(t, "shop.example", "www.shop.example"), 0o644, 0o600)
	next := m.ca.issue(t, "shop.example", "www.shop.example")
	killAt(m, "nginx -t", func() { m.host.Apply(context.Background(), site, next.bundle(), installWork(site, next.sha)) })
	again := m.ca.issue(t, "shop.example", "www.shop.example")
	r := m.host.Apply(context.Background(), site, again.bundle(), installWork(site, again.sha))
	if r.OK || steps(r) != "checked written!" || !strings.Contains(message(r), "interrupted") {
		t.Errorf("%s: %s", steps(r), message(r))
	}
}

// The agent stopping (SIGTERM ends the run context) never cuts an install in half.
func TestAnInstallIsNotCutShortWhenTheAgentStops(t *testing.T) {
	m := newMachine(t, nginxOnItsOwn())
	site := nginxSite(m, m.ca.issue(t, "shop.example", "www.shop.example"), 0o644, 0o600)
	next := m.ca.issue(t, "shop.example", "www.shop.example")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := m.host.Apply(ctx, site, next.bundle(), installWork(site, next.sha))
	if !r.OK || m.runner.count("nginx -s reload") != 1 {
		t.Errorf("%s: %s; ran %q", steps(r), message(r), m.runner.commands())
	}
}

func TestASiteTheAgentCannotInstallOn(t *testing.T) {
	m := newMachine(t, nginxOnItsOwn())
	old := m.ca.issue(t, "shop.example", "www.shop.example")
	next := m.ca.issue(t, "shop.example", "www.shop.example")
	site := nginxSite(m, old, 0o644, 0o600)
	blocked := site
	blocked.Blocked = ptr(protocol.BlockedPathVariable)
	unknown := site
	unknown.SiteKey = strings.Repeat("0", 32)
	certbot := site
	certbot.Owner, certbot.CertbotName = ptr(protocol.OwnerCertbot), ptr("shop.example")
	for name, c := range map[string]struct {
		site protocol.Site
		want string
	}{
		"blocked":                   {blocked, "path_variable"},
		"not in the last read":      {unknown, "not known"},
		"certbot's, not taken over": {certbot, "certbot renews"},
	} {
		r := m.host.Apply(context.Background(), c.site, next.bundle(), installWork(c.site, next.sha))
		if r.OK || !strings.Contains(message(r), c.want) {
			t.Errorf("%s: %s: %s", name, steps(r), message(r))
		}
		// Told before the bundle is fetched, with the same reason.
		if err := m.host.CanInstall(c.site, installWork(c.site, next.sha)); err == nil || !strings.Contains(err.Error(), c.want) ||
			!strings.HasPrefix(err.Error(), "nothing was written: ") {
			t.Errorf("%s: CanInstall %v", name, err)
		}
	}
	if err := m.host.CanInstall(site, installWork(site, next.sha)); err != nil {
		t.Errorf("a site it can install on: %v", err)
	}
	if !bytes.Equal(m.read("/etc/ssl/shop.key"), old.keyPEM) {
		t.Error("written")
	}
}

func TestDiskSHA(t *testing.T) {
	m := newMachine(t, nginxOnItsOwn())
	c := m.ca.issue(t, "shop.example")
	path := "/etc/ssl/shop.pem"
	site := protocol.Site{CertPath: &path}
	for name, data := range map[string][]byte{
		"the certificate with its chain":          cat(c.leafPEM, c.chainPEM),
		"the key first, as in HAProxy's own file": cat(c.keyPEM, c.leafPEM, c.chainPEM),
	} {
		m.write(path, data, 0o644)
		if sha, err := m.host.DiskSHA(site); err != nil || sha != c.sha {
			t.Errorf("%s: %q, %v", name, sha, err)
		}
	}
	m.write(path, []byte("no certificate here\n"), 0o644)
	if sha, err := m.host.DiskSHA(site); err != nil || sha != "" {
		t.Errorf("none: %q, %v", sha, err)
	}
	other := "/etc/ssl/missing.pem"
	if _, err := m.host.DiskSHA(protocol.Site{CertPath: &other}); err == nil {
		t.Error("a missing file has a SHA-256")
	}
	if _, err := m.host.DiskSHA(protocol.Site{}); err == nil {
		t.Error("a site without a certificate file has a SHA-256")
	}
}

func ptr[T any](v T) *T { return &v }

// Killed with temporary files beside several files of one directory: every one of them goes on the next start (an
// HAProxy crt directory would load any left).
func TestEveryTemporaryFileOfAnInterruptedInstallIsRemoved(t *testing.T) {
	haproxy := map[string]error{"haproxy -c -f /etc/haproxy/haproxy.cfg": nil, "systemctl is-active haproxy": nil, "systemctl reload haproxy": nil}
	for name, c := range map[string]struct {
		answers map[string]error
		test    string
		dir     string
		files   []string
		use     inventory.Use
	}{
		"nginx, certificate and key": {nginxOnItsOwn(), "nginx -t", "/etc/ssl", []string{"shop.key", "shop.pem"},
			inventory.Use{Kind: protocol.WebServerNginx, ConfigPath: "/etc/nginx/nginx.conf", Names: []string{"shop.example"},
				CertPath: "/etc/ssl/shop.pem", KeyPath: "/etc/ssl/shop.key"}},
		"HAProxy, the key beside the certificate": {haproxy, "haproxy -c -f /etc/haproxy/haproxy.cfg", "/etc/haproxy/certs", []string{"shop.pem", "shop.pem.key"},
			inventory.Use{Kind: protocol.WebServerHAProxy, ConfigPath: "/etc/haproxy/haproxy.cfg", Names: []string{"shop.example"},
				CertPath: "/etc/haproxy/certs/shop.pem", KeyPath: "/etc/haproxy/certs/shop.pem.key"}},
	} {
		m := newMachine(t, c.answers)
		old := m.ca.issue(t, "shop.example")
		m.write(c.use.CertPath, cat(old.leafPEM, old.chainPEM), 0o644)
		m.write(c.use.KeyPath, old.keyPEM, 0o600)
		m.write(c.dir+"/other.pem", []byte("another site's\n"), 0o644)
		c.use.Ports = []int{closedPort(t)}
		site := m.site(c.use)
		next := m.ca.issue(t, "shop.example")
		killAt(m, c.test, func() { m.host.Apply(context.Background(), site, next.bundle(), installWork(site, next.sha)) })
		// Left by a kill while staging: two beside each file.
		for i, f := range c.files {
			for j := range 2 {
				m.write(fmt.Sprintf("%s/.%s.nslookup-agent-%d%d", c.dir, f, i, j), next.keyPEM, 0o600)
			}
		}
		rec, err := m.host.RecoverPending(context.Background())
		if err != nil || rec == nil || !rec.Result.OK {
			t.Fatalf("%s: %+v, %v", name, rec, err)
		}
		if extra := m.leftovers(c.dir, append(c.files, "other.pem")...); len(extra) > 0 {
			t.Errorf("%s: left %q", name, extra)
		}
	}
}

// The agent's own files (pending.json, the manifest and files of a set of previous files, a certbot record) are never
// read through a link: one that is a link is refused, and nothing it points at is written.
func TestTheAgentsOwnFilesAreNeverReadThroughALink(t *testing.T) {
	t.Run("pending.json", func(t *testing.T) {
		m := newMachine(t, nginxOnItsOwn())
		site := nginxSite(m, m.ca.issue(t, "shop.example", "www.shop.example"), 0o644, 0o600)
		next := m.ca.issue(t, "shop.example", "www.shop.example")
		killAt(m, "nginx -t", func() { m.host.Apply(context.Background(), site, next.bundle(), installWork(site, next.sha)) })
		elsewhere := filepath.Join(t.TempDir(), "pending.json")
		if err := os.Rename(filepath.Join(m.state, "pending.json"), elsewhere); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(elsewhere, filepath.Join(m.state, "pending.json")); err != nil {
			t.Fatal(err)
		}
		if rec, err := m.host.RecoverPending(context.Background()); rec != nil || err == nil || !strings.Contains(err.Error(), "symbolic link") {
			t.Errorf("%+v, %v", rec, err)
		}
	})
	t.Run("a set of previous files", func(t *testing.T) {
		m := newMachine(t, nginxOnItsOwn())
		site := nginxSite(m, m.ca.issue(t, "shop.example", "www.shop.example"), 0o644, 0o600)
		next := m.ca.issue(t, "shop.example", "www.shop.example")
		killAt(m, "nginx -t", func() { m.host.Apply(context.Background(), site, next.bundle(), installWork(site, next.sha)) })
		sets, _ := os.ReadDir(filepath.Join(m.state, "previous", site.SiteKey))
		set := filepath.Join(m.state, "previous", site.SiteKey, sets[0].Name())
		for _, name := range []string{"set.json", "0"} {
			elsewhere := filepath.Join(t.TempDir(), name)
			if err := os.Rename(filepath.Join(set, name), elsewhere); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(elsewhere, filepath.Join(set, name)); err != nil {
				t.Fatal(err)
			}
		}
		m.runner.set("nginx -t", errors.New("nginx -t failed"))
		rec, err := m.host.RecoverPending(context.Background())
		if err == nil || !strings.Contains(err.Error(), "symbolic link") {
			t.Errorf("%+v, %v", rec, err)
		}
		if !bytes.Equal(m.read("/etc/ssl/shop.key"), next.keyPEM) {
			t.Error("files were put back from a set read through a link")
		}
	})
	t.Run("a certbot record", func(t *testing.T) {
		m := newMachine(t, nginxOnItsOwn())
		if err := os.MkdirAll(filepath.Join(m.state, "certbot"), 0o700); err != nil {
			t.Fatal(err)
		}
		elsewhere := filepath.Join(t.TempDir(), "shop.example.json")
		if err := os.WriteFile(elsewhere, []byte(`{"name":"shop.example"}`), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(elsewhere, filepath.Join(m.state, "certbot", "shop.example.json")); err != nil {
			t.Fatal(err)
		}
		if _, err := m.host.readRecord("shop.example"); err == nil || !strings.Contains(err.Error(), "symbolic link") {
			t.Errorf("%v", err)
		}
	})
}

// Previous files that cannot be put back (their directory became read-only, say) hold up only their own
// site: the agent tries again with that site's next install, and after 3 failed tries sets them aside, says so, and
// lets the site be installed on again. Other sites are never held up.
func TestPreviousFilesThatCannotBeRestoredHoldUpOnlyTheirSite(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root can change any directory")
	}
	m := newMachine(t, nginxOnItsOwn())
	shop := nginxSite(m, m.ca.issue(t, "shop.example", "www.shop.example"), 0o644, 0o600)
	m.write("/srv/blog/blog.pem", []byte("x"), 0o644)
	oldBlog := m.ca.issue(t, "blog.example")
	m.write("/srv/blog/blog.pem", cat(oldBlog.leafPEM, oldBlog.chainPEM), 0o644)
	m.write("/srv/blog/blog.key", oldBlog.keyPEM, 0o600)
	blog := m.site(inventory.Use{Kind: protocol.WebServerNginx, ConfigPath: "/etc/nginx/sites-enabled/blog", Names: []string{"blog.example"},
		CertPath: "/srv/blog/blog.pem", KeyPath: "/srv/blog/blog.key", Ports: []int{closedPort(t)}})
	sslDir := m.path("/etc/ssl")
	t.Cleanup(func() { os.Chmod(sslDir, 0o755) })
	blocked := filepath.Join(m.state, "blocked", shop.SiteKey+".json")

	// The test fails, and meanwhile /etc/ssl became read-only: the previous files cannot go back.
	m.runner.set("nginx -t", errors.New("nginx -t failed: nginx: [emerg] cannot load certificate"))
	m.runner.hooks["nginx -t"] = func() { os.Chmod(sslDir, 0o555) }
	first := m.ca.issue(t, "shop.example", "www.shop.example")
	r := m.host.Apply(context.Background(), shop, first.bundle(), installWork(shop, first.sha))
	if r.OK || !strings.Contains(steps(r), "restored!") {
		t.Fatalf("%s: %s", steps(r), message(r))
	}
	delete(m.runner.hooks, "nginx -t")
	m.runner.set("nginx -t", nil)
	if fileExists(filepath.Join(m.state, "pending.json")) || !fileExists(blocked) {
		t.Fatalf("pending.json %v, blocked %v", fileExists(filepath.Join(m.state, "pending.json")), fileExists(blocked))
	}

	// Another site is installed on all the same.
	nextBlog := m.ca.issue(t, "blog.example")
	if r := m.host.Apply(context.Background(), blog, nextBlog.bundle(), installWork(blog, nextBlog.sha)); !r.OK {
		t.Errorf("another site: %s: %s", steps(r), message(r))
	}

	// The site itself: tried again with each install, refused while it fails.
	for try := 2; try <= 3; try++ {
		next := m.ca.issue(t, "shop.example", "www.shop.example")
		r := m.host.Apply(context.Background(), shop, next.bundle(), installWork(shop, next.sha))
		want := fmt.Sprintf("try %d of 3", try)
		if try == 3 {
			want = "after 3 tries"
		}
		if r.OK || !strings.Contains(message(r), "could not be put back") || !strings.Contains(message(r), want) {
			t.Errorf("try %d: %s: %s", try, steps(r), message(r))
		}
	}
	if fileExists(blocked) {
		t.Error("still held up after 3 tries")
	}
	// Set aside under blocked/, the previous files with it: kept however many installs follow.
	aside, _ := filepath.Glob(filepath.Join(m.state, "blocked", shop.SiteKey+"-set-aside-*"))
	if len(aside) != 1 || !fileExists(filepath.Join(aside[0], "record.json")) || !fileExists(filepath.Join(aside[0], "previous", "set.json")) {
		t.Fatalf("set aside: %v", aside)
	}

	// Fixed by hand: installs on the site go on, and the previous files set aside stay.
	if err := os.Chmod(sslDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		next := m.ca.issue(t, "shop.example", "www.shop.example")
		if r := m.host.Apply(context.Background(), shop, next.bundle(), installWork(shop, next.sha)); !r.OK {
			t.Errorf("after: %s: %s", steps(r), message(r))
		}
	}
	if kept, err := readSet(filepath.Join(aside[0], "previous")); err != nil || kept.find("/etc/ssl/shop.key").SHA256 == "" {
		t.Errorf("the previous files set aside are gone: %+v, %v", kept, err)
	}
}

// Previous files that could not be put back are put back with the site's next install once that works, which then goes
// on.
func TestPreviousFilesAreRestoredWithTheSitesNextInstall(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root can change any directory")
	}
	m := newMachine(t, nginxOnItsOwn())
	old := m.ca.issue(t, "shop.example", "www.shop.example")
	shop := nginxSite(m, old, 0o644, 0o600)
	sslDir := m.path("/etc/ssl")
	t.Cleanup(func() { os.Chmod(sslDir, 0o755) })
	m.runner.set("nginx -t", errors.New("nginx -t failed"))
	m.runner.hooks["nginx -t"] = func() { os.Chmod(sslDir, 0o555) }
	first := m.ca.issue(t, "shop.example", "www.shop.example")
	if r := m.host.Apply(context.Background(), shop, first.bundle(), installWork(shop, first.sha)); r.OK {
		t.Fatalf("%s: %s", steps(r), message(r))
	}
	delete(m.runner.hooks, "nginx -t")
	m.runner.set("nginx -t", nil)
	if err := os.Chmod(sslDir, 0o755); err != nil {
		t.Fatal(err)
	}
	next := m.ca.issue(t, "shop.example", "www.shop.example")
	if r := m.host.Apply(context.Background(), shop, next.bundle(), installWork(shop, next.sha)); !r.OK {
		t.Fatalf("%s: %s", steps(r), message(r))
	}
	if fileExists(filepath.Join(m.state, "blocked", shop.SiteKey+".json")) {
		t.Error("still held up")
	}
	// The set kept before this install is the restored one: the old files.
	sets, _ := os.ReadDir(filepath.Join(m.state, "previous", shop.SiteKey))
	last, err := readSet(filepath.Join(m.state, "previous", shop.SiteKey, sets[len(sets)-1].Name()))
	if err != nil || last.find("/etc/ssl/shop.key").SHA256 != sha256Hex(old.keyPEM) {
		t.Errorf("the last set %+v, %v", last, err)
	}
}
