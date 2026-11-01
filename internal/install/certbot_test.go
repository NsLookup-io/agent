package install

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nslookup-io/agent/internal/inventory"
	"github.com/nslookup-io/agent/internal/protocol"
)

const (
	renewalConf = "renews_with = certbot\narchive_dir = /etc/letsencrypt/archive/blog.example\n"
	otherConf   = "archive_dir = /etc/letsencrypt/archive/other.example\n"
)

// certbotMachine has two certbot certificates, blog.example (an nginx site) and other.example, in certbot's own
// layout: live/<name>/ links into archive/<name>/, and a renewal file each.
func certbotMachine(t *testing.T, answers map[string]error) (*machine, protocol.Site, issued) {
	m := newMachine(t, answers)
	certbot := m.ca.issue(t, "blog.example", "www.blog.example")
	for _, name := range []string{"blog.example", "other.example"} {
		archive := "/etc/letsencrypt/archive/" + name + "/"
		m.write(archive+"cert1.pem", certbot.leafPEM, 0o644)
		m.write(archive+"chain1.pem", certbot.chainPEM, 0o644)
		m.write(archive+"fullchain1.pem", cat(certbot.leafPEM, certbot.chainPEM), 0o644)
		m.write(archive+"privkey1.pem", certbot.keyPEM, 0o600)
		for _, f := range []string{"cert", "chain", "fullchain", "privkey"} {
			m.link("/etc/letsencrypt/live/"+name+"/"+f+".pem", "../../archive/"+name+"/"+f+"1.pem")
		}
		m.write("/etc/letsencrypt/live/"+name+"/README", []byte("certbot's README\n"), 0o644)
	}
	m.write("/etc/letsencrypt/renewal/blog.example.conf", []byte(renewalConf), 0o644)
	m.write("/etc/letsencrypt/renewal/other.example.conf", []byte(otherConf), 0o600)
	site := m.site(inventory.Use{Kind: protocol.WebServerNginx, ConfigPath: "/etc/nginx/sites-enabled/blog", Names: []string{"blog.example", "www.blog.example"},
		CertPath: "/etc/letsencrypt/live/blog.example/fullchain.pem", KeyPath: "/etc/letsencrypt/live/blog.example/privkey.pem", Ports: []int{closedPort(t)}})
	site.Owner, site.CertbotName = ptr(protocol.OwnerCertbot), ptr("blog.example")
	return m, site, certbot
}

func takeOverWork(s protocol.Site, sha string) protocol.Work {
	w := installWork(s, sha)
	w.Certbot = ptr(protocol.CertbotTakeOver)
	return w
}

func giveBackWork(s protocol.Site, sha string) protocol.Work {
	return protocol.Work{AssignmentID: testAssignment, SiteKey: s.SiteKey, SHA256: sha, Action: protocol.ActionRelease, Certbot: ptr(protocol.CertbotGiveBack)}
}

// certbotUntouched checks what a take-over never changes: other.example, the archive, the links the site does not use.
func certbotUntouched(t *testing.T, m *machine, certbot issued) {
	t.Helper()
	for _, name := range []string{"blog.example", "other.example"} {
		for _, f := range []string{"cert", "chain"} {
			checkLink(t, m, "/etc/letsencrypt/live/"+name+"/"+f+".pem", "../../archive/"+name+"/"+f+"1.pem")
		}
		if !bytes.Equal(m.read("/etc/letsencrypt/archive/"+name+"/privkey1.pem"), certbot.keyPEM) ||
			string(m.read("/etc/letsencrypt/live/"+name+"/README")) != "certbot's README\n" {
			t.Errorf("%s's archive or README changed", name)
		}
	}
	for _, f := range []string{"fullchain", "privkey"} {
		checkLink(t, m, "/etc/letsencrypt/live/other.example/"+f+".pem", "../../archive/other.example/"+f+"1.pem")
	}
	if string(m.read("/etc/letsencrypt/renewal/other.example.conf")) != otherConf || m.mode("/etc/letsencrypt/renewal/other.example.conf").Perm() != 0o600 {
		t.Error("other.example's renewal file changed")
	}
}

func checkLink(t *testing.T, m *machine, p, target string) {
	t.Helper()
	got, err := os.Readlink(m.path(p))
	if err != nil || got != target {
		t.Errorf("%s: link to %q (%v), want %q", p, got, err, target)
	}
}

func TestCertbotTakeOverThenGiveBack(t *testing.T) {
	m, site, certbot := certbotMachine(t, nginxOnItsOwn())
	first := m.ca.issue(t, "blog.example", "www.blog.example")

	r := m.host.Apply(context.Background(), site, first.bundle(), takeOverWork(site, first.sha))
	if !r.OK || steps(r) != "checked written certbot_disabled tested reloaded checked_locally!" {
		t.Fatalf("%s: %s", steps(r), message(r))
	}
	live := "/etc/letsencrypt/live/blog.example/"
	// The links the site uses are real files now, with the modes of the files they pointed at.
	if m.mode(live+"fullchain.pem") != 0o644 || !bytes.Equal(m.read(live+"fullchain.pem"), cat(first.leafPEM, first.chainPEM)) {
		t.Errorf("fullchain.pem: %v", m.mode(live+"fullchain.pem"))
	}
	if m.mode(live+"privkey.pem") != 0o600 || !bytes.Equal(m.read(live+"privkey.pem"), first.keyPEM) {
		t.Errorf("privkey.pem: %v", m.mode(live+"privkey.pem"))
	}
	// certbot skips the name: its renewal file is set aside, as it was.
	if m.exists("/etc/letsencrypt/renewal/blog.example.conf") || string(m.read("/etc/letsencrypt/renewal/blog.example.conf.nslookup-disabled")) != renewalConf ||
		m.mode("/etc/letsencrypt/renewal/blog.example.conf.nslookup-disabled").Perm() != 0o644 {
		t.Error("the renewal file was not set aside")
	}
	if !fileExists(filepath.Join(m.state, "certbot", "blog.example.json")) {
		t.Error("no record of the take-over")
	}
	certbotUntouched(t, m, certbot)

	// A renewal: the inventory no longer says certbot renews the site.
	renewed := site
	renewed.Owner, renewed.CertbotName = nil, nil
	second := m.ca.issue(t, "blog.example", "www.blog.example")
	if r := m.host.Apply(context.Background(), renewed, second.bundle(), takeOverWork(renewed, second.sha)); !r.OK || steps(r) != "checked written tested reloaded checked_locally!" {
		t.Fatalf("renewal: %s: %s", steps(r), message(r))
	}
	if !bytes.Equal(m.read(live+"privkey.pem"), second.keyPEM) || m.mode(live+"privkey.pem") != 0o600 {
		t.Error("renewal: the key")
	}

	// Given back: the exact links and the renewal file, and certbot's certificate loaded again.
	reloads := m.runner.count("nginx -s reload")
	r = m.host.Apply(context.Background(), renewed, protocol.Bundle{AssignmentID: testAssignment, SHA256: second.sha}, giveBackWork(renewed, second.sha))
	if !r.OK || steps(r) != "tested reloaded certbot_restored" {
		t.Fatalf("give back: %s: %s", steps(r), message(r))
	}
	checkLink(t, m, live+"fullchain.pem", "../../archive/blog.example/fullchain1.pem")
	checkLink(t, m, live+"privkey.pem", "../../archive/blog.example/privkey1.pem")
	if string(m.read("/etc/letsencrypt/renewal/blog.example.conf")) != renewalConf || m.mode("/etc/letsencrypt/renewal/blog.example.conf").Perm() != 0o644 ||
		m.exists("/etc/letsencrypt/renewal/blog.example.conf.nslookup-disabled") {
		t.Error("the renewal file is not back")
	}
	if fileExists(filepath.Join(m.state, "certbot", "blog.example.json")) {
		t.Error("the record is left")
	}
	if m.runner.count("nginx -s reload") != reloads+1 {
		t.Errorf("ran %q", m.runner.commands())
	}
	certbotUntouched(t, m, certbot)
	if sha, err := m.host.DiskSHA(renewed); err != nil || sha != certbot.sha {
		t.Errorf("on disk %q, %v", sha, err)
	}
}

// A take-over whose test fails leaves certbot exactly as it was.
func TestATakeOverThatFailsItsTestLeavesCertbotAsItWas(t *testing.T) {
	m, site, certbot := certbotMachine(t, nginxOnItsOwn())
	m.runner.set("nginx -t", errors.New("nginx -t failed (exit status 1)"))
	next := m.ca.issue(t, "blog.example", "www.blog.example")
	r := m.host.Apply(context.Background(), site, next.bundle(), takeOverWork(site, next.sha))
	if r.OK || steps(r) != "checked written certbot_disabled tested! restored certbot_restored" {
		t.Fatalf("%s: %s", steps(r), message(r))
	}
	live := "/etc/letsencrypt/live/blog.example/"
	checkLink(t, m, live+"fullchain.pem", "../../archive/blog.example/fullchain1.pem")
	checkLink(t, m, live+"privkey.pem", "../../archive/blog.example/privkey1.pem")
	if string(m.read("/etc/letsencrypt/renewal/blog.example.conf")) != renewalConf || m.exists("/etc/letsencrypt/renewal/blog.example.conf.nslookup-disabled") {
		t.Error("the renewal file is not back")
	}
	if fileExists(filepath.Join(m.state, "certbot", "blog.example.json")) {
		t.Error("a record of a take-over that did not happen")
	}
	if extra := m.leftovers(live, "cert.pem", "chain.pem", "fullchain.pem", "privkey.pem", "README"); len(extra) > 0 {
		t.Errorf("left %q", extra)
	}
	certbotUntouched(t, m, certbot)
}

// Killed in the middle of a take-over and its test fails on the next start: certbot is back as it was.
func TestATakeOverKilledAfterWritingIsUndoneOnStart(t *testing.T) {
	m, site, certbot := certbotMachine(t, nginxOnItsOwn())
	next := m.ca.issue(t, "blog.example", "www.blog.example")
	killAt(m, "nginx -t", func() { m.host.Apply(context.Background(), site, next.bundle(), takeOverWork(site, next.sha)) })
	m.runner.set("nginx -t", errors.New("nginx -t failed (exit status 1)"))
	rec, err := m.host.RecoverPending(context.Background())
	if err != nil || rec == nil || rec.Result.OK || steps(rec.Result) != "written certbot_disabled tested! restored certbot_restored reloaded" {
		t.Fatalf("%+v, %v", rec, err)
	}
	checkLink(t, m, "/etc/letsencrypt/live/blog.example/privkey.pem", "../../archive/blog.example/privkey1.pem")
	if string(m.read("/etc/letsencrypt/renewal/blog.example.conf")) != renewalConf || fileExists(filepath.Join(m.state, "certbot", "blog.example.json")) {
		t.Error("certbot is not as it was")
	}
	certbotUntouched(t, m, certbot)
}

func TestAGiveBackNeedsCertbotsFilesAndItsRecord(t *testing.T) {
	m, site, _ := certbotMachine(t, nginxOnItsOwn())
	next := m.ca.issue(t, "blog.example", "www.blog.example")
	give := protocol.Bundle{AssignmentID: testAssignment, SHA256: next.sha}
	// Never taken over: certbot renews it as it is, so there is nothing to give back.
	if r := m.host.Apply(context.Background(), site, give, giveBackWork(site, next.sha)); !r.OK || !strings.Contains(detail(r, protocol.StepCertbotRestored), "already given back") {
		t.Errorf("never taken over: %s: %s", steps(r), detail(r, protocol.StepCertbotRestored))
	}
	if r := m.host.Apply(context.Background(), site, next.bundle(), takeOverWork(site, next.sha)); !r.OK {
		t.Fatalf("%s: %s", steps(r), message(r))
	}
	// certbot's archive file is gone: nothing is given back.
	if err := os.Remove(m.path("/etc/letsencrypt/archive/blog.example/privkey1.pem")); err != nil {
		t.Fatal(err)
	}
	r := m.host.Apply(context.Background(), site, give, giveBackWork(site, next.sha))
	if r.OK || steps(r) != "certbot_restored!" || !strings.Contains(message(r), "privkey1.pem") {
		t.Errorf("archive gone: %s: %s", steps(r), message(r))
	}
	if m.mode("/etc/letsencrypt/live/blog.example/privkey.pem")&fs.ModeSymlink != 0 || m.exists("/etc/letsencrypt/renewal/blog.example.conf") {
		t.Error("given back in part")
	}
	// No record, and the files are not certbot's links: nothing to go by.
	if err := os.Remove(filepath.Join(m.state, "certbot", "blog.example.json")); err != nil {
		t.Fatal(err)
	}
	if r := m.host.Apply(context.Background(), site, give, giveBackWork(site, next.sha)); r.OK || !strings.Contains(message(r), "no record") {
		t.Errorf("no record: %s: %s", steps(r), message(r))
	}
}

// A give-back is asked for again when its result was not accepted: given back already, it is reported done. Both
// orders: given back, then asked again; given back at a restart (the agent was stopped in it), then asked again.
func TestAGiveBackAskedForAgainIsDone(t *testing.T) {
	for _, interrupted := range []bool{false, true} {
		m, site, certbot := certbotMachine(t, nginxOnItsOwn())
		next := m.ca.issue(t, "blog.example", "www.blog.example")
		if r := m.host.Apply(context.Background(), site, next.bundle(), takeOverWork(site, next.sha)); !r.OK {
			t.Fatalf("%s: %s", steps(r), message(r))
		}
		renewed := site
		renewed.Owner, renewed.CertbotName = nil, nil
		give := protocol.Bundle{AssignmentID: testAssignment, SHA256: next.sha}
		if interrupted {
			killAt(m, "nginx -t", func() { m.host.Apply(context.Background(), renewed, give, giveBackWork(renewed, next.sha)) })
			rec, err := m.host.RecoverPending(context.Background())
			if err != nil || rec == nil || !rec.Result.OK || rec.Installed || steps(rec.Result) != "tested reloaded certbot_restored" {
				t.Fatalf("recovered: %+v, %v", rec, err)
			}
		} else if r := m.host.Apply(context.Background(), renewed, give, giveBackWork(renewed, next.sha)); !r.OK {
			t.Fatalf("%s: %s", steps(r), message(r))
		}
		// As the inventory reports the site once certbot's again.
		reloads := m.runner.count("nginx -s reload")
		r := m.host.Apply(context.Background(), site, give, giveBackWork(site, next.sha))
		if !r.OK || steps(r) != "certbot_restored" || !strings.Contains(detail(r, protocol.StepCertbotRestored), "already given back") {
			t.Errorf("interrupted %v: again: %s: %s", interrupted, steps(r), message(r))
		}
		if m.runner.count("nginx -s reload") != reloads {
			t.Errorf("interrupted %v: reloaded again", interrupted)
		}
		checkLink(t, m, "/etc/letsencrypt/live/blog.example/privkey.pem", "../../archive/blog.example/privkey1.pem")
		if string(m.read("/etc/letsencrypt/renewal/blog.example.conf")) != renewalConf {
			t.Errorf("interrupted %v: the renewal file", interrupted)
		}
		certbotUntouched(t, m, certbot)
	}
}

// A link of certbot's is replaced only in a take-over, and only under live/<the site's name>/.
func TestOnlyATakeOverReplacesCertbotsLinks(t *testing.T) {
	m, site, _ := certbotMachine(t, nginxOnItsOwn())
	next := m.ca.issue(t, "blog.example", "www.blog.example")
	notCertbots := site
	notCertbots.Owner, notCertbots.CertbotName = nil, nil
	r := m.host.Apply(context.Background(), notCertbots, next.bundle(), installWork(notCertbots, next.sha))
	if r.OK || !strings.Contains(message(r), "symbolic link") {
		t.Errorf("%s: %s", steps(r), message(r))
	}
	// A site using another name's key.
	m.add(site, []inventory.Use{{Kind: protocol.WebServerNginx, ConfigPath: "/etc/nginx/sites-enabled/blog", Names: []string{"blog.example", "www.blog.example"},
		CertPath: "/etc/letsencrypt/live/blog.example/fullchain.pem", KeyPath: "/etc/letsencrypt/live/other.example/privkey.pem"}})
	r = m.host.Apply(context.Background(), site, next.bundle(), takeOverWork(site, next.sha))
	if r.OK || !strings.Contains(message(r), "symbolic link") {
		t.Errorf("another name's link: %s: %s", steps(r), message(r))
	}
	checkLink(t, m, "/etc/letsencrypt/live/blog.example/fullchain.pem", "../../archive/blog.example/fullchain1.pem")
	if !m.exists("/etc/letsencrypt/renewal/blog.example.conf") {
		t.Error("the renewal file moved")
	}
}

// One certbot name taken over for two sites of different files: it goes back to certbot only once no site Autopilot
// still renews (the server still assigns it a certificate) uses it; then every link of the name is made again.
func TestACertbotNameAnotherAutopilotSiteUsesIsNotGivenBack(t *testing.T) {
	answers := nginxOnItsOwn()
	answers["apachectl -t"], answers["apachectl -k graceful"] = nil, nil
	m, nginxSite, _ := certbotMachine(t, answers)
	m.write("/etc/ssl/blog-apache.key", []byte("the old key\n"), 0o600)
	apacheSite := m.site(inventory.Use{Kind: protocol.WebServerApache, ConfigPath: "/etc/apache2/sites-enabled/blog-ssl.conf", Names: []string{"blog.example"},
		CertPath: "/etc/letsencrypt/live/blog.example/cert.pem", KeyPath: "/etc/ssl/blog-apache.key", ChainPath: "/etc/letsencrypt/live/blog.example/chain.pem",
		Ports: []int{closedPort(t)}})
	apacheSite.Owner, apacheSite.CertbotName = ptr(protocol.OwnerCertbot), ptr("blog.example")
	for _, s := range []protocol.Site{nginxSite, apacheSite} {
		next := m.ca.issue(t, "blog.example", "www.blog.example")
		if r := m.host.Apply(context.Background(), s, next.bundle(), takeOverWork(s, next.sha)); !r.OK {
			t.Fatalf("take-over of %s: %s: %s", *s.ConfigPath, steps(r), message(r))
		}
	}
	live := "/etc/letsencrypt/live/blog.example/"
	give := protocol.Bundle{AssignmentID: testAssignment}

	// The Apache site is still Autopilot's: nothing is given back, and the result says why.
	m.host.SetAssigned([]string{nginxSite.SiteKey, apacheSite.SiteKey})
	r := m.host.Apply(context.Background(), nginxSite, give, giveBackWork(nginxSite, strings.Repeat("a", 64)))
	if r.OK || steps(r) != "certbot_restored!" || !strings.Contains(message(r), "/etc/apache2/sites-enabled/blog-ssl.conf") {
		t.Errorf("%s: %s", steps(r), message(r))
	}
	if m.mode(live+"fullchain.pem")&fs.ModeSymlink != 0 || m.exists("/etc/letsencrypt/renewal/blog.example.conf") {
		t.Error("given back while another site uses it")
	}

	// It is not any more (stopped, say): the whole name goes back to certbot, the Apache site's links too.
	m.host.SetAssigned([]string{nginxSite.SiteKey})
	r = m.host.Apply(context.Background(), nginxSite, give, giveBackWork(nginxSite, strings.Repeat("a", 64)))
	if !r.OK {
		t.Fatalf("%s: %s", steps(r), message(r))
	}
	for _, f := range []string{"fullchain", "privkey", "cert", "chain"} {
		checkLink(t, m, live+f+".pem", "../../archive/blog.example/"+f+"1.pem")
	}
	if string(m.read("/etc/letsencrypt/renewal/blog.example.conf")) != renewalConf {
		t.Error("the renewal file is not back")
	}
}
