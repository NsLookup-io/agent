package install

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nslookup-io/agent/internal/inventory"
	"github.com/nslookup-io/agent/internal/protocol"
)

const secret = "root:$6$the-shadow-file:19000:0:99999:7:::\n"

// A file in a directory a user other than root can change could be swapped for a link between the agent's checks and
// its writes: such a site is refused before anything is read or written.
func TestADirectoryOthersCanChangeIsRefused(t *testing.T) {
	for name, c := range map[string]struct {
		prepare func(m *machine)
		where   string
	}{
		"group-writable": {func(m *machine) { chmod(m, "/srv/app/ssl", 0o775) }, "/srv/app/ssl"},
		"writable by all, sticky (like /tmp)": {func(m *machine) {
			chmod(m, "/srv/app/ssl", 0o1777)
		}, "/srv/app/ssl"},
		"an ancestor group-writable": {func(m *machine) { chmod(m, "/srv/app", 0o770) }, "/srv/app"},
		// The walk starts at the root: the first directory it finds is the root itself.
		"owned by another user": {func(m *machine) { m.host.DirOwner = os.Getuid() + 1 }, "/"},
		// A link on the way leads into a directory others can change.
		"a linked directory": {func(m *machine) {
			m.mkdirs("/home/deploy/certs")
			chmod(m, "/home/deploy/certs", 0o777)
			for _, f := range []string{"shop.pem", "shop.key"} {
				if err := os.Rename(m.path("/srv/app/ssl/"+f), m.path("/home/deploy/certs/"+f)); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Remove(m.path("/srv/app/ssl")); err != nil {
				t.Fatal(err)
			}
			m.link("/srv/app/ssl", "../../home/deploy/certs")
		}, "/home/deploy/certs"},
	} {
		m := newMachine(t, nginxOnItsOwn())
		old := m.ca.issue(t, "shop.example")
		m.write("/srv/app/ssl/shop.pem", old.leafPEM, 0o644)
		m.write("/srv/app/ssl/shop.key", old.keyPEM, 0o600)
		site := m.site(inventory.Use{Kind: protocol.WebServerNginx, ConfigPath: "/etc/nginx/nginx.conf", Names: []string{"shop.example"},
			CertPath: "/srv/app/ssl/shop.pem", KeyPath: "/srv/app/ssl/shop.key"})
		c.prepare(m)
		next := m.ca.issue(t, "shop.example")
		r := m.host.Apply(context.Background(), site, next.bundle(), installWork(site, next.sha))
		if r.OK || steps(r) != "checked written!" || !strings.Contains(message(r), "is in "+c.where+", "+m.changeableBy()) {
			t.Errorf("%s: %s: %s", name, steps(r), message(r))
		}
		if got := m.read("/srv/app/ssl/shop.key"); !bytes.Equal(got, old.keyPEM) {
			t.Errorf("%s: written", name)
		}
		if len(m.runner.commands()) != 0 {
			t.Errorf("%s: ran %q", name, m.runner.commands())
		}
	}
}

func chmod(m *machine, p string, mode fs.FileMode) {
	m.t.Helper()
	if err := os.Chmod(m.path(p), mode); err != nil {
		m.t.Fatal(err)
	}
	m.t.Cleanup(func() { _ = os.Chmod(m.path(p), 0o755) })
}

// A file swapped for a link after the install was planned is refused: nothing is read through the link, nothing is
// written.
func TestAFileSwappedForALinkAfterPlanningIsRefused(t *testing.T) {
	m := newMachine(t, nginxOnItsOwn())
	old := m.ca.issue(t, "shop.example", "www.shop.example")
	site := nginxSite(m, old, 0o644, 0o600)
	m.write("/etc/shadow", []byte(secret), 0o600)
	next := m.ca.issue(t, "shop.example", "www.shop.example")
	c, err := checkBundle(next.leafPEM, next.chainPEM, next.keyPEM, next.sha, site.Names, m.host.clock())
	if err != nil {
		t.Fatal(err)
	}
	tr := m.host.newTree()
	defer tr.close()
	op, err := m.host.planInstall(tr, site, c, installWork(site, next.sha), m.host.usesOf(site.SiteKey))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(m.path("/etc/ssl/shop.key")); err != nil {
		t.Fatal(err)
	}
	m.link("/etc/ssl/shop.key", "../shadow")

	var o Outcome
	if m.host.run(context.Background(), op, &o) || o.message == nil || !strings.Contains(*o.message, "/etc/ssl/shop.key changed while the install was prepared") {
		t.Fatalf("%+v", o)
	}
	checkLink(t, m, "/etc/ssl/shop.key", "../shadow")
	if string(m.read("/etc/shadow")) != secret || !bytes.Equal(m.read("/etc/ssl/shop.pem"), cat(old.leafPEM, old.chainPEM)) {
		t.Error("written")
	}
	noSecretKept(t, m)
	if fileExists(filepath.Join(m.state, "pending.json")) || len(m.runner.commands()) != 0 {
		t.Errorf("pending.json or commands %q", m.runner.commands())
	}
}

// What a set keeps of a link is the link: a restore makes the link again, and never writes what it pointed at.
func TestARestoreNeverWritesContentReadThroughALink(t *testing.T) {
	m := newMachine(t, nginxOnItsOwn())
	m.write("/etc/shadow", []byte(secret), 0o600)
	m.link("/etc/ssl/shop.key", "../shadow")
	m.write("/etc/ssl/shop.pem", []byte("certificate\n"), 0o644)
	tr := m.host.newTree()
	defer tr.close()
	dir, s, err := tr.saveSet(strings.Repeat("a", 32), []string{"/etc/ssl/shop.key", "/etc/ssl/shop.pem"}, m.host.clock())
	if err != nil {
		t.Fatal(err)
	}
	if k := s.find("/etc/ssl/shop.key"); k.State != stateLink || k.Target != "../shadow" || k.Data != "" {
		t.Errorf("kept %+v", k)
	}
	noSecretKept(t, m)

	// Replaced by a file, then restored: the link again, its target untouched.
	if err := os.Remove(m.path("/etc/ssl/shop.key")); err != nil {
		t.Fatal(err)
	}
	m.write("/etc/ssl/shop.key", []byte("a key\n"), 0o600)
	if err := tr.restoreSet(dir); err != nil {
		t.Fatal(err)
	}
	checkLink(t, m, "/etc/ssl/shop.key", "../shadow")
	if string(m.read("/etc/shadow")) != secret || string(m.read("/etc/ssl/shop.pem")) != "certificate\n" {
		t.Error("restored through the link")
	}

	// A restore (at a restart: a new walk) into a directory others can change now is refused for that file.
	chmod(m, "/etc/ssl", 0o777)
	again := m.host.newTree()
	defer again.close()
	if err := again.restoreSet(dir); err == nil || !strings.Contains(err.Error(), m.changeableBy()) {
		t.Errorf("%v", err)
	}
}

// noSecretKept checks no file of the previous sets holds the secret.
func noSecretKept(t *testing.T, m *machine) {
	t.Helper()
	_ = filepath.WalkDir(filepath.Join(m.state, "previous"), func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			if data, _ := os.ReadFile(p); bytes.Contains(data, []byte("the-shadow-file")) {
				t.Errorf("%s holds the secret", p)
			}
		}
		return nil
	})
}

// The certificate must cover every name of every configuration using the file, not only the 100 the site reports.
func TestTheCertificateMustCoverEveryNameOfEveryConfiguration(t *testing.T) {
	var names []string
	for i := range 150 {
		names = append(names, fmt.Sprintf("n%03d.example", i))
	}
	m := newMachine(t, nginxOnItsOwn())
	old := m.ca.issue(t, names...)
	m.write("/etc/ssl/many.pem", old.leafPEM, 0o644)
	m.write("/etc/ssl/many.key", old.keyPEM, 0o600)
	site := m.site(inventory.Use{Kind: protocol.WebServerNginx, ConfigPath: "/etc/nginx/nginx.conf", Names: names,
		CertPath: "/etc/ssl/many.pem", KeyPath: "/etc/ssl/many.key", Ports: []int{closedPort(t)}})
	site.Names = site.Names[:100] // as the inventory reports it

	first100 := m.ca.issue(t, names[:100]...)
	r := m.host.Apply(context.Background(), site, first100.bundle(), installWork(site, first100.sha))
	if r.OK || steps(r) != "checked!" || !strings.Contains(message(r), "does not cover n100.example") {
		t.Errorf("%s: %s", steps(r), message(r))
	}
	all := m.ca.issue(t, names...)
	if r := m.host.Apply(context.Background(), site, all.bundle(), installWork(site, all.sha)); !r.OK {
		t.Errorf("%s: %s", steps(r), message(r))
	}
}

// A chain file other sites share is left as it is when it already holds the new chain, and refused otherwise.
func TestAChainFileSharedWithOtherSites(t *testing.T) {
	for _, same := range []bool{true, false} {
		m := newMachine(t, map[string]error{"apachectl -t": nil, "apachectl -k graceful": nil})
		old := m.ca.issue(t, "a.example")
		chain := old.chainPEM
		if !same {
			chain = newCA(t).pem
		}
		m.write("/etc/ssl/chain.pem", chain, 0o644)
		m.write("/etc/ssl/a.pem", old.leafPEM, 0o644)
		m.write("/etc/ssl/a.key", old.keyPEM, 0o600)
		m.write("/etc/ssl/b.pem", old.leafPEM, 0o644)
		apache := func(name, cert, key string) inventory.Use {
			return inventory.Use{Kind: protocol.WebServerApache, ConfigPath: "/etc/apache2/sites-enabled/" + name + ".conf", Names: []string{name + ".example"},
				CertPath: cert, KeyPath: key, ChainPath: "/etc/ssl/chain.pem", Ports: []int{closedPort(t)}}
		}
		a := m.site(apache("a", "/etc/ssl/a.pem", "/etc/ssl/a.key"))
		m.site(apache("b", "/etc/ssl/b.pem", "/etc/ssl/b.key"))
		next := m.ca.issue(t, "a.example")
		r := m.host.Apply(context.Background(), a, next.bundle(), installWork(a, next.sha))
		if same {
			if !r.OK || !bytes.Equal(m.read("/etc/ssl/a.pem"), next.leafPEM) {
				t.Errorf("the same chain: %s: %s", steps(r), message(r))
			}
		} else if r.OK || steps(r) != "checked written!" ||
			message(r) != "nothing was written: the chain file /etc/ssl/chain.pem is shared with other sites; Autopilot can't replace it" {
			t.Errorf("another chain: %s: %s", steps(r), message(r))
		}
		// Never written either way.
		if info, err := os.Stat(m.path("/etc/ssl/chain.pem")); err != nil || !bytes.Equal(m.read("/etc/ssl/chain.pem"), chain) || info.Mode().Perm() != 0o644 {
			t.Errorf("same %v: the chain file changed", same)
		}
		if extra := m.leftovers("/etc/ssl", "chain.pem", "a.pem", "a.key", "b.pem"); len(extra) > 0 {
			t.Errorf("same %v: left %q", same, extra)
		}
	}
}

// linkedMachine is a site whose configuration names /etc/ssl/site/shop.pem, where /etc/ssl/site is a link to
// /opt/x/l2, itself a link to /etc/ssl/real: the files are in /etc/ssl/real. /etc/ssl/other is another directory only
// root can change, with files of its own.
func linkedMachine(t *testing.T, optX fs.FileMode) (*machine, protocol.Site, issued) {
	m := newMachine(t, nginxOnItsOwn())
	old := m.ca.issue(t, "shop.example")
	for _, d := range []string{"/etc/ssl/real", "/etc/ssl/other"} {
		m.write(d+"/shop.pem", old.leafPEM, 0o644)
		m.write(d+"/shop.key", old.keyPEM, 0o600)
	}
	m.link("/opt/x/l2", "../../etc/ssl/real")
	m.link("/etc/ssl/site", "../../opt/x/l2")
	chmod(m, "/opt/x", optX)
	site := m.site(inventory.Use{Kind: protocol.WebServerNginx, ConfigPath: "/etc/nginx/nginx.conf", Names: []string{"shop.example"},
		CertPath: "/etc/ssl/site/shop.pem", KeyPath: "/etc/ssl/site/shop.key", Ports: []int{closedPort(t)}})
	return m, site, old
}

// A link on the way is followed only when it sits in a directory only root can change: one in a directory others can
// change (/opt/x 0777) is refused, nothing is written anywhere.
func TestALinkOnTheWayInADirectoryOthersCanChangeIsRefused(t *testing.T) {
	m, site, old := linkedMachine(t, 0o777)
	next := m.ca.issue(t, "shop.example")
	r := m.host.Apply(context.Background(), site, next.bundle(), installWork(site, next.sha))
	if r.OK || steps(r) != "checked written!" || !strings.Contains(message(r), "is in /opt/x, "+m.changeableBy()) {
		t.Fatalf("%s: %s", steps(r), message(r))
	}
	for _, d := range []string{"/etc/ssl/real", "/etc/ssl/other"} {
		if !bytes.Equal(m.read(d+"/shop.key"), old.keyPEM) {
			t.Errorf("%s written", d)
		}
	}
}

// A link that sits in a directory only root can change is followed. Every operation after planning goes through the
// directory reached then: a link repointed afterwards (by root) changes nothing of this install, in its writes or in
// its restore.
func TestALinkInARootOnlyDirectoryIsFollowedOnceForTheWholeInstall(t *testing.T) {
	m, site, old := linkedMachine(t, 0o755)
	repoint := func() {
		if err := os.Remove(m.path("/opt/x/l2")); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("../../etc/ssl/other", m.path("/opt/x/l2")); err != nil {
			t.Fatal(err)
		}
	}

	// Repointed after planning: the files go where the walk at planning led.
	next := m.ca.issue(t, "shop.example")
	tr := m.host.newTree()
	c, err := checkBundle(next.leafPEM, next.chainPEM, next.keyPEM, next.sha, site.Names, m.host.clock())
	if err != nil {
		t.Fatal(err)
	}
	op, err := m.host.planInstall(tr, site, c, installWork(site, next.sha), m.host.usesOf(site.SiteKey))
	if err != nil {
		t.Fatal(err)
	}
	repoint()
	var o Outcome
	if !m.host.run(context.Background(), op, &o) {
		t.Fatalf("%+v", o)
	}
	tr.close()
	if !bytes.Equal(m.read("/etc/ssl/real/shop.key"), next.keyPEM) || !bytes.Equal(m.read("/etc/ssl/other/shop.key"), old.keyPEM) {
		t.Error("the install went where the link points now")
	}

	// Repointed while the configuration is tested, and the test fails: the restore goes back to the same directory.
	m, site, old = linkedMachine(t, 0o755)
	m.runner.set("nginx -t", errors.New("nginx -t failed (exit status 1)"))
	m.runner.hooks["nginx -t"] = repoint
	next = m.ca.issue(t, "shop.example")
	r := m.host.Apply(context.Background(), site, next.bundle(), installWork(site, next.sha))
	if r.OK || steps(r) != "checked written tested! restored" {
		t.Fatalf("%s: %s", steps(r), message(r))
	}
	for _, d := range []string{"/etc/ssl/real", "/etc/ssl/other"} {
		if !bytes.Equal(m.read(d+"/shop.key"), old.keyPEM) || !bytes.Equal(m.read(d+"/shop.pem"), old.leafPEM) {
			t.Errorf("%s is not as it was", d)
		}
	}
	if extra := m.leftovers("/etc/ssl/other", "shop.pem", "shop.key"); len(extra) > 0 {
		t.Errorf("left in /etc/ssl/other: %q", extra)
	}
}

// A directory on the way that others can change is refused even when it only holds a link to a directory only root
// can change (they could swap the link).
func TestALinkedAncestorInADirectoryOthersCanChangeIsRefused(t *testing.T) {
	m := newMachine(t, nginxOnItsOwn())
	old := m.ca.issue(t, "shop.example")
	m.write("/etc/app/shop.pem", old.leafPEM, 0o644)
	m.write("/etc/app/shop.key", old.keyPEM, 0o600)
	m.link("/srv/app", "../etc/app")
	chmod(m, "/srv", 0o777)
	site := m.site(inventory.Use{Kind: protocol.WebServerNginx, ConfigPath: "/etc/nginx/nginx.conf", Names: []string{"shop.example"},
		CertPath: "/srv/app/shop.pem", KeyPath: "/srv/app/shop.key"})
	next := m.ca.issue(t, "shop.example")
	r := m.host.Apply(context.Background(), site, next.bundle(), installWork(site, next.sha))
	if r.OK || !strings.Contains(message(r), "is in /srv, "+m.changeableBy()) {
		t.Errorf("%s: %s", steps(r), message(r))
	}
	if !bytes.Equal(m.read("/etc/app/shop.key"), old.keyPEM) {
		t.Error("written")
	}
}

// A walk follows at most 40 links.
func TestAWalkFollowsAtMost40Links(t *testing.T) {
	for _, n := range []int{40, 41} {
		m := newMachine(t, nginxOnItsOwn())
		old := m.ca.issue(t, "shop.example")
		m.write("/etc/ssl/real/shop.pem", old.leafPEM, 0o644)
		m.write("/etc/ssl/real/shop.key", old.keyPEM, 0o600)
		// l0 → l1 → … → l<n-1> → /etc/ssl/real: n links, the last absolute (from the root the agent installs on).
		for i := range n {
			target := fmt.Sprintf("l%d", i+1)
			if i == n-1 {
				target = "/etc/ssl/real"
			}
			m.link(fmt.Sprintf("/etc/ssl/l%d", i), target)
		}
		site := m.site(inventory.Use{Kind: protocol.WebServerNginx, ConfigPath: "/etc/nginx/nginx.conf", Names: []string{"shop.example"},
			CertPath: "/etc/ssl/l0/shop.pem", KeyPath: "/etc/ssl/l0/shop.key", Ports: []int{closedPort(t)}})
		next := m.ca.issue(t, "shop.example")
		r := m.host.Apply(context.Background(), site, next.bundle(), installWork(site, next.sha))
		if n == 40 && !r.OK {
			t.Errorf("40 links: %s: %s", steps(r), message(r))
		}
		if n == 41 && (r.OK || !strings.Contains(message(r), "more than 40 links")) {
			t.Errorf("41 links: %s: %s", steps(r), message(r))
		}
	}
}

// A refusal names who may change the directories the agent writes in: root, and the agent's own user when it runs
// as another (Docker's --user, say).
func TestARefusalNamesWhoMayChangeTheDirectories(t *testing.T) {
	for _, agent := range []int{0, os.Getuid() + 1} {
		if os.Getuid() == 0 && agent == 0 {
			continue
		}
		m := newMachine(t, nginxOnItsOwn())
		m.host.DirOwner = agent
		tr := m.host.newTree()
		_, _, err := tr.at("/etc/ssl/shop.pem")
		tr.close()
		who := "root"
		if agent != 0 {
			who = fmt.Sprintf("root or the agent's user (uid %d)", agent)
		}
		want := fmt.Sprintf("/etc/ssl/shop.pem is in /, which a user other than %s can change (owner %d, mode 0755); the agent writes only in "+
			"directories only %s can change", who, os.Getuid(), who)
		if err == nil || err.Error() != want {
			t.Errorf("agent %d: %v\nwant %s", agent, err, want)
		}
	}
}
