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

// hookCommand is how the folder hook shows (never its text: it is agent.yaml's).
const hookCommand = "the folder hook"

// folderMachine is a machine with the folder root /certs (0755, its owner the agent's) and a Folder writing there.
func folderMachine(t *testing.T) (*machine, *Folder) {
	t.Helper()
	m := newMachine(t, map[string]error{})
	m.mkdirs("/certs")
	return m, &Folder{Host: m.host, Root: "/certs"}
}

func folderWork(name, sha string) protocol.Work {
	return protocol.Work{AssignmentID: testAssignment, SHA256: sha, Action: protocol.ActionInstall, FolderName: &name}
}

func TestAFolderCertificateIsWrittenAsFourFiles(t *testing.T) {
	m, f := folderMachine(t)
	c := m.ca.issue(t, "shop.example", "www.shop.example")
	w := folderWork("shop.example", c.sha)
	if disk, err := f.DiskSHA(w); disk != "" || err != nil {
		t.Fatalf("before: %q, %v", disk, err)
	}
	r := f.Apply(context.Background(), w, c.bundle())
	if !r.OK || steps(r) != "checked written" || r.Message != nil {
		t.Fatalf("%s: %s", steps(r), message(r))
	}
	for name, want := range map[string][]byte{
		"fullchain.pem": cat(c.leafPEM, c.chainPEM),
		"cert.pem":      c.leafPEM,
		"chain.pem":     c.chainPEM,
		"privkey.pem":   c.keyPEM,
	} {
		if got := m.read("/certs/shop.example/" + name); !bytes.Equal(got, want) {
			t.Errorf("%s holds %q", name, got)
		}
	}
	for p, want := range map[string]fs.FileMode{
		"/certs/shop.example":               fs.ModeDir | 0o750,
		"/certs/shop.example/fullchain.pem": 0o644,
		"/certs/shop.example/cert.pem":      0o644,
		"/certs/shop.example/chain.pem":     0o644,
		"/certs/shop.example/privkey.pem":   0o600,
	} {
		if got := m.mode(p); got != want {
			t.Errorf("%s: mode %v, want %v", p, got, want)
		}
	}
	if extra := m.leftovers("/certs/shop.example", "fullchain.pem", "cert.pem", "chain.pem", "privkey.pem"); len(extra) > 0 {
		t.Errorf("left %q", extra)
	}
	if disk, err := f.DiskSHA(w); disk != c.sha || err != nil {
		t.Errorf("after: %q, %v", disk, err)
	}
	if sets, _ := os.ReadDir(filepath.Join(m.state, "previous", "folder-shop.example")); len(sets) != 1 {
		t.Errorf("%d previous sets", len(sets))
	}
	if fileExists(filepath.Join(m.state, "pending.json")) {
		t.Error("pending.json is left")
	}
	if len(m.chowned) != 0 {
		t.Errorf("new files were given an owner: %q", m.chowned)
	}
}

// A renewal keeps each file's owner, group and mode, a key never wider than 0640; the previous files are kept, the
// last two sets.
func TestARenewalKeepsModesAndTheLastTwoSets(t *testing.T) {
	m, f := folderMachine(t)
	first := m.ca.issue(t, "mail.example")
	if r := f.Apply(context.Background(), folderWork("mail.example", first.sha), first.bundle()); !r.OK {
		t.Fatalf("%s: %s", steps(r), message(r))
	}
	chmod(m, "/certs/mail.example/privkey.pem", 0o644)
	chmod(m, "/certs/mail.example/cert.pem", 0o640)
	var last issued
	for range 3 {
		last = m.ca.issue(t, "mail.example")
		if r := f.Apply(context.Background(), folderWork("mail.example", last.sha), last.bundle()); !r.OK {
			t.Fatalf("%s: %s", steps(r), message(r))
		}
	}
	if got := m.mode("/certs/mail.example/privkey.pem"); got != 0o640 {
		t.Errorf("key mode %v", got)
	}
	if got := m.mode("/certs/mail.example/cert.pem"); got != 0o640 {
		t.Errorf("certificate mode %v", got)
	}
	if !bytes.Equal(m.read("/certs/mail.example/privkey.pem"), last.keyPEM) {
		t.Error("the last key is not in place")
	}
	if !strings.Contains(strings.Join(m.chowned, ","), "/certs/mail.example/privkey.pem ") {
		t.Errorf("the key's owner was not kept: %q", m.chowned)
	}
	sets, _ := os.ReadDir(filepath.Join(m.state, "previous", "folder-mail.example"))
	if len(sets) != 2 {
		t.Errorf("%d previous sets", len(sets))
	}
}

func TestAFolderNameIsSanitised(t *testing.T) {
	for given, want := range map[string]string{
		"shop.example":           "shop.example",
		"Shop.Example.TEST":      "shop.example.test",
		"wildcard.example":       "wildcard.example",
		"../etc":                 "etc",
		"../../etc/passwd":       "etcpasswd",
		"/etc":                   "etc",
		"..":                     testAssignment,
		".":                      testAssignment,
		"":                       testAssignment,
		"...hidden":              "hidden",
		"a b/c\\d*e?f":           "abcdef",
		"münchen.example":        "mnchen.example",
		strings.Repeat("a", 100): strings.Repeat("a", 64),
		// A leading dash would read as an option to a hook given the name (NSL_CERTIFICATE).
		"-dash":       "dash",
		"--rf":        "rf",
		"-.-.x":       "x",
		"-":           testAssignment,
		"shop-1.test": "shop-1.test",
	} {
		if got := FolderName(folderWork(given, "")); got != want {
			t.Errorf("%q: %q, want %q", given, got, want)
		}
	}
	w := folderWork("", "")
	w.FolderName = nil
	w.AssignmentID = strings.ToUpper(testAssignment)
	if got := FolderName(w); got != testAssignment {
		t.Errorf("no name: %q", got)
	}
}

// The server's folder name can never make the agent write outside the folder root.
func TestAFolderNameCannotLeaveTheRoot(t *testing.T) {
	m, f := folderMachine(t)
	m.write("/etc/passwd", []byte(secret), 0o644)
	for _, name := range []string{"../etc", "../../etc", "..", "/etc"} {
		c := m.ca.issue(t, "shop.example")
		if r := f.Apply(context.Background(), folderWork(name, c.sha), c.bundle()); !r.OK {
			t.Fatalf("%q: %s: %s", name, steps(r), message(r))
		}
	}
	if got := m.read("/etc/passwd"); string(got) != secret {
		t.Error("/etc/passwd changed")
	}
	if extra := m.leftovers("/etc", "passwd"); len(extra) > 0 {
		t.Errorf("written into /etc: %q", extra)
	}
	if extra := m.leftovers("/certs", "etc", testAssignment); len(extra) > 0 {
		t.Errorf("other folders: %q", extra)
	}
	if extra := m.leftovers("/", "certs", "etc"); len(extra) > 0 {
		t.Errorf("written next to the root: %q", extra)
	}
}

func TestFolderModeThatIsNotSetUp(t *testing.T) {
	m := newMachine(t, map[string]error{})
	f := &Folder{Host: m.host}
	c := m.ca.issue(t, "shop.example")
	w := folderWork("shop.example", c.sha)
	if disk, err := f.DiskSHA(w); disk != "" || err != nil {
		t.Errorf("%q, %v", disk, err)
	}
	r := f.Apply(context.Background(), w, c.bundle())
	want := "folder mode isn't set up on this server: set folder.root in /etc/nslookup-agent/agent.yaml"
	if r.OK || steps(r) != "written!" || message(r) != want {
		t.Errorf("%s: %s", steps(r), message(r))
	}
}

func TestTheBundleIsCheckedBeforeAFolderIsTouched(t *testing.T) {
	m, f := folderMachine(t)
	c := m.ca.issue(t, "shop.example")
	other := m.ca.issue(t, "shop.example")
	b := c.bundle()
	b.KeyPEM = other.keyPEM
	r := f.Apply(context.Background(), folderWork("shop.example", c.sha), b)
	if r.OK || steps(r) != "checked!" || !strings.Contains(message(r), "does not match") {
		t.Errorf("%s: %s", steps(r), message(r))
	}
	if m.exists("/certs/shop.example") {
		t.Error("the folder was made")
	}
}

func TestTheFolderRootMustExistAndOnlyTheAgentMayChangeIt(t *testing.T) {
	for name, c := range map[string]struct {
		prepare func(m *machine)
		want    string
	}{
		"no root": {func(m *machine) {
			if err := os.Remove(m.path("/certs")); err != nil {
				t.Fatal(err)
			}
		}, "nothing was written: /certs does not exist"},
		"a root others can change": {func(m *machine) { chmod(m, "/certs", 0o777) }, "is in /certs, {who}"},
		"a folder others can change": {func(m *machine) {
			m.mkdirs("/certs/shop.example")
			chmod(m, "/certs/shop.example", 0o775)
		}, "is in /certs/shop.example, {who}"},
		"a folder that is a link": {func(m *machine) {
			m.mkdirs("/srv/elsewhere")
			m.link("/certs/shop.example", "/srv/elsewhere")
		}, "/certs/shop.example is a symbolic link"},
		"a file that is a link": {func(m *machine) {
			m.write("/srv/key.pem", []byte(secret), 0o600)
			m.mkdirs("/certs/shop.example")
			m.link("/certs/shop.example/privkey.pem", "/srv/key.pem")
		}, "/certs/shop.example/privkey.pem is a symbolic link"},
		"another owner": {func(m *machine) { m.host.DirOwner = os.Getuid() + 1 }, "is in /, {who}"},
	} {
		m, f := folderMachine(t)
		c.prepare(m)
		cert := m.ca.issue(t, "shop.example")
		r := f.Apply(context.Background(), folderWork("shop.example", cert.sha), cert.bundle())
		if want := strings.ReplaceAll(c.want, "{who}", m.changeableBy()); r.OK || steps(r) != "checked written!" || !strings.Contains(message(r), want) {
			t.Errorf("%s: %s: %s", name, steps(r), message(r))
		}
		if m.exists("/srv/key.pem") && string(m.read("/srv/key.pem")) != secret {
			t.Errorf("%s: written through the link", name)
		}
		if m.exists("/srv/elsewhere") && len(m.leftovers("/srv/elsewhere")) > 0 {
			t.Errorf("%s: written through the link", name)
		}
	}
}

func TestDiskSHAOfAFolder(t *testing.T) {
	m, f := folderMachine(t)
	c := m.ca.issue(t, "shop.example")
	w := folderWork("shop.example", c.sha)
	m.mkdirs("/certs/shop.example")
	if disk, err := f.DiskSHA(w); disk != "" || err != nil {
		t.Errorf("an empty folder: %q, %v", disk, err)
	}
	m.write("/certs/shop.example/fullchain.pem", cat(c.leafPEM, c.chainPEM), 0o644)
	if disk, err := f.DiskSHA(w); disk != c.sha || err != nil {
		t.Errorf("%q, %v", disk, err)
	}
	m.write("/certs/shop.example/fullchain.pem", []byte("not a certificate\n"), 0o644)
	if disk, err := f.DiskSHA(w); disk != "" || err != nil {
		t.Errorf("no certificate: %q, %v", disk, err)
	}
	if err := os.Remove(m.path("/certs/shop.example/fullchain.pem")); err != nil {
		t.Fatal(err)
	}
	m.write("/srv/fullchain.pem", cat(c.leafPEM, c.chainPEM), 0o644)
	m.link("/certs/shop.example/fullchain.pem", "/srv/fullchain.pem")
	if disk, err := f.DiskSHA(w); disk != "" || err == nil {
		t.Errorf("a link: %q, %v", disk, err)
	}
	chmod(m, "/certs", 0o777)
	if _, err := f.DiskSHA(w); err == nil || !strings.Contains(err.Error(), "is in /certs, "+m.changeableBy()) {
		t.Errorf("a root others can change: %v", err)
	}
}

// The hook (host mode) runs once the files are in place, with the minimal environment, the folder and the name.
func TestTheHookRunsAfterTheFilesAreWritten(t *testing.T) {
	m, f := folderMachine(t)
	m.host.Runner = inventory.SystemRunner{}
	out := filepath.Join(t.TempDir(), "hook.out")
	t.Setenv("AGENT_SECRET", "leaked")
	f.Hook = `cat "$NSL_FOLDER/cert.pem" > "` + out + `.cert"; printf '%s|%s|%s|%s' "$NSL_FOLDER" "$NSL_CERTIFICATE" "$AGENT_SECRET" "$PATH" > "` + out + `"`
	c := m.ca.issue(t, "mail.example")
	r := f.Apply(context.Background(), folderWork("mail.example", c.sha), c.bundle())
	if !r.OK || steps(r) != "checked written hook_ran" || r.Message != nil {
		t.Fatalf("%s: %s", steps(r), message(r))
	}
	got, err := os.ReadFile(out)
	want := m.path("/certs/mail.example") + "|mail.example||/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
	if err != nil || string(got) != want {
		t.Errorf("the hook saw %q (%v), want %q", got, err, want)
	}
	if cert, err := os.ReadFile(out + ".cert"); err != nil || !bytes.Equal(cert, c.leafPEM) {
		t.Errorf("the hook read %q (%v)", cert, err)
	}
	if strings.Contains(detail(r, protocol.StepHookRan), "cat") {
		t.Errorf("the hook's command was reported: %q", detail(r, protocol.StepHookRan))
	}
}

// A failing hook is a failed hook_ran step; the files stay.
func TestAFailingHookIsAFailedStepAndTheFilesStay(t *testing.T) {
	m, f := folderMachine(t)
	m.host.Runner = inventory.SystemRunner{}
	f.Hook = `echo "postfix: fatal: cannot reload" >&2; exit 3`
	c := m.ca.issue(t, "mail.example")
	r := f.Apply(context.Background(), folderWork("mail.example", c.sha), c.bundle())
	if r.OK || steps(r) != "checked written hook_ran!" {
		t.Fatalf("%s: %s", steps(r), message(r))
	}
	d := detail(r, protocol.StepHookRan)
	if !strings.Contains(d, "postfix: fatal: cannot reload") || strings.Contains(d, "echo") || message(r) != d {
		t.Errorf("detail %q, message %q", d, message(r))
	}
	if !bytes.Equal(m.read("/certs/mail.example/privkey.pem"), c.keyPEM) {
		t.Error("the files did not stay")
	}
	if fileExists(filepath.Join(m.state, "pending.json")) {
		t.Error("pending.json is left")
	}
}

func TestNoHookNoStep(t *testing.T) {
	m, f := folderMachine(t)
	f.Reload = &DockerReload{}
	c := m.ca.issue(t, "mail.example")
	if r := f.Apply(context.Background(), folderWork("mail.example", c.sha), c.bundle()); !r.OK || steps(r) != "checked written" {
		t.Errorf("%s: %s", steps(r), message(r))
	}
	if len(m.runner.commands()) != 0 {
		t.Errorf("ran %q", m.runner.commands())
	}
}

// Killed while the hook ran: on the next start the files are found in place and the hook runs again.
func TestAFolderInstallKilledWhileItsHookRanIsFinishedOnStart(t *testing.T) {
	m, f := folderMachine(t)
	f.Hook = "postfix reload"
	m.runner.set(hookCommand, nil)
	c := m.ca.issue(t, "mail.example")
	killAt(m, hookCommand, func() { f.Apply(context.Background(), folderWork("mail.example", c.sha), c.bundle()) })
	if !fileExists(filepath.Join(m.state, "pending.json")) {
		t.Fatal("not killed in the hook")
	}
	rec, err := f.RecoverPending(context.Background())
	if err != nil || rec == nil || !rec.Installed || rec.AssignmentID != testAssignment {
		t.Fatalf("%+v, %v", rec, err)
	}
	if r := rec.Result; !r.OK || r.SHA256 != c.sha || steps(r) != "written hook_ran" {
		t.Errorf("%s: %s", steps(r), message(r))
	}
	if m.runner.count(hookCommand) != 2 {
		t.Errorf("ran %q", m.runner.commands())
	}
	if fileExists(filepath.Join(m.state, "pending.json")) || f.ReloadOwed(folderWork("mail.example", c.sha)) || rec.ReloadOwed {
		t.Error("pending.json or the owed reload is left")
	}
	if rec, err := f.RecoverPending(context.Background()); rec != nil || err != nil {
		t.Errorf("again: %+v, %v", rec, err)
	}
}

// A hook that failed is owed: the next Apply of the same certificate finds the files in place and only runs the hook.
func TestAFailedHookRunsAgainOnTheNextApply(t *testing.T) {
	m, f := folderMachine(t)
	f.Hook = "postfix reload"
	m.runner.set(hookCommand, errors.New("the folder hook failed (exit status 1): postfix: not running"))
	c := m.ca.issue(t, "mail.example")
	w := folderWork("mail.example", c.sha)
	if r := f.Apply(context.Background(), w, c.bundle()); r.OK || steps(r) != "checked written hook_ran!" {
		t.Fatalf("%s: %s", steps(r), message(r))
	}
	if !f.ReloadOwed(w) {
		t.Fatal("the reload is not owed")
	}
	if f.ReloadOwed(folderWork("other.example", c.sha)) {
		t.Error("owed for another folder")
	}
	before, _ := os.ReadDir(filepath.Join(m.state, "previous", "folder-mail.example"))

	// Still failing: still owed, nothing written.
	r := f.Apply(context.Background(), w, c.bundle())
	if r.OK || steps(r) != "checked hook_ran!" || detail(r, protocol.StepChecked) != "already in place" || !f.ReloadOwed(w) {
		t.Errorf("again: %s: %s", steps(r), message(r))
	}
	m.runner.set(hookCommand, nil)
	r = f.Apply(context.Background(), w, c.bundle())
	if !r.OK || steps(r) != "checked hook_ran" || detail(r, protocol.StepChecked) != "already in place" || r.Message != nil {
		t.Errorf("fixed: %s: %s", steps(r), message(r))
	}
	if f.ReloadOwed(w) {
		t.Error("still owed")
	}
	if after, _ := os.ReadDir(filepath.Join(m.state, "previous", "folder-mail.example")); len(after) != len(before) {
		t.Errorf("written again: %d sets, %d before", len(after), len(before))
	}
	if m.runner.count(hookCommand) != 3 || fileExists(filepath.Join(m.state, "pending.json")) {
		t.Errorf("ran %q", m.runner.commands())
	}
	if !bytes.Equal(m.read("/certs/mail.example/privkey.pem"), c.keyPEM) {
		t.Error("the files changed")
	}
}

// Stopped while the hook ran, and the hook fails on the next start: the files are in place but nothing is marked
// installed; the reload stays owed for the next work.
func TestARecoveredFolderInstallWhoseHookFailsIsNotInstalled(t *testing.T) {
	m, f := folderMachine(t)
	f.Hook = "postfix reload"
	m.runner.set(hookCommand, nil)
	c := m.ca.issue(t, "mail.example")
	w := folderWork("mail.example", c.sha)
	killAt(m, hookCommand, func() { f.Apply(context.Background(), w, c.bundle()) })
	m.runner.set(hookCommand, errors.New("the folder hook failed (exit status 1): postfix: not running"))
	rec, err := f.RecoverPending(context.Background())
	if err != nil || rec == nil || rec.Installed || !rec.ReloadOwed || rec.Result.OK || rec.Result.SHA256 != c.sha ||
		steps(rec.Result) != "written hook_ran!" || !strings.Contains(message(rec.Result), "postfix: not running") {
		t.Fatalf("%+v, %v", rec, err)
	}
	if fileExists(filepath.Join(m.state, "pending.json")) || !f.ReloadOwed(w) {
		t.Error("pending.json left, or the reload not owed")
	}
	m.runner.set(hookCommand, nil)
	if r := f.Apply(context.Background(), w, c.bundle()); !r.OK || steps(r) != "checked hook_ran" || f.ReloadOwed(w) {
		t.Errorf("the next work: %s: %s", steps(r), message(r))
	}
}

// Stopped again while the recovery ran the hook: the reload is still owed, and the next work runs it.
func TestAFolderInstallKilledInTheRecoveryHookIsReloadedWithTheNextWork(t *testing.T) {
	m, f := folderMachine(t)
	f.Hook = "postfix reload"
	m.runner.set(hookCommand, nil)
	c := m.ca.issue(t, "mail.example")
	w := folderWork("mail.example", c.sha)
	killAt(m, hookCommand, func() { f.Apply(context.Background(), w, c.bundle()) })
	killAt(m, hookCommand, func() { f.RecoverPending(context.Background()) })
	if !f.ReloadOwed(w) {
		t.Fatal("the reload is not owed")
	}
	if rec, err := f.RecoverPending(context.Background()); rec != nil || err != nil {
		t.Errorf("recovered again: %+v, %v", rec, err)
	}
	if r := f.Apply(context.Background(), w, c.bundle()); !r.OK || steps(r) != "checked hook_ran" || f.ReloadOwed(w) {
		t.Errorf("the next work: %s: %s", steps(r), message(r))
	}
	if m.runner.count(hookCommand) != 3 {
		t.Errorf("ran %q", m.runner.commands())
	}
}

// Nothing to reload any more (the hook taken out of agent.yaml): the owed reload is settled by the next Apply.
func TestAnOwedReloadWithNoHookLeftIsSettled(t *testing.T) {
	m, f := folderMachine(t)
	f.Hook = "postfix reload"
	m.runner.set(hookCommand, errors.New("the folder hook failed (exit status 1)"))
	c := m.ca.issue(t, "mail.example")
	w := folderWork("mail.example", c.sha)
	f.Apply(context.Background(), w, c.bundle())
	f.Hook = ""
	if r := f.Apply(context.Background(), w, c.bundle()); !r.OK || steps(r) != "checked" || f.ReloadOwed(w) {
		t.Errorf("%s: %s", steps(r), message(r))
	}
}

// Killed before every file was in place: the previous files go back (none, for a first install), no hook runs.
func TestAFolderInstallKilledBeforeItsFilesWereInPlaceIsUndoneOnStart(t *testing.T) {
	m, f := folderMachine(t)
	f.Hook = "postfix reload"
	m.runner.set(hookCommand, nil)
	old := m.ca.issue(t, "mail.example")
	if r := f.Apply(context.Background(), folderWork("mail.example", old.sha), old.bundle()); !r.OK {
		t.Fatalf("%s: %s", steps(r), message(r))
	}
	next := m.ca.issue(t, "mail.example")
	killAt(m, hookCommand, func() { f.Apply(context.Background(), folderWork("mail.example", next.sha), next.bundle()) })
	m.write("/certs/mail.example/privkey.pem", old.keyPEM, 0o600)
	m.write("/certs/mail.example/.cert.pem.nslookup-agent-0123", next.leafPEM, 0o600)

	rec, err := f.RecoverPending(context.Background())
	if err != nil || rec == nil || rec.Installed || rec.Result.OK || steps(rec.Result) != "written! restored" {
		t.Fatalf("%+v, %v", rec, err)
	}
	if !bytes.Equal(m.read("/certs/mail.example/cert.pem"), old.leafPEM) {
		t.Error("the previous certificate is not back")
	}
	if extra := m.leftovers("/certs/mail.example", "fullchain.pem", "cert.pem", "chain.pem", "privkey.pem"); len(extra) > 0 {
		t.Errorf("left %q", extra)
	}
	if m.runner.count(hookCommand) != 2 {
		t.Errorf("ran %q", m.runner.commands())
	}
}

// A folder install waits for an interrupted install, and a site install for an interrupted folder install.
func TestAFolderInstallWaitsForAnInterruptedOne(t *testing.T) {
	m, f := folderMachine(t)
	f.Hook = "postfix reload"
	m.runner.set(hookCommand, nil)
	c := m.ca.issue(t, "mail.example")
	killAt(m, hookCommand, func() { f.Apply(context.Background(), folderWork("mail.example", c.sha), c.bundle()) })
	again := m.ca.issue(t, "mail.example")
	r := f.Apply(context.Background(), folderWork("mail.example", again.sha), again.bundle())
	if r.OK || steps(r) != "checked written!" || !strings.Contains(message(r), "interrupted") {
		t.Errorf("%s: %s", steps(r), message(r))
	}
}

func TestAPendingFolderInstallIsChecked(t *testing.T) {
	m, f := folderMachine(t)
	for name, text := range map[string]string{
		"a name that climbs":     `{"siteKey":"folder-..","set":"20261029T120000.000000000Z","folder":{"path":"/certs/..","name":".."}}`,
		"a key of another name":  `{"siteKey":"folder-a","set":"20261029T120000.000000000Z","folder":{"path":"/certs/b","name":"b"}}`,
		"a relative path":        `{"siteKey":"folder-b","set":"20261029T120000.000000000Z","folder":{"path":"certs/b","name":"b"}}`,
		"a path of another name": `{"siteKey":"folder-b","set":"20261029T120000.000000000Z","folder":{"path":"/certs/c","name":"b"}}`,
	} {
		if err := writeStateFile(filepath.Join(m.state, "pending.json"), []byte(text)); err != nil {
			t.Fatal(err)
		}
		if rec, err := f.RecoverPending(context.Background()); rec != nil || err == nil || !strings.Contains(err.Error(), "set aside as") {
			t.Errorf("%s: %+v, %v", name, rec, err)
		}
	}
}

// A server without folder.root says so before the bundle is fetched.
func TestFolderModeNotSetUpIsToldBeforeTheBundle(t *testing.T) {
	m := newMachine(t, nil)
	f := &Folder{Host: m.host}
	if err := f.CanInstall(folderWork("shop.example", strings.Repeat("a", 64))); err == nil || err.Error() != notSetUp {
		t.Errorf("%v", err)
	}
	f.Root = "/etc/ssl/nslookup"
	if err := f.CanInstall(folderWork("shop.example", strings.Repeat("a", 64))); err != nil {
		t.Errorf("set up: %v", err)
	}
}
