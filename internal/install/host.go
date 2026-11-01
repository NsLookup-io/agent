// Package install installs certificates on this machine. Host installs on the sites of the web servers (nginx,
// Apache, HAProxy): it checks the bundle, writes the files the configuration names in the format each directive
// expects, keeps the files it replaces, tests every web server using them and reloads each, and puts the previous files
// back when a test or a reload fails. It also takes certbot's sites over and gives them back. Folder writes folder
// certificates, each into a folder of its own, and reloads what uses them as this machine's configuration says.
//
// The server never names a path or a command: a work item names a site by its key (or a folder, by a name kept to
// [a-z0-9.-]), the paths are the agent's own inventory's or its agent.yaml's, and the commands are package inventory's
// allowlist and agent.yaml's folder hook. The agent never edits a web server's configuration.
package install

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/nslookup-io/agent/internal/inventory"
	"github.com/nslookup-io/agent/internal/protocol"
)

const (
	// opTimeout: an install, from writing its files to a reload or a restore, runs on its own time, so the agent being
	// stopped never cuts it in half (a kill is what pending.json covers).
	opTimeout = 2 * time.Minute
	// undoTimeout: the reload after the previous files are put back gets its own time, even when the install's is
	// spent (by a command that hung).
	undoTimeout = time.Minute
	// maxDetail and maxMessage are the server's limits for a step's detail and a result's message.
	maxDetail  = 1000
	maxMessage = 2000
)

// kindOrder: the web servers using a file are tested and reloaded in this order.
var kindOrder = []protocol.WebServerKind{protocol.WebServerNginx, protocol.WebServerApache, protocol.WebServerHAProxy}

// Host installs on the sites of the web servers on this machine (host mode). SetInventory gives it each inventory the
// agent reads; Apply installs on a site of the last one. Not for concurrent installs.
type Host struct {
	// Root is the machine's file system root: "/".
	Root string
	// StateDir is the agent's own directory (/var/lib/nslookup-agent): previous/<siteKey>/ (the files replaced, the last
	// two sets), certbot/<name>.json (the records of take-overs) and pending.json (an install under way).
	StateDir string
	// Runner runs the web servers' configuration tests and reloads.
	Runner inventory.Runner
	// Log: nil = slog.Default().
	Log *slog.Logger
	// DirOwner is the user who may own a directory an install goes through, besides root (tree.at): the agent's own
	// effective user (root on a server).
	DirOwner int

	// now: nil = time.Now. chown, when set, stands in for changing a file's owner (path as configured).
	now   func() time.Time
	chown func(path string, uid, gid int) error
	// localWait: the zero value = the real wait of the local TLS check.
	localWait localWait

	mu sync.Mutex
	// uses are the configurations using each site's file, haproxyFiles the HAProxy configuration files read: both from
	// the last inventory read.
	uses         map[string][]inventory.Use
	haproxyFiles []string
	// assigned are the sites the server assigns certificates to now (SetAssigned).
	assigned map[string]bool
}

// SetInventory keeps what the installs need of an inventory read: the configurations using each site's file and the
// HAProxy configuration files.
func (h *Host) SetInventory(inv inventory.Inventory) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.uses = maps.Clone(inv.Uses)
	h.haproxyFiles = slices.Clone(inv.HAProxyFiles)
}

func (h *Host) log() *slog.Logger {
	if h.Log == nil {
		return slog.Default()
	}
	return h.Log
}

func (h *Host) clock() time.Time {
	if h.now == nil {
		return time.Now()
	}
	return h.now()
}

// DiskSHA is the SHA-256 of the leaf certificate (the first) in the site's certificate file: "" when the file holds no
// certificate, an error when it cannot be read.
func (h *Host) DiskSHA(site protocol.Site) (string, error) {
	if site.CertPath == nil {
		return "", errors.New("this site names no certificate file")
	}
	data, err := readRegular(h.abs(*site.CertPath))
	if err != nil {
		return "", fmt.Errorf("%s: %w", *site.CertPath, err)
	}
	defer clear(data)
	return LeafSHA(data), nil
}

// Apply installs b on site (w.Certbot take_over: taking it over from certbot first), or for a release with certbot
// give_back gives the site back to certbot, and says how it went. From the first file written to the last reload it
// runs on its own time, whatever happens to ctx.
func (h *Host) Apply(ctx context.Context, site protocol.Site, b protocol.Bundle, w protocol.Work) protocol.InstallResult {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), opTimeout)
	defer cancel()
	if w.Action == protocol.ActionRelease {
		if w.Certbot == nil || *w.Certbot != protocol.CertbotGiveBack {
			var o Outcome
			o.Fail(protocol.StepCertbotRestored, "this release asks for nothing this agent does")
			return o.Result(false)
		}
		return h.giveBackSite(ctx, site, w)
	}
	return h.install(ctx, site, b, w)
}

// operation is one install: what pending.json says of it, what it changes, and the tree its every file operation goes
// through.
type operation struct {
	pending
	changes []change
	uses    []inventory.Use
	setDir  string
	tree    *tree
}

func (op *operation) clear() {
	for _, c := range op.changes {
		clear(c.data)
	}
}

// unchanged checks that every path still holds what it held when the operation was planned (s is what it holds now):
// a file swapped for a link in between is refused, never followed.
func (op *operation) unchanged(s set) error {
	for _, c := range op.changes {
		now := s.find(c.path)
		if c.was != "" && (now.State != c.was || now.Target != c.wasTarget) {
			return fmt.Errorf("%s changed while the install was prepared", c.path)
		}
		if c.isMove() && s.find(c.from).State != stateFile {
			return fmt.Errorf("%s changed while the install was prepared", c.from)
		}
	}
	return nil
}

// paths are every path the operation changes, each once.
func (op *operation) paths() []string {
	var out []string
	for _, c := range op.changes {
		for _, p := range []string{c.path, c.from} {
			if p != "" && !slices.Contains(out, p) {
				out = append(out, p)
			}
		}
	}
	return out
}

func (h *Host) install(ctx context.Context, site protocol.Site, b protocol.Bundle, w protocol.Work) protocol.InstallResult {
	var o Outcome
	known := h.usesOf(site.SiteKey)
	// Every name of every configuration using the file: the site reports at most 100.
	names := slices.Clone(site.Names)
	for _, u := range known.uses {
		names = append(names, u.Names...)
	}
	slices.Sort(names)
	c, err := checkBundle(b.CertPEM, b.ChainPEM, b.KeyPEM, w.SHA256, slices.Compact(names), h.clock())
	if err != nil {
		o.Fail(protocol.StepChecked, err.Error())
		return o.Result(false)
	}
	defer c.clear()
	o.OK(protocol.StepChecked, "")
	t := h.newTree()
	defer t.close()
	op, err := h.planInstall(t, site, c, w, known)
	if err != nil {
		o.Fail(protocol.StepWritten, "nothing was written: "+err.Error())
		return o.Result(false)
	}
	defer op.clear()
	if !h.run(ctx, op, &o) {
		return o.Result(false)
	}
	served, detail := checkLocally(ctx, op.uses, w.SHA256, h.localWait)
	o.Step(protocol.StepCheckedLocally, served, detail)
	r := o.Result(true)
	r.ServedLocally = &served
	return r
}

// planInstall plans writing c to the site: its files in every configuration's format, owners and modes, certbot's
// take-over when the work asks for it, the web servers to test and reload. Every file is reached through t: in
// directories only root can change.
func (h *Host) planInstall(t *tree, site protocol.Site, c *certificate, w protocol.Work, known sites) (*operation, error) {
	if err := installable(site, w, known); err != nil {
		return nil, err
	}
	takeOver := w.Certbot != nil && *w.Certbot == protocol.CertbotTakeOver
	uses := known.uses
	all, err := layout(uses, c)
	if err != nil {
		return nil, err
	}
	var files []file
	for _, f := range all {
		if known.others[f.path] {
			// A chain file other sites share is left as it is when it already holds the new chain.
			if !f.chain {
				return nil, fmt.Errorf("%s is also used by another site, whose certificate would no longer match it", f.path)
			}
			if !t.holdsChain(f) {
				return nil, fmt.Errorf("the chain file %s is shared with other sites; Autopilot can't replace it", f.path)
			}
			continue
		}
		files = append(files, f)
	}
	op := &operation{pending: pending{AssignmentID: w.AssignmentID, SHA256: w.SHA256, SiteKey: site.SiteKey}, uses: uses, tree: t}
	var links map[string]bool
	var moves []change
	if takeOver {
		if links, moves, op.Certbot, op.NewRecord, err = t.takeOver(site, files, h.clock()); err != nil {
			return nil, err
		}
		op.CertbotMoved = len(moves) > 0
	}
	for _, f := range files {
		ch, err := t.writeChange(f, links[f.path])
		if err != nil {
			return nil, err
		}
		op.changes = append(op.changes, ch)
	}
	op.changes = append(op.changes, moves...)
	op.Servers = serversOf(uses, known.haproxyFiles)
	return op, nil
}

// CanInstall says, before the bundle is fetched, why the agent cannot install on site as w asks (nil: it may try): the
// site is blocked or not a web server's, certbot renews it and w does not take it over, or its configuration is not
// known from the last read. Apply refuses for the same reasons.
func (h *Host) CanInstall(site protocol.Site, w protocol.Work) error {
	if err := installable(site, w, h.usesOf(site.SiteKey)); err != nil {
		return fmt.Errorf("nothing was written: %w", err)
	}
	return nil
}

// installable is why the agent cannot install on site as w asks, with what the last read knows of it; nil when it may.
func installable(site protocol.Site, w protocol.Work, known sites) error {
	switch {
	case site.Blocked != nil:
		return fmt.Errorf("the agent cannot install on this site (%s)", *site.Blocked)
	case site.Kind != protocol.SiteNginx && site.Kind != protocol.SiteApache && site.Kind != protocol.SiteHAProxy:
		return fmt.Errorf("the agent installs on nginx, Apache and HAProxy sites here, not on %q", site.Kind)
	case site.CertPath == nil:
		return errors.New("this site names no certificate file")
	}
	takeOver := w.Certbot != nil && *w.Certbot == protocol.CertbotTakeOver
	if site.Owner != nil && *site.Owner == protocol.OwnerCertbot && !takeOver {
		return errors.New("certbot renews this site; the agent installs on it only once it is taken over from certbot in the portal")
	}
	if len(known.uses) == 0 {
		return errors.New("this site's configuration is not known; the sites are read again first")
	}
	for _, u := range known.uses {
		if u.CertPath != *site.CertPath || u.KeyPath == "" {
			return errors.New("this site's configuration is not known; the sites are read again first")
		}
	}
	return nil
}

// holdsChain reports whether the chain file f names already holds f's chain: the same certificates, in order.
func (t *tree) holdsChain(f file) bool {
	d, name, err := t.at(f.path)
	if err != nil {
		return false
	}
	data, _, err := d.read(name)
	if err != nil {
		return false
	}
	return slices.EqualFunc(certificatesOf(data), certificatesOf(f.data), bytes.Equal)
}

// sites is what the last inventory read says of a site: the configurations using its file, every path other sites'
// configurations use, the HAProxy configuration files.
type sites struct {
	uses         []inventory.Use
	others       map[string]bool
	haproxyFiles []string
}

func (h *Host) usesOf(siteKey string) sites {
	h.mu.Lock()
	defer h.mu.Unlock()
	others := map[string]bool{}
	for key, list := range h.uses {
		if key == siteKey {
			continue
		}
		for _, u := range list {
			for _, p := range []string{u.CertPath, u.KeyPath, u.ChainPath} {
				if p != "" {
					others[p] = true
				}
			}
		}
	}
	return sites{uses: slices.Clone(h.uses[siteKey]), others: others, haproxyFiles: slices.Clone(h.haproxyFiles)}
}

// serversOf are the web servers among uses, in kindOrder; HAProxy's test is given the configuration files read.
func serversOf(uses []inventory.Use, haproxyFiles []string) []server {
	var out []server
	for _, kind := range kindOrder {
		if !slices.ContainsFunc(uses, func(u inventory.Use) bool { return u.Kind == kind }) {
			continue
		}
		s := server{Kind: kind}
		if kind == protocol.WebServerHAProxy {
			s.HAProxyConfigs = haproxyFiles
		}
		out = append(out, s)
	}
	return out
}

// giveBackSite gives a site taken over from certbot back to it: certbot's links made again, its renewal file moved
// back, the web servers tested and reloaded with certbot's certificate.
func (h *Host) giveBackSite(ctx context.Context, site protocol.Site, w protocol.Work) protocol.InstallResult {
	var o Outcome
	t := h.newTree()
	defer t.close()
	changes, rec, name, err := t.giveBack(site)
	if err != nil {
		o.Fail(protocol.StepCertbotRestored, "nothing was given back: "+err.Error())
		return o.Result(false)
	}
	if rec == nil {
		// Given back already, and its record gone (a result that was not accepted, or a give-back finished at a restart).
		o.OK(protocol.StepCertbotRestored, "already given back to certbot: certbot renews "+name)
		return o.Result(true)
	}
	known := h.usesOf(site.SiteKey)
	if len(known.uses) == 0 {
		o.Fail(protocol.StepCertbotRestored, "nothing was given back: this site's configuration is not known; the sites are read again first")
		return o.Result(false)
	}
	op := &operation{
		pending: pending{AssignmentID: w.AssignmentID, SHA256: w.SHA256, GiveBack: true, SiteKey: site.SiteKey, Certbot: rec,
			Servers: serversOf(known.uses, known.haproxyFiles)},
		changes: changes,
		uses:    known.uses,
		tree:    t,
	}
	if len(changes) == 0 {
		// Given back already (a result that was not sent, say): only the record is left.
		h.removeRecord(rec.Name)
		o.OK(protocol.StepCertbotRestored, "certbot renews "+rec.Name+" again")
		return o.Result(true)
	}
	if !h.run(ctx, op, &o) {
		if last := o.steps[len(o.steps)-1]; last.Name != protocol.StepCertbotRestored {
			o.Fail(protocol.StepCertbotRestored, "the files are as Autopilot had them; certbot does not renew "+rec.Name)
		}
		return o.Result(false)
	}
	return o.Result(true)
}

// run puts op's changes in place, then tests and reloads every web server using them; a failure puts the previous
// files back (and reloads again after a reload). It says whether the changes stand.
func (h *Host) run(ctx context.Context, op *operation, o *Outcome) bool {
	return h.write(ctx, op, o) && h.testAndReload(ctx, op, o, false)
}

// write puts op's changes in place: the files there now kept as a new set, pending.json written, each change staged
// beside its path and renamed into place. A failure before the first rename leaves nothing behind; one during the
// renames puts the previous files back. It says whether the changes are in place; pending.json then stays until the
// install is finished.
func (h *Host) write(ctx context.Context, op *operation, o *Outcome) bool {
	writeStep := protocol.StepWritten
	if op.GiveBack {
		writeStep = protocol.StepCertbotRestored
	}
	if p, err := h.readPending(); p != nil || err != nil {
		o.Fail(writeStep, "nothing was written: an earlier install was interrupted and is not finished; the agent finishes or undoes it when it starts again")
		return false
	}
	if err := h.unstick(op.tree, op.SiteKey); err != nil {
		o.Fail(writeStep, "nothing was written: "+err.Error())
		return false
	}
	dir, kept, err := op.tree.saveSet(op.SiteKey, op.paths(), h.clock())
	if err != nil {
		o.Fail(writeStep, "nothing was written: the files in place could not be kept: "+err.Error())
		return false
	}
	if err := op.unchanged(kept); err != nil {
		os.RemoveAll(dir)
		o.Fail(writeStep, "nothing was written: "+err.Error())
		return false
	}
	op.setDir, op.Set, op.Intended, op.StartedAt = dir, filepath.Base(dir), intendedOf(op.changes, kept), h.clock().UTC()
	abandon := func(why string, err error) bool {
		h.removePending()
		os.RemoveAll(dir)
		if op.NewRecord {
			h.removeRecord(op.Certbot.Name)
		}
		o.Fail(writeStep, "nothing was written: "+why+err.Error())
		return false
	}
	if err := h.writePending(op.pending); err != nil {
		return abandon("pending.json could not be written: ", err)
	}
	if op.Certbot != nil && !op.GiveBack {
		if err := h.writeRecord(op.Certbot); err != nil {
			return abandon("the take-over from certbot could not be recorded: ", err)
		}
	}
	st, err := op.tree.stage(op.changes)
	if err != nil {
		return abandon("", err)
	}
	if err := op.tree.commit(st); err != nil {
		o.Fail(writeStep, err.Error())
		h.undo(ctx, op, o, false)
		return false
	}
	h.pruneSets(op.SiteKey)
	if !op.GiveBack {
		o.OK(protocol.StepWritten, "")
		if op.CertbotMoved {
			o.OK(protocol.StepCertbotDisabled, "certbot no longer renews "+op.Certbot.Name)
		}
	}
	return true
}

// testAndReload tests every web server of op (all must pass), then reloads each; a failure undoes op. On success the
// operation is finished: a give-back's record removed, pending.json removed. reloadOnFailure: a failing test is also
// followed by a reload (when it is not known what the web servers loaded).
func (h *Host) testAndReload(ctx context.Context, op *operation, o *Outcome, reloadOnFailure bool) bool {
	if err := h.testAll(ctx, op.Servers); err != nil {
		o.Fail(protocol.StepTested, err.Error())
		h.undo(ctx, op, o, reloadOnFailure)
		return false
	}
	o.OK(protocol.StepTested, "")
	if err := h.reloadAll(ctx, op.Servers); err != nil {
		o.Fail(protocol.StepReloaded, err.Error())
		h.undo(ctx, op, o, true)
		return false
	}
	o.OK(protocol.StepReloaded, "")
	if op.GiveBack {
		h.removeRecord(op.Certbot.Name)
		o.OK(protocol.StepCertbotRestored, "certbot renews "+op.Certbot.Name+" again")
	}
	h.removePending()
	return true
}

// undo puts the previous files back (certbot as it was with them), reloads the web servers when asked, and removes
// pending.json once the files are back. When they cannot be put back, the site is held up (hold): its next install
// tries again, the other sites go on.
func (h *Host) undo(ctx context.Context, op *operation, o *Outcome, reload bool) {
	if err := op.tree.restoreSet(op.setDir); err != nil {
		h.log().Error("the previous files could not all be put back", "site", op.SiteKey, "set", op.setDir, "error", err)
		detail := "the previous files could not all be put back: " + err.Error()
		if h.hold(op.pending, err) {
			detail += "; the next install on this site tries again"
		}
		o.Fail(protocol.StepRestored, detail)
	} else {
		o.OK(protocol.StepRestored, "the previous files are back")
		if op.CertbotMoved {
			o.OK(protocol.StepCertbotRestored, "certbot renews "+op.Certbot.Name+" again")
		}
		if op.NewRecord {
			h.removeRecord(op.Certbot.Name)
		}
		defer h.removePending()
	}
	if reload {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), undoTimeout)
		defer cancel()
		if err := h.reloadAll(ctx, op.Servers); err != nil {
			o.Fail(protocol.StepReloaded, "with the previous files: "+err.Error())
		} else {
			o.OK(protocol.StepReloaded, "with the previous files")
		}
	}
}

// testAll tests the configuration of every web server; the first failure is the error.
func (h *Host) testAll(ctx context.Context, servers []server) error {
	if h.Runner == nil {
		return errors.New("the agent has no way to run the web servers' tests")
	}
	for _, s := range servers {
		if err := inventory.ConfigTest(ctx, h.Runner, s.Kind, s.HAProxyConfigs); err != nil {
			return err
		}
	}
	return nil
}

// reloadAll reloads every web server, each even when one before it failed; the errors are joined.
func (h *Host) reloadAll(ctx context.Context, servers []server) error {
	if h.Runner == nil {
		return errors.New("the agent has no way to reload the web servers")
	}
	var errs []error
	for _, s := range servers {
		if err := inventory.Reload(ctx, h.Runner, s.Kind); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// Recovered is an install the agent was stopped in, finished or undone when it started again.
type Recovered struct {
	AssignmentID string
	Result       protocol.InstallResult
	// Installed: the certificate the result names is on disk now (a folder certificate's: and what uses it reloaded).
	Installed bool
	// ReloadOwed: a folder certificate's new files are in place but reloading what uses them failed; the next work for
	// it reloads again.
	ReloadOwed bool
	// folder is the folder of a folder certificate found in place: its reload is Folder.RecoverPending's.
	folder *folderPending
}

// RecoverPending finishes or undoes an install the agent was stopped in (pending.json left): every file in place and
// the configuration tests passing → reloaded, finished; otherwise the previous files are put back and the web servers
// reloaded. A folder certificate has no web server: in place is finished, otherwise its previous files are put back.
// nil when there was none. A pending.json that cannot be used is set aside, and the error says where.
func (h *Host) RecoverPending(ctx context.Context) (*Recovered, error) {
	p, err := h.readPending()
	if err != nil {
		return nil, fmt.Errorf("%w; set aside as %s", err, h.setAside(h.clock()))
	}
	if p == nil {
		return nil, nil
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), opTimeout)
	defer cancel()
	t := h.newTree()
	defer t.close()
	op := &operation{pending: *p, setDir: filepath.Join(h.setsDir(p.SiteKey), p.Set), tree: t}
	if _, err := readSet(op.setDir); err != nil {
		return nil, fmt.Errorf("the previous files of the interrupted install cannot be read (%w); pending.json set aside as %s", err, h.setAside(h.clock()))
	}
	t.removeTemps(p.Intended)
	var o Outcome
	rec := &Recovered{AssignmentID: p.AssignmentID}
	if !t.inPlace(p.Intended) {
		step := protocol.StepWritten
		if p.GiveBack {
			step = protocol.StepCertbotRestored
		}
		o.Fail(step, "the agent was stopped before every file was in place")
		h.undo(ctx, op, &o, p.Folder == nil)
	} else {
		if !p.GiveBack {
			o.OK(protocol.StepWritten, "the agent was stopped during this install; its files were in place when it started again")
			if p.CertbotMoved {
				o.OK(protocol.StepCertbotDisabled, "certbot no longer renews "+p.Certbot.Name)
			}
		}
		if p.Folder != nil {
			// Reloading what uses the files is Folder.RecoverPending's: owed until it succeeds, so a stop while it runs
			// is reloaded with the next work.
			h.oweReload(p.Folder.Name, p.SHA256)
			h.removePending()
			rec.folder = p.Folder
		} else {
			rec.Installed = h.testAndReload(ctx, op, &o, true) && !p.GiveBack
		}
	}
	rec.Result = o.Result(o.message == nil)
	rec.Result.SHA256 = p.SHA256
	return rec, nil
}

// Outcome gathers an install's steps as they happen; the first failure is its message. Details and the message are
// clipped to the server's limits. Every installer uses it (a Kubernetes secret's too).
type Outcome struct {
	steps   []protocol.Step
	message *string
}

// Step records a step and how it went; detail "" is none.
func (o *Outcome) Step(name protocol.StepName, ok bool, detail string) {
	s := protocol.Step{Name: name, OK: ok}
	if detail != "" {
		d := protocol.Clip(detail, maxDetail)
		s.Detail = &d
	}
	o.steps = append(o.steps, s)
}

// OK records a step that went well.
func (o *Outcome) OK(name protocol.StepName, detail string) { o.Step(name, true, detail) }

// Fail records a step that failed; the first failure's detail is the message.
func (o *Outcome) Fail(name protocol.StepName, detail string) {
	o.Step(name, false, detail)
	if o.message == nil {
		m := protocol.Clip(detail, maxMessage)
		o.message = &m
	}
}

// Result is the install's result: ok, the steps and the message.
func (o *Outcome) Result(ok bool) protocol.InstallResult {
	return protocol.InstallResult{OK: ok, Steps: o.steps, Message: o.message}
}
