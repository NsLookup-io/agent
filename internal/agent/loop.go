package agent

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"math/rand/v2"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/nslookup-io/agent/internal/client"
	"github.com/nslookup-io/agent/internal/protocol"
	"github.com/nslookup-io/agent/internal/version"
)

const (
	// inventoryEvery: the inventory is read again at most this often, unless the server asks for it.
	inventoryEvery = 5 * time.Minute
	defaultPoll    = 60 * time.Second
	minPoll        = 30 * time.Second
	maxPoll        = time.Hour
	// pollJitter spreads heartbeats: each waits the server's poll ± this.
	pollJitter   = 10 * time.Second
	firstBackoff = 15 * time.Second
	maxBackoff   = 5 * time.Minute
	// maxSites is the most sites the server takes in one inventory.
	maxSites = 500
	// unreadInventory is the hash sent until an inventory was read: no real hash equals it, so the server keeps asking.
	unreadInventory = "unread"
	// removedEvery: a removed agent says so again this often while it waits to be uninstalled.
	removedEvery = 24 * time.Hour
	// maxDetail is the server's limit for a step's detail and a result's message.
	maxDetail = 1000
	// maxHeartbeatBody: the server takes a heartbeat of at most 4 MiB; the agent keeps its own within 3.5 MiB.
	maxHeartbeatBody = 3<<20 + 1<<19
	// maxInstalled is the most entries the server takes in a heartbeat's installed list.
	maxInstalled = 1000
	// assignedFor: a site the server's work named is kept in a cut inventory for this long after the work last named
	// it (a paused assignment's site is named by no work, and must not look gone).
	assignedFor = 30 * 24 * time.Hour
	// maxRefused: a result the server keeps refusing for its own sake is dropped after this long.
	maxRefused = 24 * time.Hour
	// maxSentAtRoundStart: the start of a round sends at most this many queued results, and of them at most
	// maxRetriedPerRound the server refused before (it takes 30 results a minute in all; the round's own results come on
	// top). The rest wait for the next round.
	maxSentAtRoundStart = 20
	maxRetriedPerRound  = 10
	// maxRound: one round of work starts no item after this long; the rest waits for the next heartbeat, so the agent
	// keeps heartbeating through a long list of installs (each runs up to 2 minutes, then up to 1 to undo).
	maxRound = 2 * time.Minute
)

var (
	sha256Hex   = regexp.MustCompile(`^[0-9a-f]{64}$`)
	siteKeyText = regexp.MustCompile(`^[0-9a-f]{32}$`)
)

// Client is what the loop needs of client.Client.
type Client interface {
	Heartbeat(ctx context.Context, beat protocol.HeartbeatRequest) (*protocol.HeartbeatResponse, error)
	Bundle(ctx context.Context, assignmentID string) (*protocol.Bundle, error)
	Result(ctx context.Context, assignmentID string, result protocol.InstallResult) error
}

// Installer installs on a site of the inventory: a web server's certificate files, a Kubernetes TLS secret.
type Installer interface {
	// Apply installs b on site as w asks and says how it went; for a release (w.Action) it gives the site back, and b
	// carries no certificate.
	Apply(ctx context.Context, site protocol.Site, b protocol.Bundle, w protocol.Work) protocol.InstallResult
	// DiskSHA is the SHA-256 (lowercase hex) of the leaf certificate the site holds now: "" when it holds none, an
	// error when that cannot be told.
	DiskSHA(site protocol.Site) (string, error)
}

// FolderInstaller writes folder certificates: work with a folderName, which belongs to no site of the inventory.
type FolderInstaller interface {
	// Apply writes b into w's folder and says how it went.
	Apply(ctx context.Context, w protocol.Work, b protocol.Bundle) protocol.InstallResult
	// DiskSHA is the SHA-256 of the leaf certificate w's folder holds now: "" when none, an error when that cannot be
	// told.
	DiskSHA(w protocol.Work) (string, error)
	// FolderOf is the folder w's certificate is written to.
	FolderOf(w protocol.Work) string
	// ReloadOwed reports whether what uses w's folder was not reloaded since its files were last written (the reload
	// failed, or the agent was stopped while it ran): Apply then finds the files in place and only reloads.
	ReloadOwed(w protocol.Work) bool
}

// Checker is an Installer that can tell, before the bundle is fetched, that it cannot install on a site as w asks: the
// server then does not unseal a key for nothing, and the reason (the error's text, a step's detail) is reported once.
type Checker interface {
	CanInstall(site protocol.Site, w protocol.Work) error
}

// FolderChecker is a FolderInstaller that can tell, before the bundle is fetched, that it cannot write w here.
type FolderChecker interface {
	CanInstall(w protocol.Work) error
}

// Recorder is an Installer that keeps its own record of what the agent installed on a site (a Kubernetes secret's
// annotation): with no record in the Ledger (a Kubernetes pod replaced, its state gone with it), that record says
// whether the certificate there now is the agent's or was changed by someone else.
type Recorder interface {
	// Recorded is the SHA-256 the agent last installed on site by its own record; "" when there is none.
	Recorded(site protocol.Site) string
}

// AssignedSetter is an Installer told, before each round of work, the sites the server assigns certificates to now
// (the sites of its install work): a certbot name one of them still uses is not given back for another.
type AssignedSetter interface {
	SetAssigned(siteKeys []string)
}

// Clock is the time the loop runs on.
type Clock interface {
	Now() time.Time
	// Sleep waits d, or returns ctx's error when ctx ends first.
	Sleep(ctx context.Context, d time.Duration) error
}

// SystemClock is the machine's clock.
type SystemClock struct{}

func (SystemClock) Now() time.Time { return time.Now() }

func (SystemClock) Sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// Loop is the agent at work: a heartbeat every pollSeconds ± 10 s, the inventory with it when it changed, and the
// work of each answer.
//
// For each install the loop compares the certificate on disk with the one the work names: the same → one "already
// installed" result the first time (the server marks installs only from results), then nothing; one the agent did not
// install last (a file changed by hand or by another tool) → a drift result once, nothing installed; otherwise the
// bundle is fetched, checked to be the named certificate, installed once per SHA-256, and the result reported (again
// on the next heartbeat while it cannot be sent). A folder certificate whose reload is owed counts as not installed
// (applied again, it only reloads); a folder the agent may not use is reported once per reason, so the customer hears
// what to fix (a site's certificate that cannot be read only waits). Work whose id is not an assignment id is skipped.
//
// The agent never adjusts its clock or deletes anything on the server's word: a removed agent (a 403 agent_removed the
// server signed; an unsigned one is a refusal like the others) stops all work and waits to be uninstalled (an exited
// process would be restarted in a loop by Docker or Kubernetes), logging how to remove it then and once a day, leaving
// its identity and every file as they are.
type Loop struct {
	Client Client
	// Inventory reads the sites on this machine.
	Inventory func(ctx context.Context) (protocol.Inventory, error)
	// Facts describes this machine; read with the inventory. nil: OS, architecture and version only.
	Facts func(ctx context.Context) protocol.AgentFacts
	// Installer installs on sites; nil: site work is reported as not possible here.
	Installer Installer
	// Folder writes folder certificates; nil: folder work is reported as not possible here.
	Folder FolderInstaller
	// Clock: nil = SystemClock.
	Clock Clock
	// Ledger keeps what was installed, and the results not yet sent, across restarts; nil = in memory only.
	Ledger Ledger
	// Log: nil = slog.Default(). Nothing secret is ever logged: ids, counts and SHA-256s only.
	Log *slog.Logger
	// RemoveHint says how to remove the agent from this machine; logged when the server removed it.
	RemoveHint string
	// Owned, when set, names the sites this machine itself says the agent installed on (Kubernetes secrets carrying the
	// agent's annotation): a cut list keeps them as it keeps the sites the server's work names.
	Owned func() []string

	inv      *protocol.Inventory
	invHash  string
	sentHash string
	// raw is the last inventory read, whole and sorted, before it is cut to what the server takes.
	raw *protocol.Inventory
	// noted: an answer of this run named the server's work (so the assigned sites are known); holding: the last read
	// must be cut, and is not sent before an answer named the work (finish).
	noted, holding bool
	// refusedHash is the hash of the last inventory the server refused (client.InventoryRefused): not sent again until
	// it changes.
	refusedHash string
	facts       protocol.AgentFacts
	readAt      time.Time
	readOK      bool
	// installedSince: an install succeeded since the last read, so the sites may serve something else now and the next
	// heartbeat reads them again, whatever inventoryEvery says.
	installedSince bool
	// want: the last answer asked for the inventory.
	want bool
	// work: the last answer's work.
	work []protocol.Work
	// folders: per folder, the assignment of the last answer's work written to it (the first naming it).
	folders map[string]string
	// onDisk: per assignment, the SHA-256 on disk when its work was last looked at (nil: none there).
	onDisk map[string]*string
	// attempted: per assignment, what was done for it in this run (an install's SHA-256, a drift or a release), so
	// nothing is done twice.
	attempted map[string]string
	// installed, pending and assigned (the sites the server's work named, and when it last did) are the Memory the
	// Ledger keeps; assignedSaved is when assigned was last saved.
	installed     map[string]string
	pending       []PendingResult
	assigned      map[string]time.Time
	assignedSaved time.Time
}

var errRemoved = errors.New("removed")

// Run heartbeats until ctx ends, and returns nil then; once the server removed the agent it only waits for ctx to end.
// It returns an error only when the loop is not set up.
func (l *Loop) Run(ctx context.Context) error {
	if l.Client == nil || l.Inventory == nil {
		return errors.New("the run loop needs a client and an inventory reader")
	}
	if l.Clock == nil {
		l.Clock = SystemClock{}
	}
	if l.Log == nil {
		l.Log = slog.Default()
	}
	l.invHash = unreadInventory
	l.onDisk, l.attempted, l.installed, l.assigned = map[string]*string{}, map[string]string{}, map[string]string{}, map[string]time.Time{}
	if l.Ledger != nil {
		m, err := l.Ledger.Load()
		switch {
		case err != nil:
			l.Log.Warn("what this agent installed before cannot be read; changes made by hand before now are not noticed", "error", err)
		case m.Installed != nil:
			l.installed, l.pending = m.Installed, m.Pending
		default:
			l.pending = m.Pending
		}
		for key, at := range m.Sites {
			if siteKeyText.MatchString(key) {
				l.assigned[key] = at
			}
		}
		l.assignedSaved = l.Clock.Now()
	}

	var backoff time.Duration
	followUp := false
	for {
		resp, sentInventory, err := l.heartbeat(ctx)
		if ctx.Err() != nil {
			return nil
		}
		if err != nil && sentInventory && client.InventoryRefused(err) {
			// The server refuses this list of sites: it is not sent again until it changes, and the heartbeat goes again at
			// once with its hash only, so the agent stays online and does its work.
			l.refusedHash = l.invHash
			l.Log.Error("the server refused the list of sites on this machine; it is not sent again until it changes", "sites", len(l.inv.Sites), "error", err)
			continue
		}
		var wait time.Duration
		switch {
		case client.RetryOf(err) == client.Removed:
			return l.idle(ctx)
		case err != nil:
			backoff = min(max(2*backoff, firstBackoff), maxBackoff)
			l.failed("the heartbeat", err, "retry", backoff)
			wait, followUp = backoff, false
		default:
			backoff = 0
			if errors.Is(l.doWork(ctx, resp.Work), errRemoved) {
				return l.idle(ctx)
			}
			if ctx.Err() != nil {
				return nil
			}
			// The work is named now (an answer below the minimum version names none: the server sends no work there): a
			// list held for its cut is cut keeping the assigned sites, and sent at once.
			l.noted = l.noted || !belowMinimum(version.Version, resp.MinVersion)
			if l.holding {
				if err := l.finish(); err != nil {
					l.Log.Warn("the list of sites could not be made", "error", err)
				}
				if !l.holding && !followUp {
					followUp, l.want = true, false
					continue
				}
			}
			// Asked for the inventory ("Check now"): read it and send it at once, one extra heartbeat at most.
			if resp.WantInventory && !sentInventory && !followUp && ((l.inv != nil && l.invHash != l.refusedHash) || l.readDue()) {
				followUp = true
				continue
			}
			wait, followUp = pollWait(resp.PollSeconds), false
		}
		if l.Clock.Sleep(ctx, wait) != nil {
			return nil
		}
	}
}

// heartbeat reads the inventory when due (or asked for), sends the heartbeat and says whether it carried the inventory
// (also when it failed). An inventory the server refused is neither read again when asked for nor sent until it
// changes.
func (l *Loop) heartbeat(ctx context.Context) (*protocol.HeartbeatResponse, bool, error) {
	if l.readDue() || (l.want && l.readOK && l.invHash != l.refusedHash) {
		l.readInventory(ctx)
	}
	beat := protocol.HeartbeatRequest{Version: version.Version, Facts: l.facts, InventoryHash: l.invHash, Installed: l.installedStates()}
	send := l.inv != nil && l.invHash != l.refusedHash && (l.invHash != l.sentHash || l.want)
	if send {
		beat.Inventory = l.inv
	}
	resp, err := l.Client.Heartbeat(ctx, beat)
	if err != nil {
		return nil, send, err
	}
	if send {
		l.sentHash = l.invHash
	}
	l.want = resp.WantInventory
	return resp, send, nil
}

func (l *Loop) readDue() bool {
	return l.readAt.IsZero() || l.installedSince || l.Clock.Now().Sub(l.readAt) >= inventoryEvery
}

// readInventory reads the facts and the sites. A failed read keeps the last inventory read (none: nothing is sent,
// never an empty list in its place, which would end every assignment).
func (l *Loop) readInventory(ctx context.Context) {
	l.readAt, l.installedSince = l.Clock.Now(), false
	if l.Facts != nil {
		l.facts = l.Facts(ctx)
	} else {
		l.facts = protocol.AgentFacts{OS: runtime.GOOS, Arch: runtime.GOARCH, AgentVersion: version.Version}
	}
	inv, err := l.Inventory(ctx)
	if err == nil {
		inv.Sites = slices.SortedStableFunc(slices.Values(inv.Sites), func(a, b protocol.Site) int { return cmp.Compare(a.SiteKey, b.SiteKey) })
		l.raw = &inv
		if err = l.finish(); err == nil {
			l.readOK = true
			return
		}
	}
	l.readOK = false
	l.Log.Warn("reading the sites on this machine failed; the last list read is kept", "error", err)
}

// finish makes the last read (raw) the inventory sent: cut to what the server takes (maxSites, maxHeartbeatBody),
// never leaving out a site it assigns certificates to. A list that loses sites before any answer of this run named the
// work is held (holding): the agent cannot tell yet which sites are assigned, and the server would pause the assignment
// of every one left out. The heartbeat then carries the hash only (the server pauses nothing then), and finish runs
// again once an answer named the work.
func (l *Loop) finish() error {
	if l.raw == nil {
		return nil
	}
	keep := l.keptSites()
	inv := protocol.Inventory{Sites: slices.Clone(l.raw.Sites)}
	tooMany := len(inv.Sites) > maxSites
	if tooMany {
		inv.Sites = keepAssigned(inv.Sites, maxSites, keep)
	}
	cut, err := l.fit(&inv, keep)
	if err != nil {
		return err
	}
	if l.holding = (tooMany || cut.sites > 0) && !l.noted; l.holding {
		l.Log.Info("the list of sites must be cut; it is sent once the server has named its work, so no assigned site is left out",
			"sites", len(l.raw.Sites))
		return nil
	}
	body, err := protocol.MarshalBody(inv)
	if err != nil {
		return err
	}
	hash := protocol.SHA256Hex(body)
	if hash != l.invHash {
		l.Log.Info("read the sites on this machine", "sites", len(inv.Sites))
		if tooMany {
			l.Log.Warn("this machine has more sites than the server takes; the rest are left out, never one the server assigns certificates to",
				"sites", len(l.raw.Sites), "sent", maxSites)
		}
		if cut.names > 0 || cut.sites > 0 {
			l.Log.Warn("the list of sites is too large for one heartbeat; parts of it are left out",
				"sitesWithoutCertificateNames", cut.names, "sitesLeftOut", cut.sites, "firstLeftOut", cut.first)
		}
	}
	l.inv, l.invHash = &inv, hash
	return nil
}

// keptSites are the sites a cut list keeps: those the server's work named (assigned), and those this machine says the
// agent installed on (Owned).
func (l *Loop) keptSites() map[string]bool {
	keep := map[string]bool{}
	for key := range l.assigned {
		keep[key] = true
	}
	if l.Owned != nil {
		for _, key := range l.Owned() {
			keep[key] = true
		}
	}
	return keep
}

// keepAssigned is the first max of sites (sorted by key), the sites keep names taken first whatever their place, still
// sorted by key.
func keepAssigned(sites []protocol.Site, max int, keep map[string]bool) []protocol.Site {
	var kept, others []protocol.Site
	for _, s := range sites {
		if keep[s.SiteKey] && len(kept) < max {
			kept = append(kept, s)
		} else {
			others = append(others, s)
		}
	}
	kept = append(kept, others[:min(len(others), max-len(kept))]...)
	slices.SortFunc(kept, func(a, b protocol.Site) int { return cmp.Compare(a.SiteKey, b.SiteKey) })
	return kept
}

// noteAssigned remembers the sites items name (work for a site, not for a folder) as assigned now, and forgets those
// no work named for assignedFor (only when there is work: an empty list can mean below the minimum version). It saves
// what it remembers when that changed, or a day after it was last saved.
func (l *Loop) noteAssigned(items []protocol.Work) {
	now, changed := l.Clock.Now(), false
	for _, w := range items {
		if w.FolderName != nil || !siteKeyText.MatchString(w.SiteKey) {
			continue
		}
		if _, known := l.assigned[w.SiteKey]; !known {
			changed = true
		}
		l.assigned[w.SiteKey] = now
	}
	if len(items) > 0 {
		for key, at := range l.assigned {
			if now.Sub(at) > assignedFor {
				delete(l.assigned, key)
				changed = true
			}
		}
	}
	if changed || now.Sub(l.assignedSaved) >= 24*time.Hour {
		l.assignedSaved = now
		l.saveLedger()
	}
}

// fitted is what fit left out: the certificate names of names sites, and sites sites at the end (first names the
// first of them).
type fitted struct {
	names, sites int
	first        string
}

// fit keeps a heartbeat carrying inv within maxHeartbeatBody, whatever the rest of the heartbeat (the facts, the
// largest installed list the server takes): it leaves out the names of the certificates the sites serve, from the last
// site back, then the last sites, until it fits; the sites the server assigns certificates to go last (their
// certificate names only), never the sites themselves, which the server would pause as gone.
func (l *Loop) fit(inv *protocol.Inventory, keep map[string]bool) (fitted, error) {
	var cut fitted
	overhead, err := l.beatOverhead()
	if err != nil {
		return cut, err
	}
	sizes := make([]int, len(inv.Sites))
	// {"sites":[...]}, with a comma between sites.
	total := len(`{"sites":[]}`) + max(len(inv.Sites)-1, 0)
	for i, s := range inv.Sites {
		body, err := protocol.MarshalBody(s)
		if err != nil {
			return cut, err
		}
		sizes[i] = len(body)
		total += sizes[i]
	}
	budget := maxHeartbeatBody - overhead
	assigned := func(s protocol.Site) bool { return keep[s.SiteKey] }
	// The certificate names of the sites, from the last back: first of those the server assigns nothing to.
	dropNames := func(ofAssigned bool) error {
		for i := len(inv.Sites) - 1; i >= 0 && total > budget; i-- {
			s := &inv.Sites[i]
			if assigned(*s) != ofAssigned || s.Served == nil || len(s.Served.Names) == 0 {
				continue
			}
			served := *s.Served
			served.Names = nil
			s.Served = &served
			body, err := protocol.MarshalBody(*s)
			if err != nil {
				return err
			}
			total -= sizes[i] - len(body)
			sizes[i] = len(body)
			cut.names++
		}
		return nil
	}
	if err := dropNames(false); err != nil {
		return cut, err
	}
	// Then those sites themselves, from the last back; a site the server assigns certificates to is never left out.
	for i := len(inv.Sites) - 1; i >= 0 && total > budget; i-- {
		if assigned(inv.Sites[i]) {
			continue
		}
		total -= sizes[i] + min(len(inv.Sites)-1, 1)
		cut.sites++
		cut.first = siteLabel(inv.Sites[i])
		inv.Sites = slices.Delete(inv.Sites, i, i+1)
		sizes = slices.Delete(sizes, i, i+1)
	}
	if err := dropNames(true); err != nil {
		return cut, err
	}
	return cut, nil
}

// beatOverhead is the size of a heartbeat with an empty inventory and the largest installed list the server takes.
func (l *Loop) beatOverhead() (int, error) {
	largest := make([]protocol.InstalledState, maxInstalled)
	sha := strings.Repeat("0", 64)
	for i := range largest {
		largest[i] = protocol.InstalledState{AssignmentID: "00000000-0000-0000-0000-000000000000", SHA256OnDisk: &sha}
	}
	body, err := protocol.MarshalBody(protocol.HeartbeatRequest{
		Version: version.Version, Facts: l.facts, InventoryHash: sha, Inventory: &protocol.Inventory{}, Installed: largest,
	})
	return len(body) - len(`{"sites":[]}`), err
}

// siteLabel names a site in the log: its configuration file or its secret.
func siteLabel(s protocol.Site) string {
	switch {
	case s.ConfigPath != nil:
		return *s.ConfigPath
	case s.Secret != nil:
		return s.Secret.Namespace + "/" + s.Secret.Name
	}
	return s.SiteKey
}

func (l *Loop) installedStates() []protocol.InstalledState {
	var states []protocol.InstalledState
	for _, w := range l.work {
		if sha, ok := l.onDisk[w.AssignmentID]; ok && w.Action == protocol.ActionInstall {
			states = append(states, protocol.InstalledState{AssignmentID: w.AssignmentID, SHA256OnDisk: sha})
		}
	}
	return states
}

// doWork sends results still pending (at most maxSentAtRoundStart, see flush), then does each work item, starting
// none after maxRound (the rest waits for the next heartbeat). Only a failure that halts (client.Halt: the network, a
// timeout, the clock, a 401, a rate limit) ends this round (the next heartbeat tries again); any other ends only its
// own work item; errRemoved ends the loop.
func (l *Loop) doWork(ctx context.Context, items []protocol.Work) error {
	l.work = items
	l.folders = l.folderOwners(items)
	l.noteAssigned(items)
	if a, ok := l.Installer.(AssignedSetter); ok {
		var keys []string
		for _, w := range items {
			if w.Action == protocol.ActionInstall && w.FolderName == nil && !slices.Contains(keys, w.SiteKey) {
				keys = append(keys, w.SiteKey)
			}
		}
		a.SetAssigned(keys)
	}
	err := l.flush(ctx)
	start, waiting := l.Clock.Now(), 0
	sites := map[string]protocol.Site{}
	if l.inv != nil {
		for _, s := range l.inv.Sites {
			sites[s.SiteKey] = s
		}
	}
	live := map[string]bool{}
	for _, w := range items {
		live[w.AssignmentID] = true
		if err != nil {
			continue
		}
		if l.Clock.Now().Sub(start) >= maxRound {
			waiting++
			continue
		}
		switch e := l.do(ctx, w, sites); client.RetryOf(e) {
		case client.Done:
		case client.Halt, client.Removed:
			err = e
		default:
			// This assignment only (gone meanwhile, a server error on its bundle); the next heartbeat tries it again.
			l.failed("installing", e, "assignment", w.AssignmentID)
		}
	}
	if waiting > 0 {
		l.Log.Info("work items wait for the next heartbeat: one round of work runs at most 2 minutes", "waiting", waiting)
	}
	switch {
	case client.RetryOf(err) == client.Removed:
		return errRemoved
	case err != nil && ctx.Err() == nil:
		l.failed("installing", err)
	}
	for id := range l.onDisk {
		if !live[id] {
			delete(l.onDisk, id)
		}
	}
	for id := range l.attempted {
		if !live[id] {
			delete(l.attempted, id)
		}
	}
	// An assignment the server no longer sends has ended for good (a new take-over is a new assignment). An empty list
	// can also mean "below the minimum version", so it forgets nothing.
	if len(items) > 0 {
		before := len(l.installed)
		maps.DeleteFunc(l.installed, func(id, _ string) bool { return !live[id] })
		if len(l.installed) != before {
			l.saveLedger()
		}
	}
	return nil
}

// do does one work item; only an error that halts (client.Halt) or the removal ends this round of work (see doWork).
func (l *Loop) do(ctx context.Context, w protocol.Work, sites map[string]protocol.Site) error {
	if !protocol.IsAssignmentID(w.AssignmentID) {
		// Never sent back to the server nor remembered: the client refuses such an id in a path.
		if l.attempted[w.AssignmentID] == "" {
			l.attempted[w.AssignmentID] = "skipped"
			l.Log.Warn("work skipped: not an assignment id", "assignment", w.AssignmentID)
		}
		return nil
	}
	if !sha256Hex.MatchString(w.SHA256) {
		l.Log.Warn("work names no SHA-256; skipped", "assignment", w.AssignmentID)
		return nil
	}
	switch w.Action {
	case protocol.ActionInstall:
		return l.install(ctx, w, sites)
	case protocol.ActionRelease:
		return l.release(ctx, w, sites)
	}
	l.Log.Warn("work asks for something this agent does not know; skipped", "assignment", w.AssignmentID, "action", string(w.Action))
	return nil
}

// folderOwners is, per folder, the first install of items written to it. The server gives each folder certificate a
// folder of its own; should two come to one folder all the same, the second is refused, never written over the first.
func (l *Loop) folderOwners(items []protocol.Work) map[string]string {
	owners := map[string]string{}
	if l.Folder == nil {
		return owners
	}
	for _, w := range items {
		if w.FolderName == nil || w.Action != protocol.ActionInstall || !protocol.IsAssignmentID(w.AssignmentID) || !sha256Hex.MatchString(w.SHA256) {
			continue
		}
		if folder := l.Folder.FolderOf(w); owners[folder] == "" {
			owners[folder] = w.AssignmentID
		}
	}
	return owners
}

// target is where an install goes: a site's files or secret, or a folder (reloadOwed set).
type target struct {
	diskSHA    func() (string, error)
	apply      func(ctx context.Context, b protocol.Bundle) protocol.InstallResult
	reloadOwed func() bool
	// check says why the bundle need not be fetched (the install cannot be done); nil: nothing to check first.
	check func() error
	// recorded is the installer's own record of what the agent installed there ("" none); nil: it keeps none.
	recorded func() string
}

// targetOf finds where w installs. ok is false when it cannot: cannot says why when the server should know (no
// installer of that kind here), and is "" when the work waits (its site is not in the inventory: the server ends the
// assignment once it gets an inventory without it).
func (l *Loop) targetOf(w protocol.Work, sites map[string]protocol.Site) (t target, cannot string, ok bool) {
	if w.FolderName != nil {
		if l.Folder == nil {
			return t, "this agent does not write folder certificates", false
		}
		if folder := l.Folder.FolderOf(w); l.folders[folder] != w.AssignmentID {
			return t, "another certificate on this agent is written to the folder " + folder + "; this one was not written", false
		}
		t := target{
			diskSHA:    func() (string, error) { return l.Folder.DiskSHA(w) },
			apply:      func(ctx context.Context, b protocol.Bundle) protocol.InstallResult { return l.Folder.Apply(ctx, w, b) },
			reloadOwed: func() bool { return l.Folder.ReloadOwed(w) },
		}
		if c, ok := l.Folder.(FolderChecker); ok {
			t.check = func() error { return c.CanInstall(w) }
		}
		return t, "", true
	}
	site, found := sites[w.SiteKey]
	if !found {
		return t, "", false
	}
	if l.Installer == nil {
		return t, "this agent cannot install on this site", false
	}
	t = target{
		diskSHA: func() (string, error) { return l.Installer.DiskSHA(site) },
		apply: func(ctx context.Context, b protocol.Bundle) protocol.InstallResult {
			return l.Installer.Apply(ctx, site, b, w)
		},
	}
	if c, ok := l.Installer.(Checker); ok {
		t.check = func() error { return c.CanInstall(site, w) }
	}
	if r, ok := l.Installer.(Recorder); ok {
		t.recorded = func() string { return r.Recorded(site) }
	}
	return t, "", true
}

func (l *Loop) install(ctx context.Context, w protocol.Work, sites map[string]protocol.Site) error {
	id := w.AssignmentID
	t, cannot, ok := l.targetOf(w, sites)
	if !ok {
		if cannot == "" || l.attempted[id] == w.SHA256 {
			return nil
		}
		l.attempted[id] = w.SHA256
		l.Log.Warn("work this agent cannot do", "assignment", id, "why", cannot)
		return l.report(ctx, id, protocol.InstallResult{
			SHA256:  w.SHA256,
			Steps:   []protocol.Step{{Name: protocol.StepChecked, OK: false, Detail: &cannot}},
			Message: &cannot,
		})
	}

	disk, err := t.diskSHA()
	if err != nil {
		delete(l.onDisk, id)
		if t.reloadOwed == nil {
			l.Log.Warn("the certificate an assignment has on this machine cannot be read; nothing done", "assignment", id, "error", err)
			return nil
		}
		// A folder the agent may not write in (another user's, or one others can change): only the customer can fix it
		// on the machine, so the server hears why, once (again when the reason changes).
		why := protocol.Clip(err.Error(), maxDetail)
		if l.attempted[id] == "unusable:"+why {
			return nil
		}
		l.attempted[id] = "unusable:" + why
		l.Log.Warn("the folder of a folder certificate cannot be used; nothing done", "assignment", id, "error", err)
		return l.report(ctx, id, protocol.InstallResult{
			SHA256:  w.SHA256,
			Steps:   []protocol.Step{{Name: protocol.StepChecked, OK: false, Detail: &why}},
			Message: &why,
		})
	}
	if disk == "" {
		l.onDisk[id] = nil
	} else {
		l.onDisk[id] = &disk
	}
	// A folder holding the certificate whose reload did not run is not installed yet: applied again, it only reloads.
	owed := disk == w.SHA256 && t.reloadOwed != nil && t.reloadOwed()
	if disk == w.SHA256 && !owed {
		// Already there (a site taken over that serves it, or put there by someone else): the server marks an install
		// only from a result, so say it once.
		if l.installed[id] == disk {
			return nil
		}
		l.installed[id] = disk
		l.Log.Info("the certificate is already installed", "assignment", id, "sha256", disk)
		already := "already installed"
		return l.report(ctx, id, protocol.InstallResult{
			SHA256: disk,
			OK:     true,
			Steps:  []protocol.Step{{Name: protocol.StepChecked, OK: true, Detail: &already}},
		})
	}
	last, known := l.installed[id]
	if !known && t.recorded != nil && !owed && disk != w.SHA256 {
		if rec := t.recorded(); sha256Hex.MatchString(rec) {
			last, known = rec, true
		}
	}
	if known && disk != last && !owed {
		drift := "drift:" + disk + ":" + w.SHA256
		if l.attempted[id] == drift {
			return nil
		}
		l.attempted[id] = drift
		l.Log.Warn("the certificate file was changed on this machine; nothing installed until it is taken over again in the portal", "assignment", id)
		message := "the certificate file was changed on this machine; nothing was installed"
		return l.report(ctx, id, protocol.InstallResult{SHA256: w.SHA256, Message: &message, Drift: true})
	}
	if l.attempted[id] == w.SHA256 {
		return nil
	}
	if t.check != nil {
		if err := t.check(); err != nil {
			// Reported once per SHA-256, as a failed install is; the bundle is not fetched.
			l.attempted[id] = w.SHA256
			l.Log.Warn("work this agent cannot do on this site; the bundle is not fetched", "assignment", id, "why", err)
			result := failedResult(protocol.StepWritten, protocol.Clip(err.Error(), maxDetail))
			result.SHA256 = w.SHA256
			return l.report(ctx, id, result)
		}
	}

	b, err := l.Client.Bundle(ctx, id)
	if err != nil {
		return err
	}
	defer clear(b.KeyPEM)
	if b.SHA256 != w.SHA256 {
		l.Log.Warn("the bundle is not the certificate the work names; nothing installed, the next heartbeat tries again", "assignment", id)
		return nil
	}
	l.attempted[id] = w.SHA256
	result := t.apply(ctx, *b)
	result.SHA256 = w.SHA256
	if result.OK && !result.Drift {
		l.remember(id, w.SHA256)
		sha := w.SHA256
		l.onDisk[id] = &sha
		l.installedSince = true
		l.Log.Info("installed a certificate", "assignment", id, "sha256", w.SHA256)
	} else {
		l.Log.Warn("installing a certificate failed", "assignment", id, "sha256", w.SHA256)
	}
	return l.report(ctx, id, result)
}

// release gives a site back (certbot's renewal), once.
func (l *Loop) release(ctx context.Context, w protocol.Work, sites map[string]protocol.Site) error {
	id := w.AssignmentID
	done := "release:" + w.SHA256
	if l.attempted[id] == done || w.FolderName != nil || l.inv == nil {
		return nil
	}
	var result protocol.InstallResult
	site, found := sites[w.SiteKey]
	switch {
	case !found:
		result = failedResult(protocol.StepCertbotRestored, "this site is no longer on this machine")
	case l.Installer == nil:
		result = failedResult(protocol.StepCertbotRestored, "this agent cannot give sites back")
	default:
		result = l.Installer.Apply(ctx, site, protocol.Bundle{AssignmentID: id, SHA256: w.SHA256}, w)
	}
	l.attempted[id] = done
	result.SHA256 = w.SHA256
	if _, known := l.installed[id]; known {
		delete(l.installed, id)
		l.saveLedger()
	}
	l.Log.Info("gave a site back", "assignment", id, "ok", result.OK)
	return l.report(ctx, id, result)
}

func failedResult(step protocol.StepName, why string) protocol.InstallResult {
	return protocol.InstallResult{Steps: []protocol.Step{{Name: step, OK: false, Detail: &why}}, Message: &why}
}

// report queues a result (replacing an older one of the same assignment), saves the queue and sends that result
// alone: the other queued results wait for the start of the next round (flush).
func (l *Loop) report(ctx context.Context, id string, result protocol.InstallResult) error {
	l.pending = slices.DeleteFunc(l.pending, func(p PendingResult) bool { return p.AssignmentID == id })
	l.pending = append(l.pending, PendingResult{AssignmentID: id, Result: result})
	l.saveLedger()
	return l.send(ctx, []int{len(l.pending) - 1})
}

// flush starts a round: it drops the results the server has refused for maxRefused, then sends at most
// maxSentAtRoundStart queued results, those never refused first, in their order, then up to maxRetriedPerRound refused
// before (client.Later), in their order: a backlog goes out a part per round, not all at once against the server's
// limit of results a minute. The rest wait for the next round. As a refused result goes to the back of the queue each
// time it is refused again (send), the refused results take turns: with n of them, each is sent again about every
// n/maxRetriedPerRound rounds.
func (l *Loop) flush(ctx context.Context) error {
	now := l.Clock.Now()
	n := len(l.pending)
	l.pending = slices.DeleteFunc(l.pending, func(p PendingResult) bool {
		if p.RefusedSince.IsZero() || now.Sub(p.RefusedSince) < maxRefused {
			return false
		}
		l.Log.Error("the server refused a result for a day; it is dropped", "assignment", p.AssignmentID, "refusedSince", p.RefusedSince)
		return true
	})
	if len(l.pending) != n {
		l.saveLedger()
	}
	var fresh, refused []int
	for i, p := range l.pending {
		switch {
		case p.RefusedSince.IsZero():
			if len(fresh) < maxSentAtRoundStart {
				fresh = append(fresh, i)
			}
		case len(refused) < maxRetriedPerRound:
			refused = append(refused, i)
		}
	}
	return l.send(ctx, append(fresh, refused[:min(len(refused), maxSentAtRoundStart-len(fresh))]...))
}

// send sends the queued results at picked (indexes in l.pending), in that order. A result is dropped when the server
// takes it, refuses it for good (client.Never: its code says so) or the client refuses to send it (its id is not an
// assignment id): sending it again would not change the answer. One refused for its own sake (client.Later: a server
// error, a proxy's answer, a 403 not signed as a removal) never holds up the others: it goes to the back of the queue,
// behind the results that waited longer for a try, and is dropped maxRefused after its first refusal (flush). A
// failure that halts (the network, the clock, a 401, a rate limit) stops the sending and is returned: it ends the round
// of work, and that result and every one not sent stay where they are, for the next round.
func (l *Loop) send(ctx context.Context, picked []int) error {
	moved := map[int]bool{}
	var back []PendingResult
	var err error
sending:
	for _, i := range picked {
		p := l.pending[i]
		e := l.Client.Result(ctx, p.AssignmentID, p.Result)
		switch client.RetryOf(e) {
		case client.Done:
		case client.Never:
			if errors.Is(e, client.ErrNotAnAssignmentID) {
				l.Log.Warn("a result was dropped: not an assignment id", "assignment", p.AssignmentID)
			} else {
				l.Log.Warn("the server refused a result; it is not sent again", "assignment", p.AssignmentID, "error", e)
			}
		case client.Later:
			if p.RefusedSince.IsZero() {
				p.RefusedSince = l.Clock.Now()
			}
			l.failed("sending a result", e, "assignment", p.AssignmentID)
			back = append(back, p)
		default:
			err = e
			break sending
		}
		moved[i] = true
	}
	if len(moved) > 0 {
		kept := make([]PendingResult, 0, len(l.pending))
		for i, p := range l.pending {
			if !moved[i] {
				kept = append(kept, p)
			}
		}
		l.pending = append(kept, back...)
		l.saveLedger()
	}
	return err
}

func (l *Loop) remember(id, sha string) {
	if l.installed[id] != sha {
		l.installed[id] = sha
		l.saveLedger()
	}
}

func (l *Loop) saveLedger() {
	if l.Ledger == nil {
		return
	}
	if err := l.Ledger.Save(Memory{Installed: maps.Clone(l.installed), Pending: slices.Clone(l.pending), Sites: maps.Clone(l.assigned)}); err != nil {
		l.Log.Warn("what this agent installed and has to report cannot be saved; a restart would forget it", "error", err)
	}
}

// idle is a removed agent: no more requests, the removal said now and once a day, until ctx ends (nil).
func (l *Loop) idle(ctx context.Context) error {
	text := "nslookup.io removed this agent; it stops now."
	if l.RemoveHint != "" {
		text += " Remove it with: " + l.RemoveHint
	}
	for {
		l.Log.Warn(text)
		if l.Clock.Sleep(ctx, removedEvery) != nil {
			return nil
		}
	}
}

// failed logs a failed call in plain words; the clock line says by how much this machine's clock is off (the server's
// unsigned word, used only for this line).
func (l *Loop) failed(what string, err error, attrs ...any) {
	var skew *client.ErrClockSkew
	switch {
	case errors.As(err, &skew):
		l.Log.Warn(fmt.Sprintf("your clock is off by %d s; fix the time on this machine", int64(skew.Offset.Abs()/time.Second)), attrs...)
	case errors.Is(err, client.ErrBadServerSignature):
		l.Log.Warn(what+" failed: the answer was not signed by the server this agent joined (is a proxy changing it?)", attrs...)
	default:
		l.Log.Warn(what+" failed", append([]any{"error", err}, attrs...)...)
	}
}

var versionText = regexp.MustCompile(`^(\d{1,9})\.(\d{1,9})\.(\d{1,9})(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$`)

// belowMinimum reports whether version is below the server's minimum (x.y.z) as the server counts it: a pre-release
// is below its own version, anything that is no version is below every minimum; no minimum (or one that is no
// version) is never above.
func belowMinimum(version, minimum string) bool {
	m := versionText.FindStringSubmatch(minimum)
	if m == nil {
		return false
	}
	v := versionText.FindStringSubmatch(version)
	if v == nil {
		return true
	}
	for i := 1; i <= 3; i++ {
		a, _ := strconv.Atoi(v[i])
		b, _ := strconv.Atoi(m[i])
		if a != b {
			return a < b
		}
	}
	return v[4] != "" && m[4] == ""
}

// pollWait is the server's poll (kept between 30 s and 1 h; 60 s when it sends none) ± 10 s.
func pollWait(seconds int) time.Duration {
	poll := defaultPoll
	if seconds > 0 {
		poll = min(max(time.Duration(seconds)*time.Second, minPoll), maxPoll)
	}
	return poll - pollJitter + time.Duration(rand.Int64N(int64(2*pollJitter)+1))
}
