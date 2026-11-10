package agent

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nslookup-io/agent/internal/client"
	"github.com/nslookup-io/agent/internal/protocol"
	"github.com/nslookup-io/agent/internal/version"
)

const (
	siteKey  = "0123456789abcdef0123456789abcdef"
	otherKey = "fedcba9876543210fedcba9876543210"
	assignX  = "9c1d4e7a-2b3f-4a8c-9d6e-0f1a2b3c4d5e"
	assignY  = "e4a7b2c9-6d1f-4e3a-8b5c-7f9d0e1a2b3c"
)

var (
	shaA = strings.Repeat("a", 64)
	shaB = strings.Repeat("b", 64)
	shaC = strings.Repeat("c", 64)
)

func ptr[T any](v T) *T { return &v }

func site(key string, names ...string) protocol.Site {
	return protocol.Site{SiteKey: key, Kind: protocol.SiteNginx, Names: names, CertPath: ptr("/etc/ssl/" + key + ".pem")}
}

func install(assignment, sha string) protocol.Work {
	return protocol.Work{AssignmentID: assignment, SiteKey: siteKey, SHA256: sha, Action: protocol.ActionInstall}
}

type applied struct {
	assignment, sha, site string
	folder                bool
	keyPEM                string
}

// harness is the server, the machine and the clock around one Loop: it records every call in events, in order.
type harness struct {
	t      *testing.T
	cancel context.CancelFunc
	// maxBeats ends the run at the heartbeat after that many.
	maxBeats int

	events []string
	beats  []protocol.HeartbeatRequest
	// answer is the server's answer to beat n (from 0); nil = poll 60 s with work.
	answer func(n int) (*protocol.HeartbeatResponse, error)
	work   []protocol.Work
	// engine: answer as the server does: an inventory without a site pauses that site's work (no work for it is sent)
	// until an inventory holds the site again; a heartbeat without an inventory pauses nothing.
	engine bool
	paused map[string]bool

	// bundleSHA is the certificate the bundle of an assignment holds; "" = the one its work names.
	bundleSHA map[string]string
	bundleErr func(n int) error
	bundles   []string

	resultErr func(n int) error
	// refuse, when set, is the error the result of an assignment gets (nil: taken).
	refuse    map[string]error
	results   []protocol.InstallResult
	resultIDs []string

	sites  []protocol.Site
	invErr error
	reads  []time.Time

	// disk is what each site (by key) or folder certificate (by assignment) holds now; owed: the folder certificates
	// (by assignment) whose reload has not run yet.
	disk    map[string]string
	diskErr map[string]error
	owed    map[string]bool
	applyOK bool
	// applyTakes is how long each install takes on the harness's clock.
	applyTakes time.Duration
	applied    []applied
	released   []string

	now    time.Time
	sleeps []time.Duration
	// idles counts the day-long waits of a removed agent; the run ends at maxIdles.
	idles    int
	maxIdles int
	logs     bytes.Buffer
	loop     *Loop
}

func newHarness(t *testing.T, maxBeats int) *harness {
	h := &harness{
		t:         t,
		maxBeats:  maxBeats,
		bundleSHA: map[string]string{},
		sites:     []protocol.Site{site(siteKey, "www.example.test", "example.test")},
		disk:      map[string]string{siteKey: shaA},
		diskErr:   map[string]error{},
		owed:      map[string]bool{},
		applyOK:   true,
		now:       time.Unix(1793275200, 0),
		maxIdles:  2,
	}
	h.loop = &Loop{
		Client:    h,
		Inventory: h.inventory,
		Facts: func(context.Context) protocol.AgentFacts {
			return protocol.AgentFacts{OS: "linux", Arch: "amd64", Hostname: "web-1", AgentVersion: version.Version}
		},
		Installer:  siteInstaller{h},
		Folder:     folderInstaller{h},
		Clock:      h,
		Log:        slog.New(slog.NewTextHandler(&h.logs, nil)),
		RemoveHint: "systemctl disable --now nslookup-agent",
	}
	return h
}

func (h *harness) run() error {
	h.t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h.cancel = cancel
	done := make(chan error, 1)
	go func() { done <- h.loop.Run(ctx) }()
	select {
	case err := <-done:
		return err
	case <-time.After(10 * time.Second):
		h.t.Fatal("the loop did not stop")
		return nil
	}
}

func (h *harness) Heartbeat(ctx context.Context, beat protocol.HeartbeatRequest) (*protocol.HeartbeatResponse, error) {
	if len(h.beats) == h.maxBeats {
		h.cancel()
		return nil, ctx.Err()
	}
	n := len(h.beats)
	h.beats = append(h.beats, beat)
	h.events = append(h.events, "beat")
	if h.answer != nil {
		if resp, err := h.answer(n); resp != nil || err != nil {
			return resp, err
		}
	}
	return &protocol.HeartbeatResponse{Now: h.now.Unix(), PollSeconds: 60, Work: h.engineWork(beat)}, nil
}

// engineWork is h.work as the server sends it for beat: everything, or (engine) without the work of the sites paused as
// gone. A site missing from an inventory is paused, and comes back with an inventory that holds it.
func (h *harness) engineWork(beat protocol.HeartbeatRequest) []protocol.Work {
	if !h.engine {
		return h.work
	}
	if h.paused == nil {
		h.paused = map[string]bool{}
	}
	if beat.Inventory != nil {
		in := map[string]bool{}
		for _, s := range beat.Inventory.Sites {
			in[s.SiteKey] = true
		}
		for _, w := range h.work {
			if w.FolderName == nil {
				h.paused[w.SiteKey] = !in[w.SiteKey]
			}
		}
	}
	var out []protocol.Work
	for _, w := range h.work {
		if w.FolderName != nil || !h.paused[w.SiteKey] {
			out = append(out, w)
		}
	}
	return out
}

// notAnAssignment is what the client answers, without sending anything, for an id that is not an assignment id.
func notAnAssignment(id string) error {
	if protocol.IsAssignmentID(id) {
		return nil
	}
	return fmt.Errorf("%q is %w", id, client.ErrNotAnAssignmentID)
}

func (h *harness) Bundle(_ context.Context, id string) (*protocol.Bundle, error) {
	if err := notAnAssignment(id); err != nil {
		h.events = append(h.events, "refused bundle "+id)
		return nil, err
	}
	h.bundles = append(h.bundles, id)
	h.events = append(h.events, "bundle "+id)
	if h.bundleErr != nil {
		if err := h.bundleErr(len(h.bundles) - 1); err != nil {
			return nil, err
		}
	}
	sha := h.bundleSHA[id]
	if sha == "" {
		for _, w := range h.work {
			if w.AssignmentID == id {
				sha = w.SHA256
			}
		}
	}
	return &protocol.Bundle{AssignmentID: id, SHA256: sha, CertPEM: []byte("cert " + sha), KeyPEM: []byte("key " + sha)}, nil
}

func (h *harness) Result(_ context.Context, id string, r protocol.InstallResult) error {
	if err := notAnAssignment(id); err != nil {
		h.resultIDs = append(h.resultIDs, "refused "+id)
		return err
	}
	h.events = append(h.events, "result "+id)
	if err := h.refuse[id]; err != nil {
		h.resultIDs = append(h.resultIDs, "failed "+id)
		return err
	}
	if h.resultErr != nil {
		if err := h.resultErr(len(h.resultIDs)); err != nil {
			h.resultIDs = append(h.resultIDs, "failed "+id)
			return err
		}
	}
	h.resultIDs = append(h.resultIDs, id)
	h.results = append(h.results, r)
	return nil
}

func (h *harness) Now() time.Time { return h.now }

func (h *harness) Sleep(ctx context.Context, d time.Duration) error {
	h.sleeps = append(h.sleeps, d)
	h.now = h.now.Add(d)
	if d == 24*time.Hour {
		h.events = append(h.events, "idle")
		if h.idles++; h.idles == h.maxIdles {
			h.cancel()
		}
		return ctx.Err()
	}
	h.events = append(h.events, "sleep")
	return ctx.Err()
}

func (h *harness) inventory(context.Context) (protocol.Inventory, error) {
	h.reads = append(h.reads, h.now)
	h.events = append(h.events, "read")
	if h.invErr != nil {
		return protocol.Inventory{}, h.invErr
	}
	return protocol.Inventory{Sites: append([]protocol.Site(nil), h.sites...)}, nil
}

func (h *harness) apply(id, sha, key, where string, folder bool, b protocol.Bundle) protocol.InstallResult {
	h.applied = append(h.applied, applied{assignment: id, sha: b.SHA256, site: where, folder: folder, keyPEM: string(b.KeyPEM)})
	h.events = append(h.events, "apply "+id)
	h.now = h.now.Add(h.applyTakes)
	if !h.applyOK {
		return protocol.InstallResult{SHA256: sha, OK: false, Steps: []protocol.Step{{Name: protocol.StepTested, OK: false, Detail: ptr("nginx: [emerg] bad")}}}
	}
	h.disk[key] = b.SHA256
	return protocol.InstallResult{SHA256: sha, OK: true, Steps: []protocol.Step{{Name: protocol.StepWritten, OK: true}}}
}

type siteInstaller struct{ h *harness }

func (s siteInstaller) Apply(_ context.Context, site protocol.Site, b protocol.Bundle, w protocol.Work) protocol.InstallResult {
	if w.Action == protocol.ActionRelease {
		s.h.released = append(s.h.released, w.AssignmentID)
		s.h.events = append(s.h.events, "release "+w.AssignmentID)
		if b.CertPEM != nil || b.KeyPEM != nil {
			s.h.t.Error("a release got a bundle")
		}
		return protocol.InstallResult{OK: true, Steps: []protocol.Step{{Name: protocol.StepCertbotRestored, OK: true}}}
	}
	return s.h.apply(w.AssignmentID, w.SHA256, site.SiteKey, site.SiteKey, false, b)
}

func (s siteInstaller) DiskSHA(site protocol.Site) (string, error) {
	return s.h.disk[site.SiteKey], s.h.diskErr[site.SiteKey]
}

type folderInstaller struct{ h *harness }

func (f folderInstaller) Apply(_ context.Context, w protocol.Work, b protocol.Bundle) protocol.InstallResult {
	return f.h.apply(w.AssignmentID, w.SHA256, w.AssignmentID, *w.FolderName, true, b)
}

func (f folderInstaller) DiskSHA(w protocol.Work) (string, error) {
	return f.h.disk[w.AssignmentID], f.h.diskErr[w.AssignmentID]
}

func (f folderInstaller) FolderOf(w protocol.Work) string { return strings.ToLower(*w.FolderName) }

func (f folderInstaller) ReloadOwed(w protocol.Work) bool { return f.h.owed[w.AssignmentID] }

func (h *harness) logLines(substr string) int {
	return strings.Count(h.logs.String(), substr)
}

var hexHash = regexp.MustCompile(`^[0-9a-f]{64}$`)

func TestTheInventoryIsSentOnceThenOnlyItsHash(t *testing.T) {
	h := newHarness(t, 4)
	if err := h.run(); err != nil {
		t.Fatal(err)
	}
	if len(h.beats) != 4 {
		t.Fatalf("%d heartbeats", len(h.beats))
	}
	first := h.beats[0]
	if first.Inventory == nil || len(first.Inventory.Sites) != 1 || first.Inventory.Sites[0].SiteKey != siteKey || !hexHash.MatchString(first.InventoryHash) {
		t.Fatalf("first heartbeat: inventory %+v, hash %q", first.Inventory, first.InventoryHash)
	}
	if first.Version != version.Version || first.Facts.Hostname != "web-1" || first.Facts.AgentVersion != version.Version {
		t.Errorf("first heartbeat: version %q, facts %+v", first.Version, first.Facts)
	}
	for i, b := range h.beats[1:] {
		if b.Inventory != nil || b.InventoryHash != first.InventoryHash {
			t.Errorf("heartbeat %d: inventory %+v, hash %q", i+1, b.Inventory, b.InventoryHash)
		}
	}
	if len(h.reads) != 1 {
		t.Errorf("read %d times in %v, want once", len(h.reads), h.now.Sub(h.reads[0]))
	}
	if h.events[0] != "read" || h.events[1] != "beat" {
		t.Errorf("events %v: the inventory is read at once, then sent", h.events)
	}
}

func TestTheInventoryHashDoesNotDependOnTheOrderOfSites(t *testing.T) {
	a := newHarness(t, 1)
	a.sites = []protocol.Site{site(siteKey, "a.example.test"), site(otherKey, "b.example.test")}
	b := newHarness(t, 1)
	b.sites = []protocol.Site{site(otherKey, "b.example.test"), site(siteKey, "a.example.test")}
	for _, h := range []*harness{a, b} {
		if err := h.run(); err != nil {
			t.Fatal(err)
		}
	}
	if a.beats[0].InventoryHash != b.beats[0].InventoryHash {
		t.Error("the same sites in another order give another hash")
	}
}

func TestTheInventoryIsReadAgainAtMostEveryFiveMinutes(t *testing.T) {
	h := newHarness(t, 12)
	h.answer = func(n int) (*protocol.HeartbeatResponse, error) {
		if n == 0 {
			// From now on the machine has a second site.
			h.sites = append(h.sites, site(otherKey, "shop.example.test"))
		}
		return nil, nil
	}
	if err := h.run(); err != nil {
		t.Fatal(err)
	}
	if len(h.reads) < 2 {
		t.Fatalf("read %d times over %v", len(h.reads), h.now.Sub(h.reads[0]))
	}
	for i := 1; i < len(h.reads); i++ {
		if gap := h.reads[i].Sub(h.reads[i-1]); gap < 5*time.Minute || gap > 5*time.Minute+70*time.Second {
			t.Errorf("read %d came %v after the one before", i, gap)
		}
	}
	// The read that found the second site is sent with the next heartbeat; the rest carry only the hash.
	var sent []int
	for i, b := range h.beats {
		if b.Inventory != nil {
			sent = append(sent, i)
		}
	}
	if len(sent) != 2 || len(h.beats[sent[1]].Inventory.Sites) != 2 || h.beats[sent[1]].InventoryHash == h.beats[0].InventoryHash {
		t.Errorf("inventories sent with heartbeats %v", sent)
	}
}

// An install changes what the sites serve, so the heartbeat after it carries a fresh read, well before the five
// minutes are up.
func TestTheInventoryIsReadAgainAfterAnInstall(t *testing.T) {
	h := newHarness(t, 3)
	h.work = []protocol.Work{install(assignX, shaB)}
	h.answer = func(n int) (*protocol.HeartbeatResponse, error) {
		if n == 0 {
			// The install that follows this answer changes what the machine reports.
			h.sites = []protocol.Site{site(siteKey, "www.example.test", "example.test", "new.example.test")}
		}
		return nil, nil
	}
	if err := h.run(); err != nil {
		t.Fatal(err)
	}
	if len(h.applied) != 1 || len(h.reads) < 2 {
		t.Fatalf("applied %d, reads %d", len(h.applied), len(h.reads))
	}
	if gap := h.reads[1].Sub(h.reads[0]); gap >= inventoryEvery {
		t.Errorf("the second read came %v after the first", gap)
	}
	if h.beats[1].Inventory == nil || len(h.beats[1].Inventory.Sites[0].Names) != 3 {
		t.Errorf("heartbeat 1 did not carry the new inventory: %+v", h.beats[1].Inventory)
	}
}

func TestTheInventoryIsNotReadEarlyAfterAFailedInstall(t *testing.T) {
	h := newHarness(t, 4)
	h.applyOK = false
	h.work = []protocol.Work{install(assignX, shaB)}
	if err := h.run(); err != nil {
		t.Fatal(err)
	}
	if len(h.applied) != 1 || len(h.reads) != 1 {
		t.Errorf("applied %d, reads %d", len(h.applied), len(h.reads))
	}
}

func TestTheInventoryIsNotReadEarlyAfterAnAlreadyInstalledReport(t *testing.T) {
	h := newHarness(t, 4)
	h.work = []protocol.Work{install(assignX, shaA)}
	if err := h.run(); err != nil {
		t.Fatal(err)
	}
	if len(h.results) != 1 || len(h.reads) != 1 {
		t.Errorf("results %d, reads %d", len(h.results), len(h.reads))
	}
}

func TestCheckNowReadsTheInventoryAtOnce(t *testing.T) {
	h := newHarness(t, 4)
	h.answer = func(n int) (*protocol.HeartbeatResponse, error) {
		if n == 1 {
			return &protocol.HeartbeatResponse{PollSeconds: 60, WantInventory: true}, nil
		}
		return nil, nil
	}
	if err := h.run(); err != nil {
		t.Fatal(err)
	}
	want := []string{"read", "beat", "sleep", "beat", "read", "beat", "sleep", "beat", "sleep"}
	if strings.Join(h.events, ",") != strings.Join(want, ",") {
		t.Errorf("events %v\nwant   %v", h.events, want)
	}
	if h.beats[2].Inventory == nil || h.beats[3].Inventory != nil {
		t.Errorf("inventory sent with heartbeat 2: %v, with 3: %v", h.beats[2].Inventory != nil, h.beats[3].Inventory != nil)
	}
}

func TestAServerThatKeepsAskingGetsOneExtraHeartbeatPerPoll(t *testing.T) {
	h := newHarness(t, 6)
	h.answer = func(int) (*protocol.HeartbeatResponse, error) {
		return &protocol.HeartbeatResponse{PollSeconds: 60, WantInventory: true}, nil
	}
	if err := h.run(); err != nil {
		t.Fatal(err)
	}
	// Each answer asks again; the agent re-reads and sends at once only after an answer to a heartbeat that did not
	// carry the inventory.
	if got := strings.Count(strings.Join(h.events, ","), "sleep"); got < 3 {
		t.Errorf("events %v: the agent did not wait between heartbeats", h.events)
	}
}

// An inventory the server refuses (413 too large, 422 not valid) is not sent again until it changes, not even when the
// server asks for it: the heartbeat goes again at once with its hash only, so the agent stays online and does its work.
func TestAnInventoryTheServerRefusesIsNotSentAgainUntilItChanges(t *testing.T) {
	for _, refusal := range []*client.APIError{{Status: 413, Code: "body_too_large"}, {Status: 422, Code: "invalid_inventory", Message: "sites[0].served.serial must be at most 128 characters"}} {
		t.Run(fmt.Sprint(refusal.Status), func(t *testing.T) {
			h := newHarness(t, 16)
			h.work = []protocol.Work{install(assignX, shaB)}
			taken := false
			h.answer = func(n int) (*protocol.HeartbeatResponse, error) {
				b := h.beats[n]
				if b.Inventory != nil && len(b.Inventory.Sites) == 1 {
					return nil, refusal
				}
				if n == 3 {
					// From now on the machine has a second site: a new list, sent at the next read.
					h.sites = append(h.sites, site(otherKey, "shop.example.test"))
				}
				// The server asks for the list until it gets one it takes.
				taken = taken || b.Inventory != nil
				return &protocol.HeartbeatResponse{PollSeconds: 60, WantInventory: !taken, Work: h.work}, nil
			}
			if err := h.run(); err != nil {
				t.Fatal(err)
			}
			if h.beats[0].Inventory == nil || h.beats[1].Inventory != nil || h.beats[1].InventoryHash != h.beats[0].InventoryHash {
				t.Fatalf("heartbeat 1 after the refusal: inventory %v, hash %q", h.beats[1].Inventory != nil, h.beats[1].InventoryHash)
			}
			if got := strings.Join(h.events[:3], ","); got != "read,beat,beat" {
				t.Errorf("events %v: the heartbeat with the hash only goes at once", h.events)
			}
			if len(h.applied) != 1 {
				t.Errorf("applied %+v: the work is done all the same", h.applied)
			}
			var sent []int
			for i, b := range h.beats {
				if b.Inventory != nil {
					sent = append(sent, i)
				}
			}
			if len(sent) != 2 || len(h.beats[sent[1]].Inventory.Sites) != 2 {
				t.Errorf("inventories sent with heartbeats %v, want the refused one and the changed one, once each", sent)
			}
			if n := strings.Count(h.logs.String(), "level=ERROR msg=\"the server refused the list of sites"); n != 1 {
				t.Errorf("%d error lines:\n%s", n, h.logs.String())
			}
			// Not read again on every heartbeat while the list is refused: every five minutes, as usual (the first
			// read after the install is the one the install asks for).
			for i := 2; i < len(h.reads); i++ {
				if gap := h.reads[i].Sub(h.reads[i-1]); gap < 5*time.Minute {
					t.Errorf("read again after %v", gap)
				}
			}
		})
	}
}

// A 422 that does not name the inventory (invalid_request: the facts, say) never marks a good inventory refused: it is
// sent again with the next heartbeat.
func TestARefusalThatDoesNotNameTheInventoryKeepsIt(t *testing.T) {
	h := newHarness(t, 3)
	h.answer = func(n int) (*protocol.HeartbeatResponse, error) {
		if n == 0 {
			return nil, &client.APIError{Status: 422, Code: "invalid_request", Message: "facts.osVersion must be at most 128 characters"}
		}
		return nil, nil
	}
	if err := h.run(); err != nil {
		t.Fatal(err)
	}
	if h.beats[1].Inventory == nil || h.events[2] != "sleep" || strings.Contains(h.logs.String(), "refused the list of sites") {
		t.Errorf("events %v; logs:\n%s", h.events, h.logs.String())
	}
}

// A heartbeat without the inventory that is refused all the same is not the inventory's fault: it backs off as usual.
func TestARefusedHeartbeatWithoutTheInventoryBacksOff(t *testing.T) {
	h := newHarness(t, 4)
	h.answer = func(n int) (*protocol.HeartbeatResponse, error) {
		if n > 0 {
			return nil, &client.APIError{Status: 422, Code: "invalid_request"}
		}
		return nil, nil
	}
	if err := h.run(); err != nil {
		t.Fatal(err)
	}
	if h.sleeps[1] != 15*time.Second || h.sleeps[2] != 30*time.Second {
		t.Errorf("waits %v", h.sleeps)
	}
}

// longNames are n names of the form <prefix>-<i>.<label>.example.test, the label of width characters.
func longNames(prefix string, n, width int) []string {
	names := make([]string, n)
	for i := range names {
		names[i] = fmt.Sprintf("%s-%03d.%s.example.test", prefix, i, strings.Repeat("x", width))
	}
	return names
}

func bigSite(i int, names, servedNames, width int) protocol.Site {
	s := site(fmt.Sprintf("%032x", i), longNames(fmt.Sprintf("s%03d", i), names, width)...)
	s.Served = &protocol.CertFacts{SHA256: shaA, Issuer: "Example", Names: longNames(fmt.Sprintf("c%03d", i), servedNames, width), Serial: "1", NotAfter: "2027-01-01T00:00:00Z"}
	return s
}

func beatSize(t *testing.T, b protocol.HeartbeatRequest) int {
	t.Helper()
	body, err := protocol.MarshalBody(b)
	if err != nil {
		t.Fatal(err)
	}
	return len(body)
}

// The heartbeat stays within 3.5 MiB (the server takes 4 MiB): the certificates' own names go first, from the last
// site back, then the last sites; what was left out is logged.
func TestAnInventoryTooLargeForOneHeartbeatIsCut(t *testing.T) {
	const limit = 3<<20 + 1<<19
	t.Run("certificate names", func(t *testing.T) {
		h := newHarness(t, 1)
		h.sites = nil
		for i := range 300 {
			h.sites = append(h.sites, bigSite(i, 100, 100, 40))
		}
		if err := h.run(); err != nil {
			t.Fatal(err)
		}
		inv := h.beats[0].Inventory
		if size := beatSize(t, h.beats[0]); size > limit || size < limit-200<<10 {
			t.Errorf("heartbeat of %d bytes", size)
		}
		if len(inv.Sites) != 300 || len(inv.Sites[0].Served.Names) != 100 || len(inv.Sites[299].Served.Names) != 0 || len(inv.Sites[299].Names) != 100 {
			t.Errorf("%d sites; first served %d names, last %d", len(inv.Sites), len(inv.Sites[0].Served.Names), len(inv.Sites[299].Served.Names))
		}
		if !strings.Contains(h.logs.String(), "too large for one heartbeat") || !strings.Contains(h.logs.String(), "sitesLeftOut=0") {
			t.Errorf("logs:\n%s", h.logs.String())
		}
	})
	t.Run("sites", func(t *testing.T) {
		// Sites left out: sent after the first answer named the work.
		h := newHarness(t, 2)
		h.sites = nil
		for i := range 500 {
			h.sites = append(h.sites, bigSite(i, 100, 10, 60))
		}
		if err := h.run(); err != nil {
			t.Fatal(err)
		}
		if h.beats[0].Inventory != nil {
			t.Error("a list cut before the first answer was sent")
		}
		inv := h.beats[1].Inventory
		if size := beatSize(t, h.beats[1]); size > limit {
			t.Errorf("heartbeat of %d bytes", size)
		}
		if len(inv.Sites) >= 500 || len(inv.Sites) < 300 || inv.Sites[0].SiteKey != fmt.Sprintf("%032x", 0) {
			t.Errorf("%d sites sent", len(inv.Sites))
		}
		for _, s := range inv.Sites {
			if len(s.Served.Names) != 0 {
				t.Fatalf("site %s still has its certificate's names", s.SiteKey)
			}
		}
		if !strings.Contains(h.logs.String(), fmt.Sprintf("sitesLeftOut=%d", 500-len(inv.Sites))) {
			t.Errorf("logs:\n%s", h.logs.String())
		}
		if want := protocol.SHA256Hex(mustMarshal(t, *inv)); h.beats[1].InventoryHash != want {
			t.Error("the hash is not the hash of the list sent")
		}
	})
}

// A Kubernetes read whose Ingress lists alone are too large loses those lists first, from the last site back: every
// site and every served certificate name stays, and the loop's own read is not edited.
func TestATooLargeHeartbeatLosesIngressListsFirst(t *testing.T) {
	const limit = 3<<20 + 1<<19
	h := newHarness(t, 1)
	h.sites = nil
	for i := range 500 {
		s := bigSite(i, 1, 5, 60)
		s.Kind = protocol.SiteK8sIngress
		s.CertPath = nil
		ref := &protocol.SecretRef{Namespace: "web", Name: fmt.Sprintf("tls-%03d", i), Ingress: "ing-000"}
		for j := range 200 {
			ref.Ingresses = append(ref.Ingresses, protocol.IngressRef{Name: fmt.Sprintf("ing-%03d-%03d.%s", i, j, strings.Repeat("x", 40))})
		}
		s.Secret = ref
		h.sites = append(h.sites, s)
	}
	if err := h.run(); err != nil {
		t.Fatal(err)
	}
	inv := h.beats[0].Inventory
	if inv == nil || len(inv.Sites) != 500 {
		t.Fatalf("inventory %v", inv)
	}
	if size := beatSize(t, h.beats[0]); size > limit {
		t.Errorf("heartbeat of %d bytes", size)
	}
	emptied := 0
	for _, s := range inv.Sites {
		if len(s.Served.Names) != 5 {
			t.Fatalf("site %s lost certificate names", s.SiteKey)
		}
		if len(s.Secret.Ingresses) == 0 {
			emptied++
		}
	}
	if emptied == 0 || emptied == 500 || len(inv.Sites[0].Secret.Ingresses) != 200 || len(inv.Sites[499].Secret.Ingresses) != 0 {
		t.Errorf("%d sites without an Ingress list; first has %d, last %d", emptied, len(inv.Sites[0].Secret.Ingresses), len(inv.Sites[499].Secret.Ingresses))
	}
	if body, err := protocol.MarshalBody(inv.Sites[499]); err != nil || !strings.Contains(string(body), `"ingresses":[]`) {
		t.Errorf("last site: %s (%v)", body, err)
	}
	for _, s := range h.loop.raw.Sites {
		if len(s.Secret.Ingresses) != 200 {
			t.Fatalf("the raw read of %s was edited: %d Ingresses", s.SiteKey, len(s.Secret.Ingresses))
		}
	}
	if !strings.Contains(h.logs.String(), fmt.Sprintf("sitesWithoutIngressList=%d", emptied)) {
		t.Errorf("logs:\n%s", h.logs.String())
	}
}

// manySites are n sites with keys 0, 1, ... (sorted by key).
func manySites(n int) []protocol.Site {
	sites := make([]protocol.Site, n)
	for i := range sites {
		sites[i] = site(fmt.Sprintf("%032x", i), fmt.Sprintf("site%d.example.test", i))
	}
	return sites
}

func hasSite(inv *protocol.Inventory, key string) bool {
	return inv != nil && slices.ContainsFunc(inv.Sites, func(s protocol.Site) bool { return s.SiteKey == key })
}

// A machine with more sites than the server takes: the sites the server assigns certificates to are never left out
// (the server would pause their assignments as gone and send no more work for them), however they sort. Before the
// server has named its work, a list that must be cut is not sent: the first heartbeat carries the hash only (the server
// pauses nothing then), and the cut list follows at once.
func TestAssignedSitesAreNeverCutFromTheInventory(t *testing.T) {
	last := fmt.Sprintf("%032x", 509)
	h := newHarness(t, 6)
	h.engine = true
	h.sites = manySites(510)
	w := install(assignX, shaB)
	w.SiteKey = last
	h.work = []protocol.Work{w}
	ledger := &memLedger{}
	h.loop.Ledger = ledger
	if err := h.run(); err != nil {
		t.Fatal(err)
	}
	if h.beats[0].Inventory != nil || h.beats[0].InventoryHash != "unread" {
		t.Fatalf("first heartbeat: %d sites, hash %q", len(h.beats[0].Inventory.Sites), h.beats[0].InventoryHash)
	}
	if got := strings.Join(h.events[:4], ","); got != "read,beat,beat,bundle "+assignX {
		t.Errorf("events %v: the cut list goes at once after the first answer", h.events)
	}
	got := h.beats[1].Inventory
	if got == nil || len(got.Sites) != 500 || !hasSite(got, last) || hasSite(got, fmt.Sprintf("%032x", 499)) {
		t.Fatalf("second heartbeat: %v", got != nil)
	}
	for i, b := range h.beats {
		if b.Inventory != nil && !hasSite(b.Inventory, last) {
			t.Errorf("heartbeat %d left the assigned site out", i)
		}
	}
	if h.paused[last] || len(h.applied) != 1 {
		t.Errorf("paused %v, applied %+v", h.paused[last], h.applied)
	}
	if !slices.IsSortedFunc(got.Sites, func(a, b protocol.Site) int { return strings.Compare(a.SiteKey, b.SiteKey) }) {
		t.Error("the sites are not in key order")
	}
	if _, ok := ledger.saved.Sites[last]; !ok {
		t.Errorf("the assigned site is not remembered: %+v", ledger.saved.Sites)
	}

	// Started again with its memory: the cut list still waits for the first answer, and keeps the site.
	again := newHarness(t, 2)
	again.engine = true
	again.sites = manySites(510)
	again.work = h.work
	again.loop.Ledger = &memLedger{load: ledger.saved}
	if err := again.run(); err != nil {
		t.Fatal(err)
	}
	if again.beats[0].Inventory != nil || !hasSite(again.beats[1].Inventory, last) {
		t.Errorf("after a restart: %v, %v", again.beats[0].Inventory != nil, again.beats[1].Inventory != nil)
	}
}

// A paused assignment gets no work, so only the agent's memory keeps its site in a cut list: a site the server paused
// earlier comes back once the agent sends it again.
func TestASitePausedAsGoneComesBackFromTheAgentsMemory(t *testing.T) {
	last := fmt.Sprintf("%032x", 509)
	h := newHarness(t, 2)
	h.engine = true
	h.paused = map[string]bool{last: true}
	h.sites = manySites(510)
	w := install(assignX, shaB)
	w.SiteKey = last
	h.work = []protocol.Work{w}
	h.loop.Ledger = &memLedger{load: Memory{Sites: map[string]time.Time{last: h.now.Add(-time.Hour)}}}
	if err := h.run(); err != nil {
		t.Fatal(err)
	}
	if !hasSite(h.beats[1].Inventory, last) || h.paused[last] {
		t.Errorf("sent %v, paused %v", hasSite(h.beats[1].Inventory, last), h.paused[last])
	}
}

// A list that needs no cut is sent with the very first heartbeat, as always; so is one that only loses certificate
// names.
func TestAListThatNeedsNoCutIsNotHeld(t *testing.T) {
	h := newHarness(t, 1)
	h.sites = manySites(500)
	if err := h.run(); err != nil {
		t.Fatal(err)
	}
	if inv := h.beats[0].Inventory; inv == nil || len(inv.Sites) != 500 {
		t.Errorf("first heartbeat carried %v", inv != nil)
	}
}

// Sites this machine itself says the agent installed on (a Kubernetes secret carrying the agent's annotation) count as
// assigned in a cut list, also when no work names them (their assignment paused).
func TestSitesTheMachineSaysTheAgentInstalledOnAreKept(t *testing.T) {
	last := fmt.Sprintf("%032x", 509)
	h := newHarness(t, 2)
	h.engine = true
	h.sites = manySites(510)
	h.loop.Owned = func() []string { return []string{last} }
	if err := h.run(); err != nil {
		t.Fatal(err)
	}
	if !hasSite(h.beats[1].Inventory, last) {
		t.Error("the site the machine says the agent installed on was cut")
	}
}

// The size cut keeps assigned sites too: the others' certificate names go first, then the others, and only then the
// assigned sites' certificate names.
func TestAssignedSitesAreNeverCutForSize(t *testing.T) {
	const limit = 3<<20 + 1<<19
	last := fmt.Sprintf("%032x", 499)
	var sites []protocol.Site
	for i := range 500 {
		sites = append(sites, bigSite(i, 100, 10, 60))
	}
	h := newHarness(t, 2)
	h.sites = sites
	h.loop.Ledger = &memLedger{load: Memory{Sites: map[string]time.Time{last: h.now}}}
	if err := h.run(); err != nil {
		t.Fatal(err)
	}
	inv := h.beats[1].Inventory
	if size := beatSize(t, h.beats[1]); size > limit {
		t.Errorf("heartbeat of %d bytes", size)
	}
	if len(inv.Sites) >= 500 || !hasSite(inv, last) {
		t.Fatalf("%d sites; the assigned one: %v", len(inv.Sites), hasSite(inv, last))
	}
	if s := inv.Sites[len(inv.Sites)-1]; s.SiteKey != last || len(s.Served.Names) != 10 {
		t.Errorf("the assigned site lost its certificate's names while others were left out: %+v", s.Served)
	}
}

func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	b, err := protocol.MarshalBody(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestAnInventoryThatCannotBeReadIsNeverSent(t *testing.T) {
	h := newHarness(t, 8)
	h.invErr = errors.New("nginx -T: exit status 1")
	h.answer = func(int) (*protocol.HeartbeatResponse, error) {
		return &protocol.HeartbeatResponse{PollSeconds: 60, WantInventory: true}, nil
	}
	if err := h.run(); err != nil {
		t.Fatal(err)
	}
	for i, b := range h.beats {
		if b.Inventory != nil || b.InventoryHash != "unread" {
			t.Errorf("heartbeat %d: inventory %+v, hash %q", i, b.Inventory, b.InventoryHash)
		}
	}
	for i := 1; i < len(h.reads); i++ {
		if gap := h.reads[i].Sub(h.reads[i-1]); gap < 5*time.Minute {
			t.Errorf("a failed read was tried again after %v", gap)
		}
	}
	if h.logLines("nginx -T: exit status 1") != len(h.reads) {
		t.Errorf("logs:\n%s", h.logs.String())
	}
}

func TestAnInventoryThatCannotBeReadAgainKeepsTheLastOne(t *testing.T) {
	h := newHarness(t, 9)
	h.answer = func(n int) (*protocol.HeartbeatResponse, error) {
		if n == 0 {
			h.invErr = errors.New("nginx -T: exit status 1")
		}
		if n == 7 {
			return &protocol.HeartbeatResponse{PollSeconds: 60, WantInventory: true}, nil
		}
		return nil, nil
	}
	if err := h.run(); err != nil {
		t.Fatal(err)
	}
	if len(h.reads) < 2 {
		t.Fatalf("read %d times", len(h.reads))
	}
	for i, b := range h.beats {
		if b.InventoryHash != h.beats[0].InventoryHash {
			t.Errorf("heartbeat %d: hash %q", i, b.InventoryHash)
		}
	}
	// Asked for it, the agent sends the last list it read.
	if h.beats[8].Inventory == nil || len(h.beats[8].Inventory.Sites) != 1 {
		t.Errorf("heartbeat 8 carried %+v", h.beats[8].Inventory)
	}
}

func TestWorkIsAppliedOncePerSHA256(t *testing.T) {
	h := newHarness(t, 6)
	h.work = []protocol.Work{install(assignX, shaB)}
	h.answer = func(n int) (*protocol.HeartbeatResponse, error) {
		if n == 4 {
			h.work = []protocol.Work{install(assignX, shaC)} // renewed
		}
		return nil, nil
	}
	if err := h.run(); err != nil {
		t.Fatal(err)
	}
	if len(h.applied) != 2 || h.applied[0].sha != shaB || h.applied[1].sha != shaC || h.applied[0].site != siteKey || h.applied[0].keyPEM != "key "+shaB {
		t.Fatalf("applied %+v", h.applied)
	}
	if len(h.bundles) != 2 {
		t.Errorf("%d bundles fetched, want 2", len(h.bundles))
	}
	if len(h.results) != 2 || !h.results[0].OK || h.results[0].SHA256 != shaB || h.results[0].Drift || h.results[1].SHA256 != shaC {
		t.Errorf("results %+v", h.results)
	}
	if strings.Contains(h.logs.String(), "key ") {
		t.Errorf("a key reached the log:\n%s", h.logs.String())
	}
	// The next heartbeat says what is on disk.
	if got := h.beats[1].Installed; len(got) != 1 || got[0].AssignmentID != assignX || got[0].SHA256OnDisk == nil || *got[0].SHA256OnDisk != shaB {
		t.Errorf("installed %+v", got)
	}
}

func TestAFailedInstallIsNotTriedAgainForTheSameSHA256(t *testing.T) {
	h := newHarness(t, 4)
	h.applyOK = false
	h.work = []protocol.Work{install(assignX, shaB)}
	if err := h.run(); err != nil {
		t.Fatal(err)
	}
	if len(h.applied) != 1 || len(h.bundles) != 1 || len(h.results) != 1 || h.results[0].OK {
		t.Errorf("applied %d, bundles %d, results %+v", len(h.applied), len(h.bundles), h.results)
	}
}

// The server stops sending a failed install once it has its result, and sends it again when it retries it later: the
// agent then tries it again, once.
func TestAFailedInstallTheServerRetriesIsTriedAgain(t *testing.T) {
	h := newHarness(t, 6)
	h.applyOK = false
	failed := []protocol.Work{install(assignX, shaB)}
	h.work = failed
	h.answer = func(n int) (*protocol.HeartbeatResponse, error) {
		switch n {
		case 1, 2:
			h.work = nil // failed: no work until the retry is due
		case 3:
			h.work = failed // the retry
		}
		return nil, nil
	}
	if err := h.run(); err != nil {
		t.Fatal(err)
	}
	if len(h.applied) != 2 || len(h.results) != 2 {
		t.Errorf("applied %d, results %d", len(h.applied), len(h.results))
	}
}

// The server marks an install only from a result, so a file that already holds the certificate (a site taken over
// that already serves it) is reported once, then left as it is.
func TestAFileAlreadyHoldingTheCertificateIsReportedOnce(t *testing.T) {
	ledger := &memLedger{}
	h := newHarness(t, 3)
	h.loop.Ledger = ledger
	h.work = []protocol.Work{install(assignX, shaA)}
	if err := h.run(); err != nil {
		t.Fatal(err)
	}
	if len(h.applied) != 0 || len(h.bundles) != 0 {
		t.Errorf("applied %d, bundles %d", len(h.applied), len(h.bundles))
	}
	want := protocol.InstallResult{SHA256: shaA, OK: true, Steps: []protocol.Step{{Name: protocol.StepChecked, OK: true, Detail: ptr("already installed")}}}
	if len(h.results) != 1 || !reflect.DeepEqual(h.results[0], want) {
		t.Fatalf("results %+v, want one %+v", h.results, want)
	}
	if ledger.saved.Installed[assignX] != shaA {
		t.Errorf("ledger %+v", ledger.saved)
	}

	// Started again: it is recorded, so nothing more is said.
	again := newHarness(t, 2)
	again.loop.Ledger = ledger
	again.work = []protocol.Work{install(assignX, shaA)}
	if err := again.run(); err != nil {
		t.Fatal(err)
	}
	if len(again.results) != 0 || len(again.bundles) != 0 {
		t.Errorf("after a restart: results %+v, bundles %d", again.results, len(again.bundles))
	}
}

// servingInstaller is a site installer that can ask whether a site serves a certificate (a Kubernetes site: its
// ingress controller); asked collects the SHA-256s it was asked about.
type servingInstaller struct {
	siteInstaller
	served bool
	asked  *[]string
}

func (s servingInstaller) CheckServed(_ context.Context, _ protocol.Site, sha string) (bool, string) {
	*s.asked = append(*s.asked, sha)
	if s.served {
		return true, "the ingress controller serves the new certificate (1 names and addresses asked)"
	}
	return false, "shop.example at 10.0.0.1:443: the ingress controller serves another certificate"
}

// After a Kubernetes pod was replaced its ledger is empty, and its one "already installed" result replaces the
// install's: it says whether the site serves the certificate, as the install's did, and leaves servedLocally empty
// when it was not seen.
func TestAnAlreadyInstalledResultSaysWhetherTheSiteServesIt(t *testing.T) {
	for _, served := range []bool{true, false} {
		t.Run(fmt.Sprint("served ", served), func(t *testing.T) {
			h := newHarness(t, 3)
			var asked []string
			h.loop.Installer = servingInstaller{siteInstaller{h}, served, &asked}
			h.work = []protocol.Work{install(assignX, shaA)} // on disk: A
			if err := h.run(); err != nil {
				t.Fatal(err)
			}
			if len(h.applied) != 0 || len(h.bundles) != 0 || !slices.Equal(asked, []string{shaA}) {
				t.Errorf("applied %d, bundles %d, asked %v", len(h.applied), len(h.bundles), asked)
			}
			saw, detail := servingInstaller{served: served, asked: new([]string)}.CheckServed(context.Background(), protocol.Site{}, shaA)
			want := protocol.InstallResult{SHA256: shaA, OK: true, Steps: []protocol.Step{
				{Name: protocol.StepChecked, OK: true, Detail: ptr("already installed")},
				{Name: protocol.StepCheckedLocally, OK: saw, Detail: &detail},
			}}
			if served {
				want.ServedLocally = ptr(true)
			}
			if len(h.results) != 1 || !reflect.DeepEqual(h.results[0], want) {
				t.Fatalf("results %+v, want one %+v", h.results, want)
			}
		})
	}
}

// memLedger is a Ledger in memory; load is what it starts with.
type memLedger struct {
	load  Memory
	saved Memory
	saves int
}

func (m *memLedger) Load() (Memory, error) {
	if m.saves > 0 {
		return m.saved, nil
	}
	return m.load, nil
}

func (m *memLedger) Save(mem Memory) error {
	m.saved = mem
	m.saves++
	return nil
}

func TestAFileChangedByHandIsReportedOnceAndNothingInstalled(t *testing.T) {
	for name, renewed := range map[string]bool{"the same certificate": false, "a renewal at the same time": true} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, 5)
			h.work = []protocol.Work{install(assignX, shaA)} // on disk: A, ours
			h.answer = func(n int) (*protocol.HeartbeatResponse, error) {
				if n == 1 {
					h.disk[siteKey] = shaC // changed by hand
					if renewed {
						h.work = []protocol.Work{install(assignX, shaB)}
					}
				}
				return nil, nil
			}
			if err := h.run(); err != nil {
				t.Fatal(err)
			}
			if len(h.applied) != 0 || len(h.bundles) != 0 {
				t.Errorf("applied %d, bundles %d; want nothing", len(h.applied), len(h.bundles))
			}
			// First "already installed" (A was on disk), then the change, once.
			if len(h.results) != 2 || !h.results[0].OK || h.results[0].SHA256 != shaA {
				t.Fatalf("results %+v", h.results)
			}
			drift := h.results[1]
			if !drift.Drift || drift.OK || drift.Message == nil || h.disk[siteKey] != shaC {
				t.Fatalf("results %+v", h.results)
			}
			if want := map[bool]string{false: shaA, true: shaB}[renewed]; drift.SHA256 != want {
				t.Errorf("the result names %s, want the work's %s", drift.SHA256, want)
			}
		})
	}
}

// recordingInstaller is a site installer that keeps its own record of what it installed (a Kubernetes secret's
// annotation).
type recordingInstaller struct {
	siteInstaller
	recorded map[string]string
}

func (r recordingInstaller) Recorded(site protocol.Site) string { return r.recorded[site.SiteKey] }

// With no ledger record (a Kubernetes pod replaced, its emptyDir gone), the installer's own record says what the agent
// installed last: a certificate changed by hand since is a drift, never overwritten.
func TestTheInstallersOwnRecordStandsInForAnEmptyLedger(t *testing.T) {
	h := newHarness(t, 2)
	h.loop.Installer = recordingInstaller{siteInstaller{h}, map[string]string{siteKey: shaA}}
	h.disk[siteKey] = shaC // changed by hand since the agent wrote A
	h.work = []protocol.Work{install(assignX, shaB)}
	if err := h.run(); err != nil {
		t.Fatal(err)
	}
	if len(h.applied) != 0 || len(h.bundles) != 0 || len(h.results) != 1 || !h.results[0].Drift {
		t.Errorf("applied %d, bundles %d, results %+v", len(h.applied), len(h.bundles), h.results)
	}

	// The record is what is on disk: a renewal installs.
	again := newHarness(t, 2)
	again.loop.Installer = recordingInstaller{siteInstaller{again}, map[string]string{siteKey: shaA}}
	again.work = []protocol.Work{install(assignX, shaB)}
	if err := again.run(); err != nil {
		t.Fatal(err)
	}
	if len(again.applied) != 1 || len(again.results) != 1 || !again.results[0].OK {
		t.Errorf("applied %d, results %+v", len(again.applied), again.results)
	}
}

func TestARestartedAgentRemembersWhatItInstalled(t *testing.T) {
	ledger := FileLedger{Path: filepath.Join(t.TempDir(), "state", "installed.json")}
	h := newHarness(t, 2)
	h.loop.Ledger = ledger
	h.work = []protocol.Work{install(assignX, shaB)}
	if err := h.run(); err != nil {
		t.Fatal(err)
	}
	if len(h.applied) != 1 {
		t.Fatalf("applied %+v", h.applied)
	}

	// Stopped; the file changed by hand; started again.
	again := newHarness(t, 2)
	again.loop.Ledger = ledger
	again.disk[siteKey] = shaC
	again.work = []protocol.Work{install(assignX, shaB)}
	if err := again.run(); err != nil {
		t.Fatal(err)
	}
	if len(again.applied) != 0 || len(again.results) != 1 || !again.results[0].Drift {
		t.Errorf("after a restart: applied %d, results %+v", len(again.applied), again.results)
	}
}

func TestTheBundleMustBeTheCertificateTheWorkNames(t *testing.T) {
	h := newHarness(t, 3)
	h.work = []protocol.Work{install(assignX, shaB)}
	h.bundleSHA[assignX] = shaC
	h.answer = func(n int) (*protocol.HeartbeatResponse, error) {
		if n == 1 {
			delete(h.bundleSHA, assignX)
		}
		return nil, nil
	}
	if err := h.run(); err != nil {
		t.Fatal(err)
	}
	if len(h.bundles) != 2 || len(h.applied) != 1 || h.applied[0].sha != shaB || len(h.results) != 1 {
		t.Errorf("bundles %d, applied %+v, results %d", len(h.bundles), h.applied, len(h.results))
	}
}

func TestARefusedBundleDoesNotHoldUpTheOtherWork(t *testing.T) {
	h := newHarness(t, 1)
	h.sites = append(h.sites, site(otherKey, "shop.example.test"))
	y := install(assignY, shaC)
	y.SiteKey = otherKey
	h.work = []protocol.Work{install(assignX, shaB), y}
	h.bundleErr = func(n int) error {
		if n == 0 {
			return &client.APIError{Status: 404, Code: "not_found"}
		}
		return nil
	}
	if err := h.run(); err != nil {
		t.Fatal(err)
	}
	if strings.Join(h.bundles, ",") != assignX+","+assignY || len(h.applied) != 1 || h.applied[0].assignment != assignY {
		t.Errorf("bundles %v, applied %+v", h.bundles, h.applied)
	}
}

func TestANetworkErrorEndsTheRoundOfWork(t *testing.T) {
	h := newHarness(t, 2)
	h.sites = append(h.sites, site(otherKey, "shop.example.test"))
	y := install(assignY, shaC)
	y.SiteKey = otherKey
	h.work = []protocol.Work{install(assignX, shaB), y}
	h.bundleErr = func(n int) error {
		if n == 0 {
			return &url.Error{Op: "Get", URL: "https://agents.example.test/agent/v1/assignments", Err: errors.New("connection reset by peer")}
		}
		return nil
	}
	if err := h.run(); err != nil {
		t.Fatal(err)
	}
	// Round 1 stops at X; round 2 does both.
	if strings.Join(h.bundles, ",") != assignX+","+assignX+","+assignY || len(h.applied) != 2 {
		t.Errorf("bundles %v, applied %+v", h.bundles, h.applied)
	}
	if h.logLines("connection reset by peer") != 1 {
		t.Errorf("logs:\n%s", h.logs.String())
	}
}

func TestAMalformedAssignmentIDDoesNotHoldUpTheOtherWork(t *testing.T) {
	ledger := &memLedger{}
	h := newHarness(t, 3)
	h.loop.Ledger = ledger
	h.loop.Folder = nil // a folder item this agent cannot do would be reported: never for a malformed id
	h.work = []protocol.Work{
		install("not-an-id", shaC),
		{AssignmentID: "../join", SHA256: shaC, Action: protocol.ActionInstall, FolderName: ptr("x")},
		install(assignX, shaB),
	}
	if err := h.run(); err != nil {
		t.Fatal(err)
	}
	if strings.Join(h.bundles, ",") != assignX || len(h.applied) != 1 || strings.Join(h.resultIDs, ",") != assignX {
		t.Errorf("bundles %v, applied %+v, results %v", h.bundles, h.applied, h.resultIDs)
	}
	if _, ok := ledger.saved.Installed["not-an-id"]; ok || len(ledger.saved.Installed) != 1 {
		t.Errorf("ledger %+v", ledger.saved)
	}
	if h.logLines("not an assignment id") != 2 { // once per id, not every heartbeat
		t.Errorf("logs:\n%s", h.logs.String())
	}
}

func TestAResultTheClientRefusesIsDropped(t *testing.T) {
	ledger := &memLedger{load: Memory{Pending: []PendingResult{{AssignmentID: "../join", Result: protocol.InstallResult{SHA256: shaC, OK: true}}}}}
	h := newHarness(t, 2)
	h.loop.Ledger = ledger
	h.work = []protocol.Work{install(assignX, shaB)}
	if err := h.run(); err != nil {
		t.Fatal(err)
	}
	if strings.Join(h.resultIDs, ",") != "refused ../join,"+assignX || len(h.applied) != 1 {
		t.Errorf("result calls %v, applied %d", h.resultIDs, len(h.applied))
	}
	if len(ledger.saved.Pending) != 0 {
		t.Errorf("still pending: %+v", ledger.saved.Pending)
	}
}

func TestAResultThatCouldNotBeSentIsSentAgain(t *testing.T) {
	h := newHarness(t, 3)
	h.work = []protocol.Work{install(assignX, shaB)}
	h.resultErr = func(n int) error {
		if n == 0 {
			return errors.New("connection reset by peer")
		}
		return nil
	}
	if err := h.run(); err != nil {
		t.Fatal(err)
	}
	if len(h.applied) != 1 || strings.Join(h.resultIDs, ",") != "failed "+assignX+","+assignX || h.results[0].SHA256 != shaB {
		t.Errorf("applied %d, result calls %v", len(h.applied), h.resultIDs)
	}
}

func TestARefusedResultIsNotSentAgain(t *testing.T) {
	h := newHarness(t, 3)
	h.work = []protocol.Work{install(assignX, shaB)}
	h.resultErr = func(n int) error {
		if n == 0 {
			return &client.APIError{Status: 404, Code: "not_found"}
		}
		return nil
	}
	if err := h.run(); err != nil {
		t.Fatal(err)
	}
	if len(h.resultIDs) != 1 {
		t.Errorf("result calls %v", h.resultIDs)
	}
}

// A result the server could not take now (its error, a proxy's, a 401 while it cannot check nonces) stays queued and
// is sent again with each heartbeat until the server takes it; the install is not done again.
func TestAResultTheServerCouldNotTakeNowIsSentAgain(t *testing.T) {
	for _, status := range []int{500, 503, 401} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			ledger := &memLedger{}
			h := newHarness(t, 4)
			h.loop.Ledger = ledger
			h.work = []protocol.Work{install(assignX, shaB)}
			h.resultErr = func(n int) error {
				if n < 2 {
					return &client.APIError{Status: status, Code: map[int]string{401: "unauthorized"}[status]}
				}
				return nil
			}
			if err := h.run(); err != nil {
				t.Fatal(err)
			}
			if got := strings.Join(h.resultIDs, ","); got != "failed "+assignX+",failed "+assignX+","+assignX {
				t.Errorf("result calls %v", got)
			}
			if len(h.applied) != 1 || len(h.bundles) != 1 || len(h.results) != 1 || h.results[0].SHA256 != shaB || !h.results[0].OK {
				t.Errorf("applied %d, bundles %d, results %+v", len(h.applied), len(h.bundles), h.results)
			}
			if len(ledger.saved.Pending) != 0 {
				t.Errorf("still pending: %+v", ledger.saved.Pending)
			}
			if h.logLines("not sent again") != 0 {
				t.Errorf("logs:\n%s", h.logs.String())
			}
		})
	}
}

// A failed install whose result could not be sent is reported all the same: the server hears it failed.
func TestAFailedInstallsResultIsKeptUntilTheServerTakesIt(t *testing.T) {
	h := newHarness(t, 4)
	h.applyOK = false
	h.work = []protocol.Work{install(assignX, shaB)}
	h.resultErr = func(n int) error {
		if n == 0 {
			return &client.APIError{Status: 503}
		}
		return nil
	}
	if err := h.run(); err != nil {
		t.Fatal(err)
	}
	if len(h.applied) != 1 || len(h.results) != 1 || h.results[0].OK {
		t.Errorf("applied %d, results %+v", len(h.applied), h.results)
	}
}

// Each refusal that is for good drops the result: sending it again would get the same answer.
func TestAResultRefusedForGoodIsDropped(t *testing.T) {
	for status, code := range map[int]string{400: "invalid_json", 404: "not_found", 409: "conflict", 410: "gone", 422: "invalid_request"} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			ledger := &memLedger{}
			h := newHarness(t, 3)
			h.loop.Ledger = ledger
			h.work = []protocol.Work{install(assignX, shaB)}
			h.resultErr = func(int) error { return &client.APIError{Status: status, Code: code} }
			if err := h.run(); err != nil {
				t.Fatal(err)
			}
			if len(h.resultIDs) != 1 || len(ledger.saved.Pending) != 0 {
				t.Errorf("result calls %v, pending %+v", h.resultIDs, ledger.saved.Pending)
			}
		})
	}
}

// A 404, 409 or 410 without the server's code (a proxy's default backend, say) says nothing about the result: it stays
// queued.
func TestABareRefusalKeepsTheResult(t *testing.T) {
	for _, status := range []int{404, 409, 410} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			ledger := &memLedger{}
			h := newHarness(t, 3)
			h.loop.Ledger = ledger
			h.work = []protocol.Work{install(assignX, shaB)}
			h.resultErr = func(n int) error {
				if n < 2 {
					return &client.APIError{Status: status}
				}
				return nil
			}
			if err := h.run(); err != nil {
				t.Fatal(err)
			}
			if strings.Join(h.resultIDs, ",") != "failed "+assignX+",failed "+assignX+","+assignX || len(ledger.saved.Pending) != 0 {
				t.Errorf("result calls %v, pending %+v", h.resultIDs, ledger.saved.Pending)
			}
		})
	}
}

// A result the server keeps refusing for its own sake (a server error, a 403 not signed as a removal, an unlisted
// status) stays queued but never holds up other work; after a day of refusals it is dropped, said at error level.
func TestAResultRefusedForItsOwnSakeNeverHoldsUpOtherWork(t *testing.T) {
	for _, refusal := range []*client.APIError{{Status: 500}, {Status: 503}, {Status: 403}, {Status: 408}, {Status: 415}, {Status: 418}} {
		t.Run(fmt.Sprint(refusal.Status), func(t *testing.T) {
			ledger := &memLedger{}
			h := newHarness(t, 30)
			h.loop.Ledger = ledger
			h.sites = append(h.sites, site(otherKey, "shop.example.test"))
			y := install(assignY, shaC)
			y.SiteKey = otherKey
			h.work = []protocol.Work{install(assignX, shaB)}
			h.refuse = map[string]error{assignX: refusal}
			h.answer = func(n int) (*protocol.HeartbeatResponse, error) {
				if n == 1 {
					h.work = []protocol.Work{install(assignX, shaB), y} // new work while X's result is refused
				}
				// An hour between heartbeats.
				return &protocol.HeartbeatResponse{PollSeconds: 3600, Work: h.work}, nil
			}
			if err := h.run(); err != nil {
				t.Fatal(err)
			}
			if len(h.applied) != 2 || h.applied[1].assignment != assignY || slices.Index(h.resultIDs, assignY) < 0 {
				t.Errorf("applied %+v, result calls %v", h.applied, h.resultIDs)
			}
			// Sent again with each heartbeat for a day, then dropped once.
			tries := strings.Count(strings.Join(h.resultIDs, ","), "failed "+assignX)
			if tries < 20 || tries > 27 || len(ledger.saved.Pending) != 0 {
				t.Errorf("%d tries, pending %+v", tries, ledger.saved.Pending)
			}
			if n := strings.Count(h.logs.String(), "level=ERROR msg=\"the server refused a result for a day"); n != 1 {
				t.Errorf("%d error lines:\n%s", n, h.logs.String())
			}
		})
	}
}

// Only the network, a timeout, a 401 (the server's clock or nonce check) and a rate limit end a round of work.
func TestWhatEndsARoundOfWork(t *testing.T) {
	for name, c := range map[string]struct {
		err  error
		ends bool
	}{
		"a 401":                 {&client.APIError{Status: 401, Code: "unauthorized"}, true},
		"the clock":             {&client.ErrClockSkew{}, true},
		"a rate limit":          {&client.APIError{Status: 429, Code: "rate_limited"}, true},
		"the network":           {&url.Error{Op: "Get", URL: "https://agents.example.test", Err: errors.New("connection reset by peer")}, true},
		"a server error":        {&client.APIError{Status: 503}, false},
		"a bad answer":          {client.ErrBadServerSignature, false},
		"a proxy's default 404": {&client.APIError{Status: 404}, false},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, 1)
			h.sites = append(h.sites, site(otherKey, "shop.example.test"))
			y := install(assignY, shaC)
			y.SiteKey = otherKey
			h.work = []protocol.Work{install(assignX, shaB), y}
			h.bundleErr = func(n int) error {
				if n == 0 {
					return c.err
				}
				return nil
			}
			if err := h.run(); err != nil {
				t.Fatal(err)
			}
			if done := slices.Contains(h.bundles, assignY); done == c.ends {
				t.Errorf("bundles %v: the round ends: %v, want %v", h.bundles, !done, c.ends)
			}
		})
	}
}

// One round of installs runs for at most 2 minutes: the rest waits for the next heartbeat, so a long list of installs
// never keeps the agent from heartbeating (the server would think it offline).
func TestARoundOfInstallsRunsAtMostTwoMinutes(t *testing.T) {
	h := newHarness(t, 2)
	h.applyTakes = 70 * time.Second
	third := "0e5c3a9d-1f2b-4c6d-8e7f-a1b2c3d4e5f6"
	for i, key := range []string{otherKey, "00112233445566778899aabbccddeeff"} {
		h.sites = append(h.sites, site(key, fmt.Sprintf("site%d.example.test", i)))
	}
	y, z := install(assignY, shaC), install(third, shaB)
	y.SiteKey, z.SiteKey = otherKey, "00112233445566778899aabbccddeeff"
	h.work = []protocol.Work{install(assignX, shaB), y, z}
	if err := h.run(); err != nil {
		t.Fatal(err)
	}
	want := "read,beat,bundle " + assignX + ",apply " + assignX + ",result " + assignX + ",bundle " + assignY + ",apply " + assignY +
		",result " + assignY + ",sleep,read,beat,bundle " + third + ",apply " + third + ",result " + third + ",sleep"
	if got := strings.Join(h.events, ","); !strings.HasPrefix(got, want) {
		t.Errorf("events %s\nwant   %s", got, want)
	}
	if h.logLines("wait for the next heartbeat") != 1 {
		t.Errorf("logs:\n%s", h.logs.String())
	}
	// What waits is still reported as on disk: nothing is forgotten.
	if got := h.beats[1].Installed; len(got) != 2 {
		t.Errorf("installed %+v", got)
	}
}

// checkingInstaller is a site installer that can tell, before the bundle, that it cannot install on a site.
type checkingInstaller struct {
	siteInstaller
	refuse map[string]string
}

func (c checkingInstaller) CanInstall(site protocol.Site, _ protocol.Work) error {
	if why := c.refuse[site.SiteKey]; why != "" {
		return errors.New(why)
	}
	return nil
}

// A site the installer cannot install on is reported before the bundle is fetched (the server unseals a key for every
// bundle it sends), once; the other work goes on.
func TestASiteThatCannotBeInstalledOnIsReportedWithoutFetchingTheBundle(t *testing.T) {
	h := newHarness(t, 3)
	h.sites = append(h.sites, site(otherKey, "shop.example.test"))
	why := "nothing was written: certbot renews this site; the agent installs on it only once it is taken over from certbot in the portal"
	h.loop.Installer = checkingInstaller{siteInstaller{h}, map[string]string{siteKey: why}}
	y := install(assignY, shaC)
	y.SiteKey = otherKey
	h.work = []protocol.Work{install(assignX, shaB), y}
	if err := h.run(); err != nil {
		t.Fatal(err)
	}
	if strings.Join(h.bundles, ",") != assignY || len(h.applied) != 1 {
		t.Errorf("bundles %v, applied %+v", h.bundles, h.applied)
	}
	want := protocol.InstallResult{SHA256: shaB, Steps: []protocol.Step{{Name: protocol.StepWritten, OK: false, Detail: &why}}, Message: &why}
	if len(h.results) != 2 || !reflect.DeepEqual(h.results[0], want) || h.resultIDs[0] != assignX {
		t.Errorf("results %v %+v", h.resultIDs, h.results)
	}
}

// assignedInstaller is a site installer told, before each round, the sites the server assigns certificates to.
type assignedInstaller struct {
	siteInstaller
	told *[][]string
}

func (a assignedInstaller) SetAssigned(keys []string) { *a.told = append(*a.told, keys) }

// Before each round the installer hears which sites the server still assigns certificates to (their install work):
// a certbot name one of them uses is not given back for another.
func TestTheInstallerHearsWhichSitesAreAssigned(t *testing.T) {
	h := newHarness(t, 2)
	var told [][]string
	h.loop.Installer = assignedInstaller{siteInstaller{h}, &told}
	release := protocol.Work{AssignmentID: assignY, SiteKey: otherKey, SHA256: shaC, Action: protocol.ActionRelease, Certbot: ptr(protocol.CertbotGiveBack)}
	folder := protocol.Work{AssignmentID: "0e5c3a9d-1f2b-4c6d-8e7f-a1b2c3d4e5f6", SHA256: shaB, Action: protocol.ActionInstall, FolderName: ptr("mail.example")}
	h.work = []protocol.Work{install(assignX, shaB), release, folder}
	if err := h.run(); err != nil {
		t.Fatal(err)
	}
	if len(told) != 2 || !reflect.DeepEqual(told[0], []string{siteKey}) {
		t.Errorf("told %v", told)
	}
}

// rateLimited is the server behind its limit of 30 results a minute per agent, which counts every result request,
// refused or not, before anything else.
type rateLimited struct {
	*harness
	window      int64
	count, sent int
	limited     int
}

func (r *rateLimited) Result(ctx context.Context, id string, result protocol.InstallResult) error {
	if w := r.harness.now.Unix() / 60; w != r.window {
		r.window, r.count = w, 0
	}
	r.count++
	r.sent++
	if r.count > 30 {
		r.limited++
		r.harness.events = append(r.harness.events, "429 "+id)
		return &client.APIError{Status: 429, Code: "rate_limited"}
	}
	return r.harness.Result(ctx, id, result)
}

// stuckResults are n queued results the server refuses for their own sake (a 503), refused before already.
func stuckResults(h *harness, n int) []PendingResult {
	var pending []PendingResult
	if h.refuse == nil {
		h.refuse = map[string]error{}
	}
	for i := range n {
		id := stuckID(i)
		pending = append(pending, PendingResult{AssignmentID: id, Result: protocol.InstallResult{SHA256: shaB, OK: true}, RefusedSince: h.now.Add(-time.Hour)})
		h.refuse[id] = &client.APIError{Status: 503}
	}
	return pending
}

// stuckID is the assignment of stuck result i; queuedID that of queued result i, never refused.
func stuckID(i int) string  { return fmt.Sprintf("00000000-0000-4000-8000-%012x", i) }
func queuedID(i int) string { return fmt.Sprintf("22222222-0000-4000-8000-%012x", i) }

// queuedResults are n queued results never refused (their sending was halted, or they were added at a restart).
func queuedResults(n int) []PendingResult {
	var pending []PendingResult
	for i := range n {
		pending = append(pending, PendingResult{AssignmentID: queuedID(i), Result: protocol.InstallResult{SHA256: shaB, OK: true}})
	}
	return pending
}

// resultsIn are the assignments of the result requests among events (joined by commas), in order.
func resultsIn(events string) []string {
	var ids []string
	for _, e := range strings.Split(events, ",") {
		if id, ok := strings.CutPrefix(e, "result "); ok {
			ids = append(ids, id)
		}
	}
	return ids
}

func pendingIDs(pending []PendingResult) []string {
	var ids []string
	for _, p := range pending {
		ids = append(ids, p.AssignmentID)
	}
	return ids
}

// Results the server keeps refusing never use up its limit of 30 results a minute: each round sends at most 10 of them,
// once, at its start; the round's installs go on and their results are sent.
func TestStuckResultsNeverUseUpTheServersResultLimit(t *testing.T) {
	for _, stuck := range []int{31, 60} {
		t.Run(fmt.Sprint(stuck), func(t *testing.T) {
			h := newHarness(t, 4)
			limit := &rateLimited{harness: h}
			h.loop.Client = limit
			ledger := &memLedger{load: Memory{Pending: stuckResults(h, stuck)}}
			h.loop.Ledger = ledger
			h.sites, h.work = nil, nil
			for i := range 10 {
				key := fmt.Sprintf("%032x", 1000+i)
				h.sites = append(h.sites, site(key, fmt.Sprintf("s%d.example.test", i)))
				w := install(fmt.Sprintf("11111111-0000-4000-8000-%012x", i), shaB)
				w.SiteKey = key
				h.work = append(h.work, w)
			}
			if err := h.run(); err != nil {
				t.Fatal(err)
			}
			if len(h.applied) != 10 || limit.limited != 0 {
				t.Fatalf("applied %d, rate limited %d times", len(h.applied), limit.limited)
			}
			// The first round: 10 stuck results, then the 10 new ones.
			rounds := strings.Split(strings.Join(h.events, ","), "beat")
			if first := strings.Count(rounds[1], "result "); first != 20 {
				t.Errorf("first round sent %d results, want 20: %s", first, rounds[1])
			}
			for i, r := range rounds[2:] {
				if n := strings.Count(r, "result 00000000-"); n > 10 {
					t.Errorf("round %d sent %d stuck results", i+2, n)
				}
			}
			for i := range 10 {
				if !slices.Contains(h.resultIDs, fmt.Sprintf("11111111-0000-4000-8000-%012x", i)) {
					t.Errorf("result %d not sent", i)
				}
			}
			if len(ledger.saved.Pending) != stuck {
				t.Errorf("%d results still queued, want the %d stuck ones", len(ledger.saved.Pending), stuck)
			}
		})
	}
}

// A result once refused is sent again at the start of the next round only, never after each install of the round; the
// oldest go first.
func TestARefusedResultIsSentAgainOncePerRound(t *testing.T) {
	h := newHarness(t, 2)
	h.loop.Ledger = &memLedger{load: Memory{Pending: stuckResults(h, 12)}}
	h.sites, h.work = nil, nil
	for i := range 3 {
		key := fmt.Sprintf("%032x", 1000+i)
		h.sites = append(h.sites, site(key, fmt.Sprintf("s%d.example.test", i)))
		w := install(fmt.Sprintf("11111111-0000-4000-8000-%012x", i), shaB)
		w.SiteKey = key
		h.work = append(h.work, w)
	}
	if err := h.run(); err != nil {
		t.Fatal(err)
	}
	first := strings.Split(strings.Join(h.events, ","), "beat")[1]
	for i := range 12 {
		want := 1
		if i >= 10 {
			want = 0 // past the 10 of this round
		}
		if n := strings.Count(first, fmt.Sprintf("result 00000000-0000-4000-8000-%012x", i)); n != want {
			t.Errorf("stuck result %d sent %d times in the first round, want %d", i, n, want)
		}
	}
	// A result refused in this round is not sent again after the next install.
	h2 := newHarness(t, 1)
	h2.sites = append(h2.sites, site(otherKey, "shop.example.test"))
	y := install(assignY, shaC)
	y.SiteKey = otherKey
	h2.work = []protocol.Work{install(assignX, shaB), y}
	h2.refuse = map[string]error{assignX: &client.APIError{Status: 503}}
	if err := h2.run(); err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(strings.Join(h2.resultIDs, ","), "failed "+assignX); n != 1 {
		t.Errorf("the refused result was sent %d times in its round: %v", n, h2.resultIDs)
	}
}

// Results the server keeps refusing take turns: one refused again goes to the back of the queue, so each of 25 is sent
// again within 3 rounds of 10, never twice in one round, and the saved queue goes on from there after a restart.
func TestRefusedResultsTakeTurns(t *testing.T) {
	h := newHarness(t, 3)
	limit := &rateLimited{harness: h}
	h.loop.Client = limit
	ledger := &memLedger{load: Memory{Pending: stuckResults(h, 25)}}
	h.loop.Ledger = ledger
	h.work = nil
	if err := h.run(); err != nil {
		t.Fatal(err)
	}
	rounds := strings.Split(strings.Join(h.events, ","), "beat")[1:]
	if len(rounds) != 3 || limit.limited != 0 {
		t.Fatalf("%d rounds, rate limited %d times: %v", len(rounds), limit.limited, h.events)
	}
	tried := map[string]int{}
	for r, events := range rounds {
		sent := resultsIn(events)
		if len(sent) != 10 {
			t.Errorf("round %d sent %d results, want 10: %v", r+1, len(sent), sent)
		}
		for _, id := range sent {
			tried[id]++
		}
		slices.Sort(sent)
		if len(slices.Compact(sent)) != len(sent) {
			t.Errorf("round %d sent a result twice: %v", r+1, resultsIn(events))
		}
	}
	for i := range 25 {
		if tried[stuckID(i)] == 0 {
			t.Errorf("stuck result %d never sent again in 3 rounds", i)
		}
	}
	// Sent in rounds 1 (0-9), 2 (10-19) and 3 (20-24, then 0-4): 5-9 waited longest and go first next.
	var want []string
	for i := range 25 {
		want = append(want, stuckID((5+i)%25))
	}
	if got := pendingIDs(ledger.saved.Pending); !slices.Equal(got, want) {
		t.Errorf("saved queue %v, want %v", got, want)
	}
}

// The start of a round sends at most 20 queued results: those never refused first, in their order, then (within the
// 20) up to 10 refused before. The rest wait, never dropped, and the next round goes on from there; the round's own
// results are sent as they come, and the held ones are not sent with them.
func TestARoundStartsWithAtMost20QueuedResults(t *testing.T) {
	h := newHarness(t, 2)
	limit := &rateLimited{harness: h}
	h.loop.Client = limit
	ledger := &memLedger{load: Memory{Pending: append(stuckResults(h, 10), queuedResults(30)...)}}
	h.loop.Ledger = ledger
	h.sites, h.work = nil, nil
	var installed []string
	for i := range 10 {
		key := fmt.Sprintf("%032x", 1000+i)
		h.sites = append(h.sites, site(key, fmt.Sprintf("s%d.example.test", i)))
		w := install(fmt.Sprintf("11111111-0000-4000-8000-%012x", i), shaB)
		w.SiteKey = key
		h.work = append(h.work, w)
		installed = append(installed, w.AssignmentID)
	}
	// An install takes a second: the next round starts in the next minute, whatever the poll's jitter.
	h.applyTakes = time.Second
	if err := h.run(); err != nil {
		t.Fatal(err)
	}
	if len(h.applied) != 10 || limit.limited != 0 {
		t.Fatalf("applied %d, rate limited %d times: %v", len(h.applied), limit.limited, h.events)
	}
	rounds := strings.Split(strings.Join(h.events, ","), "beat")
	first, second := rounds[1], rounds[2]
	installs := strings.Index(first, "bundle ")
	if installs < 0 {
		t.Fatalf("no install in the first round: %s", first)
	}
	var queued, stuck []string
	for i := range 30 {
		queued = append(queued, queuedID(i))
	}
	for i := range 10 {
		stuck = append(stuck, stuckID(i))
	}
	if got := resultsIn(first[:installs]); !slices.Equal(got, queued[:20]) {
		t.Errorf("the first round started with %d results %v, want the first 20 never refused", len(got), got)
	}
	if got := resultsIn(first[installs:]); !slices.Equal(got, installed) {
		t.Errorf("the first round's installs sent %v, want only their own results", got)
	}
	if got, want := resultsIn(second), append(slices.Clone(queued[20:]), stuck...); !slices.Equal(got, want) {
		t.Errorf("the second round sent %v, want %v", got, want)
	}
	for _, id := range append(queued, installed...) {
		if n := strings.Count(strings.Join(h.resultIDs, ","), id); n != 1 {
			t.Errorf("result %s taken %d times", id, n)
		}
	}
	if got := pendingIDs(ledger.saved.Pending); !slices.Equal(got, stuck) {
		t.Errorf("still queued %v, want the 10 stuck ones", got)
	}
}

// A failure that halts (the network, a 401, a rate limit) at the start of a round keeps every result not sent, in its
// order; one refused again before the halt still goes to the back. Nothing is sent twice in the round, and the next
// round goes on from there.
func TestAHaltKeepsTheResultsNotSentInTheirOrder(t *testing.T) {
	s0, s1, s2 := stuckID(0), stuckID(1), stuckID(2)
	q0, q1, q2 := queuedID(0), queuedID(1), queuedID(2)
	for name, halt := range map[string]error{
		"the network":  &url.Error{Op: "Post", URL: "https://agents.example.test", Err: errors.New("connection reset by peer")},
		"a 401":        &client.APIError{Status: 401, Code: "unauthorized"},
		"a rate limit": &client.APIError{Status: 429, Code: "rate_limited"},
	} {
		for _, c := range []struct {
			where string
			// errs are the answers to the first round's requests (nil: taken); the rest are taken.
			errs                      []error
			firstRound, kept, nextRun []string
		}{
			{
				"among the results never refused", []error{nil, halt},
				[]string{q0, q1}, []string{s0, s1, s2, q1, q2}, []string{q1, q2, s0, s1, s2},
			},
			{
				"among the results refused before", []error{nil, nil, nil, &client.APIError{Status: 503}, halt},
				[]string{q0, q1, q2, s0, s1}, []string{s1, s2, s0}, []string{s1, s2, s0},
			},
		} {
			t.Run(name+" "+c.where, func(t *testing.T) {
				h := newHarness(t, 2)
				pending := append(stuckResults(h, 3), queuedResults(3)...)
				h.refuse = nil
				ledger := &memLedger{load: Memory{Pending: pending}}
				h.loop.Ledger = ledger
				h.work = nil
				h.resultErr = func(n int) error {
					if n < len(c.errs) {
						return c.errs[n]
					}
					return nil
				}
				var kept []string
				h.answer = func(n int) (*protocol.HeartbeatResponse, error) {
					if n == 1 {
						kept = pendingIDs(ledger.saved.Pending)
					}
					return nil, nil
				}
				if err := h.run(); err != nil {
					t.Fatal(err)
				}
				rounds := strings.Split(strings.Join(h.events, ","), "beat")
				if got := resultsIn(rounds[1]); !slices.Equal(got, c.firstRound) {
					t.Errorf("first round sent %v, want %v", got, c.firstRound)
				}
				if !slices.Equal(kept, c.kept) {
					t.Errorf("kept %v, want %v", kept, c.kept)
				}
				if got := resultsIn(rounds[2]); !slices.Equal(got, c.nextRun) {
					t.Errorf("next round sent %v, want %v", got, c.nextRun)
				}
				if len(ledger.saved.Pending) != 0 {
					t.Errorf("still queued %v", pendingIDs(ledger.saved.Pending))
				}
			})
		}
	}
}

// An answer below the server's minimum version names no work (the server sends none there): a list that must be cut
// stays held until an answer at or above the minimum names the work.
func TestAnAnswerBelowTheMinimumVersionNamesNoWork(t *testing.T) {
	last := fmt.Sprintf("%032x", 509)
	h := newHarness(t, 4)
	h.engine = true
	h.sites = manySites(510)
	w := install(assignX, shaB)
	w.SiteKey = last
	h.work = []protocol.Work{w}
	h.answer = func(n int) (*protocol.HeartbeatResponse, error) {
		if n < 2 {
			return &protocol.HeartbeatResponse{PollSeconds: 60, MinVersion: "99.0.0"}, nil
		}
		return nil, nil
	}
	if err := h.run(); err != nil {
		t.Fatal(err)
	}
	if h.beats[0].Inventory != nil || h.beats[1].Inventory != nil {
		t.Fatal("a cut list was sent before an answer named the work")
	}
	if h.beats[3].Inventory == nil || !hasSite(h.beats[3].Inventory, last) {
		t.Errorf("after the work was named: %v", h.beats[3].Inventory != nil)
	}
}

func TestBelowMinimum(t *testing.T) {
	for _, c := range []struct {
		version, min string
		below        bool
	}{
		{"1.0.0", "", false},
		{"1.0.0", "1.0.0", false},
		{"1.2.0", "1.10.0", true},
		{"2.0.0", "1.10.3", false},
		{"1.0.0-rc.1", "1.0.0", true},
		{"1.0.0-rc.1", "1.0.0-rc.1", false},
		{"0.0.0-dev", "1.0.0", true},
		{"dev", "1.0.0", true},
		{"1.0.0", "not a version", false},
	} {
		if got := belowMinimum(c.version, c.min); got != c.below {
			t.Errorf("belowMinimum(%q, %q) = %v, want %v", c.version, c.min, got, c.below)
		}
	}
}

func TestFolderWorkGoesToTheFolderInstaller(t *testing.T) {
	h := newHarness(t, 2)
	w := protocol.Work{AssignmentID: assignY, SHA256: shaB, Action: protocol.ActionInstall, FolderName: ptr("shop.example.test")}
	h.work = []protocol.Work{w}
	if err := h.run(); err != nil {
		t.Fatal(err)
	}
	if len(h.applied) != 1 || !h.applied[0].folder || h.applied[0].site != "shop.example.test" || h.disk[assignY] != shaB {
		t.Errorf("applied %+v", h.applied)
	}
	if len(h.results) != 1 || !h.results[0].OK {
		t.Errorf("results %+v", h.results)
	}
}

// Two folder certificates in one folder: the first of the answer is written there; the second is refused once, with
// the reason, never written over the first's files.
func TestTwoWorksNamingOneFolder(t *testing.T) {
	h := newHarness(t, 3)
	h.work = []protocol.Work{
		{AssignmentID: assignX, SHA256: shaB, Action: protocol.ActionInstall, FolderName: ptr("shop.example.test")},
		{AssignmentID: assignY, SHA256: shaC, Action: protocol.ActionInstall, FolderName: ptr("Shop.Example.Test")},
	}
	if err := h.run(); err != nil {
		t.Fatal(err)
	}
	if len(h.applied) != 1 || h.applied[0].assignment != assignX || len(h.bundles) != 1 {
		t.Errorf("applied %+v, bundles %q", h.applied, h.bundles)
	}
	if len(h.results) != 2 || h.resultIDs[1] != assignY || h.results[1].OK || h.results[1].Message == nil ||
		*h.results[1].Message != "another certificate on this agent is written to the folder shop.example.test; this one was not written" {
		t.Errorf("results %q %+v", h.resultIDs, h.results)
	}
}

// A folder the agent may not write in (another user's, or one others can change: the usual mistake when mounting
// one into Docker) is reported, once and again when the reason changes, so the portal says what to fix. A site's
// certificate that cannot be read only waits, as before.
func TestAFolderTheAgentMayNotWriteInIsReported(t *testing.T) {
	h := newHarness(t, 4)
	first := "/certs/shop.example.test/fullchain.pem is in /certs, which a user other than root can change (owner 1000, mode 0755); " +
		"the agent writes only in directories only root can change"
	h.diskErr[assignY] = errors.New(first)
	h.diskErr[siteKey] = errors.New("/etc/ssl/site.pem: permission denied")
	h.work = []protocol.Work{
		{AssignmentID: assignY, SHA256: shaB, Action: protocol.ActionInstall, FolderName: ptr("shop.example.test")},
		install(assignX, shaB),
	}
	h.answer = func(n int) (*protocol.HeartbeatResponse, error) {
		if n == 2 {
			h.diskErr[assignY] = errors.New("/certs/shop.example.test is a symbolic link")
		}
		return nil, nil
	}
	if err := h.run(); err != nil {
		t.Fatal(err)
	}
	if len(h.bundles) != 0 || len(h.applied) != 0 {
		t.Errorf("bundles %q, applied %+v", h.bundles, h.applied)
	}
	if len(h.results) != 2 || h.resultIDs[0] != assignY || h.resultIDs[1] != assignY {
		t.Fatalf("results %q %+v", h.resultIDs, h.results)
	}
	for i, want := range []string{first, "/certs/shop.example.test is a symbolic link"} {
		r := h.results[i]
		if r.OK || r.SHA256 != shaB || r.Drift || len(r.Steps) != 1 || r.Steps[0].Name != protocol.StepChecked || r.Steps[0].OK ||
			r.Steps[0].Detail == nil || *r.Steps[0].Detail != want || r.Message == nil || *r.Message != want {
			t.Errorf("result %d: %+v", i, r)
		}
	}
	if h.logLines("cannot be read; nothing done") != 4 {
		t.Errorf("logs %s", h.logs.String())
	}
}

// A folder whose reload failed (or was cut short) holds the certificate already: the work is applied again, so the
// reload runs, instead of "already installed", and never counts as a file changed by hand.
func TestAReloadStillOwedIsAppliedAgain(t *testing.T) {
	h := newHarness(t, 3)
	ledger := &memLedger{load: Memory{Installed: map[string]string{assignY: shaA}}}
	h.loop.Ledger = ledger
	h.work = []protocol.Work{{AssignmentID: assignY, SHA256: shaB, Action: protocol.ActionInstall, FolderName: ptr("mail.example.test")}}
	h.disk[assignY] = shaB
	h.owed[assignY] = true
	if err := h.run(); err != nil {
		t.Fatal(err)
	}
	if len(h.applied) != 1 || len(h.bundles) != 1 || len(h.results) != 1 || !h.results[0].OK || h.results[0].Drift {
		t.Errorf("applied %+v, bundles %q, results %+v", h.applied, h.bundles, h.results)
	}
	if ledger.saved.Installed[assignY] != shaB {
		t.Errorf("ledger %+v", ledger.saved)
	}
}

func TestWorkThisAgentCannotDoIsReportedOnce(t *testing.T) {
	h := newHarness(t, 3)
	h.loop.Folder = nil
	h.work = []protocol.Work{{AssignmentID: assignY, SHA256: shaB, Action: protocol.ActionInstall, FolderName: ptr("shop.example.test")}}
	if err := h.run(); err != nil {
		t.Fatal(err)
	}
	if len(h.bundles) != 0 || len(h.results) != 1 || h.results[0].OK || len(h.results[0].Steps) != 1 || h.results[0].Steps[0].Name != protocol.StepChecked {
		t.Errorf("bundles %d, results %+v", len(h.bundles), h.results)
	}
}

func TestWorkForASiteNotInTheInventoryWaits(t *testing.T) {
	h := newHarness(t, 2)
	w := install(assignX, shaB)
	w.SiteKey = otherKey
	h.work = []protocol.Work{w}
	if err := h.run(); err != nil {
		t.Fatal(err)
	}
	if len(h.bundles) != 0 || len(h.results) != 0 {
		t.Errorf("bundles %d, results %d", len(h.bundles), len(h.results))
	}
}

func TestReleaseWorkGivesTheSiteBackOnce(t *testing.T) {
	h := newHarness(t, 3)
	h.work = []protocol.Work{{AssignmentID: assignX, SiteKey: siteKey, SHA256: shaA, Action: protocol.ActionRelease, Certbot: ptr(protocol.CertbotGiveBack)}}
	if err := h.run(); err != nil {
		t.Fatal(err)
	}
	if len(h.released) != 1 || len(h.bundles) != 0 || len(h.results) != 1 || !h.results[0].OK || h.results[0].SHA256 != shaA {
		t.Errorf("released %v, bundles %d, results %+v", h.released, len(h.bundles), h.results)
	}
}

// A removed agent stops all work and waits to be uninstalled (an exited process would be restarted in a loop by
// Docker or Kubernetes), saying so when it stops and then once a day.
func TestARemovedAgentStopsWorkingAndWaits(t *testing.T) {
	h := newHarness(t, 5)
	h.maxIdles = 3
	h.work = []protocol.Work{install(assignX, shaB)}
	h.answer = func(n int) (*protocol.HeartbeatResponse, error) {
		if n == 1 {
			return nil, client.ErrRemoved
		}
		return nil, nil
	}
	if err := h.run(); err != nil {
		t.Fatalf("Run: %v, want nil once its context ends", err)
	}
	want := []string{"read", "beat", "bundle " + assignX, "apply " + assignX, "result " + assignX, "sleep", "read", "beat", "idle", "idle", "idle"}
	if strings.Join(h.events, ",") != strings.Join(want, ",") {
		t.Errorf("events %v\nwant   %v", h.events, want)
	}
	line := "nslookup.io removed this agent; it stops now. Remove it with: systemctl disable --now nslookup-agent"
	if h.logLines(line) != 3 || h.logLines("removed this agent") != 3 {
		t.Errorf("the removal is logged %d times over 3 days, want 3; logs:\n%s", h.logLines(line), h.logs.String())
	}
}

func TestARemovedAgentStopsWhileWorking(t *testing.T) {
	h := newHarness(t, 5)
	h.work = []protocol.Work{install(assignX, shaB)}
	h.bundleErr = func(int) error { return client.ErrRemoved }
	if err := h.run(); err != nil {
		t.Fatal(err)
	}
	if len(h.beats) != 1 || len(h.applied) != 0 || h.idles != 2 || h.logLines("nslookup.io removed this agent") != 2 {
		t.Errorf("beats %d, applied %d, idles %d, logs:\n%s", len(h.beats), len(h.applied), h.idles, h.logs.String())
	}
}

func TestClockSkewIsLoggedAndTriedAgainLater(t *testing.T) {
	for _, offset := range []time.Duration{400 * time.Second, -250 * time.Second} {
		h := newHarness(t, 4)
		h.answer = func(n int) (*protocol.HeartbeatResponse, error) {
			if n < 2 {
				return nil, &client.ErrClockSkew{Offset: offset}
			}
			return nil, nil
		}
		if err := h.run(); err != nil {
			t.Fatal(err)
		}
		seconds := int(offset.Abs() / time.Second)
		line := fmt.Sprintf("your clock is off by %d s; fix the time on this machine", seconds)
		if h.logLines(line) != 2 {
			t.Errorf("offset %v, logs:\n%s", offset, h.logs.String())
		}
		if h.sleeps[0] != 15*time.Second || h.sleeps[1] != 30*time.Second || h.sleeps[2] < 50*time.Second || h.sleeps[2] > 70*time.Second {
			t.Errorf("offset %v, sleeps %v", offset, h.sleeps)
		}
		if h.now.Unix() != time.Unix(1793275200, 0).Add(sum(h.sleeps)).Unix() {
			t.Error("the clock was moved")
		}
	}
}

func sum(ds []time.Duration) time.Duration {
	var total time.Duration
	for _, d := range ds {
		total += d
	}
	return total
}

func TestNetworkErrorsBackOffFrom15SecondsToFiveMinutes(t *testing.T) {
	h := newHarness(t, 10)
	h.answer = func(n int) (*protocol.HeartbeatResponse, error) {
		if n < 8 {
			return nil, errors.New("dial tcp: connection refused")
		}
		return nil, nil
	}
	if err := h.run(); err != nil {
		t.Fatal(err)
	}
	want := []time.Duration{15, 30, 60, 120, 240, 300, 300, 300}
	for i, w := range want {
		if h.sleeps[i] != w*time.Second {
			t.Errorf("sleep %d = %v, want %v", i, h.sleeps[i], w*time.Second)
		}
	}
	if d := h.sleeps[8]; d < 50*time.Second || d > 70*time.Second {
		t.Errorf("after a success the agent waits %v, want 60 s ± 10 s", d)
	}
}

func TestTheServersPollIsUsedWithJitter(t *testing.T) {
	h := newHarness(t, 30)
	h.answer = func(int) (*protocol.HeartbeatResponse, error) {
		return &protocol.HeartbeatResponse{PollSeconds: 120}, nil
	}
	if err := h.run(); err != nil {
		t.Fatal(err)
	}
	distinct := map[time.Duration]bool{}
	for _, d := range h.sleeps {
		if d < 110*time.Second || d > 130*time.Second {
			t.Errorf("waited %v, want 120 s ± 10 s", d)
		}
		distinct[d] = true
	}
	if len(distinct) < 2 {
		t.Errorf("no jitter: %v", h.sleeps)
	}
}

func TestTheLoopStopsWithItsContext(t *testing.T) {
	h := newHarness(t, 1)
	if err := h.run(); err != nil {
		t.Errorf("Run: %v, want nil", err)
	}
}

func TestAResultNotYetAcceptedIsSentAfterARestart(t *testing.T) {
	ledger := FileLedger{Path: filepath.Join(t.TempDir(), "state", "installed.json")}
	h := newHarness(t, 1)
	h.loop.Ledger = ledger
	h.work = []protocol.Work{install(assignX, shaB)}
	h.resultErr = func(int) error { return errors.New("connection reset by peer") }
	if err := h.run(); err != nil {
		t.Fatal(err)
	}
	if len(h.applied) != 1 || len(h.results) != 0 {
		t.Fatalf("applied %d, results %d", len(h.applied), len(h.results))
	}

	// Started again: the file already holds B, so only the saved result tells the server it was installed.
	again := newHarness(t, 2)
	again.loop.Ledger = ledger
	again.disk[siteKey] = shaB
	again.work = []protocol.Work{install(assignX, shaB)}
	if err := again.run(); err != nil {
		t.Fatal(err)
	}
	if len(again.applied) != 0 || len(again.results) != 1 || !again.results[0].OK || again.results[0].SHA256 != shaB || len(again.results[0].Steps) != 1 {
		t.Errorf("after a restart: applied %d, results %+v", len(again.applied), again.results)
	}
	if m, err := ledger.Load(); err != nil || len(m.Pending) != 0 || m.Installed[assignX] != shaB {
		t.Errorf("ledger %+v, %v", m, err)
	}
}

func TestTheLedgerFile(t *testing.T) {
	ledger := FileLedger{Path: filepath.Join(t.TempDir(), "state", "installed.json")}
	got, err := ledger.Load()
	if err != nil || len(got.Installed) != 0 || len(got.Pending) != 0 {
		t.Fatalf("a ledger never saved: %+v, %v", got, err)
	}
	saved := Memory{
		Installed: map[string]string{assignX: shaB},
		Pending:   []PendingResult{{AssignmentID: assignY, Result: protocol.InstallResult{SHA256: shaC, OK: true, Steps: []protocol.Step{{Name: protocol.StepWritten, OK: true}}}}},
	}
	if err := ledger.Save(saved); err != nil {
		t.Fatal(err)
	}
	got, err = ledger.Load()
	if err != nil || got.Installed[assignX] != shaB || len(got.Pending) != 1 || got.Pending[0].AssignmentID != assignY || got.Pending[0].Result.SHA256 != shaC || !got.Pending[0].Result.OK {
		t.Errorf("loaded %+v, %v", got, err)
	}
	info, err := os.Stat(ledger.Path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("mode %v, %v", info.Mode(), err)
	}
}

// The ledger is never read through a link.
func TestTheLedgerIsNeverReadThroughALink(t *testing.T) {
	real := FileLedger{Path: filepath.Join(t.TempDir(), "installed.json")}
	if err := real.Save(Memory{Installed: map[string]string{assignX: shaB}}); err != nil {
		t.Fatal(err)
	}
	link := FileLedger{Path: filepath.Join(t.TempDir(), "installed.json")}
	if err := os.Symlink(real.Path, link.Path); err != nil {
		t.Fatal(err)
	}
	if got, err := link.Load(); err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Errorf("%+v, %v", got, err)
	}
}

func TestTheLedgerDropsWhatIsNotWellFormed(t *testing.T) {
	ledger := FileLedger{Path: filepath.Join(t.TempDir(), "installed.json")}
	text := `{
  "installed": {"` + assignX + `": "` + shaB + `", "abc-def": "` + shaA + `", "` + assignY + `": "B"},
  "pending": [
    {"assignmentId": "9c1d4e7a-2b3f-4a8c-9d6e-0f1a2b3c4d5", "result": {"sha256": "` + shaA + `", "ok": true}},
    {"assignmentId": "../join", "result": {"sha256": "` + shaA + `", "ok": true}},
    {"assignmentId": "` + assignY + `", "result": {"sha256": "short", "ok": true}},
    {"assignmentId": "` + assignX + `", "result": {"sha256": "` + shaB + `", "ok": true}}
  ]
}`
	if err := os.WriteFile(ledger.Path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	m, err := ledger.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Installed) != 1 || m.Installed[assignX] != shaB || len(m.Pending) != 1 || m.Pending[0].AssignmentID != assignX {
		t.Errorf("loaded %+v", m)
	}
}

// An install the agent finished or undid when it started again is reported with the first heartbeat, like a result
// the loop queued itself; a finished one is remembered as installed, so it is not reported again as already there.
func TestAResultAddedBeforeTheLoopStartsIsSentFirst(t *testing.T) {
	ledger := FileLedger{Path: filepath.Join(t.TempDir(), "state", "installed.json")}
	finished := protocol.InstallResult{SHA256: shaB, OK: true, Steps: []protocol.Step{{Name: protocol.StepWritten, OK: true}}}
	if err := AddResult(ledger, assignX, protocol.InstallResult{SHA256: shaA}, false); err != nil {
		t.Fatal(err)
	}
	// The same assignment again: one result, the last.
	if err := AddResult(ledger, assignX, finished, true); err != nil {
		t.Fatal(err)
	}
	h := newHarness(t, 1)
	h.loop.Ledger = ledger
	h.disk[siteKey] = shaB
	h.work = []protocol.Work{install(assignX, shaB)}
	if err := h.run(); err != nil {
		t.Fatal(err)
	}
	if len(h.applied) != 0 || len(h.results) != 1 || !reflect.DeepEqual(h.results[0], finished) {
		t.Errorf("applied %d, results %+v", len(h.applied), h.results)
	}
	if m, err := ledger.Load(); err != nil || len(m.Pending) != 0 || m.Installed[assignX] != shaB {
		t.Errorf("ledger %+v, %v", m, err)
	}

	// An undone install is not remembered as installed.
	if err := AddResult(ledger, assignY, protocol.InstallResult{SHA256: shaC}, false); err != nil {
		t.Fatal(err)
	}
	if m, _ := ledger.Load(); len(m.Pending) != 1 || m.Installed[assignY] != "" {
		t.Errorf("ledger %+v", m)
	}
	if err := AddResult(ledger, "../join", finished, true); err == nil {
		t.Error("a result that is not an assignment's was added")
	}
}
