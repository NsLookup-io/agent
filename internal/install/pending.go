package install

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/nslookup-io/agent/internal/protocol"
	"github.com/nslookup-io/agent/internal/state"
)

const pendingName = "pending.json"

var (
	siteKeyPattern    = regexp.MustCompile(`^[0-9a-f]{32}$`)
	setNamePattern    = regexp.MustCompile(`^[0-9]{8}T[0-9]{6}\.[0-9]{9}Z$`)
	folderNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{0,63}$`)
)

// pending is an install under way. pending.json is written once the files in place are kept, before the first
// temporary file is written beside them, and removed once the new files are tested and loaded (or the previous ones
// put back): an agent killed in between finds it when it starts again (RecoverPending), removes its temporary files,
// tests again and finishes or undoes the install.
type pending struct {
	AssignmentID string `json:"assignmentId"`
	SHA256       string `json:"sha256"`
	// GiveBack: the install gives a site back to certbot.
	GiveBack bool   `json:"giveBack"`
	SiteKey  string `json:"siteKey"`
	// Set is the directory, under previous/<siteKey>/, of the files as they were before.
	Set string `json:"set"`
	// Intended is what the install makes of each path.
	Intended []intended `json:"intended"`
	Servers  []server   `json:"servers"`
	// Certbot is the record of the site taken over from certbot (a take-over writes it, a give-back removes it); nil
	// when certbot is not concerned.
	Certbot *certbotRecord `json:"certbot"`
	// CertbotMoved: a take-over sets certbot's renewal file aside in this install.
	CertbotMoved bool `json:"certbotMoved"`
	// NewRecord: the take-over's record did not exist before; it goes when the install is undone.
	NewRecord bool `json:"newRecord"`
	// Folder is the folder of a folder certificate (SiteKey is then folder-<its name>); nil for a site.
	Folder    *folderPending `json:"folder,omitempty"`
	StartedAt time.Time      `json:"startedAt"`
}

// folderPending is the folder of a folder certificate being written: its path as configured and its name (the last
// element of the path).
type folderPending struct {
	Path string `json:"path"`
	Name string `json:"name"`
}

// server is a web server an install tests and reloads; HAProxy's test is given the configuration files read.
type server struct {
	Kind           protocol.WebServerKind `json:"kind"`
	HAProxyConfigs []string               `json:"haproxyConfigs,omitempty"`
}

func (h *Host) pendingPath() string { return filepath.Join(h.StateDir, pendingName) }

func (h *Host) writePending(p pending) error {
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	return writeStateFile(h.pendingPath(), data)
}

// readPending reads pending.json; nil when there is none.
func (h *Host) readPending() (*pending, error) {
	data, err := state.ReadFile(h.pendingPath(), maxFile)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var p pending
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("%s is not valid JSON: %w", h.pendingPath(), err)
	}
	switch {
	case !setNamePattern.MatchString(p.Set),
		p.Folder == nil && !siteKeyPattern.MatchString(p.SiteKey),
		p.Folder != nil && !p.Folder.valid(p.SiteKey):
		return nil, fmt.Errorf("%s does not name a set of previous files", h.pendingPath())
	}
	return &p, nil
}

// valid reports whether f is a folder whose sets are under siteKey: a sanitised name, the last element of a clean
// absolute path.
func (f *folderPending) valid(siteKey string) bool {
	return folderNamePattern.MatchString(f.Name) && siteKey == folderKey(f.Name) &&
		path.IsAbs(f.Path) && path.Clean(f.Path) == f.Path && path.Base(f.Path) == f.Name
}

// The reload owed for a folder certificate is noted in reload-owed/<folder name> (its content the certificate's
// SHA-256) from when it fails, or a recovery is about to run it, until one succeeds.

func (h *Host) owedPath(name string) string { return filepath.Join(h.StateDir, "reload-owed", name) }

func (h *Host) reloadOwed(name string) bool {
	_, err := os.Lstat(h.owedPath(name))
	return err == nil
}

func (h *Host) oweReload(name, sha string) {
	if err := writeStateFile(h.owedPath(name), []byte(sha+"\n")); err != nil {
		h.log().Error("a reload still owed could not be noted; the next work does not reload again", "folder", name, "error", err)
	}
}

func (h *Host) settleReload(name string) {
	if err := os.Remove(h.owedPath(name)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		h.log().Error("a reload done could not be noted; the next work reloads again", "folder", name, "error", err)
	}
}

func (h *Host) removePending() {
	if err := os.Remove(h.pendingPath()); err != nil && !errors.Is(err, fs.ErrNotExist) {
		h.log().Error("pending.json could not be removed; the next start tests the install again", "error", err)
	}
}

// maxRestoreTries: previous files that cannot be put back hold up their site for this many tries in all, then are set
// aside.
const maxRestoreTries = 3

// stuck is an install whose previous files could not be put back: blocked/<siteKey>.json. It holds up its own site
// only (never the others, as pending.json would): each install on that site first tries again to put them back, and
// after maxRestoreTries failed tries it is set aside (setStuckAside: blocked/<siteKey>-set-aside-<time>/, its record
// and previous files) and said, so the site can be installed on again.
type stuck struct {
	pending
	Tries     int    `json:"tries"`
	LastError string `json:"lastError"`
}

func (h *Host) stuckPath(siteKey string) string {
	return filepath.Join(h.StateDir, "blocked", siteKey+".json")
}

// readStuck reads the stuck install of siteKey; nil when there is none.
func (h *Host) readStuck(siteKey string) (*stuck, error) {
	p := h.stuckPath(siteKey)
	data, err := state.ReadFile(p, maxFile)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var s stuck
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("%s is not valid JSON: %w", p, err)
	}
	switch {
	case s.SiteKey != siteKey, !setNamePattern.MatchString(s.Set),
		s.Folder == nil && !siteKeyPattern.MatchString(s.SiteKey),
		s.Folder != nil && !s.Folder.valid(s.SiteKey):
		return nil, fmt.Errorf("%s does not name a set of previous files", p)
	}
	return &s, nil
}

// hold notes that the previous files of p could not be put back (why): its site is held up, pending.json goes so the
// other sites are not. It says whether it could (when not, pending.json stays and holds up every install, as before).
func (h *Host) hold(p pending, why error) bool {
	s, err := h.readStuck(p.SiteKey)
	if err != nil || s == nil || s.Set != p.Set {
		s = &stuck{pending: p}
	}
	s.Tries++
	s.LastError = why.Error()
	data, err := json.MarshalIndent(s, "", "  ")
	if err == nil {
		err = writeStateFile(h.stuckPath(p.SiteKey), data)
	}
	if err != nil {
		h.log().Error("an install whose previous files could not be put back could not be noted; every install waits for it", "site", p.SiteKey, "error", err)
		return false
	}
	h.log().Error("the previous files of an install could not be put back; the next install on this site tries again, other sites go on",
		"site", p.SiteKey, "try", s.Tries, "error", why)
	h.removePending()
	return true
}

// unstick tries again to put back the previous files of the stuck install of siteKey, through t, before an install on
// that site: nil when there is none or they are back (the install goes on); otherwise an error that says the try and,
// after the last, that they were set aside (the install then stops; the next goes on).
func (h *Host) unstick(t *tree, siteKey string) error {
	s, err := h.readStuck(siteKey)
	if err != nil {
		aside := h.setStuckAside(siteKey, "")
		return fmt.Errorf("the record of an earlier install on this site that could not be undone cannot be read (%v); it is set aside in %s", err, aside)
	}
	if s == nil {
		return nil
	}
	setDir := filepath.Join(h.setsDir(siteKey), s.Set)
	err = t.restoreSet(setDir)
	if err == nil {
		if s.NewRecord && s.Certbot != nil {
			h.removeRecord(s.Certbot.Name)
		}
		if err := os.Remove(h.stuckPath(siteKey)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			h.log().Error("an install whose previous files are back again could not be noted", "site", siteKey, "error", err)
		}
		h.log().Info("the previous files of an earlier install are back", "site", siteKey)
		return nil
	}
	s.Tries++
	s.LastError = err.Error()
	if s.Tries >= maxRestoreTries {
		aside := h.setStuckAside(siteKey, setDir)
		kept := filepath.Join(aside, "previous")
		h.log().Error("the previous files of an earlier install could not be put back; set aside, the site is installed on again", "site", siteKey,
			"tries", s.Tries, "kept", kept, "error", err)
		return fmt.Errorf("the previous files of an earlier install on this site could not be put back after %d tries (%v); they are kept in %s "+
			"and no longer hold up this site: check its files by hand", s.Tries, err, kept)
	}
	if data, merr := json.MarshalIndent(s, "", "  "); merr == nil {
		if werr := writeStateFile(h.stuckPath(siteKey), data); werr != nil {
			h.log().Error("a try to put back previous files could not be noted", "site", siteKey, "error", werr)
		}
	}
	return fmt.Errorf("the previous files of an earlier install on this site could not be put back (try %d of %d): %v; the next install on "+
		"this site tries again", s.Tries, maxRestoreTries, err)
}

// setStuckAside moves the stuck install of siteKey out of the way, into a directory of its own under blocked/
// (<siteKey>-set-aside-<time>/): its record as record.json and, when setDir is given, its previous files as previous/,
// where pruning the site's sets never reaches them. It returns that directory.
func (h *Host) setStuckAside(siteKey, setDir string) string {
	aside := filepath.Join(h.StateDir, "blocked", siteKey+"-set-aside-"+h.clock().UTC().Format(stampFormat))
	err := os.Mkdir(aside, 0o700)
	if err == nil {
		err = os.Rename(h.stuckPath(siteKey), filepath.Join(aside, "record.json"))
	}
	if err == nil && setDir != "" {
		err = os.Rename(setDir, filepath.Join(aside, "previous"))
	}
	if err != nil {
		h.log().Error("an install that could not be undone could not be set aside", "site", siteKey, "error", err)
	}
	return aside
}

// setAside moves a pending.json that cannot be used out of the way (pending.json.unusable-<time>), so installs go on.
func (h *Host) setAside(now time.Time) string {
	aside := h.pendingPath() + ".unusable-" + now.UTC().Format(stampFormat)
	if err := os.Rename(h.pendingPath(), aside); err != nil {
		h.log().Error("pending.json could not be set aside", "error", err)
	}
	return aside
}

// removeTemps removes the temporary files an interrupted install left beside the paths it changes (named
// .<file name>.nslookup-agent-…, see stageOne), through the tree: in an HAProxy crt directory HAProxy would load them.
func (t *tree) removeTemps(list []intended) {
	for _, want := range list {
		d, base, err := t.at(want.Path)
		if err != nil {
			continue
		}
		names, err := d.names()
		if err != nil {
			continue
		}
		for _, name := range names {
			if !strings.HasPrefix(name, "."+base+tempMark) {
				continue
			}
			if err := d.remove(name); err != nil && !errors.Is(err, fs.ErrNotExist) {
				t.host.log().Warn("a temporary file could not be removed", "file", path.Join(d.real, name), "error", err)
			}
		}
	}
}
