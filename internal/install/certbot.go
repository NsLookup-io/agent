package install

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/nslookup-io/agent/internal/protocol"
	"github.com/nslookup-io/agent/internal/state"
)

// certbot: a site whose files are certbot's (links under /etc/letsencrypt/live/<name>/ into archive/) is taken over
// by setting its renewal file aside (renewal/<name>.conf → <name>.conf.nslookup-disabled, which certbot skips) and
// replacing the links the site uses with real files; given back by moving the renewal file back and making the links
// again, as the record of the take-over says. No other certbot file, and no other name, is touched.

const (
	certbotLive    = "/etc/letsencrypt/live/"
	certbotRenewal = "/etc/letsencrypt/renewal/"
	disabledSuffix = ".nslookup-disabled"
	maxCertbotName = 255
)

// certbotRecord is what a take-over did: /var/lib/nslookup-agent/certbot/<name>.json.
type certbotRecord struct {
	Name    string `json:"name"`
	SiteKey string `json:"siteKey"`
	// Renewal is certbot's renewal file for the name, set aside while Autopilot renews it; "" when there was none.
	Renewal string        `json:"renewal"`
	Links   []certbotLink `json:"links"`
	TakenAt time.Time     `json:"takenAt"`
}

// certbotLink is a link of live/<name>/ the take-over replaced, and what it pointed at.
type certbotLink struct {
	Path   string `json:"path"`
	Target string `json:"target"`
}

// certbotNameOf is the certbot name of a file directly under /etc/letsencrypt/live/<name>/.
func certbotNameOf(p string) (string, bool) {
	rest, ok := strings.CutPrefix(p, certbotLive)
	if !ok {
		return "", false
	}
	name, file, ok := strings.Cut(rest, "/")
	if !ok || name == "" || name == "." || name == ".." || len(name) > maxCertbotName || file == "" || strings.Contains(file, "/") {
		return "", false
	}
	return name, true
}

func renewalFile(name string) string { return certbotRenewal + name + ".conf" }

func (h *Host) recordPath(name string) string {
	return filepath.Join(h.StateDir, "certbot", name+".json")
}

// readRecord reads the record of the take-over of name; nil when there is none. A record that names anything but
// name's own files is refused.
func (h *Host) readRecord(name string) (*certbotRecord, error) {
	data, err := state.ReadFile(h.recordPath(name), maxFile)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var r certbotRecord
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("%s is not valid JSON: %w", h.recordPath(name), err)
	}
	ok := r.Name == name && (r.Renewal == "" || r.Renewal == renewalFile(name))
	for _, l := range r.Links {
		n, under := certbotNameOf(l.Path)
		ok = ok && under && n == name && l.Target != ""
	}
	if !ok {
		return nil, fmt.Errorf("%s names files that are not certbot's for %s", h.recordPath(name), name)
	}
	return &r, nil
}

func (h *Host) writeRecord(r *certbotRecord) error {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(h.recordPath(r.Name)), 0o700); err != nil {
		return err
	}
	return writeStateFile(h.recordPath(r.Name), data)
}

func (h *Host) removeRecord(name string) {
	if err := os.Remove(h.recordPath(name)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		h.log().Warn("the record of a take-over from certbot could not be removed", "name", name, "error", err)
	}
}

// takeOver is what taking the site over from certbot does besides writing its files: the links among files directly
// under live/<name>/ (name from the site's certificate path) may be replaced by real files (links), and certbot's
// renewal file is set aside (moves). rec is the record to write first (nil: nothing of certbot's changes, as in a
// renewal after the take-over), isNew when there was none. A site whose certificate is not under live/ has nothing of
// certbot's to take over. Every look goes through the tree.
func (t *tree) takeOver(site protocol.Site, files []file, now time.Time) (links map[string]bool, moves []change, rec *certbotRecord, isNew bool, err error) {
	name, ok := certbotNameOf(*site.CertPath)
	if !ok {
		return nil, nil, nil, false, nil
	}
	rec, err = t.host.readRecord(name)
	if err != nil {
		return nil, nil, nil, false, err
	}
	isNew = rec == nil
	if isNew {
		rec = &certbotRecord{Name: name}
	}
	changed := isNew || rec.SiteKey != site.SiteKey
	links = map[string]bool{}
	for _, f := range files {
		if n, under := certbotNameOf(f.path); !under || n != name {
			continue
		}
		d, base, err := t.at(f.path)
		if err != nil {
			return nil, nil, nil, false, err
		}
		if e, err := d.stat(base); err != nil || e.kind != kindLink {
			continue
		}
		target, err := d.readlink(base)
		if err != nil {
			return nil, nil, nil, false, err
		}
		links[f.path] = true
		rec.Links = slices.DeleteFunc(rec.Links, func(l certbotLink) bool { return l.Path == f.path })
		rec.Links = append(rec.Links, certbotLink{Path: f.path, Target: target})
		changed = true
	}
	conf := renewalFile(name)
	disabled := conf + disabledSuffix
	confErr, disabledErr := error(fs.ErrNotExist), error(fs.ErrNotExist)
	var confEntry entry
	// No renewal directory: certbot renews nothing here. One others can change: refused.
	switch d, confName, err := t.at(conf); {
	case err == nil:
		confEntry, confErr = d.stat(confName)
		_, disabledErr = d.stat(path.Base(disabled))
	case !errors.Is(err, fs.ErrNotExist):
		return nil, nil, nil, false, err
	}
	switch {
	case confErr == nil && confEntry.kind != kindFile:
		return nil, nil, nil, false, fmt.Errorf("%s is not a regular file", conf)
	case confErr == nil && disabledErr == nil:
		return nil, nil, nil, false, fmt.Errorf("both %s and %s exist; remove the one certbot should not use", conf, disabled)
	case confErr == nil:
		moves = append(moves, change{path: disabled, from: conf, was: stateAbsent})
		rec.Renewal, changed = conf, true
	case !errors.Is(confErr, fs.ErrNotExist):
		return nil, nil, nil, false, confErr
	case disabledErr == nil && rec.Renewal != conf:
		rec.Renewal, changed = conf, true
	}
	if !changed || (isNew && len(rec.Links) == 0 && rec.Renewal == "") {
		return links, moves, nil, false, nil
	}
	rec.SiteKey, rec.TakenAt = site.SiteKey, now.UTC()
	return links, moves, rec, isNew, nil
}

// giveBack is what giving the site back to certbot changes, from the record of its take-over: each link made again
// (certbot's file must still be there), the renewal file moved back. Done already: no change; with no record left,
// rec is nil (name says which certbot certificate). Every look goes through the tree.
func (t *tree) giveBack(site protocol.Site) (changes []change, rec *certbotRecord, name string, err error) {
	if site.CertPath == nil {
		return nil, nil, "", errors.New("this site names no certificate file")
	}
	name, ok := certbotNameOf(*site.CertPath)
	if !ok {
		return nil, nil, "", errors.New("this site's certificate is not in certbot's live directory")
	}
	if rec, err = t.host.readRecord(name); err != nil {
		return nil, nil, "", err
	}
	if rec == nil {
		if t.certbotRenews(site, name) {
			return nil, nil, name, nil
		}
		return nil, nil, "", fmt.Errorf("there is no record of taking %s over from certbot", name)
	}
	if other := t.host.stillRenewing(rec, site); other != "" {
		return nil, nil, "", fmt.Errorf("certbot's certificate %s is also used by a site Autopilot still renews (%s); it goes back to certbot "+
			"once no such site uses it: give that site back too", name, other)
	}
	for _, l := range rec.Links {
		d, base, err := t.at(l.Path)
		if err != nil {
			return nil, nil, "", err
		}
		c := change{path: l.Path, target: l.Target, uid: -1, gid: -1, was: stateFile}
		e, err := d.stat(base)
		switch {
		case err == nil && e.kind == kindLink:
			if target, _ := d.readlink(base); target == l.Target {
				continue
			}
			return nil, nil, "", fmt.Errorf("%s links somewhere else now", l.Path)
		case err == nil && e.kind != kindFile:
			return nil, nil, "", fmt.Errorf("%s is not a regular file", l.Path)
		case errors.Is(err, fs.ErrNotExist):
			c.was = stateAbsent
		case err != nil:
			return nil, nil, "", err
		}
		target := linkedPath(d, l.Target)
		td, tname, err := t.at(target)
		if err != nil {
			return nil, nil, "", err
		}
		if e, err := td.stat(tname); err != nil || e.kind != kindFile {
			return nil, nil, "", fmt.Errorf("certbot's file %s is gone, so %s cannot link to it again", target, l.Path)
		}
		changes = append(changes, c)
	}
	if rec.Renewal != "" {
		d, confName, err := t.at(rec.Renewal)
		if err != nil {
			return nil, nil, "", err
		}
		_, confErr := d.stat(confName)
		_, disabledErr := d.stat(confName + disabledSuffix)
		switch {
		case confErr == nil:
		case disabledErr == nil:
			changes = append(changes, change{path: rec.Renewal, from: rec.Renewal + disabledSuffix, was: stateAbsent})
		default:
			return nil, nil, "", fmt.Errorf("certbot's renewal file for %s is gone (%s)", name, rec.Renewal+disabledSuffix)
		}
	}
	return changes, rec, name, nil
}

// certbotRenews reports whether certbot renews the site as it is: its files under live/<name>/ are links (certbot's
// layout) and renewal/<name>.conf is there. So it is when it was given back already, or never taken over.
func (t *tree) certbotRenews(site protocol.Site, name string) bool {
	links := 0
	for _, p := range []*string{site.CertPath, site.KeyPath, site.ChainPath} {
		if p == nil {
			continue
		}
		if n, under := certbotNameOf(*p); !under || n != name {
			continue
		}
		d, base, err := t.at(*p)
		if err != nil {
			return false
		}
		if e, err := d.stat(base); err != nil || e.kind != kindLink {
			return false
		}
		links++
	}
	d, conf, err := t.at(renewalFile(name))
	if err != nil {
		return false
	}
	e, err := d.stat(conf)
	return links > 0 && err == nil && e.kind == kindFile
}

// SetAssigned tells the host which sites the server assigns certificates to now (the sites of its install work): a
// certbot name another of them still uses is not given back.
func (h *Host) SetAssigned(siteKeys []string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.assigned = map[string]bool{}
	for _, k := range siteKeys {
		h.assigned[k] = true
	}
}

// stillRenewing names (by its configuration file) a site other than site that the server still assigns certificates
// to and whose files are among those taken over from certbot with rec: Autopilot still renews them, so certbot must not
// get the name back yet. "" when there is none.
func (h *Host) stillRenewing(rec *certbotRecord, site protocol.Site) string {
	own := map[string]bool{}
	for _, p := range []*string{site.CertPath, site.KeyPath, site.ChainPath} {
		if p != nil {
			own[*p] = true
		}
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, key := range slices.Sorted(maps.Keys(h.assigned)) {
		if key == site.SiteKey {
			continue
		}
		for _, u := range h.uses[key] {
			for _, p := range []string{u.CertPath, u.KeyPath, u.ChainPath} {
				if p != "" && !own[p] && slices.ContainsFunc(rec.Links, func(l certbotLink) bool { return l.Path == p }) {
					return u.ConfigPath
				}
			}
		}
	}
	return ""
}
