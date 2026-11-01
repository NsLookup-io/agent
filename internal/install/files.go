package install

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/nslookup-io/agent/internal/state"
)

const (
	// keptSets: the previous files of a site are kept for its last two installs.
	keptSets = 2
	// maxFile: no file an install replaces or reads is larger (certificates, keys and certbot's renewal files are a
	// few kilobytes).
	maxFile = 1 << 20
	// tempMark is in the name of every temporary file the agent puts beside a file it replaces.
	tempMark = ".nslookup-agent-"
	// keyModeMax and certModeMax: a key file never gets more than 0640, a certificate file that replaces a link never
	// more than 0644.
	keyModeMax  = 0o640
	certModeMax = 0o644
	setManifest = "set.json"
	stampFormat = "20060102T150405.000000000Z"
)

// change is one change an install makes to a path (as configured, absolute): a regular file written (data, with mode,
// uid and gid), a symbolic link made (target), or the file at from moved here. was (and wasTarget for a link) is what
// the path held when the change was planned: the install goes ahead only while it still does.
type change struct {
	path      string
	data      []byte
	mode      fs.FileMode
	uid, gid  int
	target    string
	from      string
	was       string
	wasTarget string
}

func (c change) isLink() bool { return c.target != "" }
func (c change) isMove() bool { return c.from != "" }

// abs is a configured path on this machine's file system (for reading what a site serves; installs go through a tree).
func (h *Host) abs(p string) string { return filepath.Join(h.Root, filepath.FromSlash(p)) }

// writeChange is the change writing f over the file at its path, keeping its owner, group and mode; a key's mode
// never gets a permission it did not have, nor more than 0640. A symbolic link is replaced only when replaceLink says
// so (certbot's, in a take-over): the link itself, never what it points at; the file then gets the owner, group and
// mode of the file the link points at, reached through the tree too (a certificate's at most 0644). Anything else
// that is not a regular file is refused. The file is looked at through one descriptor, opened without following a
// link, in its directory reached through the tree.
func (t *tree) writeChange(f file, replaceLink bool) (change, error) {
	d, name, err := t.at(f.path)
	if err != nil {
		return change{}, err
	}
	c := change{path: f.path, data: f.data, was: stateFile}
	fd, err := d.open(name)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return change{}, fmt.Errorf("%s does not exist", f.path)
	case errors.Is(err, errLink) && replaceLink:
		raw, err := d.readlink(name)
		if err != nil {
			return change{}, err
		}
		target := linkedPath(d, raw)
		td, tname, err := t.at(target)
		if err != nil {
			return change{}, err
		}
		e, err := td.stat(tname)
		if err != nil || e.kind != kindFile {
			return change{}, fmt.Errorf("%s links to %s, which is not a regular file", f.path, target)
		}
		c.mode, c.uid, c.gid = e.perm&certModeMax, e.uid, e.gid
		c.was, c.wasTarget = stateLink, raw
	case errors.Is(err, errLink):
		return change{}, fmt.Errorf("%s is a symbolic link; the agent does not write through links", f.path)
	case err != nil:
		return change{}, err
	default:
		info, err := fd.Stat()
		fd.Close()
		if err != nil {
			return change{}, err
		}
		if !info.Mode().IsRegular() {
			return change{}, fmt.Errorf("%s is not a regular file", f.path)
		}
		c.mode = info.Mode().Perm()
		c.uid, c.gid = owner(info)
	}
	if f.key {
		c.mode &= keyModeMax
	}
	return c, nil
}

// linkedPath is the path (from the root) of what a link in d with the text raw points at.
func linkedPath(d *dir, raw string) string {
	if path.IsAbs(raw) {
		return path.Clean(raw)
	}
	return path.Join(d.real, raw)
}

// owner is the user and group owning a file; -1 when they cannot be told.
func owner(info fs.FileInfo) (uid, gid int) {
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		return int(st.Uid), int(st.Gid)
	}
	return -1, -1
}

// kept is a path as it was before an install: a regular file (its content in the set's file Data), a symbolic link
// (Target) or nothing.
type kept struct {
	Path   string      `json:"path"`
	State  string      `json:"state"`
	Mode   fs.FileMode `json:"mode,omitempty"`
	UID    int         `json:"uid"`
	GID    int         `json:"gid"`
	Target string      `json:"target,omitempty"`
	Data   string      `json:"data,omitempty"`
	SHA256 string      `json:"sha256,omitempty"`
}

const (
	stateFile   = "file"
	stateLink   = "link"
	stateAbsent = "absent"
)

// set is the previous files of one install: previous/<siteKey>/<UTC time>/, a manifest and each file's content.
type set struct {
	SiteKey string    `json:"siteKey"`
	SavedAt time.Time `json:"savedAt"`
	Files   []kept    `json:"files"`
}

func (s set) find(p string) kept {
	for _, k := range s.Files {
		if k.Path == p {
			return k
		}
	}
	return kept{}
}

func (h *Host) setsDir(siteKey string) string { return filepath.Join(h.StateDir, "previous", siteKey) }

// saveSet keeps paths as they are now in a new set of the site, and returns its directory. Nothing is left of a set
// that could not be saved whole.
func (t *tree) saveSet(siteKey string, paths []string, now time.Time) (dir string, s set, err error) {
	parent := t.host.setsDir(siteKey)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return "", s, err
	}
	if err := os.Chmod(parent, 0o700); err != nil {
		return "", s, err
	}
	for stamp := now.UTC(); ; stamp = stamp.Add(time.Nanosecond) {
		dir = filepath.Join(parent, stamp.Format(stampFormat))
		if err = os.Mkdir(dir, 0o700); !errors.Is(err, fs.ErrExist) {
			break
		}
	}
	if err != nil {
		return "", s, err
	}
	defer func() {
		if err != nil {
			os.RemoveAll(dir)
		}
	}()
	s = set{SiteKey: siteKey, SavedAt: now.UTC()}
	for i, p := range paths {
		k, err := t.keep(dir, strconv.Itoa(i), p)
		if err != nil {
			return "", s, fmt.Errorf("%s: %w", p, err)
		}
		s.Files = append(s.Files, k)
	}
	manifest, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return "", s, err
	}
	if err := writeStateFile(filepath.Join(dir, setManifest), manifest); err != nil {
		return "", s, err
	}
	return dir, s, nil
}

// keep puts the path's current state in the set dir, its content (a regular file) in the set's file name. The file is
// read through one descriptor opened without following a link: a link is kept as a link, never what it points at.
func (t *tree) keep(setDir, name, p string) (kept, error) {
	d, base, err := t.at(p)
	if err != nil {
		return kept{}, err
	}
	data, info, err := d.read(base)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return kept{Path: p, State: stateAbsent}, nil
	case errors.Is(err, errLink):
		e, err := d.stat(base)
		if err != nil {
			return kept{}, err
		}
		target, err := d.readlink(base)
		if err != nil {
			return kept{}, err
		}
		return kept{Path: p, State: stateLink, Target: target, UID: e.uid, GID: e.gid}, nil
	case err != nil:
		return kept{}, err
	}
	defer clear(data)
	if err := writeStateFile(filepath.Join(setDir, name), data); err != nil {
		return kept{}, err
	}
	uid, gid := owner(info)
	return kept{Path: p, State: stateFile, Mode: info.Mode().Perm(), UID: uid, GID: gid, Data: name, SHA256: sha256Hex(data)}, nil
}

// readSet reads the set in dir.
func readSet(dir string) (set, error) {
	var s set
	data, err := state.ReadFile(filepath.Join(dir, setManifest), maxFile)
	if err != nil {
		return s, err
	}
	if err := json.Unmarshal(data, &s); err != nil {
		return s, fmt.Errorf("%s: %w", dir, err)
	}
	for _, k := range s.Files {
		if !filepath.IsAbs(filepath.FromSlash(k.Path)) || (k.State == stateFile && (k.Data == "" || strings.ContainsAny(k.Data, `/\`) || k.Data == "..")) {
			return s, fmt.Errorf("%s: the manifest is not well formed", dir)
		}
	}
	return s, nil
}

// pruneSets keeps the site's last two sets.
func (h *Host) pruneSets(siteKey string) {
	parent := h.setsDir(siteKey)
	entries, err := os.ReadDir(parent)
	if err != nil {
		return
	}
	var sets []string
	for _, e := range entries {
		if e.IsDir() {
			sets = append(sets, e.Name())
		}
	}
	slices.Sort(sets)
	for _, name := range sets[:max(0, len(sets)-keptSets)] {
		if err := os.RemoveAll(filepath.Join(parent, name)); err != nil {
			h.log().Warn("an old set of previous files could not be removed", "set", filepath.Join(parent, name), "error", err)
		}
	}
}

// restoreSet puts every path of the set in dir back as it was, through the tree. It goes on after a path that fails,
// and says which.
func (t *tree) restoreSet(dir string) error {
	s, err := readSet(dir)
	if err != nil {
		return err
	}
	var errs []error
	for _, k := range s.Files {
		if err := t.restore(dir, k); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", k.Path, err))
		}
	}
	return errors.Join(errs...)
}

func (t *tree) restore(setDir string, k kept) error {
	d, name, err := t.at(k.Path)
	if err != nil {
		return err
	}
	switch k.State {
	case stateAbsent:
		if err := d.remove(name); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		d.sync()
		return nil
	case stateLink:
		return t.put(change{path: k.Path, target: k.Target, uid: k.UID, gid: k.GID})
	case stateFile:
		data, err := state.ReadFile(filepath.Join(setDir, k.Data), maxFile)
		if err != nil {
			return err
		}
		defer clear(data)
		return t.put(change{path: k.Path, data: data, mode: k.Mode, uid: k.UID, gid: k.GID})
	}
	return fmt.Errorf("unknown state %q", k.State)
}

// put writes one file or link change in place at once (staged, then renamed).
func (t *tree) put(c change) error {
	st, err := t.stageOne(c)
	if err != nil {
		return err
	}
	if err := st.dir.rename(st.temp, st.name); err != nil {
		st.dir.remove(st.temp)
		return err
	}
	st.dir.sync()
	return nil
}

// staged is a change ready to be put in place: its directory, its name there and its temporary file or link beside it
// (none for a move, whose from is fromName in the same directory).
type staged struct {
	change
	dir            *dir
	name, fromName string
	temp           string
}

// stage writes every file and link change to a temporary file beside its path, owner, group and mode set, and checks
// each move can be made (within one directory). Nothing is left of what was staged when one fails.
func (t *tree) stage(changes []change) ([]staged, error) {
	var out []staged
	fail := func(err error) ([]staged, error) {
		t.unstage(out)
		return nil, err
	}
	for _, c := range changes {
		if !c.isMove() {
			st, err := t.stageOne(c)
			if err != nil {
				return fail(fmt.Errorf("%s: %w", c.path, err))
			}
			out = append(out, st)
			continue
		}
		d, name, err := t.at(c.path)
		if err != nil {
			return fail(err)
		}
		from, fromName, err := t.at(c.from)
		if err != nil {
			return fail(err)
		}
		if from != d {
			return fail(fmt.Errorf("%s and %s are not in one directory", c.from, c.path))
		}
		if e, err := d.stat(fromName); err != nil || e.kind != kindFile {
			return fail(fmt.Errorf("%s is not a regular file", c.from))
		}
		if _, err := d.stat(name); !errors.Is(err, fs.ErrNotExist) {
			return fail(fmt.Errorf("%s is in the way", c.path))
		}
		out = append(out, staged{change: c, dir: d, name: name, fromName: fromName})
	}
	return out, nil
}

// stageOne writes c to a temporary file (or link) in its path's directory: written, synced, owned and moded as c says
// through its descriptor (created 0600, so no one else can read a key while it is written).
func (t *tree) stageOne(c change) (staged, error) {
	d, name, err := t.at(c.path)
	if err != nil {
		return staged{}, err
	}
	st := staged{change: c, dir: d, name: name}
	if c.isLink() {
		if st.temp, err = d.symlinkTemp(name, c.target); err != nil {
			return staged{}, err
		}
		if err := t.host.setOwner(c, func(uid, gid int) error { return d.lchown(st.temp, uid, gid) }); err != nil {
			d.remove(st.temp)
			return staged{}, err
		}
		return st, nil
	}
	f, temp, err := d.createTemp(name)
	if err != nil {
		return staged{}, err
	}
	st.temp = temp
	if err := writeOpen(f, c.data, func() error { return t.host.setOwner(c, f.Chown) }, c.mode); err != nil {
		d.remove(temp)
		return staged{}, err
	}
	return st, nil
}

// writeOpen writes data to f, syncs it, sets its owner (chown) and mode through its descriptor, and closes it.
func writeOpen(f *os.File, data []byte, chown func() error, mode fs.FileMode) error {
	_, err := f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	if err == nil && chown != nil {
		err = chown()
	}
	if err == nil {
		err = f.Chmod(mode)
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	return err
}

// setOwner gives c's temporary file (through chown, its descriptor's) the owner c says; nothing when it does not say
// (-1).
func (h *Host) setOwner(c change, chown func(uid, gid int) error) error {
	if c.uid < 0 && c.gid < 0 {
		return nil
	}
	if h.chown != nil {
		return h.chown(c.path, c.uid, c.gid)
	}
	return chown(c.uid, c.gid)
}

func (t *tree) unstage(st []staged) {
	for _, s := range st {
		if s.temp != "" {
			if err := s.dir.remove(s.temp); err != nil && !errors.Is(err, fs.ErrNotExist) {
				t.host.log().Warn("a temporary file could not be removed", "file", path.Join(s.dir.real, s.temp), "error", err)
			}
		}
	}
}

// commit puts the staged changes in place, in order, each renamed within its directory. On a failure the rest are not
// put in place (their temporary files removed); the caller puts back the previous files.
func (t *tree) commit(st []staged) error {
	dirs := map[*dir]bool{}
	for i, s := range st {
		var err error
		if s.isMove() {
			if _, e := s.dir.stat(s.name); !errors.Is(e, fs.ErrNotExist) {
				err = fmt.Errorf("%s is in the way", s.path)
			} else {
				err = s.dir.rename(s.fromName, s.name)
			}
		} else {
			err = s.dir.rename(s.temp, s.name)
		}
		if err != nil {
			t.unstage(st[i:])
			return fmt.Errorf("%s could not be put in place: %w", s.path, err)
		}
		dirs[s.dir] = true
	}
	for d := range dirs {
		d.sync()
	}
	return nil
}

// intended is what a path holds once an install is in place: a file with this SHA-256, a link to this target, nothing.
type intended struct {
	Path   string `json:"path"`
	State  string `json:"state"`
	SHA256 string `json:"sha256,omitempty"`
	Target string `json:"target,omitempty"`
}

// intendedOf is what the changes make of their paths; s is the set kept before them (a move's file is the one kept).
func intendedOf(changes []change, s set) []intended {
	var out []intended
	for _, c := range changes {
		switch {
		case c.isMove():
			out = append(out, intended{Path: c.path, State: stateFile, SHA256: s.find(c.from).SHA256}, intended{Path: c.from, State: stateAbsent})
		case c.isLink():
			out = append(out, intended{Path: c.path, State: stateLink, Target: c.target})
		default:
			out = append(out, intended{Path: c.path, State: stateFile, SHA256: sha256Hex(c.data)})
		}
	}
	return out
}

// inPlace reports whether every path holds what the install made of it.
func (t *tree) inPlace(list []intended) bool {
	for _, want := range list {
		d, name, err := t.at(want.Path)
		if err != nil {
			return false
		}
		e, err := d.stat(name)
		switch want.State {
		case stateAbsent:
			if !errors.Is(err, fs.ErrNotExist) {
				return false
			}
		case stateLink:
			if err != nil || e.kind != kindLink {
				return false
			}
			if target, err := d.readlink(name); err != nil || target != want.Target {
				return false
			}
		case stateFile:
			data, _, err := d.read(name)
			match := err == nil && sha256Hex(data) == want.SHA256
			clear(data)
			if !match {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// readRegular reads the regular file at p, a link to one included, at most maxFile bytes, without waiting on a named
// pipe: what a site's certificate file holds now (certbot's are links). The agent's own files are read with
// state.ReadFile, never through a link.
func readRegular(p string) ([]byte, error) {
	f, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, _, err := readOpen(f)
	return data, err
}

// writeStateFile writes a file of the agent's own (0600) in place at once: temporary file, sync, rename, directory
// sync.
func writeStateFile(p string, data []byte) error {
	dir := filepath.Dir(p)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, "."+filepath.Base(p)+".tmp-*")
	if err != nil {
		return err
	}
	if err := writeOpen(f, data, nil, 0o600); err != nil {
		os.Remove(f.Name())
		return err
	}
	if err := os.Rename(f.Name(), p); err != nil {
		os.Remove(f.Name())
		return err
	}
	syncDir(dir)
	return nil
}

// syncDir makes the renames in dir last through a power cut, as far as the file system can (pending.json covers the
// rest).
func syncDir(dir string) {
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		d.Close()
	}
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func randomHex() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
