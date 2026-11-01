package install

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"strings"

	"github.com/nslookup-io/agent/internal/inventory"
	"github.com/nslookup-io/agent/internal/protocol"
)

const (
	// maxFolderName is the longest folder name kept.
	maxFolderName = 64
	// folderPerm is the mode of a folder the agent makes: its own and its group's to read.
	folderPerm = 0o750
	// newCertMode and newKeyMode are the modes of files written where there were none.
	newCertMode = 0o644
	newKeyMode  = 0o600
	// notSetUp is a folder work's result on a server whose agent.yaml sets no folder.root.
	notSetUp = "folder mode isn't set up on this server: set folder.root in /etc/nslookup-agent/agent.yaml"
)

// Folder writes folder certificates (folder mode), for what the agent cannot read the configuration of: a web server
// in another container (a Docker agent), or Postfix, Dovecot, a Java application on a server. Each certificate goes
// into a folder of its own under Root as fullchain.pem (the certificate and its chain), cert.pem, chain.pem and
// privkey.pem, then a reload defined on this machine runs: agent.yaml's folder.hook (on a server) or a signal to
// containers through the Docker socket (Docker).
//
// The server names only the folder, which FolderName sanitises: Root, the hook and the containers come from this
// machine's agent.yaml or the container's environment. The files are written as on a site: through directories only
// root or the agent's user can change, each staged beside its path and renamed into place, owner, group and mode kept
// (a key never wider than it was, nor than 0640), the previous files kept (the last two sets, under
// previous/folder-<name>/), and pending.json from the first file written until the reload has run. Not for concurrent
// installs, nor beside one of Host's.
type Folder struct {
	// Host writes the files: its Root, StateDir, DirOwner and Log are used, and its Runner runs Hook.
	Host *Host
	// Root is the directory the folders are in (agent.yaml folder.root; /certs in Docker): an absolute path other than
	// /. "" = folder mode is not set up.
	Root string
	// Hook is agent.yaml's folder.hook (on a server); "" = none.
	Hook string
	// Reload signals containers (Docker); nil = none.
	Reload *DockerReload
}

// FolderName is the folder w's certificate is written to, under the root: its folderName lowercased with only
// [a-z0-9.-] kept, leading dots and dashes stripped, at most 64 characters; the assignment id when nothing is left. So
// it never holds a "/", is never "." or "..", never names a hidden file and never reads as an option (a hook gets it
// as NSL_CERTIFICATE).
func FolderName(w protocol.Work) string {
	keep := func(s string) string {
		s = strings.Map(func(r rune) rune {
			if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '.' || r == '-' {
				return r
			}
			return -1
		}, strings.ToLower(s))
		s = strings.TrimLeft(s, ".-")
		return s[:min(len(s), maxFolderName)]
	}
	if w.FolderName != nil {
		if name := keep(*w.FolderName); name != "" {
			return name
		}
	}
	return keep(w.AssignmentID)
}

// FolderOf is the folder w's certificate is written to (FolderName).
func (f *Folder) FolderOf(w protocol.Work) string { return FolderName(w) }

// folderKey is the name a folder's sets of previous files are kept under (previous/<key>/), and its key in
// pending.json: never a site's (32 hex characters).
func folderKey(name string) string { return "folder-" + name }

// DiskSHA is the SHA-256 of the leaf certificate (the first) in w's fullchain.pem: "" when the folder, the file or a
// certificate in it is not there (or folder mode is not set up), an error when it cannot be read through directories
// only root or the agent's user can change.
func (f *Folder) DiskSHA(w protocol.Work) (string, error) {
	name := FolderName(w)
	if f.Root == "" || name == "" {
		return "", nil
	}
	t := f.Host.newTree()
	defer t.close()
	folder := path.Join(f.Root, name)
	if err := t.folderIsDirectory(folder); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return "", nil
		}
		return "", err
	}
	d, base, err := t.at(path.Join(folder, "fullchain.pem"))
	if err != nil {
		return "", err
	}
	data, _, err := d.read(base)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return "", nil
	case errors.Is(err, errLink):
		return "", fmt.Errorf("%s/fullchain.pem is a symbolic link", folder)
	case err != nil:
		return "", fmt.Errorf("%s/fullchain.pem: %w", folder, err)
	}
	defer clear(data)
	return LeafSHA(data), nil
}

// Apply writes b into w's folder (made when it is not there), then reloads, and says how it went: a failed reload is
// a failed hook_ran step, the files stay and the reload is owed (ReloadOwed). Files already holding b (a reload owed)
// are not written again: only the reload runs. No Docker socket mounted is a hook_ran step that says to reload by
// hand; the install still counts. From the first file written to the end of the reload it runs on its own time,
// whatever happens to ctx.
func (f *Folder) Apply(ctx context.Context, w protocol.Work, b protocol.Bundle) protocol.InstallResult {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), opTimeout)
	defer cancel()
	var o Outcome
	if f.Root == "" {
		o.Fail(protocol.StepWritten, notSetUp)
		return o.Result(false)
	}
	c, err := checkBundle(b.CertPEM, b.ChainPEM, b.KeyPEM, w.SHA256, nil, f.Host.clock())
	if err != nil {
		o.Fail(protocol.StepChecked, err.Error())
		return o.Result(false)
	}
	defer c.clear()
	t := f.Host.newTree()
	defer t.close()
	op, err := f.plan(t, FolderName(w), c, w)
	if err != nil {
		o.OK(protocol.StepChecked, "")
		o.Fail(protocol.StepWritten, "nothing was written: "+err.Error())
		return o.Result(false)
	}
	defer op.clear()
	if t.inPlace(intendedOf(op.changes, set{})) {
		o.OK(protocol.StepChecked, "already in place")
		f.reloadOwing(ctx, op.Folder, w.SHA256, &o)
		return o.Result(o.message == nil)
	}
	o.OK(protocol.StepChecked, "")
	if !f.Host.write(ctx, op, &o) {
		return o.Result(false)
	}
	f.reloadOwing(ctx, op.Folder, w.SHA256, &o)
	f.Host.removePending()
	return o.Result(o.message == nil)
}

// CanInstall says, before the bundle is fetched, why the agent cannot write w's folder certificate here (nil: it may
// try): folder mode is not set up.
func (f *Folder) CanInstall(w protocol.Work) error {
	if f.Root == "" {
		return errors.New(notSetUp)
	}
	return nil
}

// ReloadOwed reports whether what uses w's folder was not reloaded since its files were last written: the reload
// failed, or the agent was stopped while it ran. The next Apply of the certificate then only reloads.
func (f *Folder) ReloadOwed(w protocol.Work) bool {
	name := FolderName(w)
	return name != "" && f.Host.reloadOwed(name)
}

// plan plans writing c into the folder name under the root, which it makes when it is not there.
func (f *Folder) plan(t *tree, name string, c *certificate, w protocol.Work) (*operation, error) {
	if !path.IsAbs(f.Root) || path.Clean(f.Root) != f.Root || f.Root == "/" {
		return nil, fmt.Errorf("the folder root %q is not an absolute path to a directory other than /", f.Root)
	}
	if name == "" {
		return nil, errors.New("this work names no folder")
	}
	folder := path.Join(f.Root, name)
	if err := t.makeFolder(folder); err != nil {
		return nil, err
	}
	op := &operation{
		pending: pending{AssignmentID: w.AssignmentID, SHA256: w.SHA256, SiteKey: folderKey(name), Folder: &folderPending{Path: folder, Name: name}},
		tree:    t,
	}
	files := []file{
		{path: path.Join(folder, "fullchain.pem"), data: cat(c.leaf, c.chain)},
		{path: path.Join(folder, "cert.pem"), data: bytes.Clone(c.leaf)},
		{path: path.Join(folder, "chain.pem"), data: bytes.Clone(c.chain)},
		{path: path.Join(folder, "privkey.pem"), data: bytes.Clone(c.key), key: true},
	}
	for _, file := range files {
		ch, err := t.folderChange(file)
		if err != nil {
			for _, f := range files {
				clear(f.data)
			}
			return nil, err
		}
		op.changes = append(op.changes, ch)
	}
	return op, nil
}

// makeFolder makes the folder (folderPerm, the agent's) in its root when it is not there.
func (t *tree) makeFolder(folder string) error {
	err := t.folderIsDirectory(folder)
	if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	d, name, err := t.at(folder)
	if errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("%s does not exist", path.Dir(folder))
	}
	if err != nil {
		return err
	}
	if err := d.mkdir(name, folderPerm); err != nil && !errors.Is(err, fs.ErrExist) {
		return fmt.Errorf("%s could not be made: %w", folder, err)
	}
	return nil
}

// folderIsDirectory checks the folder, in its root reached through the tree, is not a symbolic link (a folder
// certificate goes into a folder of its own); fs.ErrNotExist when it, or its root, is not there.
func (t *tree) folderIsDirectory(folder string) error {
	d, name, err := t.at(folder)
	if err != nil {
		return err
	}
	e, err := d.stat(name)
	if err != nil {
		return err
	}
	if e.kind == kindLink {
		return fmt.Errorf("%s is a symbolic link; folder certificates are written only into a folder of their own", folder)
	}
	return nil
}

// folderChange is the change writing f: over the file there (as on a site: owner, group and mode kept), or a new
// file of the agent's with mode 0644 (a key 0600).
func (t *tree) folderChange(f file) (change, error) {
	d, name, err := t.at(f.path)
	if err != nil {
		return change{}, err
	}
	if _, err := d.stat(name); !errors.Is(err, fs.ErrNotExist) {
		return t.writeChange(f, false)
	}
	mode := fs.FileMode(newCertMode)
	if f.key {
		mode = newKeyMode
	}
	return change{path: f.path, data: f.data, mode: mode, uid: -1, gid: -1, was: stateAbsent}, nil
}

// reloadOwing reloads what uses the folder, whose files hold the certificate sha, and notes whether the reload is still
// owed (it failed) or settled.
func (f *Folder) reloadOwing(ctx context.Context, folder *folderPending, sha string, o *Outcome) (owed bool) {
	if owed = f.reload(ctx, folder, o); owed {
		f.Host.oweReload(folder.Name, sha)
	} else {
		f.Host.settleReload(folder.Name)
	}
	return owed
}

// reload runs the hook, or signals the containers, once the folder's files are in place: one hook_ran step (none when
// nothing is set). It says whether the reload failed (no Docker socket mounted is no failure: the step says to reload
// by hand).
func (f *Folder) reload(ctx context.Context, folder *folderPending, o *Outcome) (failed bool) {
	switch {
	case f.Hook != "":
		if f.Host.Runner == nil {
			o.Fail(protocol.StepHookRan, "the agent has no way to run the folder hook")
			return true
		}
		if _, err := f.Host.Runner.Run(ctx, inventory.FolderHook(f.Hook, f.Host.abs(folder.Path), folder.Name)); err != nil {
			o.Fail(protocol.StepHookRan, err.Error())
			return true
		}
		o.OK(protocol.StepHookRan, "")
	case f.Reload != nil && len(f.Reload.Containers) > 0:
		return f.Reload.run(ctx, o)
	}
	return false
}

// RecoverPending is Host.RecoverPending, and the reload of a folder certificate it found in place (owed from then
// until it succeeds): the agent may have been stopped before its reload ran, or while it ran. A reload that fails
// leaves the certificate not installed and the reload owed (Recovered.ReloadOwed): the next work for it reloads again.
func (f *Folder) RecoverPending(ctx context.Context) (*Recovered, error) {
	rec, err := f.Host.RecoverPending(ctx)
	if err != nil || rec == nil || rec.folder == nil {
		return rec, err
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), opTimeout)
	defer cancel()
	o := Outcome{steps: rec.Result.Steps, message: rec.Result.Message}
	sha := rec.Result.SHA256
	rec.ReloadOwed = f.reloadOwing(ctx, rec.folder, sha, &o)
	rec.Installed = !rec.ReloadOwed
	rec.Result = o.Result(o.message == nil)
	rec.Result.SHA256 = sha
	return rec, nil
}
