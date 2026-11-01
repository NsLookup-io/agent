package install

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"strings"

	"golang.org/x/sys/unix"
)

// Every file an install reads or writes is reached through directories only root can change, and every operation on it
// is made relative to its directory's descriptor: no path is resolved twice, so no one else can swap a file, a
// directory on the way or a link followed on the way between the agent's checks and its writes.

const (
	// maxLinks: a walk follows at most this many links (like the kernel's ELOOP).
	maxLinks = 40
	// maxLink is the longest link text read.
	maxLink = 4096
)

// errLink is a name that is a symbolic link where the agent does not follow one.
var errLink = errors.New("a symbolic link")

// tree is the directories of one install, each walked to once from the root and kept open for every operation on its
// files (close it when the install is done).
type tree struct {
	host *Host
	root int
	dirs map[string]*dir
}

func (h *Host) newTree() *tree { return &tree{host: h, root: -1, dirs: map[string]*dir{}} }

func (t *tree) close() {
	for _, d := range t.dirs {
		unix.Close(d.fd)
	}
	if t.root >= 0 {
		unix.Close(t.root)
	}
	t.dirs, t.root = map[string]*dir{}, -1
}

// dir is a directory reached by a verified walk. real is where the walk ended (links followed), from the root.
type dir struct {
	fd   int
	real string
}

// untrusted is a directory a user other than root (and the agent's own user, agent) can change.
type untrusted struct {
	dir   string
	uid   int
	mode  uint32
	agent int
}

func (u *untrusted) Error() string {
	return fmt.Sprintf("%s can be changed by a user other than %s (owner %d, mode %04o)", u.dir, trustedOwners(u.agent), u.uid, u.mode&0o7777)
}

// trustedOwners names who may own a directory the agent writes in: root, and the agent's own user (uid agent) when
// it runs as another.
func trustedOwners(agent int) string {
	if agent == 0 {
		return "root"
	}
	return fmt.Sprintf("root or the agent's user (uid %d)", agent)
}

// at is the directory of the file p (as configured) and the file's name in it. The walk starts at the root and opens
// one name at a time (never following a link at an open): each directory opened must be owned by root or the agent's
// user (DirOwner) and writable by its owner only, without the sticky bit (such as /tmp, where anyone creates files); a
// link on the way is followed only from a directory that passed, so only root could have made it, and at most 40 of
// them.
func (t *tree) at(p string) (*dir, string, error) {
	if !path.IsAbs(p) || path.Clean(p) != p || p == "/" {
		return nil, "", fmt.Errorf("%q is not a file path", p)
	}
	parent, name := path.Split(p)
	parent = path.Clean(parent)
	if d, ok := t.dirs[parent]; ok {
		return d, name, nil
	}
	d, err := t.walk(parent)
	var u *untrusted
	switch {
	case errors.As(err, &u):
		who := trustedOwners(u.agent)
		return nil, "", fmt.Errorf("%s is in %s, which a user other than %s can change (owner %d, mode %04o); the agent writes only "+
			"in directories only %s can change", p, u.dir, who, u.uid, u.mode&0o7777, who)
	case err != nil:
		return nil, "", fmt.Errorf("the directory of %s: %w", p, err)
	}
	t.dirs[parent] = d
	return d, name, nil
}

func (t *tree) walk(p string) (*dir, error) {
	if t.root < 0 {
		fd, err := unix.Open(t.host.Root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
		if err != nil {
			return nil, err
		}
		if err := t.trusted(fd, "/"); err != nil {
			unix.Close(fd)
			return nil, err
		}
		t.root = fd
	}
	type step struct {
		fd   int
		name string
	}
	start := func() ([]step, error) {
		fd, err := unix.Dup(t.root)
		return []step{{fd: fd}}, err
	}
	stack, err := start()
	if err != nil {
		return nil, err
	}
	defer func() {
		for _, s := range stack {
			unix.Close(s.fd)
		}
	}()
	where := func() string {
		var names []string
		for _, s := range stack[1:] {
			names = append(names, s.name)
		}
		return "/" + strings.Join(names, "/")
	}
	queue := strings.Split(p, "/")
	links := 0
	for len(queue) > 0 {
		name := queue[0]
		queue = queue[1:]
		switch name {
		case "", ".":
			continue
		case "..":
			// Above the root is the root, as for the kernel above /.
			if len(stack) > 1 {
				unix.Close(stack[len(stack)-1].fd)
				stack = stack[:len(stack)-1]
			}
			continue
		}
		top := stack[len(stack)-1].fd
		fd, err := unix.Openat(top, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			var st unix.Stat_t
			if unix.Fstatat(top, name, &st, unix.AT_SYMLINK_NOFOLLOW) != nil || uint32(st.Mode)&unix.S_IFMT != unix.S_IFLNK {
				return nil, fmt.Errorf("%s: %w", path.Join(where(), name), err)
			}
			// A link in a directory that passed: only root could have made it.
			if links++; links > maxLinks {
				return nil, fmt.Errorf("%s: more than %d links on the way", p, maxLinks)
			}
			target, err := readlinkAt(top, name)
			if err != nil {
				return nil, err
			}
			if strings.HasPrefix(target, "/") {
				for _, s := range stack {
					unix.Close(s.fd)
				}
				if stack, err = start(); err != nil {
					return nil, err
				}
			}
			queue = append(strings.Split(target, "/"), queue...)
			continue
		}
		stack = append(stack, step{fd: fd, name: name})
		if err := t.trusted(fd, where()); err != nil {
			return nil, err
		}
	}
	last := stack[len(stack)-1]
	d := &dir{fd: last.fd, real: where()}
	stack = stack[:len(stack)-1]
	return d, nil
}

// trusted checks the directory open at fd (shown is where it is) is root's or the agent's user's, and only its owner's
// to change.
func (t *tree) trusted(fd int, shown string) error {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return err
	}
	mode := uint32(st.Mode)
	if mode&unix.S_IFMT != unix.S_IFDIR {
		return fmt.Errorf("%s is not a directory", shown)
	}
	if (int(st.Uid) != t.host.DirOwner && st.Uid != 0) || mode&0o022 != 0 || mode&unix.S_ISVTX != 0 {
		return &untrusted{dir: shown, uid: int(st.Uid), mode: mode, agent: t.host.DirOwner}
	}
	return nil
}

// entry is what a name in a directory is, its link not followed.
type entry struct {
	kind     string
	perm     fs.FileMode
	uid, gid int
}

const (
	kindFile  = "file"
	kindLink  = "link"
	kindOther = "other"
)

// stat says what name is (fs.ErrNotExist when nothing).
func (d *dir) stat(name string) (entry, error) {
	var st unix.Stat_t
	if err := unix.Fstatat(d.fd, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return entry{}, err
	}
	e := entry{kind: kindOther, perm: fs.FileMode(uint32(st.Mode) & 0o777), uid: int(st.Uid), gid: int(st.Gid)}
	switch uint32(st.Mode) & unix.S_IFMT {
	case unix.S_IFREG:
		e.kind = kindFile
	case unix.S_IFLNK:
		e.kind = kindLink
	}
	return e, nil
}

// open opens name for reading, never following a link (errLink); a named pipe does not hold the open.
func (d *dir) open(name string) (*os.File, error) {
	fd, err := unix.Openat(d.fd, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ELOOP) {
		return nil, errLink
	}
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), name), nil
}

// read reads the regular file name (a link is errLink), at most maxFile bytes, and says what it is, through one
// descriptor.
func (d *dir) read(name string) ([]byte, fs.FileInfo, error) {
	f, err := d.open(name)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	return readOpen(f)
}

func (d *dir) readlink(name string) (string, error) { return readlinkAt(d.fd, name) }

func readlinkAt(fd int, name string) (string, error) {
	buf := make([]byte, maxLink)
	n, err := unix.Readlinkat(fd, name, buf)
	if err != nil {
		return "", err
	}
	if n == 0 || n >= len(buf) {
		return "", fmt.Errorf("%s: a link this agent does not follow", name)
	}
	return string(buf[:n]), nil
}

// createTemp creates a new temporary file for base in the directory (0600, never through a link).
func (d *dir) createTemp(base string) (*os.File, string, error) {
	for {
		name := "." + base + tempMark + randomHex()
		fd, err := unix.Openat(d.fd, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
		if errors.Is(err, unix.EEXIST) {
			continue
		}
		if err != nil {
			return nil, "", err
		}
		return os.NewFile(uintptr(fd), name), name, nil
	}
}

// symlinkTemp makes a new temporary link to target for base in the directory.
func (d *dir) symlinkTemp(base, target string) (string, error) {
	for {
		name := "." + base + tempMark + randomHex()
		err := unix.Symlinkat(target, d.fd, name)
		if errors.Is(err, unix.EEXIST) {
			continue
		}
		return name, err
	}
}

// mkdir makes the directory name in d with exactly perm, whatever the umask: set through a descriptor of the new
// directory, opened without following a link.
func (d *dir) mkdir(name string, perm uint32) error {
	if err := unix.Mkdirat(d.fd, name, perm); err != nil {
		return err
	}
	fd, err := unix.Openat(d.fd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	return unix.Fchmod(fd, perm)
}

func (d *dir) rename(from, to string) error { return unix.Renameat(d.fd, from, d.fd, to) }

func (d *dir) remove(name string) error { return unix.Unlinkat(d.fd, name, 0) }

func (d *dir) lchown(name string, uid, gid int) error {
	return unix.Fchownat(d.fd, name, uid, gid, unix.AT_SYMLINK_NOFOLLOW)
}

// names lists the directory, through a descriptor of its own opened from d's: a dup would share d's read offset, so a
// second listing would come back empty.
func (d *dir) names() ([]string, error) {
	fd, err := unix.Openat(d.fd, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), d.real)
	defer f.Close()
	return f.Readdirnames(-1)
}

// sync makes the renames in the directory last through a power cut, as far as the file system can (pending.json
// covers the rest).
func (d *dir) sync() { _ = unix.Fsync(d.fd) }

func readOpen(f *os.File) ([]byte, fs.FileInfo, error) {
	info, err := f.Stat()
	if err != nil {
		return nil, nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, nil, errors.New("not a regular file")
	}
	data, err := io.ReadAll(io.LimitReader(f, maxFile+1))
	if err != nil {
		return nil, nil, err
	}
	if len(data) > maxFile {
		clear(data)
		return nil, nil, fmt.Errorf("larger than %d bytes", maxFile)
	}
	return data, info, nil
}
