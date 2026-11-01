// Package state guards the agent's own directory (/var/lib/nslookup-agent): what it keeps there drives what it writes
// as root (the previous files it puts back, the install it finishes, its take-overs from certbot) and holds its private
// keys, so only root or the agent's own user may be able to change it. Check checks the directories, ReadFile reads a
// file in them without following a link, and Lock keeps a second copy of the agent from running with the same
// directory.
package state

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// LockFile is the file in the state directory a running agent holds locked.
const LockFile = "agent.lock"

// Check checks the agent's own directories (dirs, absolute paths under root, the machine's /) before the agent trusts
// anything in them: root and every directory from it down to each of dirs must be a directory, not a symbolic link,
// owned by root or the user uid (the agent's), and not writable by its group or others (nor sticky). A directory that is
// not there yet ends the walk: the agent makes it, 0700, in one that passed. The error names the first that fails
// and how to fix it.
func Check(root string, uid int, dirs ...string) error {
	for _, d := range dirs {
		rel, err := filepath.Rel(root, d)
		if err != nil || !filepath.IsAbs(d) || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return fmt.Errorf("%s is not a directory under %s", d, root)
		}
		names := []string{}
		if rel != "." {
			names = strings.Split(rel, string(filepath.Separator))
		}
		p := root
		for i := 0; i <= len(names); i++ {
			if i > 0 {
				p = filepath.Join(p, names[i-1])
			}
			shown := "/" + strings.Join(names[:i], "/")
			there, err := checkDir(p, shown, uid)
			if err != nil {
				return err
			}
			if !there {
				break
			}
		}
	}
	return nil
}

// checkDir checks one directory (shown is its path on the machine); there is false when it does not exist.
func checkDir(p, shown string, uid int) (there bool, err error) {
	var st unix.Stat_t
	if err := unix.Lstat(p, &st); errors.Is(err, unix.ENOENT) {
		return false, nil
	} else if err != nil {
		return false, &fs.PathError{Op: "lstat", Path: p, Err: err}
	}
	mode := uint32(st.Mode)
	switch mode & unix.S_IFMT {
	case unix.S_IFDIR:
	case unix.S_IFLNK:
		return false, fmt.Errorf("%s is a symbolic link; the agent keeps its keys and what it installed only in directories that are not links: "+
			"make it a directory of its own", shown)
	default:
		return false, fmt.Errorf("%s is not a directory", shown)
	}
	if (int(st.Uid) != uid && st.Uid != 0) || mode&0o022 != 0 || mode&unix.S_ISVTX != 0 {
		who := owners(uid)
		return false, fmt.Errorf("%s can be changed by a user other than %s (owner %d, mode %04o); the agent keeps its keys and what it "+
			"installed under it, so it does not start: make it %s's and writable by its owner only (chmod go-w %s)", shown, who, st.Uid, mode&0o7777, who, shown)
	}
	return true, nil
}

// owners names who may own the agent's directories: root, and the agent's own user (uid) when it runs as another.
func owners(uid int) string {
	if uid == 0 {
		return "root"
	}
	return fmt.Sprintf("root or the agent's user (uid %d)", uid)
}

// ReadFile reads the agent's own file at p: a regular file of at most max bytes, opened without following a link (a
// link is an error) and without waiting on a named pipe. A missing file is fs.ErrNotExist.
func ReadFile(p string, max int64) ([]byte, error) {
	fd, err := unix.Open(p, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	switch {
	case errors.Is(err, unix.ELOOP):
		return nil, fmt.Errorf("%s is a symbolic link; the agent does not read its own files through links", p)
	case err != nil:
		return nil, &fs.PathError{Op: "open", Path: p, Err: err}
	}
	f := os.NewFile(uintptr(fd), p)
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", p)
	}
	data, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > max {
		clear(data)
		return nil, fmt.Errorf("%s is larger than %d bytes", p, max)
	}
	return data, nil
}

// RunningError: another copy of the agent runs with this state directory.
type RunningError struct {
	Dir string
	// PID is the other copy's process id; 0 when it cannot be read.
	PID int
}

func (e *RunningError) Error() string {
	who := "another nslookup-agent"
	if e.PID > 0 {
		who += " (pid " + strconv.Itoa(e.PID) + ")"
	}
	return who + " is running with " + e.Dir + "; only one may run at a time"
}

// Lock locks dir for this process: an exclusive lock on dir/agent.lock (0600, never through a link), which holds this
// process's id. A second copy gets *RunningError at once, naming the first. The lock lasts until the file is closed or
// the process ends.
func Lock(dir string) (*os.File, error) {
	p := filepath.Join(dir, LockFile)
	fd, err := unix.Open(p, unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	switch {
	case errors.Is(err, unix.ELOOP):
		return nil, fmt.Errorf("%s is a symbolic link; the agent does not lock through links", p)
	case err != nil:
		return nil, &fs.PathError{Op: "open", Path: p, Err: err}
	}
	f := os.NewFile(uintptr(fd), p)
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		defer f.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			text, _ := io.ReadAll(io.LimitReader(f, 32))
			pid, _ := strconv.Atoi(strings.TrimSpace(string(text)))
			return nil, &RunningError{Dir: dir, PID: pid}
		}
		return nil, fmt.Errorf("locking %s: %w", p, err)
	}
	err = f.Chmod(0o600)
	if err == nil {
		err = f.Truncate(0)
	}
	if err == nil {
		_, err = f.WriteAt([]byte(strconv.Itoa(os.Getpid())+"\n"), 0)
	}
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("writing %s: %w", p, err)
	}
	return f, nil
}
