package inventory

import (
	"io/fs"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// HostFS is the machine's file system from root (the agent reads "/"), as os.DirFS is, except that it opens every
// file without waiting: a named pipe put where a configuration or certificate file was is opened at once (and then
// refused as no regular file) instead of holding up the read until something writes to it.
type HostFS string

// Open opens name (a path as fs.FS names it) for reading, without waiting on a named pipe.
func (root HostFS) Open(name string) (fs.File, error) {
	if !fs.ValidPath(name) {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrInvalid}
	}
	f, err := os.OpenFile(filepath.Join(string(root), filepath.FromSlash(name)), os.O_RDONLY|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, &fs.PathError{Op: "open", Path: name, Err: unwrapPath(err)}
	}
	return f, nil
}

// Stat describes name without opening it.
func (root HostFS) Stat(name string) (fs.FileInfo, error) {
	if !fs.ValidPath(name) {
		return nil, &fs.PathError{Op: "stat", Path: name, Err: fs.ErrInvalid}
	}
	info, err := os.Stat(filepath.Join(string(root), filepath.FromSlash(name)))
	if err != nil {
		return nil, &fs.PathError{Op: "stat", Path: name, Err: unwrapPath(err)}
	}
	return info, nil
}

func unwrapPath(err error) error {
	if pe, ok := err.(*fs.PathError); ok {
		return pe.Err
	}
	return err
}
