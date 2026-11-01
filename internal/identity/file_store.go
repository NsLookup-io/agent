package identity

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// maxFileBytes: every file of an identity is far smaller.
const maxFileBytes = 64 << 10

// FileStore keeps the identity in one directory: agent.json (the agent id, the server and its pinned key) and the two
// private keys, sign.key and seal.key (PKCS #8 PEM). The directory is created 0700 and every file 0600, each written
// to a temporary file and renamed into place, agent.json last: a save that stops half way leaves no identity. A
// directory other users can open, or a key file they can read, is refused and nothing is read from it or written to
// it; so is a directory or a file that is a symbolic link.
type FileStore struct {
	Dir string
}

// Load reads the identity: ErrNotFound when the directory or its agent.json does not exist.
func (s FileStore) Load() (*Identity, error) {
	if err := s.checkDir(); err != nil {
		return nil, err
	}
	agent, err := s.read(AgentFile, false)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	files := map[string][]byte{AgentFile: agent}
	defer func() {
		for _, data := range files {
			clear(data)
		}
	}()
	for _, name := range []string{SignKeyFile, SealKeyFile} {
		if files[name], err = s.read(name, true); err != nil {
			return nil, err
		}
	}
	return FromFiles(files, s.path)
}

// Save writes a joined identity, creating the directory 0700 when it does not exist.
func (s FileStore) Save(id *Identity) error {
	files, err := id.Files()
	if err != nil {
		return err
	}
	defer func() {
		for _, data := range files {
			clear(data)
		}
	}()
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return err
	}
	if err := s.checkDir(); err != nil {
		return err
	}
	// agent.json last: a save that stops half way leaves no identity.
	for _, name := range []string{SignKeyFile, SealKeyFile, AgentFile} {
		if err := writeFile(s.Dir, name, files[name]); err != nil {
			return err
		}
	}
	return syncDir(s.Dir)
}

// SaveServerKeys rewrites agent.json with id's set of trusted server keys: written to a temporary file and renamed
// into place, so the set is replaced whole or not at all. The key files are not written.
func (s FileStore) SaveServerKeys(id *Identity) error {
	agent, err := AgentFileOf(id)
	if err != nil {
		return err
	}
	if err := s.checkDir(); err != nil {
		return err
	}
	if err := writeFile(s.Dir, AgentFile, agent); err != nil {
		return err
	}
	return syncDir(s.Dir)
}

func (s FileStore) path(name string) string { return filepath.Join(s.Dir, name) }

// checkDir: ErrNotFound when the directory does not exist; an error when it is not a directory or other users can
// open it.
func (s FileStore) checkDir() error {
	info, err := os.Lstat(s.Dir)
	if errors.Is(err, fs.ErrNotExist) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if info.Mode()&fs.ModeSymlink != 0 {
		return fmt.Errorf("%s is a symbolic link; the agent keeps its identity only in a directory of its own", s.Dir)
	}
	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory", s.Dir)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return fmt.Errorf("%s can be opened by other users (mode %04o); it holds the agent's private keys: run chmod 700 %s", s.Dir, perm, s.Dir)
	}
	return nil
}

// read reads one file of the identity, never through a link; a key file (private) must be a regular file other users
// cannot read.
func (s FileStore) read(name string, private bool) ([]byte, error) {
	f, err := os.OpenFile(s.path(name), os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if errors.Is(err, unix.ELOOP) {
		return nil, fmt.Errorf("%s is a symbolic link; the agent does not read its identity through links", s.path(name))
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", s.path(name))
	}
	if perm := info.Mode().Perm(); private && perm&0o077 != 0 {
		return nil, fmt.Errorf("%s can be read by other users (mode %04o); it is a private key: run chmod 600 %s", s.path(name), perm, s.path(name))
	}
	data, err := io.ReadAll(io.LimitReader(f, maxFileBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxFileBytes {
		return nil, fmt.Errorf("%s is larger than %d bytes", s.path(name), maxFileBytes)
	}
	return data, nil
}

// writeFile writes name in dir through a temporary file in the same directory (0600), synced and renamed into place;
// on failure the temporary file is removed and the old file is untouched.
func writeFile(dir, name string, data []byte) (err error) {
	tmp, err := os.CreateTemp(dir, "."+name+".tmp-*")
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			tmp.Close()
			os.Remove(tmp.Name())
		}
	}()
	if err = tmp.Chmod(0o600); err != nil {
		return err
	}
	if _, err = tmp.Write(data); err != nil {
		return err
	}
	if err = tmp.Sync(); err != nil {
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), filepath.Join(dir, name))
}

// syncDir makes the renames in dir durable.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
