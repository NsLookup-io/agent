package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/nslookup-io/agent/internal/protocol"
	"github.com/nslookup-io/agent/internal/state"
)

// Ledger keeps what the agent must remember across restarts (Memory).
type Ledger interface {
	Load() (Memory, error)
	Save(Memory) error
}

// Memory is what the loop remembers across restarts.
type Memory struct {
	// Installed is, per assignment, the SHA-256 the agent last installed (or found already in place): a certificate on
	// disk that is neither that one nor the one the server asks for was changed by someone else, and the agent leaves
	// it alone.
	Installed map[string]string `json:"installed"`
	// Pending are the results the server has not accepted yet, one per assignment, in the order they are sent: a new
	// result goes to the back, and so does one the server refused for its own sake each time it is refused. An install
	// whose result was lost would otherwise never be reported (the file already holds the certificate).
	Pending []PendingResult `json:"pending"`
	// Sites are the keys of the sites the server assigned certificates to (its work named them), and when it last
	// did: an inventory too large for the server keeps them, so it never pauses their assignments as gone.
	Sites map[string]time.Time `json:"sites,omitempty"`
}

// PendingResult is a result waiting to be sent.
type PendingResult struct {
	AssignmentID string                 `json:"assignmentId"`
	Result       protocol.InstallResult `json:"result"`
	// RefusedSince is when the server first refused it for its own sake (zero: never); it is dropped a day later.
	RefusedSince time.Time `json:"refusedSince,omitzero"`
}

// AddResult queues a result for the loop to send first, replacing one queued for the same assignment, as if the loop
// had reported it: for an install the agent finished or undid when it started again. installed: the certificate the
// result names is on disk now, and the loop remembers it as installed.
func AddResult(l Ledger, id string, result protocol.InstallResult, installed bool) error {
	if !protocol.IsAssignmentID(id) || !sha256Hex.MatchString(result.SHA256) {
		return errors.New("a result is added for an assignment id and a SHA-256 only")
	}
	m, err := l.Load()
	if err != nil {
		return err
	}
	if m.Installed == nil {
		m.Installed = map[string]string{}
	}
	m.Pending = slices.DeleteFunc(m.Pending, func(p PendingResult) bool { return p.AssignmentID == id })
	m.Pending = append(m.Pending, PendingResult{AssignmentID: id, Result: result})
	if installed {
		m.Installed[id] = result.SHA256
	}
	return l.Save(m)
}

// maxLedger: a ledger is far smaller (an entry per assignment, a result per assignment).
const maxLedger = 16 << 20

// FileLedger keeps the Memory in one JSON file (0600, its directory created 0700), written through a temporary file
// renamed into place, and read without following a link. A file that was never saved is an empty Memory; entries that
// are not well formed (an id that is not an assignment id, a SHA-256 that is not one) are dropped.
type FileLedger struct {
	Path string
}

func (f FileLedger) Load() (Memory, error) {
	m := Memory{Installed: map[string]string{}}
	data, err := state.ReadFile(f.Path, maxLedger)
	if errors.Is(err, fs.ErrNotExist) {
		return m, nil
	}
	if err != nil {
		return Memory{}, err
	}
	var file Memory
	if err := json.Unmarshal(data, &file); err != nil {
		return Memory{}, fmt.Errorf("%s is not valid JSON: %w", f.Path, err)
	}
	for id, sha := range file.Installed {
		if protocol.IsAssignmentID(id) && sha256Hex.MatchString(sha) {
			m.Installed[id] = sha
		}
	}
	for _, p := range file.Pending {
		if protocol.IsAssignmentID(p.AssignmentID) && sha256Hex.MatchString(p.Result.SHA256) {
			m.Pending = append(m.Pending, p)
		}
	}
	for key, at := range file.Sites {
		if siteKeyText.MatchString(key) {
			if m.Sites == nil {
				m.Sites = map[string]time.Time{}
			}
			m.Sites[key] = at
		}
	}
	return m, nil
}

func (f FileLedger) Save(m Memory) (err error) {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(f.Path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(f.Path)+".tmp-*")
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
	if _, err = tmp.Write(append(data, '\n')); err != nil {
		return err
	}
	if err = tmp.Sync(); err != nil {
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), f.Path)
}
