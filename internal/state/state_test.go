package state

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// machine is a test machine's root: its directories are the test user's (who stands for the agent's user), 0755.
func machine(t *testing.T, dirs ...string) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "root")
	for _, d := range append([]string{""}, dirs...) {
		p := filepath.Join(root, d)
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestTheAgentsOwnDirectoriesAreChecked(t *testing.T) {
	uid := os.Getuid()
	t.Run("only root or the agent's user can change them", func(t *testing.T) {
		root := machine(t, "var/lib/nslookup-agent/identity")
		state := filepath.Join(root, "var/lib/nslookup-agent")
		if err := Check(root, uid, state, filepath.Join(state, "identity")); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("not made yet", func(t *testing.T) {
		root := machine(t, "var/lib")
		state := filepath.Join(root, "var/lib/nslookup-agent")
		if err := Check(root, uid, state, filepath.Join(state, "identity")); err != nil {
			t.Fatal(err)
		}
	})
	for name, c := range map[string]struct {
		chmod string
		mode  os.FileMode
		want  string
	}{
		"a group-writable state directory": {"var/lib/nslookup-agent", 0o770, "/var/lib/nslookup-agent can be changed by a user other than"},
		"a parent others can write":        {"var/lib", 0o757, "/var/lib can be changed by a user other than"},
		"a sticky parent":                  {"var", 0o1777, "/var can be changed by a user other than"},
		"the identity directory":           {"var/lib/nslookup-agent/identity", 0o720, "/var/lib/nslookup-agent/identity can be changed by a user other than"},
		"the root":                         {"", 0o775, "/ can be changed by a user other than"},
	} {
		t.Run(name, func(t *testing.T) {
			root := machine(t, "var/lib/nslookup-agent/identity")
			if err := os.Chmod(filepath.Join(root, c.chmod), c.mode); err != nil {
				t.Fatal(err)
			}
			state := filepath.Join(root, "var/lib/nslookup-agent")
			err := Check(root, uid, state, filepath.Join(state, "identity"))
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("%v, want %q", err, c.want)
			}
		})
	}
	t.Run("a symbolic link on the way", func(t *testing.T) {
		root := machine(t, "var/data/nslookup-agent", "var/lib")
		if err := os.Symlink("../data/nslookup-agent", filepath.Join(root, "var/lib/nslookup-agent")); err != nil {
			t.Fatal(err)
		}
		state := filepath.Join(root, "var/lib/nslookup-agent")
		if err := Check(root, uid, state); err == nil || !strings.Contains(err.Error(), "/var/lib/nslookup-agent is a symbolic link") {
			t.Errorf("%v", err)
		}
	})
	t.Run("another user's", func(t *testing.T) {
		root := machine(t, "var/lib/nslookup-agent")
		state := filepath.Join(root, "var/lib/nslookup-agent")
		// The agent runs as another user than the test's (who owns the directories) and than root.
		err := Check(root, uid+1, state)
		want := "/ can be changed by a user other than root or the agent's user (uid " + strconv.Itoa(uid+1) + ")"
		if uid == 0 {
			want = "" // root's directories pass for every agent
		}
		if want == "" && err != nil || want != "" && (err == nil || !strings.Contains(err.Error(), want)) {
			t.Errorf("%v, want %q", err, want)
		}
	})
	t.Run("not under the root", func(t *testing.T) {
		root := machine(t)
		if err := Check(root, uid, filepath.Join(filepath.Dir(root), "elsewhere")); err == nil {
			t.Error("a directory outside the root was checked")
		}
	})
}

func TestReadFileNeverFollowsALinkNorWaitsOnAPipe(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "pending.json")
	if err := os.WriteFile(file, []byte(`{"a":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if data, err := ReadFile(file, 1<<10); err != nil || string(data) != `{"a":1}` {
		t.Errorf("%q, %v", data, err)
	}
	if _, err := ReadFile(filepath.Join(dir, "none.json"), 1<<10); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("a missing file: %v", err)
	}
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(file, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadFile(link, 1<<10); err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Errorf("a link: %v", err)
	}
	if _, err := ReadFile(file, 3); err == nil || !strings.Contains(err.Error(), "larger than 3 bytes") {
		t.Errorf("too large: %v", err)
	}
	fifo := filepath.Join(dir, "fifo.json")
	if err := unix.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := ReadFile(fifo, 1<<10)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "not a regular file") {
			t.Errorf("a named pipe: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("reading a named pipe waits for a writer")
	}
}

func TestOneAgentRunsPerStateDirectory(t *testing.T) {
	dir := t.TempDir()
	first, err := Lock(dir)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Lock(dir)
	var running *RunningError
	if !errors.As(err, &running) || running.PID != os.Getpid() {
		t.Fatalf("a second lock: %v", err)
	}
	if !strings.Contains(err.Error(), "another nslookup-agent (pid "+strconv.Itoa(os.Getpid())+") is running with "+dir) {
		t.Errorf("message %q", err.Error())
	}
	if info, err := os.Lstat(filepath.Join(dir, "agent.lock")); err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("the lock file: %v, %v", info, err)
	}
	first.Close()
	again, err := Lock(dir)
	if err != nil {
		t.Fatalf("once the first stopped: %v", err)
	}
	again.Close()
}
