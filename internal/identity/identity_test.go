package identity

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func joined(t *testing.T) *Identity {
	t.Helper()
	id, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	server, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	id.AgentID = "3f2b8c1e-7a4d-4e9b-b1c6-5d8e2f0a7c93"
	id.Server = "https://agents.example.test"
	id.ServerSignPublicKey = server
	return id
}

// privateDir is an empty directory only its owner can open, as the store wants it.
func privateDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "identity")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func entries(t *testing.T, dir string) []string {
	t.Helper()
	list, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range list {
		names = append(names, e.Name())
	}
	return names
}

func TestGenerateMakesTwoFreshKeyPairs(t *testing.T) {
	a, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	b, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	if len(a.SignKey) != ed25519.PrivateKeySize || a.SealKey == nil || a.SealKey.Curve() != ecdh.X25519() {
		t.Fatalf("keys = %d bytes, %v", len(a.SignKey), a.SealKey)
	}
	if a.SignKey.Equal(b.SignKey) || a.SealKey.Equal(b.SealKey) {
		t.Error("two identities share a key")
	}
	if a.AgentID != "" || a.Server != "" || a.ServerSignPublicKey != nil {
		t.Errorf("a fresh identity has joined: %+v", a)
	}
}

func TestFileStoreRoundTrip(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state", "identity")
	store := FileStore{Dir: dir}
	id := joined(t)
	if err := store.Save(id); err != nil {
		t.Fatal(err)
	}
	got, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if got.AgentID != id.AgentID || got.Server != id.Server || !got.ServerSignPublicKey.Equal(id.ServerSignPublicKey) ||
		!got.SignKey.Equal(id.SignKey) || !got.SealKey.Equal(id.SealKey) {
		t.Errorf("loaded %+v, saved %+v", got, id)
	}
}

func TestFileStoreModes(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "identity")
	if err := (FileStore{Dir: dir}).Save(joined(t)); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Errorf("directory mode %04o, want 0700", info.Mode().Perm())
	}
	names := entries(t, dir)
	if strings.Join(names, ",") != "agent.json,seal.key,sign.key" {
		t.Errorf("files %v, want agent.json, seal.key and sign.key (no temporary files)", names)
	}
	for _, name := range names {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Errorf("%s mode %04o, want 0600", name, info.Mode().Perm())
		}
	}
}

func TestTheAgentFileHoldsNoKey(t *testing.T) {
	dir := privateDir(t)
	id := joined(t)
	if err := (FileStore{Dir: dir}).Save(id); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "agent.json"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte("PRIVATE")) || !bytes.Contains(data, []byte(id.AgentID)) {
		t.Errorf("agent.json = %s", data)
	}
}

func TestNothingStoredIsErrNotFound(t *testing.T) {
	root := privateDir(t)
	for name, dir := range map[string]string{
		"no directory":    filepath.Join(root, "missing"),
		"empty directory": root,
	} {
		if _, err := (FileStore{Dir: dir}).Load(); !errors.Is(err, ErrNotFound) {
			t.Errorf("%s: %v, want ErrNotFound", name, err)
		}
	}
	// Key files without agent.json (a save that stopped half way) are no identity either.
	if err := os.WriteFile(filepath.Join(root, "sign.key"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := (FileStore{Dir: root}).Load(); !errors.Is(err, ErrNotFound) {
		t.Errorf("keys without agent.json: %v, want ErrNotFound", err)
	}
}

func TestADirectoryOtherUsersCanOpenIsRefused(t *testing.T) {
	for _, mode := range []os.FileMode{0o755, 0o750, 0o701} {
		dir := filepath.Join(t.TempDir(), "identity")
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(dir, mode); err != nil {
			t.Fatal(err)
		}
		store := FileStore{Dir: dir}
		if err := store.Save(joined(t)); err == nil || !strings.Contains(err.Error(), "other users") {
			t.Errorf("save into %04o: %v, want a refusal", mode, err)
		}
		if names := entries(t, dir); len(names) != 0 {
			t.Errorf("save into %04o wrote %v", mode, names)
		}

		if err := os.Chmod(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := store.Save(joined(t)); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(dir, mode); err != nil {
			t.Fatal(err)
		}
		if _, err := store.Load(); err == nil || errors.Is(err, ErrNotFound) || !strings.Contains(err.Error(), "other users") {
			t.Errorf("load from %04o: %v, want a refusal", mode, err)
		}
	}
}

func TestAKeyFileOtherUsersCanReadIsRefused(t *testing.T) {
	for _, name := range []string{"sign.key", "seal.key"} {
		dir := privateDir(t)
		store := FileStore{Dir: dir}
		if err := store.Save(joined(t)); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(filepath.Join(dir, name), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := store.Load(); err == nil || errors.Is(err, ErrNotFound) || !strings.Contains(err.Error(), name) {
			t.Errorf("%s 0644: %v, want a refusal naming it", name, err)
		}
	}
}

func TestADamagedIdentityIsAnErrorNotErrNotFound(t *testing.T) {
	cases := map[string]func(dir string) error{
		"agent.json is not JSON": func(dir string) error {
			return os.WriteFile(filepath.Join(dir, "agent.json"), []byte("{"), 0o600)
		},
		"agent.json names no agent": func(dir string) error {
			return os.WriteFile(filepath.Join(dir, "agent.json"), []byte(`{"format":1,"agentId":"","server":"https://agents.example.test","serverSignPublicKey":"1VSN2LzbUEa0lyYDWYTaeAwwAbIeqKOnyl5PPJ-mRMw"}`), 0o600)
		},
		"a server key of 31 bytes": func(dir string) error {
			return os.WriteFile(filepath.Join(dir, "agent.json"), []byte(`{"format":1,"agentId":"a1","server":"https://agents.example.test","serverSignPublicKey":"1VSN2LzbUEa0lyYDWYTaeAwwAbIeqKOnyl5PPJ-mRA"}`), 0o600)
		},
		"an unknown format": func(dir string) error {
			return os.WriteFile(filepath.Join(dir, "agent.json"), []byte(`{"format":2,"agentId":"a1","server":"https://agents.example.test","serverSignPublicKey":"1VSN2LzbUEa0lyYDWYTaeAwwAbIeqKOnyl5PPJ-mRMw"}`), 0o600)
		},
		"no signing key": func(dir string) error { return os.Remove(filepath.Join(dir, "sign.key")) },
		"the sealing key in place of the signing key": func(dir string) error {
			seal, err := os.ReadFile(filepath.Join(dir, "seal.key"))
			if err != nil {
				return err
			}
			return os.WriteFile(filepath.Join(dir, "sign.key"), seal, 0o600)
		},
		"the signing key in place of the sealing key": func(dir string) error {
			sign, err := os.ReadFile(filepath.Join(dir, "sign.key"))
			if err != nil {
				return err
			}
			return os.WriteFile(filepath.Join(dir, "seal.key"), sign, 0o600)
		},
		"a key file that is not PEM": func(dir string) error {
			return os.WriteFile(filepath.Join(dir, "seal.key"), []byte("not a key"), 0o600)
		},
	}
	for name, damage := range cases {
		t.Run(name, func(t *testing.T) {
			dir := privateDir(t)
			store := FileStore{Dir: dir}
			if err := store.Save(joined(t)); err != nil {
				t.Fatal(err)
			}
			if err := damage(dir); err != nil {
				t.Fatal(err)
			}
			id, err := store.Load()
			if err == nil || errors.Is(err, ErrNotFound) {
				t.Errorf("got %+v, %v; want an error other than ErrNotFound", id, err)
			}
		})
	}
}

func TestOnlyAJoinedIdentityIsSaved(t *testing.T) {
	noAgent := joined(t)
	noAgent.AgentID = ""
	noServer := joined(t)
	noServer.Server = ""
	noServerKey := joined(t)
	noServerKey.ServerSignPublicKey = nil
	noSealKey := joined(t)
	noSealKey.SealKey = nil
	for name, id := range map[string]*Identity{"nil": nil, "no agent id": noAgent, "no server": noServer, "no server key": noServerKey, "no sealing key": noSealKey} {
		dir := filepath.Join(t.TempDir(), "identity")
		if err := (FileStore{Dir: dir}).Save(id); err == nil {
			t.Errorf("%s: saved", name)
		}
		if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s: the directory was created", name)
		}
	}
}

// The identity is never read through a link: neither its directory nor one of its files may be one.
func TestAnIdentityIsNeverReadThroughALink(t *testing.T) {
	id := joined(t)
	real := filepath.Join(t.TempDir(), "identity")
	if err := (FileStore{Dir: real}).Save(id); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "identity")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if _, err := (FileStore{Dir: link}).Load(); err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Errorf("a linked directory: %v", err)
	}
	for _, name := range []string{AgentFile, SignKeyFile} {
		dir := filepath.Join(t.TempDir(), "identity")
		if err := (FileStore{Dir: dir}).Save(id); err != nil {
			t.Fatal(err)
		}
		elsewhere := filepath.Join(t.TempDir(), name)
		if err := os.Rename(filepath.Join(dir, name), elsewhere); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(elsewhere, filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
		if _, err := (FileStore{Dir: dir}).Load(); err == nil || !strings.Contains(err.Error(), "symbolic link") {
			t.Errorf("%s as a link: %v", name, err)
		}
	}
}

func newServerKey(t *testing.T) ed25519.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

// An identity trusts the server keys of its set, which starts as the key pinned at join; one written before there was
// a set trusts its pinned key.
func TestTheTrustedServerKeys(t *testing.T) {
	id := joined(t)
	if got := id.TrustedServerKeys(); len(got) != 1 || !bytes.Equal(got[0], id.ServerSignPublicKey) {
		t.Errorf("a new identity trusts %x", got)
	}
	dir := privateDir(t)
	store := FileStore{Dir: dir}
	if err := store.Save(id); err != nil {
		t.Fatal(err)
	}
	// As an earlier agent wrote it: no set.
	agent, err := os.ReadFile(filepath.Join(dir, AgentFile))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(agent, []byte("serverSignPublicKeys")) {
		t.Errorf("a set written with only the pinned key: %s", agent)
	}
	loaded, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if got := loaded.TrustedServerKeys(); len(got) != 1 || !bytes.Equal(got[0], id.ServerSignPublicKey) {
		t.Errorf("loaded, trusts %x", got)
	}

	// The server rolled its key over: the set is saved in agent.json alone, and read back.
	next := newServerKey(t)
	loaded.ServerSignPublicKeys = []ed25519.PublicKey{id.ServerSignPublicKey, next}
	signBefore, _ := os.ReadFile(filepath.Join(dir, SignKeyFile))
	if err := store.SaveServerKeys(loaded); err != nil {
		t.Fatal(err)
	}
	again, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if got := again.TrustedServerKeys(); len(got) != 2 || !bytes.Equal(got[0], id.ServerSignPublicKey) || !bytes.Equal(got[1], next) {
		t.Errorf("after the rollover, trusts %x", got)
	}
	if !bytes.Equal(again.ServerSignPublicKey, id.ServerSignPublicKey) {
		t.Error("the key pinned at join changed")
	}
	if signAfter, _ := os.ReadFile(filepath.Join(dir, SignKeyFile)); !bytes.Equal(signBefore, signAfter) {
		t.Error("the signing key file was written")
	}
	if names := entries(t, dir); len(names) != 3 {
		t.Errorf("files %v", names)
	}
}

// A set that is not 1 or 2 well-formed keys is a damaged identity.
func TestADamagedKeySetIsAnError(t *testing.T) {
	for name, set := range map[string]string{
		"empty":     `[]`,
		"three":     `["1VSN2LzbUEa0lyYDWYTaeAwwAbIeqKOnyl5PPJ-mRMw","QvGLMLZu4Jzl-anDUufSnsUBSh2ZdHCNzrHIW2cbxDo","1VSN2LzbUEa0lyYDWYTaeAwwAbIeqKOnyl5PPJ-mRMw"]`,
		"31 bytes":  `["1VSN2LzbUEa0lyYDWYTaeAwwAbIeqKOnyl5PPJ-mRA"]`,
		"not a key": `["AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"]`,
	} {
		t.Run(name, func(t *testing.T) {
			dir := privateDir(t)
			store := FileStore{Dir: dir}
			if err := store.Save(joined(t)); err != nil {
				t.Fatal(err)
			}
			text := `{"format":1,"agentId":"a1","server":"https://agents.example.test","serverSignPublicKey":"1VSN2LzbUEa0lyYDWYTaeAwwAbIeqKOnyl5PPJ-mRMw","serverSignPublicKeys":` + set + `}`
			if err := os.WriteFile(filepath.Join(dir, AgentFile), []byte(text), 0o600); err != nil {
				t.Fatal(err)
			}
			if id, err := store.Load(); err == nil || !strings.Contains(err.Error(), "serverSignPublicKeys") {
				t.Errorf("%+v, %v", id, err)
			}
		})
	}
}
