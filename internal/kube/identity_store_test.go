package kube

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/nslookup-io/agent/internal/identity"
)

func joinedIdentity(t *testing.T) *identity.Identity {
	t.Helper()
	id, err := identity.Generate()
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

func TestSecretStoreRoundTrip(t *testing.T) {
	cs := cluster()
	store := SecretStore{Client: cs, Namespace: "agents"}
	if _, err := store.Load(); !errors.Is(err, identity.ErrNotFound) {
		t.Fatalf("nothing stored: %v", err)
	}
	id := joinedIdentity(t)
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

	s := secretOf(t, cs, "agents", "nslookup-agent-identity")
	var keys []string
	for k := range s.Data {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	if strings.Join(keys, ",") != "agent.json,seal.key,sign.key" || s.Type != corev1.SecretTypeOpaque ||
		s.Labels["app.kubernetes.io/managed-by"] != "nslookup-agent" {
		t.Errorf("keys %v, type %s, labels %v", keys, s.Type, s.Labels)
	}
	if bytes.Contains(s.Data["agent.json"], []byte("PRIVATE")) || !bytes.Contains(s.Data["agent.json"], []byte(id.AgentID)) {
		t.Errorf("agent.json = %s", s.Data["agent.json"])
	}
	// The same entries a file store keeps: one read back from the other.
	dir := filepath.Join(t.TempDir(), "identity")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, data := range s.Data {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if fromFiles, err := (identity.FileStore{Dir: dir}).Load(); err != nil || fromFiles.AgentID != id.AgentID || !fromFiles.SignKey.Equal(id.SignKey) {
		t.Errorf("%+v, %v", fromFiles, err)
	}
}

// An identity is never replaced: a secret of that name already there, whatever it holds, refuses the save.
func TestSecretStoreNeverReplacesAnIdentity(t *testing.T) {
	cs := cluster()
	store := SecretStore{Client: cs, Namespace: "agents"}
	first := joinedIdentity(t)
	if err := store.Save(first); err != nil {
		t.Fatal(err)
	}
	if err := store.Save(joinedIdentity(t)); err == nil || !strings.Contains(err.Error(), "never replaced") {
		t.Errorf("a second save: %v", err)
	}
	if got, err := store.Load(); err != nil || !got.SignKey.Equal(first.SignKey) {
		t.Errorf("%+v, %v", got, err)
	}
	for _, a := range writes(cs) {
		if a.GetVerb() != "create" {
			t.Errorf("a %s of %s", a.GetVerb(), a.GetResource().Resource)
		}
	}
}

// A secret of that name that holds no identity is an error, not ErrNotFound: joining would spend a code and then
// fail to save.
func TestSecretStoreAForeignSecretIsAnError(t *testing.T) {
	for name, data := range map[string]map[string][]byte{
		"no agent.json":       {"sign.key": []byte("x")},
		"agent.json not JSON": {"agent.json": []byte("{"), "sign.key": []byte("x"), "seal.key": []byte("x")},
	} {
		cs := cluster(&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "agents", Name: "nslookup-agent-identity"}, Data: data})
		if id, err := (SecretStore{Client: cs, Namespace: "agents"}).Load(); err == nil || errors.Is(err, identity.ErrNotFound) {
			t.Errorf("%s: %+v, %v", name, id, err)
		}
	}
}

func TestSecretStoreSavesOnlyAJoinedIdentity(t *testing.T) {
	cs := cluster()
	id := joinedIdentity(t)
	id.AgentID = ""
	if err := (SecretStore{Client: cs, Namespace: "agents"}).Save(id); err == nil {
		t.Error("saved an identity with no agent id")
	}
	if len(writes(cs)) != 0 {
		t.Errorf("writes %v", writes(cs))
	}
}

func TestOwnNamespace(t *testing.T) {
	file := filepath.Join(t.TempDir(), "namespace")
	if err := os.WriteFile(file, []byte("from-file\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{}
	getenv := func(k string) string { return env[k] }
	if ns, err := ownNamespace(getenv, file); err != nil || ns != "from-file" {
		t.Errorf("%q, %v", ns, err)
	}
	env["POD_NAMESPACE"] = "from-env"
	if ns, err := ownNamespace(getenv, file); err != nil || ns != "from-env" {
		t.Errorf("%q, %v", ns, err)
	}
	delete(env, "POD_NAMESPACE")
	if _, err := ownNamespace(getenv, filepath.Join(t.TempDir(), "missing")); err == nil || !strings.Contains(err.Error(), "POD_NAMESPACE") {
		t.Errorf("%v", err)
	}
	env["POD_NAMESPACE"] = "Not A Namespace"
	if _, err := ownNamespace(getenv, file); err == nil {
		t.Error("took a namespace that is no namespace name")
	}
}

// Run outside the cluster with KUBECONFIG: its current context's cluster and namespace.
func TestConnectWithAKubeconfig(t *testing.T) {
	config := filepath.Join(t.TempDir(), "config")
	if err := os.WriteFile(config, []byte(`apiVersion: v1
kind: Config
clusters:
- name: test
  cluster:
    server: https://127.0.0.1:6443
users:
- name: test
  user:
    token: not-a-real-token
contexts:
- name: test
  context:
    cluster: test
    user: test
    namespace: agents
current-context: test
`), 0o600); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{"KUBECONFIG": config}
	cs, ns, err := Connect(func(k string) string { return env[k] })
	if err != nil || cs == nil || ns != "agents" {
		t.Fatalf("%v, %q, %v", cs, ns, err)
	}
	env["POD_NAMESPACE"] = "pod-ns"
	if _, ns, err := Connect(func(k string) string { return env[k] }); err != nil || ns != "pod-ns" {
		t.Errorf("%q, %v", ns, err)
	}
	env["KUBECONFIG"] = filepath.Join(t.TempDir(), "missing")
	if _, _, err := Connect(func(k string) string { return env[k] }); err == nil {
		t.Error("connected with a kubeconfig that does not exist")
	}
}

// In Kubernetes the set of trusted server keys is kept in the identity Secret too: its agent.json alone is rewritten,
// on the Secret as read.
func TestSecretStoreKeepsTheTrustedServerKeys(t *testing.T) {
	cs := cluster()
	store := SecretStore{Client: cs, Namespace: "agents"}
	id := joinedIdentity(t)
	if err := store.Save(id); err != nil {
		t.Fatal(err)
	}
	before := secretOf(t, cs, "agents", IdentitySecret)
	next, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	id.ServerSignPublicKeys = []ed25519.PublicKey{id.ServerSignPublicKey, next}
	cs.ClearActions()
	if err := store.SaveServerKeys(id); err != nil {
		t.Fatal(err)
	}
	got, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if keys := got.TrustedServerKeys(); len(keys) != 2 || !keys[1].Equal(next) || !got.ServerSignPublicKey.Equal(id.ServerSignPublicKey) {
		t.Errorf("trusts %x", keys)
	}
	after := secretOf(t, cs, "agents", IdentitySecret)
	if !bytes.Equal(before.Data[identity.SignKeyFile], after.Data[identity.SignKeyFile]) || after.Labels[ManagedByLabel] != ManagedBy {
		t.Error("more than agent.json changed")
	}
	if w := writes(cs); len(w) != 1 || w[0].GetVerb() != "update" {
		t.Errorf("writes %v", w)
	}
	// A Secret that is not the agent's identity is never written.
	foreign := after.DeepCopy()
	foreign.Labels = nil
	if _, err := cs.CoreV1().Secrets("agents").Update(t.Context(), foreign, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveServerKeys(id); err == nil {
		t.Error("wrote a Secret that is not the agent's")
	}
}

// An identity Secret whose data is gone (emptied by hand) gets agent.json written, never a crash.
func TestSecretStoreWritesTheKeysIntoASecretWithoutData(t *testing.T) {
	cs := cluster(&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "agents", Name: IdentitySecret, Labels: map[string]string{ManagedByLabel: ManagedBy}}})
	store := SecretStore{Client: cs, Namespace: "agents"}
	if err := store.SaveServerKeys(joinedIdentity(t)); err != nil {
		t.Fatal(err)
	}
	if s := secretOf(t, cs, "agents", IdentitySecret); len(s.Data[identity.AgentFile]) == 0 {
		t.Errorf("data %v", s.Data)
	}
}
