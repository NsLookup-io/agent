package kube

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/nslookup-io/agent/internal/identity"
)

// IdentitySecret is the Secret, in the agent's own namespace, that holds its identity.
const IdentitySecret = "nslookup-agent-identity"

// SecretStore keeps the agent's identity in the Secret nslookup-agent-identity of the agent's own namespace
// (identity.Store): the entries a FileStore keeps as files (agent.json, sign.key, seal.key), in a Secret of type Opaque
// labelled app.kubernetes.io/managed-by: nslookup-agent. It is created once, at join, and never replaced: a Secret of
// that name already there refuses the save, whatever it holds.
type SecretStore struct {
	Client    kubernetes.Interface
	Namespace string
}

// String names the Secret: "<namespace>/nslookup-agent-identity".
func (s SecretStore) String() string { return s.Namespace + "/" + IdentitySecret }

// Load reads the identity: ErrNotFound when the Secret does not exist; an error when it exists but holds no identity
// (joining then would spend a code and fail to save it).
func (s SecretStore) Load() (*identity.Identity, error) {
	ctx, cancel := context.WithTimeout(context.Background(), apiTimeout)
	defer cancel()
	secret, err := getSecret(ctx, s.Client, s.Namespace, IdentitySecret)
	if err != nil {
		return nil, fmt.Errorf("reading the secret %s: %w", s, err)
	}
	if secret == nil {
		return nil, identity.ErrNotFound
	}
	defer clearData(secret)
	id, err := identity.FromFiles(secret.Data, func(name string) string { return fmt.Sprintf("the secret %s (%s)", s, name) })
	if errors.Is(err, identity.ErrNotFound) {
		return nil, fmt.Errorf("the secret %s holds no agent identity; delete it to join", s)
	}
	return id, err
}

// Save creates the Secret with a joined identity.
func (s SecretStore) Save(id *identity.Identity) error {
	files, err := id.Files()
	if err != nil {
		return err
	}
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: s.Namespace, Name: IdentitySecret, Labels: map[string]string{ManagedByLabel: ManagedBy}},
		Type:       corev1.SecretTypeOpaque,
		Data:       files,
	}
	defer clearData(secret)
	ctx, cancel := context.WithTimeout(context.Background(), apiTimeout)
	defer cancel()
	created, err := s.Client.CoreV1().Secrets(s.Namespace).Create(ctx, secret, metav1.CreateOptions{})
	clearData(created)
	switch {
	case apierrors.IsAlreadyExists(err):
		return fmt.Errorf("the secret %s exists already; an identity is never replaced", s)
	case err != nil:
		return fmt.Errorf("creating the secret %s: %w", s, err)
	}
	return nil
}

// SaveServerKeys rewrites the agent.json of the identity Secret with id's set of trusted server keys, on the Secret as
// read (its resourceVersion; one changed meanwhile is read again once). A Secret not labelled as the agent's is never
// written.
func (s SecretStore) SaveServerKeys(id *identity.Identity) error {
	agent, err := identity.AgentFileOf(id)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), apiTimeout)
	defer cancel()
	secrets := s.Client.CoreV1().Secrets(s.Namespace)
	for again := false; ; again = true {
		secret, err := getSecret(ctx, s.Client, s.Namespace, IdentitySecret)
		switch {
		case err != nil:
			return fmt.Errorf("reading the secret %s: %w", s, err)
		case secret == nil:
			return fmt.Errorf("the secret %s is gone", s)
		case secret.Labels[ManagedByLabel] != ManagedBy:
			clearData(secret)
			return fmt.Errorf("the secret %s is not labelled %s: %s; it is not written", s, ManagedByLabel, ManagedBy)
		}
		// A copy: the secret's data is cleared after the write, and a conflict writes again.
		if secret.Data == nil {
			secret.Data = map[string][]byte{}
		}
		secret.Data[identity.AgentFile] = bytes.Clone(agent)
		updated, err := secrets.Update(ctx, secret, metav1.UpdateOptions{})
		clearData(secret)
		clearData(updated)
		switch {
		case err == nil:
			return nil
		case apierrors.IsConflict(err) && !again:
			continue
		}
		return fmt.Errorf("writing the secret %s: %w", s, err)
	}
}
