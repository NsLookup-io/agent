// Package identity holds what an agent is to the server: the id it was given at join, its two private keys and the
// server's signing key it pinned at join, and where they are kept between runs.
package identity

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/nslookup-io/agent/internal/protocol"
)

// ErrNotFound: no identity is stored yet; the agent has not joined.
var ErrNotFound = errors.New("no agent identity is stored")

// Identity is one agent's keys and ids. The private keys never leave the machine; their public halves were sent at
// join.
type Identity struct {
	// AgentID is the id the server gave the agent at join; empty before.
	AgentID string
	// Server is the origin of the server the agent joined (https://…); empty before. Its answers are checked with
	// ServerSignPublicKey, so the agent talks to this server only.
	Server string
	// SignKey signs every request after join (Ed25519).
	SignKey ed25519.PrivateKey
	// SealKey opens the private keys the server seals to the agent (X25519).
	SealKey *ecdh.PrivateKey
	// ServerSignPublicKey is the server's signing key pinned from the join answer; nil before.
	ServerSignPublicKey ed25519.PublicKey
	// ServerSignPublicKeys are the server keys the agent trusts now (1 or 2), learnt from heartbeat answers when the
	// server rolls its key over; nil until then: the pinned key alone (TrustedServerKeys).
	ServerSignPublicKeys []ed25519.PublicKey
}

// TrustedServerKeys are the keys an answer's signature is checked with: the set learnt from the server, else the key
// pinned at join.
func (id *Identity) TrustedServerKeys() []ed25519.PublicKey {
	switch {
	case id == nil:
		return nil
	case len(id.ServerSignPublicKeys) > 0:
		return id.ServerSignPublicKeys
	case len(id.ServerSignPublicKey) == ed25519.PublicKeySize:
		return []ed25519.PublicKey{id.ServerSignPublicKey}
	}
	return nil
}

// Store keeps an agent's identity between runs: a directory on a server or in a Docker volume (FileStore), a Secret
// in Kubernetes.
type Store interface {
	// Load returns the stored identity: ErrNotFound when none is stored, another error when one is there but cannot
	// be used (it is then left as it is).
	Load() (*Identity, error)
	// Save stores a joined identity (see Joined).
	Save(*Identity) error
	// SaveServerKeys stores the stored identity's new set of trusted server keys (id.ServerSignPublicKeys), at once
	// and whole; nothing else of it changes.
	SaveServerKeys(*Identity) error
}

// Generate makes a fresh agent's two key pairs, before it joins.
func Generate() (*Identity, error) {
	_, sign, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	seal, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Identity{SignKey: sign, SealKey: seal}, nil
}

// Joined says what a joined identity is missing, or nil when it is complete: an agent id, the server, both private
// keys and the server's pinned key.
func (id *Identity) Joined() error {
	switch {
	case id == nil:
		return errors.New("no identity")
	case id.AgentID == "":
		return errors.New("the identity names no agent")
	case id.Server == "":
		return errors.New("the identity names no server")
	case len(id.SignKey) != ed25519.PrivateKeySize:
		return errors.New("the identity has no signing key")
	case id.SealKey == nil || id.SealKey.Curve() != ecdh.X25519():
		return errors.New("the identity has no sealing key")
	case len(id.ServerSignPublicKey) != ed25519.PublicKeySize:
		return errors.New("the identity has no server key")
	}
	return nil
}

// The entries of a stored identity, by name: the files of a FileStore, the keys of a Kubernetes Secret.
const (
	// AgentFile holds the agent id, the server and the server's pinned key (JSON, no private key).
	AgentFile = "agent.json"
	// SignKeyFile and SealKeyFile hold the two private keys (PKCS #8 PEM).
	SignKeyFile = "sign.key"
	SealKeyFile = "seal.key"
	// fileFormat is the version of agent.json's shape.
	fileFormat = 1
)

type agentJSON struct {
	Format              int    `json:"format"`
	AgentID             string `json:"agentId"`
	Server              string `json:"server"`
	ServerSignPublicKey string `json:"serverSignPublicKey"`
	// ServerSignPublicKeys is the set of trusted server keys once the server rolled its key over; absent before (and
	// in an identity an earlier agent wrote): the pinned key alone.
	ServerSignPublicKeys []string `json:"serverSignPublicKeys,omitempty"`
}

// Files is a joined identity as every store keeps it: agent.json, sign.key and seal.key, by name.
func (id *Identity) Files() (map[string][]byte, error) {
	if err := id.Joined(); err != nil {
		return nil, err
	}
	signKey, err := keyPEM(id.SignKey)
	if err != nil {
		return nil, err
	}
	sealKey, err := keyPEM(id.SealKey)
	if err != nil {
		return nil, err
	}
	agent, err := id.agentFile()
	if err != nil {
		return nil, err
	}
	return map[string][]byte{AgentFile: agent, SignKeyFile: signKey, SealKeyFile: sealKey}, nil
}

// agentFile is agent.json of a joined identity.
func (id *Identity) agentFile() ([]byte, error) {
	if err := id.Joined(); err != nil {
		return nil, err
	}
	file := agentJSON{
		Format:              fileFormat,
		AgentID:             id.AgentID,
		Server:              id.Server,
		ServerSignPublicKey: protocol.EncodeB64URL(id.ServerSignPublicKey),
	}
	// The set only once it is other than the pinned key alone, so an identity is written as before until then.
	if keys := id.ServerSignPublicKeys; len(keys) > 0 && !(len(keys) == 1 && keys[0].Equal(id.ServerSignPublicKey)) {
		for _, k := range keys {
			file.ServerSignPublicKeys = append(file.ServerSignPublicKeys, protocol.EncodeB64URL(k))
		}
	}
	agent, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(agent, '\n'), nil
}

// AgentFileOf is agent.json of a joined identity, as every store keeps it (a store saving only the server keys
// rewrites this entry alone).
func AgentFileOf(id *Identity) ([]byte, error) { return id.agentFile() }

// FromFiles reads an identity from its entries (Files): ErrNotFound when there is no agent.json, an error naming the
// entry (where says where it is) when one is missing or damaged, or the identity is not a joined one.
func FromFiles(files map[string][]byte, where func(name string) string) (*Identity, error) {
	data, ok := files[AgentFile]
	if !ok {
		return nil, ErrNotFound
	}
	var file agentJSON
	if err := json.Unmarshal(data, &file); err != nil {
		return nil, fmt.Errorf("%s is not valid JSON: %w", where(AgentFile), err)
	}
	if file.Format != fileFormat {
		return nil, fmt.Errorf("%s has format %d; this agent reads format %d", where(AgentFile), file.Format, fileFormat)
	}
	serverKey, err := protocol.ParseSignPublicKey(file.ServerSignPublicKey)
	if err != nil {
		return nil, fmt.Errorf("%s: serverSignPublicKey: %w", where(AgentFile), err)
	}
	var trusted []ed25519.PublicKey
	if file.ServerSignPublicKeys != nil {
		if trusted, err = protocol.ParseServerKeys(file.ServerSignPublicKeys); err != nil {
			return nil, fmt.Errorf("%s: serverSignPublicKeys: %w", where(AgentFile), err)
		}
	}
	signKey, err := readKey(files, SignKeyFile, where)
	if err != nil {
		return nil, err
	}
	sign, ok := signKey.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%s does not hold an Ed25519 key", where(SignKeyFile))
	}
	sealKey, err := readKey(files, SealKeyFile, where)
	if err != nil {
		return nil, err
	}
	seal, ok := sealKey.(*ecdh.PrivateKey)
	if !ok || seal.Curve() != ecdh.X25519() {
		return nil, fmt.Errorf("%s does not hold an X25519 key", where(SealKeyFile))
	}
	id := &Identity{AgentID: file.AgentID, Server: file.Server, SignKey: sign, SealKey: seal, ServerSignPublicKey: serverKey, ServerSignPublicKeys: trusted}
	if err := id.Joined(); err != nil {
		return nil, fmt.Errorf("%s: %w", where(AgentFile), err)
	}
	return id, nil
}

func readKey(files map[string][]byte, name string, where func(string) string) (any, error) {
	data, ok := files[name]
	if !ok {
		return nil, fmt.Errorf("%s is missing", where(name))
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("%s does not hold a PKCS #8 private key", where(name))
	}
	defer clear(block.Bytes)
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", where(name), err)
	}
	return key, nil
}

func keyPEM(key any) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	defer clear(der)
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}
