package install

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/nslookup-io/agent/internal/inventory"
	"github.com/nslookup-io/agent/internal/protocol"
)

// certificate is a bundle checked and ready to write: its parts as PEM blocks re-encoded from what was parsed, so no
// other text of the server's answer ever reaches a file.
type certificate struct {
	leaf  []byte
	chain []byte
	key   []byte
}

func (c *certificate) clear() { clear(c.key) }

// checkBundle checks a bundle before anything is written: its leaf (the first certificate) is the one the work names
// (sha, the SHA-256 of its DER), it matches the key, covers every name of the site and has not expired; the chain
// holds certificates only.
func checkBundle(certPEM, chainPEM, keyPEM []byte, sha string, names []string, now time.Time) (*certificate, error) {
	block := firstBlock(certPEM, "CERTIFICATE")
	if block == nil {
		return nil, errors.New("the bundle holds no certificate")
	}
	sum := sha256.Sum256(block.Bytes)
	if hex.EncodeToString(sum[:]) != sha {
		return nil, errors.New("the bundle's certificate is not the certificate the work names")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("the bundle's certificate cannot be read: %w", err)
	}
	if now.After(leaf.NotAfter) {
		return nil, fmt.Errorf("the certificate expired on %s", leaf.NotAfter.UTC().Format(time.RFC3339))
	}
	for _, n := range names {
		if !covers(leaf.DNSNames, n) {
			return nil, fmt.Errorf("the certificate does not cover %s", n)
		}
	}
	c := &certificate{leaf: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: block.Bytes})}
	for rest := chainPEM; ; {
		var b *pem.Block
		if b, rest = pem.Decode(rest); b == nil {
			break
		}
		if b.Type != "CERTIFICATE" || len(b.Headers) > 0 {
			return nil, fmt.Errorf("the bundle's chain holds a %s, not only certificates", b.Type)
		}
		if _, err := x509.ParseCertificate(b.Bytes); err != nil {
			return nil, fmt.Errorf("a certificate of the bundle's chain cannot be read: %w", err)
		}
		c.chain = append(c.chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: b.Bytes})...)
	}
	key, err := checkKey(keyPEM, leaf)
	if err != nil {
		return nil, err
	}
	c.key = key
	return c, nil
}

// CheckBundle is the check every install starts with (checkBundle), for an installer outside this package (a Kubernetes
// secret): the leaf, the chain and the key of b as PEM re-encoded from what was parsed. The caller clears the key.
func CheckBundle(b protocol.Bundle, sha string, names []string, now time.Time) (leaf, chain, key []byte, err error) {
	c, err := checkBundle(b.CertPEM, b.ChainPEM, b.KeyPEM, sha, names, now)
	if err != nil {
		return nil, nil, nil, err
	}
	return c.leaf, c.chain, c.key, nil
}

// checkKey reads the key PEM (PKCS #8, PKCS #1 RSA or SEC 1 EC, unencrypted) and checks it is the leaf's.
func checkKey(keyPEM []byte, leaf *x509.Certificate) ([]byte, error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil || len(block.Headers) > 0 {
		return nil, errors.New("the bundle's key is not an unencrypted PEM key")
	}
	defer clear(block.Bytes)
	var key any
	var err error
	switch block.Type {
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("the bundle's key is a %s, not a private key", block.Type)
	}
	if err != nil {
		return nil, errors.New("the bundle's key cannot be read")
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, errors.New("the bundle's key cannot be read")
	}
	public, ok := signer.Public().(interface{ Equal(crypto.PublicKey) bool })
	if !ok || !public.Equal(leaf.PublicKey) {
		return nil, errors.New("the bundle's key does not match its certificate")
	}
	return pem.EncodeToMemory(&pem.Block{Type: block.Type, Bytes: block.Bytes}), nil
}

// LeafSHA is the SHA-256 (lowercase hex) of the first certificate in data, the leaf: what an install compares with the
// certificate a work names. "" when data holds no certificate.
func LeafSHA(data []byte) string {
	block := firstBlock(data, "CERTIFICATE")
	if block == nil {
		return ""
	}
	return sha256Hex(block.Bytes)
}

// firstBlock is the first PEM block of type typ in data; nil when there is none.
func firstBlock(data []byte, typ string) *pem.Block {
	for rest := data; ; {
		i := bytes.Index(rest, []byte("-----BEGIN "+typ+"-----"))
		if i < 0 {
			return nil
		}
		var b *pem.Block
		if b, rest = pem.Decode(rest[i:]); b == nil {
			return nil
		}
		if b.Type == typ {
			return b
		}
	}
}

// covers reports whether a certificate for sans covers name: the same name, or a wildcard (*.example.com) for one
// label more (a.example.com, never a.b.example.com).
func covers(sans []string, name string) bool {
	for _, san := range sans {
		san = strings.ToLower(san)
		if san == name {
			return true
		}
		if rest, ok := strings.CutPrefix(san, "*."); ok {
			if label, parent, found := strings.Cut(name, "."); found && label != "" && label != "*" && parent == rest {
				return true
			}
		}
	}
	return false
}

// file is one file an install writes: its path as configured and its content; key says it holds the private key,
// chain that it is a chain file (and nothing else).
type file struct {
	path  string
	data  []byte
	key   bool
	chain bool
}

// layout is what every configuration using a certificate file expects in each file it names:
//   - the certificate's file: the certificate with its chain (nginx's ssl_certificate, Apache's SSLCertificateFile,
//     HAProxy's crt), only the certificate when the configuration names a chain file (Apache's
//     SSLCertificateChainFile), and the key first when the key is in it (HAProxy's one file, Apache without
//     SSLCertificateKeyFile);
//   - the key's file, when it is another: the key;
//   - the chain's file, when there is one: the chain.
//
// The configurations must expect the same: one that does not would get files it cannot use.
func layout(uses []inventory.Use, c *certificate) ([]file, error) {
	planned := map[string]file{}
	by := map[string]inventory.Use{}
	for _, u := range uses {
		for _, f := range useLayout(u, c) {
			if f.err != nil {
				return nil, f.err
			}
			if prev, ok := planned[f.path]; ok && !bytes.Equal(prev.data, f.data) {
				other := by[f.path]
				return nil, fmt.Errorf("the configurations using %s expect different files: %s (%s) and %s (%s); fix them to name the same files",
					uses[0].CertPath, other.ConfigPath, other.Kind, u.ConfigPath, u.Kind)
			}
			planned[f.path], by[f.path] = f.file, u
		}
	}
	files := make([]file, 0, len(planned))
	for _, f := range planned {
		files = append(files, f)
	}
	slices.SortFunc(files, func(a, b file) int { return strings.Compare(a.path, b.path) })
	return files, nil
}

type plannedFile struct {
	file
	err error
}

func useLayout(u inventory.Use, c *certificate) []plannedFile {
	chainFile := u.ChainPath != "" && u.ChainPath != u.CertPath
	cert := c.leaf
	if !chainFile {
		cert = cat(c.leaf, c.chain)
	}
	if u.KeyPath == u.CertPath {
		cert = cat(c.key, cert)
	}
	out := []plannedFile{{file: file{path: u.CertPath, data: cert, key: u.KeyPath == u.CertPath}}}
	if u.KeyPath != u.CertPath {
		out = append(out, plannedFile{file: file{path: u.KeyPath, data: c.key, key: true}})
	}
	if chainFile {
		switch {
		case u.ChainPath == u.KeyPath:
			out = append(out, plannedFile{err: fmt.Errorf("%s names one file for the key and the chain", u.ConfigPath)})
		case len(c.chain) == 0:
			out = append(out, plannedFile{err: fmt.Errorf("the certificate comes with no chain for %s", u.ChainPath)})
		default:
			out = append(out, plannedFile{file: file{path: u.ChainPath, data: c.chain, chain: true}})
		}
	}
	return out
}

func cat(parts ...[]byte) []byte { return bytes.Join(parts, nil) }

// certificatesOf are the DER bytes of the CERTIFICATE blocks of data, in order; nil when data holds anything else.
func certificatesOf(data []byte) [][]byte {
	var ders [][]byte
	for rest := bytes.TrimSpace(data); len(rest) > 0; rest = bytes.TrimSpace(rest) {
		var b *pem.Block
		if b, rest = pem.Decode(rest); b == nil || b.Type != "CERTIFICATE" {
			return nil
		}
		ders = append(ders, b.Bytes)
	}
	return ders
}
