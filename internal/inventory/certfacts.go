package inventory

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"io/fs"
	"math/big"
	"path"
	"strings"
	"time"
	"unicode"

	"github.com/nslookup-io/agent/internal/protocol"
)

const (
	// maxCertFile: a certificate file with its chain (and HAProxy's key) is a few kilobytes.
	maxCertFile = 1 << 20
	// maxCertNames is the most names the server takes for one certificate.
	maxCertNames = 1000
	maxIssuer    = 1024
	maxSerial    = 128
)

var certBegin = []byte("-----BEGIN CERTIFICATE-----")

// ReadCertFacts describes the certificate file at p (an absolute path): its first certificate, the leaf. Nothing
// before the first certificate is decoded, so a private key in the same file (HAProxy's combined file) is never
// parsed, and what was read is cleared.
func ReadCertFacts(fsys fs.FS, p string) (protocol.CertFacts, error) {
	leaf, err := certFacts(fsys, p, time.Now())
	return leaf.facts, err
}

// leafFacts are the facts of a file's leaf certificate, the names left out (those the server would refuse), and
// whether the certificate is one a host can rely on at the time read (trusted: not self-signed, not expired), so its
// names may stand for the hosts a site serves beyond the names it lists.
type leafFacts struct {
	facts   protocol.CertFacts
	odd     []string
	trusted bool
}

// certFacts is ReadCertFacts, with the names left out and whether the certificate is trusted at now.
func certFacts(fsys fs.FS, p string, now time.Time) (leafFacts, error) {
	data, err := readFile(fsys, p, maxCertFile)
	if err != nil {
		return leafFacts{}, err
	}
	defer clear(data)
	facts, odd, leaf, err := certFactsOf(data, p)
	if err != nil {
		return leafFacts{}, err
	}
	// Self-signed (a snakeoil certificate naming the machine) or expired: no host relies on it today.
	trusted := !bytes.Equal(leaf.RawIssuer, leaf.RawSubject) && now.Before(leaf.NotAfter)
	return leafFacts{facts: facts, odd: odd, trusted: trusted}, nil
}

// CertFactsOf describes the first certificate in data, the leaf, as ReadCertFacts does a file's (a Kubernetes secret's
// tls.crt).
func CertFactsOf(data []byte) (protocol.CertFacts, error) {
	facts, _, _, err := certFactsOf(data, "the data")
	return facts, err
}

// certFactsOf is CertFactsOf, where saying where data comes from in errors, with the names left out.
func certFactsOf(data []byte, where string) (facts protocol.CertFacts, odd []string, leaf *x509.Certificate, err error) {
	i := bytes.Index(data, certBegin)
	if i < 0 {
		return facts, nil, nil, fmt.Errorf("%s holds no certificate", where)
	}
	block, _ := pem.Decode(data[i:])
	if block == nil || block.Type != "CERTIFICATE" {
		return facts, nil, nil, fmt.Errorf("%s: the first certificate is not readable PEM", where)
	}
	leaf, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		return facts, nil, nil, fmt.Errorf("%s: %w", where, err)
	}
	sum := sha256.Sum256(leaf.Raw)
	issuer := leaf.Issuer.CommonName
	if len(leaf.Issuer.Organization) > 0 && strings.TrimSpace(leaf.Issuer.Organization[0]) != "" {
		issuer = leaf.Issuer.Organization[0]
	}
	names := leaf.DNSNames
	if len(names) == 0 {
		names = []string{leaf.Subject.CommonName}
	}
	facts = protocol.CertFacts{
		SHA256:   hex.EncodeToString(sum[:]),
		Issuer:   protocol.Clip(issuer, maxIssuer),
		Serial:   serialText(leaf.SerialNumber),
		NotAfter: leaf.NotAfter.UTC().Format(time.RFC3339),
	}
	for _, raw := range names {
		n, ok := certName(raw)
		switch {
		case !ok && raw != "":
			odd = append(odd, raw)
		case ok && len(facts.Names) < maxCertNames:
			facts.Names = append(facts.Names, n)
		}
	}
	return facts, odd, leaf, nil
}

// serialText is a serial number as the server takes it: lowercase hex, at most 128 characters.
func serialText(serial *big.Int) string {
	return protocol.Clip(serial.Text(16), maxSerial)
}

// certName is a certificate's name as the server takes it: lowercase, 1 to 253 characters (bytes, so never more
// UTF-16 units), no control character and no space of any kind (Unicode white space, the byte order mark). The server
// refuses the whole inventory for one such name.
func certName(raw string) (string, bool) {
	n := strings.ToLower(raw)
	odd := func(r rune) bool { return unicode.IsSpace(r) || r == '\ufeff' || unicode.IsControl(r) }
	if n == "" || len(n) > maxHostName || strings.ContainsFunc(n, odd) {
		return "", false
	}
	return n, true
}

// readFile reads the file at the absolute path p, refusing anything but a regular file and a file over max bytes. The
// file is looked at through the descriptor it is read from (HostFS opens without waiting on a named pipe), so nothing
// swapped in between can hold the read.
func readFile(fsys fs.FS, p string, max int64) ([]byte, error) {
	f, err := fsys.Open(fsPath(p))
	if err != nil {
		return nil, err
	}
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

// isFile reports whether the absolute path p is a regular file (a link to one counts).
func isFile(fsys fs.FS, p string) bool {
	info, err := fs.Stat(fsys, fsPath(p))
	return err == nil && info.Mode().IsRegular()
}

// fsPath is an absolute path as an fs.FS rooted at / names it: no leading slash, "." for / itself.
func fsPath(p string) string {
	p = strings.TrimPrefix(path.Clean("/"+p), "/")
	if p == "" {
		return "."
	}
	return p
}
