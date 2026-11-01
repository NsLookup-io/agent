package inventory

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"io/fs"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"golang.org/x/sys/unix"
)

func TestCertFactsAreTheLeafs(t *testing.T) {
	m := newMachine(t)
	// HAProxy's order: the key first, then the leaf, then the chain.
	m.combined("/etc/ssl/site.pem", "Site.Example", "www.site.example")
	got, err := ReadCertFacts(m.fs, "/etc/ssl/site.pem")
	if err != nil {
		t.Fatal(err)
	}
	want := *m.facts("/etc/ssl/site.pem")
	want.Names = []string{"site.example", "www.site.example"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v\nwant %+v", got, want)
	}
	if !strings.HasSuffix(got.NotAfter, "Z") || len(got.SHA256) != 64 || got.Serial != strings.ToLower(got.Serial) {
		t.Errorf("formats %+v", got)
	}
}

// selfSigned is a certificate with the given subject and names and no issuer organisation.
func selfSigned(t *testing.T, subject pkix.Name, names []string, serial int64) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      subject,
		DNSNames:     names,
		NotBefore:    time.Unix(1700000000, 0),
		NotAfter:     time.Unix(1800000000, 0),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return certPEM(c)
}

func TestCertFactsWithoutNamesOrOrganisation(t *testing.T) {
	m := newMachine(t)
	m.file("/etc/ssl/cn.pem", selfSigned(t, pkix.Name{CommonName: "legacy.example"}, nil, 0xab01))
	got, err := ReadCertFacts(m.fs, "/etc/ssl/cn.pem")
	if err != nil {
		t.Fatal(err)
	}
	// No organisation: the issuer is its common name; no DNS names: the common name.
	if got.Issuer != "legacy.example" || !slices.Equal(got.Names, []string{"legacy.example"}) || got.Serial != "ab01" || got.NotAfter != "2027-01-15T08:00:00Z" {
		t.Errorf("facts %+v", got)
	}

	// A common name that is no host name is not a name.
	m.file("/etc/ssl/odd.pem", selfSigned(t, pkix.Name{CommonName: "Example Device\x01 1"}, []string{"ok.example", "bad name.example", ""}, 7))
	got, err = ReadCertFacts(m.fs, "/etc/ssl/odd.pem")
	if err != nil || !slices.Equal(got.Names, []string{"ok.example"}) || got.Issuer != "Example Device 1" {
		t.Errorf("facts %+v, %v", got, err)
	}
}

func TestCertFactsRefuses(t *testing.T) {
	m := newMachine(t)
	m.file("/etc/ssl/key-only.pem", []byte("-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49\n-----END PRIVATE KEY-----\n"))
	m.file("/etc/ssl/broken.pem", []byte("-----BEGIN CERTIFICATE-----\nnot base64\n-----END CERTIFICATE-----\n"))
	m.file("/etc/ssl/big.pem", make([]byte, 1<<20+1))
	for _, p := range []string{"/etc/ssl/key-only.pem", "/etc/ssl/broken.pem", "/etc/ssl/big.pem", "/etc/ssl/missing.pem", "/etc/ssl"} {
		if f, err := ReadCertFacts(m.fs, p); err == nil {
			t.Errorf("%s: %+v", p, f)
		}
	}
}

// A serial is sent as lowercase hex of at most 128 characters, the server's limit (a certificate's serial is at most
// 20 bytes, but not every certificate keeps to that).
func TestASerialFitsTheServersLimit(t *testing.T) {
	long := new(big.Int).Lsh(big.NewInt(1), 1000)
	if got := serialText(long); len(got) != 128 || strings.Trim(got, "0") != "1" {
		t.Errorf("%d characters: %q", len(got), got)
	}
	if got := serialText(big.NewInt(0xAB12)); got != "ab12" {
		t.Errorf("%q", got)
	}
}

// A named pipe put where a certificate file was never holds up the read: the file is opened without waiting for a
// writer and looked at through the open descriptor.
func TestANamedPipeNeverHoldsUpTheRead(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "etc/ssl"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(filepath.Join(root, "etc/ssl/site.pem"), 0o644); err != nil {
		t.Fatal(err)
	}
	// The pipe swapped in after it was looked at: a file system whose Stat still sees the regular file.
	swapped := swappedFS{FS: HostFS(root)}
	done := make(chan error, 1)
	go func() {
		_, err := ReadCertFacts(swapped, "/etc/ssl/site.pem")
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "not a regular file") {
			t.Errorf("%v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("reading a named pipe waits for a writer")
	}
}

// HostFS reads the machine's files as os.DirFS does.
func TestHostFS(t *testing.T) {
	root := t.TempDir()
	m := newMachine(t)
	m.cert("/etc/ssl/site.pem", "", "site.example")
	if err := os.MkdirAll(filepath.Join(root, "etc/ssl"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "etc/ssl/site.pem"), m.fs["etc/ssl/site.pem"].Data, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("site.pem", filepath.Join(root, "etc/ssl/link.pem")); err != nil {
		t.Fatal(err)
	}
	fsys := HostFS(root)
	if err := fstest.TestFS(fsys, "etc/ssl/site.pem", "etc/ssl/link.pem"); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"/etc/ssl/site.pem", "/etc/ssl/link.pem"} {
		if got, err := ReadCertFacts(fsys, p); err != nil || !reflect.DeepEqual(got, *m.facts("/etc/ssl/site.pem")) {
			t.Errorf("%s: %+v, %v", p, got, err)
		}
	}
	if _, err := fsys.Open("../etc"); err == nil {
		t.Error("a path out of the root was opened")
	}
}

// swappedFS is a file system where every name was a regular file when looked at (Stat), whatever it is when opened.
type swappedFS struct{ fs.FS }

func (s swappedFS) Stat(name string) (fs.FileInfo, error) {
	return fstest.MapFS{name: &fstest.MapFile{Data: []byte("x"), Mode: 0o644}}.Stat(name)
}
