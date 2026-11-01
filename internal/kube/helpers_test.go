package kube

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"slices"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/nslookup-io/agent/internal/protocol"
)

const testAssignment = "6a1f0c2e-3b4d-4e5f-8a9b-0c1d2e3f4a5b"

// testCA issues the test certificates.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

func newCA(t *testing.T) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA", Organization: []string{"Test CA Org"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(48 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &testCA{cert: cert, key: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

// issued is a certificate with its key and chain.
type issued struct {
	leafPEM, keyPEM, chainPEM []byte
	sha                       string
}

func (ca *testCA) issue(t *testing.T, names ...string) issued {
	return ca.issueUntil(t, time.Now().Add(24*time.Hour), names...)
}

func (ca *testCA) issueUntil(t *testing.T, notAfter time.Time, names ...string) issued {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: names[0]},
		DNSNames:     names,
		NotBefore:    time.Now().Add(-48 * time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(der)
	return issued{
		leafPEM:  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		keyPEM:   pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
		chainPEM: ca.pem,
		sha:      hex.EncodeToString(sum[:]),
	}
}

// bundle is what the loop hands the installer for c (its key opened).
func (c issued) bundle() protocol.Bundle {
	return protocol.Bundle{AssignmentID: testAssignment, SHA256: c.sha, CertPEM: c.leafPEM, ChainPEM: c.chainPEM, KeyPEM: bytes.Clone(c.keyPEM)}
}

func (c issued) work(siteKey string) protocol.Work {
	return protocol.Work{AssignmentID: testAssignment, SiteKey: siteKey, SHA256: c.sha, Action: protocol.ActionInstall}
}

// ingress is an Ingress of namespace ns: tls entries (hosts and secret), then rule hosts.
func ingress(ns, name string, tls []networkingv1.IngressTLS, hosts ...string) *networkingv1.Ingress {
	ing := &networkingv1.Ingress{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name}, Spec: networkingv1.IngressSpec{TLS: tls}}
	for _, h := range hosts {
		ing.Spec.Rules = append(ing.Spec.Rules, networkingv1.IngressRule{Host: h})
	}
	return ing
}

func tlsEntry(secret string, hosts ...string) networkingv1.IngressTLS {
	return networkingv1.IngressTLS{SecretName: secret, Hosts: hosts}
}

func withClass(ing *networkingv1.Ingress, class string) *networkingv1.Ingress {
	ing.Spec.IngressClassName = &class
	return ing
}

func annotated(obj metav1.Object, key, value string) {
	a := obj.GetAnnotations()
	if a == nil {
		a = map[string]string{}
	}
	a[key] = value
	obj.SetAnnotations(a)
}

// tlsSecret is a kubernetes.io/tls secret holding c, with a ca.crt beside it.
func tlsSecret(ns, name string, c issued) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, ResourceVersion: "7"},
		Type:       corev1.SecretTypeTLS,
		Data: map[string][]byte{
			corev1.TLSCertKey:       append(bytes.Clone(c.leafPEM), c.chainPEM...),
			corev1.TLSPrivateKeyKey: bytes.Clone(c.keyPEM),
			"ca.crt":                []byte("customer's own CA bundle"),
		},
	}
}

func cluster(objects ...runtime.Object) *fake.Clientset {
	return fake.NewClientset(objects...)
}

// writes are the create, update and patch calls on secrets (and every write on ingresses) the client saw.
func writes(cs *fake.Clientset) []k8stesting.Action {
	var out []k8stesting.Action
	for _, a := range cs.Actions() {
		switch a.GetVerb() {
		case "get", "list", "watch":
			continue
		}
		out = append(out, a)
	}
	return out
}

// secretOf reads a secret from the fake cluster's store.
func secretOf(t *testing.T, cs *fake.Clientset, ns, name string) *corev1.Secret {
	t.Helper()
	obj, err := cs.Tracker().Get(corev1.SchemeGroupVersion.WithResource("secrets"), ns, name)
	if err != nil {
		t.Fatalf("secret %s/%s: %v", ns, name, err)
	}
	return obj.(*corev1.Secret)
}

func siteByName(t *testing.T, sites []protocol.Site, secret string) protocol.Site {
	t.Helper()
	i := slices.IndexFunc(sites, func(s protocol.Site) bool { return s.Secret != nil && s.Secret.Name == secret })
	if i < 0 {
		t.Fatalf("no site for the secret %s among %d sites", secret, len(sites))
	}
	return sites[i]
}
