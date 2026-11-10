package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/version"
	fakediscovery "k8s.io/client-go/discovery/fake"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/nslookup-io/agent/internal/protocol"
)

// inCluster makes the agent's cluster a fake one, the agent running in namespace agents, with an Ingress in shop and
// one in web.
func (h *harness) inCluster() *fake.Clientset {
	class := "nginx"
	ingress := func(ns, name, host string) *networkingv1.Ingress {
		return &networkingv1.Ingress{
			ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
			Spec: networkingv1.IngressSpec{
				IngressClassName: &class,
				TLS:              []networkingv1.IngressTLS{{Hosts: []string{host}, SecretName: name + "-tls"}},
				Rules:            []networkingv1.IngressRule{{Host: host}},
			},
		}
	}
	cs := fake.NewClientset(ingress("shop", "storefront", "shop.example.test"), ingress("web", "status", "status.example.test"))
	cs.Discovery().(*fakediscovery.FakeDiscovery).FakedServerVersion = &version.Info{GitVersion: "v1.31.2"}
	h.cli.kube = func() (kubernetes.Interface, string, error) { return cs, "agents", nil }
	return cs
}

func TestAKubernetesAgentKeepsItsIdentityInASecret(t *testing.T) {
	h := newCLI(t)
	cs := h.inCluster()
	e := newEngine(t)
	if code := h.run("join", "--mode=kubernetes", "--server="+e.srv.URL, testCode); code != 0 {
		t.Fatalf("exit %d: %s", code, h.stderr.String())
	}
	if len(e.joins) != 1 || e.joins[0].Kind != protocol.KindKubernetes || e.joins[0].Facts.Kubernetes == nil ||
		e.joins[0].Facts.Kubernetes.Version != "1.31.2" || *e.joins[0].Facts.Kubernetes.IngressController != "nginx" {
		t.Errorf("join requests %+v", e.joins)
	}
	secret, err := cs.CoreV1().Secrets("agents").Get(context.Background(), "nslookup-agent-identity", metav1.GetOptions{})
	if err != nil || !bytes.Contains(secret.Data["agent.json"], []byte(testAgentID)) {
		t.Fatalf("%+v, %v", secret, err)
	}
	if _, err := os.Stat(filepath.Join(h.cli.stateDir, "identity")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("an identity directory: %v", err)
	}

	if code := h.run("join", "--mode=kubernetes", "--server="+e.srv.URL, testCode); code != 1 {
		t.Errorf("a second join: exit %d", code)
	}
	if want := "already joined as " + testAgentID + "; remove the secret agents/nslookup-agent-identity to join again"; !strings.Contains(h.stderr.String(), want) {
		t.Errorf("stderr %q, want %q", h.stderr.String(), want)
	}

	// Run: joined already, the code is not used again; removed, it says how to remove it from the cluster.
	h.env["NSL_JOIN"] = testCode
	removed := "Remove it with: helm uninstall nslookup-agent -n agents, then kubectl delete secret nslookup-agent-identity -n agents"
	if code := h.runUntil(removed, "run", "--mode=kubernetes"); code != 0 {
		t.Fatalf("exit %d: %s", code, h.stderr.String())
	}
	if len(e.joins) != 1 || e.beats != 1 || !strings.Contains(h.stderr.String(), "already joined; the join code is not used") {
		t.Errorf("%d joins, %d heartbeats: %s", len(e.joins), e.beats, h.stderr.String())
	}
}

func TestAKubernetesAgentReportsTheIngressesOfItsNamespaces(t *testing.T) {
	h := newCLI(t)
	h.inCluster()
	if code := h.run("inventory", "--mode=kubernetes", "--namespaces=shop"); code != 0 {
		t.Fatalf("exit %d: %s", code, h.stderr.String())
	}
	var out struct {
		Facts     protocol.AgentFacts `json:"facts"`
		Inventory protocol.Inventory  `json:"inventory"`
	}
	if err := json.Unmarshal(h.stdout.Bytes(), &out); err != nil {
		t.Fatalf("%v: %s", err, h.stdout.String())
	}
	if k := out.Facts.Kubernetes; k == nil || k.Version != "1.31.2" || k.IngressController == nil || *k.IngressController != "nginx" || len(out.Facts.WebServers) != 0 {
		t.Errorf("facts %s", h.stdout.String())
	}
	sites := out.Inventory.Sites
	if len(sites) != 1 || sites[0].Kind != protocol.SiteK8sIngress || sites[0].Secret.Namespace != "shop" || sites[0].Secret.Name != "storefront-tls" || sites[0].Secret.Ingress != "storefront" {
		t.Errorf("sites %s", h.stdout.String())
	}
}

// A Kubernetes agent installs into the TLS secrets of the sites it read: the work names only the site's key.
func TestAKubernetesAgentWritesTheSecretsOfTheSitesItRead(t *testing.T) {
	h := newCLI(t)
	cs := h.inCluster()
	p := h.parts(settings{kind: protocol.KindKubernetes, namespaces: []string{"shop"}})
	if p.folder != nil || p.recover != nil {
		t.Errorf("parts %+v", p)
	}
	inv, err := p.inventory(context.Background())
	if err != nil || len(inv.Sites) != 1 {
		t.Fatalf("%+v, %v", inv, err)
	}
	site := inv.Sites[0]
	if disk, err := p.installer.DiskSHA(site); err != nil || disk != "" {
		t.Fatalf("on disk %q, %v", disk, err)
	}
	cert, key, sha := selfSigned(t, "shop.example.test")
	work := protocol.Work{AssignmentID: "6a1f0c2e-3b4d-4e5f-8a9b-0c1d2e3f4a5b", SiteKey: site.SiteKey, SHA256: sha, Action: protocol.ActionInstall}
	if r := p.installer.Apply(context.Background(), site, protocol.Bundle{AssignmentID: work.AssignmentID, SHA256: sha, CertPEM: cert, KeyPEM: key}, work); !r.OK {
		t.Fatalf("%+v", r)
	}
	secret, err := cs.CoreV1().Secrets("shop").Get(context.Background(), "storefront-tls", metav1.GetOptions{})
	if err != nil || secret.Type != corev1.SecretTypeTLS || !bytes.Equal(secret.Data[corev1.TLSPrivateKeyKey], key) {
		t.Fatalf("%+v, %v", secret, err)
	}
	if disk, err := p.installer.DiskSHA(site); err != nil || disk != sha {
		t.Errorf("on disk %q, %v", disk, err)
	}
}

func TestAKubernetesAgentThatCannotConnect(t *testing.T) {
	h := newCLI(t)
	h.cli.kube = func() (kubernetes.Interface, string, error) {
		return nil, "", errors.New("unable to load in-cluster configuration (outside a cluster, set KUBECONFIG)")
	}
	if code := h.run("inventory", "--mode=kubernetes"); code != 1 || !strings.Contains(h.stderr.String(), "connecting to the cluster: unable to load in-cluster configuration") {
		t.Errorf("exit %d, stderr %s", code, h.stderr.String())
	}
	// The other modes never connect.
	if code := h.run("inventory", "--mode=docker"); code != 0 {
		t.Errorf("exit %d, stderr %s", code, h.stderr.String())
	}
}

// A Kubernetes agent names the sites whose secret carries its own record of an install: its loop keeps them in a cut
// list even when no work names them.
func TestAKubernetesAgentNamesTheSitesItInstalledOn(t *testing.T) {
	h := newCLI(t)
	cs := h.inCluster()
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "storefront-tls", Labels: map[string]string{"app.kubernetes.io/managed-by": "nslookup-agent"},
			Annotations: map[string]string{"nslookup.io/sha256": strings.Repeat("a", 64)}},
		Type: corev1.SecretTypeTLS,
	}
	if _, err := cs.CoreV1().Secrets("shop").Create(context.Background(), secret, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	p := h.parts(settings{kind: protocol.KindKubernetes})
	if p.owned == nil {
		t.Fatal("no owned sites")
	}
	inv, err := p.inventory(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var want string
	for _, s := range inv.Sites {
		if s.Secret.Name == "storefront-tls" {
			want = s.SiteKey
		}
	}
	if got := p.owned(); len(got) != 1 || got[0] != want {
		t.Errorf("owned %v, want [%s]", got, want)
	}
}

// The annotations switch reaches both what the agent says about itself (facts) and what it reads (the inventory).
func TestAnnotationsSwitchReachesFactsAndInventory(t *testing.T) {
	for _, on := range []bool{false, true} {
		h := newCLI(t)
		ing := &networkingv1.Ingress{
			ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "web", Annotations: map[string]string{protocol.AnnotationEnabled: "true"}},
			Spec: networkingv1.IngressSpec{
				TLS:   []networkingv1.IngressTLS{{Hosts: []string{"shop.example.test"}, SecretName: "shop-tls"}},
				Rules: []networkingv1.IngressRule{{Host: "shop.example.test"}},
			},
		}
		cs := fake.NewClientset(ing)
		h.cli.kube = func() (kubernetes.Interface, string, error) { return cs, "agents", nil }
		p, err := h.cli.parts(settings{kind: protocol.KindKubernetes, annotations: on})
		if err != nil {
			t.Fatal(err)
		}
		facts := p.facts(context.Background())
		if facts.Kubernetes == nil || facts.Kubernetes.Annotations != on {
			t.Errorf("annotations %v: facts = %+v", on, facts.Kubernetes)
		}
		inv, err := p.inventory(context.Background())
		if err != nil || len(inv.Sites) != 1 {
			t.Fatalf("annotations %v: %+v, %v", on, inv, err)
		}
		if got := inv.Sites[0].Autopilot != nil; got != on {
			t.Errorf("annotations %v: a site carries autopilot = %v", on, got)
		}
	}
}
