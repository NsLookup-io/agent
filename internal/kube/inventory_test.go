package kube

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/version"
	fakediscovery "k8s.io/client-go/discovery/fake"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/nslookup-io/agent/internal/inventory"
	"github.com/nslookup-io/agent/internal/protocol"
)

// fixture is a cluster with a site of every kind: a TLS secret two Ingresses share, cert-manager's (by the Ingress's
// issuer, by the secret's annotations), one with ownerReferences, an Opaque one, an immutable one, and hosts served
// without TLS.
type fixture struct {
	cs   *fake.Clientset
	shop issued
}

func newFixture(t *testing.T) fixture {
	ca := newCA(t)
	shop := ca.issue(t, "shop.example.test", "www.shop.example.test", "admin.shop.example.test")

	gateway := ingress("api", "gateway", []networkingv1.IngressTLS{tlsEntry("api-tls", "api.example.test")}, "api.example.test")
	annotated(gateway, "cert-manager.io/cluster-issuer", "letsencrypt")
	legacySecret := tlsSecret("api", "legacy-tls", ca.issue(t, "legacy.example.test"))
	annotated(legacySecret, "cert-manager.io/certificate-name", "legacy")
	owned := tlsSecret("web", "owned-tls", ca.issue(t, "owned.example.test"))
	owned.OwnerReferences = []metav1.OwnerReference{{APIVersion: "v1", Kind: "ConfigMap", Name: "owner", UID: "1"}}
	opaque := tlsSecret("web", "opaque-tls", ca.issue(t, "opaque.example.test"))
	opaque.Type = corev1.SecretTypeOpaque
	frozen := tlsSecret("web", "frozen-tls", ca.issue(t, "frozen.example.test"))
	immutable := true
	frozen.Immutable = &immutable

	objects := []runtime.Object{
		withClass(ingress("shop", "storefront", []networkingv1.IngressTLS{tlsEntry("shop-tls", "shop.example.test", "WWW.shop.example.test")},
			"shop.example.test", "www.shop.example.test"), "nginx"),
		withClass(ingress("shop", "admin", []networkingv1.IngressTLS{tlsEntry("shop-tls", "admin.shop.example.test")}, "admin.shop.example.test"), "nginx"),
		tlsSecret("shop", "shop-tls", shop),
		withClass(gateway, "traefik"),
		ingress("api", "legacy", []networkingv1.IngressTLS{tlsEntry("legacy-tls", "legacy.example.test")}),
		legacySecret,
		ingress("web", "owned", []networkingv1.IngressTLS{tlsEntry("owned-tls", "owned.example.test")}),
		owned,
		ingress("web", "opaque", []networkingv1.IngressTLS{tlsEntry("opaque-tls", "opaque.example.test")}),
		opaque,
		ingress("web", "frozen", []networkingv1.IngressTLS{tlsEntry("frozen-tls", "frozen.example.test")}),
		frozen,
		// Served without TLS: status and the wildcard; docs is under a TLS wildcard of another Ingress.
		withClass(ingress("web", "status", nil, "status.example.test", "*.apps.example.test", "docs.wild.example.test"), "nginx"),
		ingress("web", "wild", []networkingv1.IngressTLS{tlsEntry("wild-tls", "*.wild.example.test")}),
	}
	return fixture{cs: cluster(objects...), shop: shop}
}

func TestInventoryReadsTheTLSSecretsOfEveryIngress(t *testing.T) {
	f := newFixture(t)
	inv, err := Inventory(context.Background(), f.cs, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	cm, other := protocol.OwnerCertManager, protocol.OwnerOther
	ownedBy, notTLS, immutable := protocol.BlockedOwnedByOther, protocol.BlockedSecretNotTLS, protocol.BlockedSecretImmutable
	want := []struct {
		namespace, secret, ingress string
		names                      []string
		owner                      *protocol.SiteOwner
		blocked                    *protocol.SiteBlocked
		served                     bool
	}{
		// Two Ingresses share shop-tls: one site with every name of both, named after the first Ingress.
		{"shop", "shop-tls", "admin", []string{"admin.shop.example.test", "shop.example.test", "www.shop.example.test"}, nil, nil, true},
		// The Ingress asks cert-manager for it: cert-manager's, though the secret does not exist yet.
		{"api", "api-tls", "gateway", []string{"api.example.test"}, &cm, nil, false},
		{"api", "legacy-tls", "legacy", []string{"legacy.example.test"}, &cm, nil, true},
		{"web", "owned-tls", "owned", []string{"owned.example.test"}, &other, &ownedBy, true},
		{"web", "opaque-tls", "opaque", []string{"opaque.example.test"}, nil, &notTLS, true},
		{"web", "frozen-tls", "frozen", []string{"frozen.example.test"}, nil, &immutable, true},
		{"web", "wild-tls", "wild", []string{"*.wild.example.test"}, nil, nil, false},
		{"web", "status-example-test-tls", "status", []string{"status.example.test"}, nil, nil, false},
		{"web", "wildcard-apps-example-test-tls", "status", []string{"*.apps.example.test"}, nil, nil, false},
	}
	if len(inv.Sites) != len(want) {
		t.Fatalf("%d sites, want %d: %+v", len(inv.Sites), len(want), inv.Sites)
	}
	for _, w := range want {
		s := siteByName(t, inv.Sites, w.secret)
		ref := protocol.SecretRef{Namespace: w.namespace, Name: w.secret, Ingress: w.ingress}
		if s.Kind != protocol.SiteK8sIngress || *s.Secret != ref || !reflect.DeepEqual(s.Names, w.names) {
			t.Errorf("%s: %s %+v %v", w.secret, s.Kind, *s.Secret, s.Names)
		}
		if key := inventory.SiteKey(protocol.SiteK8sIngress, w.namespace+"/"+w.ingress, w.secret); s.SiteKey != key {
			t.Errorf("%s: site key %s, want %s", w.secret, s.SiteKey, key)
		}
		if !reflect.DeepEqual(s.Owner, w.owner) || !reflect.DeepEqual(s.Blocked, w.blocked) {
			t.Errorf("%s: owner %v, blocked %v; want %v, %v", w.secret, ptrString(s.Owner), ptrString(s.Blocked), ptrString(w.owner), ptrString(w.blocked))
		}
		if (s.Served != nil) != w.served {
			t.Errorf("%s: served %+v", w.secret, s.Served)
		}
		if s.ConfigPath != nil || s.CertPath != nil || s.KeyPath != nil || s.ChainPath != nil || s.CertbotName != nil {
			t.Errorf("%s: paths on a Kubernetes site: %+v", w.secret, s)
		}
	}
	shop := siteByName(t, inv.Sites, "shop-tls")
	if shop.Served.SHA256 != f.shop.sha || shop.Served.Issuer != "Test CA Org" || len(shop.Served.Names) != 3 {
		t.Errorf("served %+v", shop.Served)
	}
	for i := 1; i < len(inv.Sites); i++ {
		if inv.Sites[i-1].SiteKey >= inv.Sites[i].SiteKey {
			t.Error("the sites are not in the order of their keys")
		}
	}
}

// The inventory holds no key material, and reading it changes nothing in the cluster.
func TestInventoryNeverSendsAKeyNorWritesAnything(t *testing.T) {
	f := newFixture(t)
	inv, err := Inventory(context.Background(), f.cs, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(inv)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"BEGIN", "PRIVATE", "customer's own CA"} {
		if bytes.Contains(body, []byte(bad)) {
			t.Errorf("the inventory holds %q: %s", bad, body)
		}
	}
	if w := writes(f.cs); len(w) != 0 {
		t.Errorf("reading wrote %v", w)
	}
	// Only the secrets the Ingresses name are read, each with a get: never a list of secrets.
	var got []string
	for _, a := range f.cs.Actions() {
		if a.GetResource().Resource != "secrets" {
			continue
		}
		g, ok := a.(k8stesting.GetAction)
		if !ok {
			t.Fatalf("a %s of secrets", a.GetVerb())
		}
		got = append(got, g.GetNamespace()+"/"+g.GetName())
	}
	if len(got) != len(inv.Sites) {
		t.Errorf("read the secrets %v", got)
	}
	// What was read is cleared in the agent's copy only: the cluster's secret is as it was.
	if s := secretOf(t, f.cs, "shop", "shop-tls"); !bytes.Equal(s.Data[corev1.TLSPrivateKeyKey], f.shop.keyPEM) {
		t.Error("the secret in the cluster changed")
	}
}

func TestInventoryReadsOnlyTheNamespacesGiven(t *testing.T) {
	f := newFixture(t)
	inv, err := Inventory(context.Background(), f.cs, []string{"shop", "web"}, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range inv.Sites {
		if s.Secret.Namespace == "api" {
			t.Errorf("a site of namespace api: %+v", s.Secret)
		}
	}
	if len(inv.Sites) != 7 {
		t.Errorf("%d sites", len(inv.Sites))
	}
	for _, a := range f.cs.Actions() {
		if a.GetResource().Resource == "ingresses" && (a.GetVerb() != "list" || a.GetNamespace() == "" || a.GetNamespace() == "api") {
			t.Errorf("%s of ingresses in %q", a.GetVerb(), a.GetNamespace())
		}
	}
}

// A secret the agent may not read is reported as unreadable; one that cannot be read for another reason fails the read,
// so the agent keeps its last list instead of sending one without the site.
func TestASecretTheAgentCannotRead(t *testing.T) {
	f := newFixture(t)
	f.cs.PrependReactor("get", "secrets", func(a k8stesting.Action) (bool, runtime.Object, error) {
		if a.(k8stesting.GetAction).GetName() == "shop-tls" {
			return true, nil, apierrors.NewForbidden(schema.GroupResource{Resource: "secrets"}, "shop-tls", errors.New("RBAC"))
		}
		return false, nil, nil
	})
	inv, err := Inventory(context.Background(), f.cs, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if s := siteByName(t, inv.Sites, "shop-tls"); s.Blocked == nil || *s.Blocked != protocol.BlockedUnreadable || s.Served != nil {
		t.Errorf("%+v", s)
	}

	f = newFixture(t)
	f.cs.PrependReactor("get", "secrets", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewServerTimeout(schema.GroupResource{Resource: "secrets"}, "get", 1)
	})
	if _, err := Inventory(context.Background(), f.cs, nil, false); err == nil {
		t.Error("a timeout gave an inventory")
	}

	f = newFixture(t)
	f.cs.PrependReactor("list", "ingresses", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(schema.GroupResource{Group: "networking.k8s.io", Resource: "ingresses"}, "", errors.New("RBAC"))
	})
	if _, err := Inventory(context.Background(), f.cs, nil, false); err == nil || !strings.Contains(err.Error(), "Ingresses") {
		t.Errorf("%v", err)
	}
}

func TestSecretNameForAHostWithoutTLS(t *testing.T) {
	long := strings.Repeat("a", 61) + "." + strings.Repeat("b", 61) + "." + strings.Repeat("c", 61) + "." + strings.Repeat("d", 61) + ".test"
	for host, want := range map[string]string{
		"status.example.test":  "status-example-test-tls",
		"*.apps.example.test":  "wildcard-apps-example-test-tls",
		"Shop.Example.Test":    "shop-example-test-tls",
		long:                   strings.ReplaceAll(long, ".", "-")[:249] + "-tls",
		"docs.example.test":    "docs-example-test-tls",
		"a-b.example-one.test": "a-b-example-one-test-tls",
	} {
		if got := secretNameFor(host); got != want {
			t.Errorf("%s: %s, want %s", host, got, want)
		}
		if len(secretNameFor(host)) > 253 {
			t.Errorf("%s: longer than 253", host)
		}
	}
}

func TestFactsNameTheClusterAndItsIngressController(t *testing.T) {
	f := newFixture(t)
	f.cs.Discovery().(*fakediscovery.FakeDiscovery).FakedServerVersion = &version.Info{GitVersion: "v1.31.2"}
	facts := Facts(context.Background(), f.cs, nil, false)
	if facts.Version != "1.31.2" || facts.IngressController == nil || *facts.IngressController != "nginx" {
		t.Errorf("%+v %v", facts, ptrString(facts.IngressController))
	}
	// Only in api: traefik.
	if facts := Facts(context.Background(), f.cs, []string{"api"}, false); *facts.IngressController != "traefik" {
		t.Errorf("%v", ptrString(facts.IngressController))
	}
	// No class anywhere.
	if facts := Facts(context.Background(), cluster(), nil, false); facts.IngressController != nil {
		t.Errorf("%v", ptrString(facts.IngressController))
	}
}

func ptrString[T ~string](p *T) string {
	if p == nil {
		return "<nil>"
	}
	return string(*p)
}

// kubernetes.io/tls-acme makes an Ingress's secrets cert-manager's when it reads as true, as cert-manager reads it.
func TestTLSACMEAnnotationAsCertManagerReadsIt(t *testing.T) {
	for value, certManager := range map[string]bool{"true": true, "True": true, "1": true, "false": false, "0": false, "": false} {
		ing := ingress("shop", "storefront", []networkingv1.IngressTLS{tlsEntry("shop-tls", "shop.example.test")}, "shop.example.test")
		if value != "" {
			annotated(ing, "kubernetes.io/tls-acme", value)
		}
		cs := cluster(ing, tlsSecret("shop", "shop-tls", newCA(t).issue(t, "shop.example.test")))
		sites, k := readSites(t, cs)
		site := sites["shop-tls"]
		if got := site.Owner != nil && *site.Owner == protocol.OwnerCertManager; got != certManager || (!certManager && site.Owner != nil) {
			t.Errorf("tls-acme %q: owner %s", value, ptrString(site.Owner))
		}
		c := newCA(t).issue(t, site.Names...)
		r := k.Apply(context.Background(), site, c.bundle(), c.work(site.SiteKey))
		if r.OK == certManager || (certManager && (len(writes(cs)) != 0 || !strings.Contains(*r.Message, "cert-manager"))) {
			t.Errorf("tls-acme %q: %+v: %s", value, r, stepsOf(r))
		}
	}
}

// The sites whose secret carries the agent's own record of an install are named with the inventory: the agent keeps
// them in a list cut to what the server takes, as sites it installed on.
func TestTheInventoryNamesTheSitesTheAgentInstalledOn(t *testing.T) {
	f := newFixture(t)
	sites, k := readSites(t, f.cs)
	if _, owned, err := ReadInventory(context.Background(), f.cs, nil, false); err != nil || len(owned) != 0 {
		t.Fatalf("before any install: %v, %v", owned, err)
	}
	site := sites["shop-tls"]
	next := newCA(t).issue(t, "shop.example.test", "www.shop.example.test", "admin.shop.example.test")
	if r := k.Apply(context.Background(), site, next.bundle(), next.work(site.SiteKey)); !r.OK {
		t.Fatalf("%+v", r)
	}
	inv, owned, err := ReadInventory(context.Background(), f.cs, nil, false)
	if err != nil || len(owned) != 1 || owned[0] != site.SiteKey || len(inv.Sites) != len(sites) {
		t.Errorf("owned %v (want %s), %d sites, %v", owned, site.SiteKey, len(inv.Sites), err)
	}
}

func TestInventoryAnnotations(t *testing.T) {
	read := func(t *testing.T, annotations bool, objects ...runtime.Object) (*fake.Clientset, []protocol.Site) {
		t.Helper()
		cs := cluster(objects...)
		inv, err := Inventory(context.Background(), cs, nil, annotations)
		if err != nil {
			t.Fatal(err)
		}
		return cs, inv.Sites
	}
	enabled := func(ing *networkingv1.Ingress, kv ...string) *networkingv1.Ingress {
		annotated(ing, protocol.AnnotationEnabled, "true")
		for i := 0; i < len(kv); i += 2 {
			annotated(ing, kv[i], kv[i+1])
		}
		return ing
	}
	shop := func(name string) *networkingv1.Ingress {
		return ingress("shop", name, []networkingv1.IngressTLS{tlsEntry("shop-tls", "shop.example.test")}, "shop.example.test")
	}

	t.Run("off", func(t *testing.T) {
		_, sites := read(t, false, enabled(shop("web")))
		if sites[0].Autopilot != nil {
			t.Fatalf("autopilot = %+v with annotations off", sites[0].Autopilot)
		}
	})
	t.Run("on", func(t *testing.T) {
		_, sites := read(t, true, enabled(shop("web"), protocol.AnnotationCA, "ZeroSSL"))
		want := &protocol.SiteAutopilot{Ingress: "web", CA: ptr("ZeroSSL"), TLSSection: true}
		if !reflect.DeepEqual(sites[0].Autopilot, want) {
			t.Fatalf("autopilot = %+v, want %+v", sites[0].Autopilot, want)
		}
	})
	t.Run("not annotated", func(t *testing.T) {
		_, sites := read(t, true, shop("web"))
		if sites[0].Autopilot != nil {
			t.Fatalf("autopilot = %+v", sites[0].Autopilot)
		}
	})
	t.Run("not true", func(t *testing.T) {
		ing := shop("web")
		annotated(ing, protocol.AnnotationEnabled, "yes")
		_, sites := read(t, true, ing)
		if sites[0].Autopilot != nil {
			t.Fatalf("autopilot = %+v for enabled: yes", sites[0].Autopilot)
		}
	})
	t.Run("values are clipped and an email is reported", func(t *testing.T) {
		_, sites := read(t, true, enabled(shop("web"), protocol.AnnotationCA, strings.Repeat("c", 100), protocol.AnnotationAlertEmail, " ops@example.test "))
		a := sites[0].Autopilot
		if len(*a.CA) != 64 || *a.AlertEmail != "ops@example.test" {
			t.Fatalf("autopilot = %+v", a)
		}
	})
	t.Run("shared secret", func(t *testing.T) {
		_, sites := read(t, true, enabled(shop("b")), enabled(shop("a"), protocol.AnnotationCA, "zerossl"))
		want := &protocol.SiteAutopilot{Ingress: "a", CA: ptr("zerossl"), TLSSection: true}
		if len(sites) != 1 || !reflect.DeepEqual(sites[0].Autopilot, want) {
			t.Fatalf("sites = %+v", sites)
		}
		_, sites = read(t, true, enabled(shop("a"), protocol.AnnotationCA, "zerossl"), enabled(shop("b"), protocol.AnnotationCA, "gts"))
		if !sites[0].Autopilot.Conflict || *sites[0].Autopilot.CA != "zerossl" {
			t.Fatalf("autopilot = %+v, want a conflict", sites[0].Autopilot)
		}
		_, sites = read(t, true, enabled(shop("a"), protocol.AnnotationAlertEmail, "x@example.test"), enabled(shop("b"), protocol.AnnotationAlertEmail, "y@example.test"))
		if !sites[0].Autopilot.Conflict {
			t.Fatalf("autopilot = %+v, want a conflict on the alert email", sites[0].Autopilot)
		}
	})
	t.Run("an Ingress that is not annotated adds no values", func(t *testing.T) {
		plain := shop("a")
		annotated(plain, protocol.AnnotationCA, "gts")
		_, sites := read(t, true, plain, enabled(shop("b"), protocol.AnnotationCA, "zerossl"))
		a := sites[0].Autopilot
		if a.Ingress != "b" || *a.CA != "zerossl" || a.Conflict {
			t.Fatalf("autopilot = %+v", a)
		}
	})
	t.Run("no tls", func(t *testing.T) {
		_, sites := read(t, true, enabled(ingress("web", "status", nil, "status.example.test")))
		site := siteByName(t, sites, "status-example-test-tls")
		if site.Autopilot == nil || site.Autopilot.TLSSection {
			t.Fatalf("autopilot = %+v, want one without a tls section", site.Autopilot)
		}
	})
	t.Run("cert-manager", func(t *testing.T) {
		ing := enabled(shop("web"))
		annotated(ing, "cert-manager.io/cluster-issuer", "letsencrypt")
		cs, sites := read(t, true, ing)
		if sites[0].Owner == nil || *sites[0].Owner != protocol.OwnerCertManager || sites[0].Autopilot == nil {
			t.Fatalf("site = %+v, want cert-manager's with its annotation reported", sites[0])
		}
		if w := writes(cs); len(w) != 0 {
			t.Fatalf("writes = %v", w)
		}
	})
	t.Run("writes", func(t *testing.T) {
		cs, _ := read(t, true, enabled(shop("web")))
		if w := writes(cs); len(w) != 0 {
			t.Fatalf("writes = %v", w)
		}
	})
	t.Run("facts", func(t *testing.T) {
		cs := cluster()
		if !Facts(context.Background(), cs, nil, true).Annotations || Facts(context.Background(), cs, nil, false).Annotations {
			t.Fatal("facts do not carry the annotations switch")
		}
	})
}
