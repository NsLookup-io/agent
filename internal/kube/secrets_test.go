package kube

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/nslookup-io/agent/internal/protocol"
)

var secretsResource = schema.GroupResource{Resource: "secrets"}

// readSites reads the cluster as the agent does, and the installer that writes on what it read.
func readSites(t *testing.T, cs *fake.Clientset, namespaces ...string) (map[string]protocol.Site, *Installer) {
	t.Helper()
	inv, err := Inventory(context.Background(), cs, namespaces, false)
	if err != nil {
		t.Fatal(err)
	}
	sites := map[string]protocol.Site{}
	for _, s := range inv.Sites {
		sites[s.Secret.Name] = s
	}
	cs.ClearActions()
	return sites, &Installer{Client: cs, Namespaces: namespaces}
}

func stepsOf(r protocol.InstallResult) string {
	var parts []string
	for _, s := range r.Steps {
		p := string(s.Name)
		if !s.OK {
			p += " failed"
		}
		if s.Detail != nil {
			p += ": " + *s.Detail
		}
		parts = append(parts, p)
	}
	return strings.Join(parts, "; ")
}

func TestApplyUpdatesTheSecretKeepingItsOtherKeys(t *testing.T) {
	f := newFixture(t)
	sites, k := readSites(t, f.cs)
	site := sites["shop-tls"]
	next := newCA(t).issue(t, "shop.example.test", "www.shop.example.test", "admin.shop.example.test")
	if disk, err := k.DiskSHA(site); err != nil || disk != f.shop.sha {
		t.Fatalf("on disk %q, %v", disk, err)
	}

	r := k.Apply(context.Background(), site, next.bundle(), next.work(site.SiteKey))
	// No Ingress of the fixture lists its controller's address: the check after the write asks nothing.
	if !r.OK || r.ServedLocally != nil || r.Message != nil || len(r.Steps) != 3 ||
		r.Steps[0].Name != protocol.StepChecked || r.Steps[1].Name != protocol.StepSecretWritten || !r.Steps[1].OK ||
		r.Steps[2].Name != protocol.StepCheckedLocally || r.Steps[2].OK {
		t.Fatalf("%+v: %s", r, stepsOf(r))
	}
	s := secretOf(t, f.cs, "shop", "shop-tls")
	if !bytes.Equal(s.Data[corev1.TLSCertKey], append(bytes.Clone(next.leafPEM), next.chainPEM...)) {
		t.Errorf("tls.crt = %s", s.Data[corev1.TLSCertKey])
	}
	if !bytes.Equal(s.Data[corev1.TLSPrivateKeyKey], next.keyPEM) {
		t.Error("tls.key is not the new key")
	}
	if string(s.Data["ca.crt"]) != "customer's own CA bundle" || s.Type != corev1.SecretTypeTLS {
		t.Errorf("ca.crt %q, type %s", s.Data["ca.crt"], s.Type)
	}
	if s.Labels["app.kubernetes.io/managed-by"] != "nslookup-agent" || s.Annotations["nslookup.io/sha256"] != next.sha {
		t.Errorf("labels %v, annotations %v", s.Labels, s.Annotations)
	}
	// One update, made on the secret as read (its resourceVersion), and never an Ingress.
	w := writes(f.cs)
	if len(w) != 1 || w[0].GetVerb() != "update" || w[0].GetResource().Resource != "secrets" {
		t.Fatalf("writes %v", w)
	}
	if rv := w[0].(k8stesting.UpdateAction).GetObject().(*corev1.Secret).ResourceVersion; rv != "7" {
		t.Errorf("updated with resourceVersion %q", rv)
	}
	if disk, err := k.DiskSHA(site); err != nil || disk != next.sha {
		t.Errorf("on disk %q, %v", disk, err)
	}
	// The secret's own record of what the agent wrote, for when the agent's pod (and its state) is new.
	if got := k.Recorded(site); got != next.sha {
		t.Errorf("recorded %q", got)
	}
}

// Only a secret the agent wrote (its label) records what it installed, and only a SHA-256.
func TestTheRecordOfAnInstallIsTheAgentsAnnotation(t *testing.T) {
	f := newFixture(t)
	sites, k := readSites(t, f.cs)
	site := sites["shop-tls"]
	if got := k.Recorded(site); got != "" {
		t.Errorf("a secret the agent never wrote: %q", got)
	}
	sha := strings.Repeat("a", 64)
	for name, c := range map[string]struct {
		labels, annotations map[string]string
		want                string
	}{
		"the agent's":    {map[string]string{ManagedByLabel: ManagedBy}, map[string]string{sha256Annotation: sha}, sha},
		"no label":       {nil, map[string]string{sha256Annotation: sha}, ""},
		"another tool's": {map[string]string{ManagedByLabel: "Helm"}, map[string]string{sha256Annotation: sha}, ""},
		"not a SHA-256":  {map[string]string{ManagedByLabel: ManagedBy}, map[string]string{sha256Annotation: "x"}, ""},
		"no annotation":  {map[string]string{ManagedByLabel: ManagedBy}, nil, ""},
	} {
		s := secretOf(t, f.cs, "shop", "shop-tls")
		s.Labels, s.Annotations = c.labels, c.annotations
		if _, err := f.cs.CoreV1().Secrets("shop").Update(context.Background(), s, metav1.UpdateOptions{}); err != nil {
			t.Fatal(err)
		}
		if got := k.Recorded(site); got != c.want {
			t.Errorf("%s: %q, want %q", name, got, c.want)
		}
	}
	if got := (&Installer{Client: f.cs, Namespaces: []string{"web"}}).Recorded(site); got != "" {
		t.Errorf("outside its namespaces: %q", got)
	}
}

// A host served without TLS gets a secret of its own; the customer adds it to the Ingress.
func TestApplyCreatesTheSecretOfAHostWithoutTLS(t *testing.T) {
	f := newFixture(t)
	sites, k := readSites(t, f.cs)
	site := sites["status-example-test-tls"]
	if disk, err := k.DiskSHA(site); err != nil || disk != "" {
		t.Fatalf("on disk %q, %v", disk, err)
	}
	c := newCA(t).issue(t, "status.example.test")
	r := k.Apply(context.Background(), site, c.bundle(), c.work(site.SiteKey))
	if !r.OK {
		t.Fatalf("%+v: %s", r, stepsOf(r))
	}
	s := secretOf(t, f.cs, "web", "status-example-test-tls")
	if s.Type != corev1.SecretTypeTLS || !bytes.Equal(s.Data[corev1.TLSPrivateKeyKey], c.keyPEM) ||
		s.Labels["app.kubernetes.io/managed-by"] != "nslookup-agent" || s.Annotations["nslookup.io/sha256"] != c.sha {
		t.Errorf("%+v", s)
	}
	if w := writes(f.cs); len(w) != 1 || w[0].GetVerb() != "create" || w[0].GetResource().Resource != "secrets" {
		t.Errorf("writes %v", w)
	}
	if !strings.Contains(stepsOf(r), "web/status-example-test-tls") {
		t.Errorf("steps %s", stepsOf(r))
	}
}

// Sites the agent never writes: refused, and the cluster records no write.
func TestApplyNeverWritesASecretAnotherToolOwns(t *testing.T) {
	for secret, why := range map[string]string{
		"api-tls":    "cert-manager",
		"legacy-tls": "cert-manager",
		"owned-tls":  "ownerReferences",
		"opaque-tls": "not kubernetes.io/tls",
		"frozen-tls": "immutable",
	} {
		t.Run(secret, func(t *testing.T) {
			f := newFixture(t)
			sites, k := readSites(t, f.cs)
			site := sites[secret]
			c := newCA(t).issue(t, site.Names...)
			r := k.Apply(context.Background(), site, c.bundle(), c.work(site.SiteKey))
			if r.OK || r.Message == nil || !strings.Contains(*r.Message, why) || !strings.Contains(*r.Message, "nothing was written") {
				t.Errorf("%+v: %s", r, stepsOf(r))
			}
			if w := writes(f.cs); len(w) != 0 {
				t.Errorf("writes %v", w)
			}
		})
	}
}

// What the inventory said is not trusted: the secret is read again right before the write.
func TestApplyReadsTheSecretAgainBeforeWriting(t *testing.T) {
	f := newFixture(t)
	sites, k := readSites(t, f.cs)
	site := sites["shop-tls"]
	s := secretOf(t, f.cs, "shop", "shop-tls")
	annotated(s, "cert-manager.io/issuer-name", "acme")
	if err := f.cs.Tracker().Update(corev1.SchemeGroupVersion.WithResource("secrets"), s, "shop"); err != nil {
		t.Fatal(err)
	}
	c := newCA(t).issue(t, site.Names...)
	if r := k.Apply(context.Background(), site, c.bundle(), c.work(site.SiteKey)); r.OK || !strings.Contains(*r.Message, "cert-manager") {
		t.Errorf("%+v: %s", r, stepsOf(r))
	}
	// An Ingress that asks cert-manager since the read: the secret is cert-manager's even before cert-manager wrote it.
	f = newFixture(t)
	sites, k = readSites(t, f.cs)
	site = sites["status-example-test-tls"]
	obj, err := f.cs.Tracker().Get(networkingv1.SchemeGroupVersion.WithResource("ingresses"), "web", "status")
	if err != nil {
		t.Fatal(err)
	}
	ing := obj.(*networkingv1.Ingress)
	annotated(ing, "cert-manager.io/issuer", "acme")
	if err := f.cs.Tracker().Update(networkingv1.SchemeGroupVersion.WithResource("ingresses"), ing, "web"); err != nil {
		t.Fatal(err)
	}
	c = newCA(t).issue(t, site.Names...)
	if r := k.Apply(context.Background(), site, c.bundle(), c.work(site.SiteKey)); r.OK || !strings.Contains(*r.Message, "cert-manager") {
		t.Errorf("%+v: %s", r, stepsOf(r))
	}
	if w := writes(f.cs); len(w) != 0 {
		t.Errorf("writes %v", w)
	}
}

func TestApplyChecksTheBundleFirst(t *testing.T) {
	ca := newCA(t)
	every := []string{"shop.example.test", "www.shop.example.test", "admin.shop.example.test"}
	other := ca.issue(t, every...)
	for name, tc := range map[string]struct {
		c    issued
		sha  string
		want string
	}{
		// Every name of every Ingress using the secret: admin's too.
		"a name missing": {ca.issue(t, "shop.example.test", "www.shop.example.test"), "", "does not cover admin.shop.example.test"},
		"another sha":    {ca.issue(t, every...), other.sha, "not the certificate the work names"},
		"expired":        {ca.issueUntil(t, time.Now().Add(-time.Minute), every...), "", "expired"},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			sites, k := readSites(t, f.cs)
			site := sites["shop-tls"]
			w := tc.c.work(site.SiteKey)
			if tc.sha != "" {
				w.SHA256 = tc.sha
			}
			r := k.Apply(context.Background(), site, tc.c.bundle(), w)
			if r.OK || len(r.Steps) != 1 || r.Steps[0].Name != protocol.StepChecked || !strings.Contains(*r.Message, tc.want) {
				t.Errorf("%+v: %s", r, stepsOf(r))
			}
			if w := writes(f.cs); len(w) != 0 {
				t.Errorf("writes %v", w)
			}
		})
	}
}

func TestApplyWritesOnlyInItsNamespaces(t *testing.T) {
	f := newFixture(t)
	sites, _ := readSites(t, f.cs)
	k := &Installer{Client: f.cs, Namespaces: []string{"web"}}
	site := sites["shop-tls"]
	c := newCA(t).issue(t, site.Names...)
	if r := k.Apply(context.Background(), site, c.bundle(), c.work(site.SiteKey)); r.OK || !strings.Contains(*r.Message, "namespace shop") {
		t.Errorf("%+v: %s", r, stepsOf(r))
	}
	if _, err := k.DiskSHA(site); err == nil {
		t.Error("read a secret outside its namespaces")
	}
	// Told before the bundle is fetched.
	if err := k.CanInstall(site, c.work(site.SiteKey)); err == nil || !strings.Contains(err.Error(), "namespace shop") {
		t.Errorf("CanInstall %v", err)
	}
	if err := (&Installer{Client: f.cs}).CanInstall(site, c.work(site.SiteKey)); err != nil {
		t.Errorf("every namespace: %v", err)
	}
	if len(f.cs.Actions()) != 0 {
		t.Errorf("actions %v", f.cs.Actions())
	}
}

// A site that is gone from the cluster since the last read (its Ingress removed or changed) is not written.
func TestApplyRefusesASiteNoLongerInTheCluster(t *testing.T) {
	f := newFixture(t)
	sites, k := readSites(t, f.cs)
	site := sites["status-example-test-tls"]
	if err := f.cs.Tracker().Delete(networkingv1.SchemeGroupVersion.WithResource("ingresses"), "web", "status"); err != nil {
		t.Fatal(err)
	}
	c := newCA(t).issue(t, site.Names...)
	if r := k.Apply(context.Background(), site, c.bundle(), c.work(site.SiteKey)); r.OK || !strings.Contains(*r.Message, "no longer") {
		t.Errorf("%+v: %s", r, stepsOf(r))
	}
	if w := writes(f.cs); len(w) != 0 {
		t.Errorf("writes %v", w)
	}
}

// A secret changed between the read and the write: read again once and written; changed again: not written.
func TestApplyRetriesOnceOnAConflict(t *testing.T) {
	for _, conflicts := range []int{1, 2} {
		f := newFixture(t)
		sites, k := readSites(t, f.cs)
		site := sites["shop-tls"]
		n := 0
		f.cs.PrependReactor("update", "secrets", func(k8stesting.Action) (bool, runtime.Object, error) {
			if n++; n <= conflicts {
				return true, nil, apierrors.NewConflict(secretsResource, "shop-tls", errors.New("the object has been modified"))
			}
			return false, nil, nil
		})
		c := newCA(t).issue(t, site.Names...)
		r := k.Apply(context.Background(), site, c.bundle(), c.work(site.SiteKey))
		if conflicts == 1 && (!r.OK || n != 2) {
			t.Errorf("one conflict: %d updates, %+v: %s", n, r, stepsOf(r))
		}
		if conflicts == 2 && (r.OK || n != 2 || !strings.Contains(*r.Message, "changed")) {
			t.Errorf("two conflicts: %d updates, %+v: %s", n, r, stepsOf(r))
		}
	}
}

// Created by someone else between the read and the create: read again, and the rules apply to what is there.
func TestApplyReadsAgainWhenTheSecretAppearedMeanwhile(t *testing.T) {
	f := newFixture(t)
	sites, k := readSites(t, f.cs)
	site := sites["status-example-test-tls"]
	f.cs.PrependReactor("create", "secrets", func(a k8stesting.Action) (bool, runtime.Object, error) {
		s := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "web", Name: "status-example-test-tls"}, Type: corev1.SecretTypeOpaque}
		if err := f.cs.Tracker().Add(s); err != nil {
			t.Fatal(err)
		}
		return true, nil, apierrors.NewAlreadyExists(secretsResource, "status-example-test-tls")
	})
	c := newCA(t).issue(t, site.Names...)
	r := k.Apply(context.Background(), site, c.bundle(), c.work(site.SiteKey))
	if r.OK || !strings.Contains(*r.Message, "not kubernetes.io/tls") {
		t.Errorf("%+v: %s", r, stepsOf(r))
	}
	if s := secretOf(t, f.cs, "web", "status-example-test-tls"); len(s.Data) != 0 {
		t.Error("the secret that appeared was written")
	}
}

// A write the API refuses (RBAC, an admission webhook) fails the secret_written step with the API's message.
func TestApplyReportsWhyTheAPIRefusedTheWrite(t *testing.T) {
	f := newFixture(t)
	sites, k := readSites(t, f.cs)
	f.cs.PrependReactor("update", "secrets", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(secretsResource, "shop-tls", errors.New(`admission webhook "policy.example.test" denied the request`))
	})
	site := sites["shop-tls"]
	c := newCA(t).issue(t, site.Names...)
	r := k.Apply(context.Background(), site, c.bundle(), c.work(site.SiteKey))
	if r.OK || len(r.Steps) != 2 || r.Steps[1].Name != protocol.StepSecretWritten || r.Steps[1].OK ||
		!strings.Contains(*r.Steps[1].Detail, `admission webhook "policy.example.test" denied the request`) {
		t.Errorf("%+v: %s", r, stepsOf(r))
	}
	if s := secretOf(t, f.cs, "shop", "shop-tls"); !bytes.Equal(s.Data[corev1.TLSPrivateKeyKey], f.shop.keyPEM) {
		t.Error("the secret changed")
	}
}

func TestApplyHasNoCertbotToGiveBack(t *testing.T) {
	f := newFixture(t)
	sites, k := readSites(t, f.cs)
	site := sites["shop-tls"]
	give := protocol.CertbotGiveBack
	w := protocol.Work{AssignmentID: testAssignment, SiteKey: site.SiteKey, SHA256: f.shop.sha, Action: protocol.ActionRelease, Certbot: &give}
	if r := k.Apply(context.Background(), site, protocol.Bundle{}, w); r.OK || len(r.Steps) != 1 || r.Steps[0].Name != protocol.StepCertbotRestored {
		t.Errorf("%+v: %s", r, stepsOf(r))
	}
	if w := writes(f.cs); len(w) != 0 {
		t.Errorf("writes %v", w)
	}
}

// A secret another deployment tool deploys is another tool's: reported, and never written (read again at write
// time). The agent's own label is no such mark.
func TestASecretAnotherDeploymentToolDeploysIsNeverWritten(t *testing.T) {
	for name, mark := range map[string]struct {
		label      bool
		key, value string
	}{
		"Helm's managed-by":        {true, "app.kubernetes.io/managed-by", "Helm"},
		"an empty managed-by":      {true, "app.kubernetes.io/managed-by", ""},
		"Helm's release":           {false, "meta.helm.sh/release-name", "shop"},
		"an Argo CD label":         {true, "argocd.argoproj.io/instance", "shop"},
		"an Argo CD annotation":    {false, "argocd.argoproj.io/tracking-id", "shop:/Secret:shop/shop-tls"},
		"a Flux Kustomize label":   {true, "kustomize.toolkit.fluxcd.io/name", "shop"},
		"a Flux Helm annotation":   {false, "helm.toolkit.fluxcd.io/name", "shop"},
		"a Flux Kustomize comment": {false, "kustomize.toolkit.fluxcd.io/reconcile", "disabled"},
	} {
		t.Run(name, func(t *testing.T) {
			put := func(s *corev1.Secret) {
				if mark.label {
					if s.Labels == nil {
						s.Labels = map[string]string{}
					}
					s.Labels[mark.key] = mark.value
				} else {
					annotated(s, mark.key, mark.value)
				}
			}
			// Marked when read: reported as another tool's.
			f := newFixture(t)
			s := secretOf(t, f.cs, "shop", "shop-tls")
			put(s)
			if err := f.cs.Tracker().Update(corev1.SchemeGroupVersion.WithResource("secrets"), s, "shop"); err != nil {
				t.Fatal(err)
			}
			sites, k := readSites(t, f.cs)
			site := sites["shop-tls"]
			if site.Owner == nil || *site.Owner != protocol.OwnerOther || site.Blocked == nil || *site.Blocked != protocol.BlockedOwnedByOther {
				t.Errorf("owner %s, blocked %s", ptrString(site.Owner), ptrString(site.Blocked))
			}
			c := newCA(t).issue(t, site.Names...)
			r := k.Apply(context.Background(), site, c.bundle(), c.work(site.SiteKey))
			if r.OK || !strings.Contains(*r.Message, "nothing was written: another tool deploys the secret shop/shop-tls") || !strings.Contains(*r.Message, mark.key) {
				t.Errorf("%+v: %s", r, stepsOf(r))
			}
			if w := writes(f.cs); len(w) != 0 {
				t.Errorf("writes %v", w)
			}

			// Marked after the read: refused all the same.
			f = newFixture(t)
			sites, k = readSites(t, f.cs)
			site = sites["shop-tls"]
			s = secretOf(t, f.cs, "shop", "shop-tls")
			put(s)
			if err := f.cs.Tracker().Update(corev1.SchemeGroupVersion.WithResource("secrets"), s, "shop"); err != nil {
				t.Fatal(err)
			}
			if r := k.Apply(context.Background(), site, c.bundle(), c.work(site.SiteKey)); r.OK || !strings.Contains(*r.Message, "another tool deploys") {
				t.Errorf("%+v: %s", r, stepsOf(r))
			}
			if w := writes(f.cs); len(w) != 0 {
				t.Errorf("writes %v", w)
			}
		})
	}

	// A secret the agent wrote (its own label) is written again, and reported as nobody else's.
	f := newFixture(t)
	sites, k := readSites(t, f.cs)
	site := sites["shop-tls"]
	for range 2 {
		c := newCA(t).issue(t, site.Names...)
		if r := k.Apply(context.Background(), site, c.bundle(), c.work(site.SiteKey)); !r.OK {
			t.Fatalf("%+v: %s", r, stepsOf(r))
		}
	}
	if s := secretOf(t, f.cs, "shop", "shop-tls"); s.Labels["app.kubernetes.io/managed-by"] != "nslookup-agent" {
		t.Fatalf("labels %v", s.Labels)
	}
	if sites, _ := readSites(t, f.cs); sites["shop-tls"].Owner != nil || sites["shop-tls"].Blocked != nil {
		t.Errorf("owner %s, blocked %s", ptrString(sites["shop-tls"].Owner), ptrString(sites["shop-tls"].Blocked))
	}
}
