// Package kube is the agent in Kubernetes: it reads the cluster's Ingresses (networking.k8s.io/v1) and the TLS secrets
// they name, writes those secrets when the server assigns them a certificate, and keeps the agent's identity in a
// Secret of the agent's own namespace.
//
// It never edits an Ingress, and never writes a secret cert-manager manages (the secret's cert-manager.io/ annotations,
// or an Ingress using it that asks cert-manager for certificates), one another object owns (ownerReferences) or another
// deployment tool deploys (Helm, Argo CD, Flux, any other app.kubernetes.io/managed-by), one of another type than
// kubernetes.io/tls or an immutable one. It reads only the secrets the Ingresses name, with a get: what it needs of the
// cluster is Ingresses get/list/watch and Secrets get/create/update/patch, nothing else. A secret's tls.key is never
// sent, logged or kept.
package kube

import (
	"cmp"
	"context"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/kubernetes"

	"github.com/nslookup-io/agent/internal/inventory"
	"github.com/nslookup-io/agent/internal/protocol"
)

const (
	// listPage: Ingresses are listed this many at a time.
	listPage = 500
	// maxSiteNames, maxVersion and maxIngressClass are the server's limits.
	maxSiteNames    = 100
	maxVersion      = 64
	maxIngressClass = 128
	// tlsSuffix ends the name of the secret made for a host served without TLS; maxSecretName is the longest name of a
	// secret.
	tlsSuffix     = "-tls"
	maxSecretName = validation.DNS1123SubdomainMaxLength
)

// group is one TLS secret and the Ingresses using it, or, for a host served without TLS, the secret made for it
// and the Ingresses serving that host: one site, with every name served from it.
type group struct {
	namespace, secret string
	// ingresses are sorted, each once; the site names the first.
	ingresses []string
	// names are every name served from the secret, sorted, each once (the site reports the first 100).
	names []string
	// certManager: an Ingress using the secret asks cert-manager for its certificates, so the secret is cert-manager's
	// even before cert-manager wrote it.
	certManager bool
}

// key is the site's key: "k8s_ingress|<namespace>/<first ingress>|<secret>".
func (g *group) key() string {
	return inventory.SiteKey(protocol.SiteK8sIngress, g.namespace+"/"+g.ingresses[0], g.secret)
}

// Inventory reads the TLS sites of the cluster's Ingresses, in every namespace or only in namespaces: one site per TLS
// secret with every name of every Ingress using it (sites sharing a secret are one), and one per host served without
// TLS, whose secret the agent makes when the site is taken over (the customer then adds it to the Ingress). A
// secret the agent may not read is reported unreadable; any other failure fails the read, so the agent keeps sending
// its last one instead of a list without those sites.
func Inventory(ctx context.Context, cs kubernetes.Interface, namespaces []string) (protocol.Inventory, error) {
	inv, _, err := ReadInventory(ctx, cs, namespaces)
	return inv, err
}

// ReadInventory is Inventory, and the keys of the sites whose secret carries the agent's own record of an install
// (labelled as the agent's, annotated with the SHA-256 it wrote): sites the agent installed on, whose assignment the
// server may have paused, so no work names them.
func ReadInventory(ctx context.Context, cs kubernetes.Interface, namespaces []string) (protocol.Inventory, []string, error) {
	ingresses, err := listIngresses(ctx, cs, namespaces)
	if err != nil {
		return protocol.Inventory{}, nil, err
	}
	inv := protocol.Inventory{Sites: []protocol.Site{}}
	var owned []string
	for _, g := range groupsOf(ingresses) {
		secret, err := getSecret(ctx, cs, g.namespace, g.secret)
		forbidden := apierrors.IsForbidden(err)
		if err != nil && !forbidden {
			return protocol.Inventory{}, nil, fmt.Errorf("reading the secret %s/%s: %w", g.namespace, g.secret, err)
		}
		site := g.site(secret, forbidden)
		inv.Sites = append(inv.Sites, site)
		if recordOf(secret) != "" {
			owned = append(owned, site.SiteKey)
		}
		clearData(secret)
	}
	return inv, owned, nil
}

// Facts describes the cluster: its Kubernetes version, and its ingress controller as the most common ingress class of
// the Ingresses read (none: null). What cannot be read is left empty.
func Facts(ctx context.Context, cs kubernetes.Interface, namespaces []string) *protocol.KubernetesFacts {
	facts := &protocol.KubernetesFacts{}
	if v, err := cs.Discovery().ServerVersion(); err == nil {
		facts.Version = protocol.Clip(strings.TrimPrefix(v.GitVersion, "v"), maxVersion)
	}
	if ingresses, err := listIngresses(ctx, cs, namespaces); err == nil {
		facts.IngressController = ingressClass(ingresses)
	}
	return facts
}

// ingressClass is the most common spec.ingressClassName (the first by name of the most common); nil when none has one.
func ingressClass(ingresses []networkingv1.Ingress) *string {
	count := map[string]int{}
	for _, ing := range ingresses {
		if c := ing.Spec.IngressClassName; c != nil && *c != "" {
			count[*c]++
		}
	}
	if len(count) == 0 {
		return nil
	}
	classes := slices.Sorted(maps.Keys(count))
	best := classes[0]
	for _, c := range classes {
		if count[c] > count[best] {
			best = c
		}
	}
	best = protocol.Clip(best, maxIngressClass)
	return &best
}

// listIngresses lists the Ingresses of every namespace, or of each of namespaces.
func listIngresses(ctx context.Context, cs kubernetes.Interface, namespaces []string) ([]networkingv1.Ingress, error) {
	scopes := namespaces
	if len(scopes) == 0 {
		scopes = []string{metav1.NamespaceAll}
	}
	var all []networkingv1.Ingress
	for _, ns := range scopes {
		opts := metav1.ListOptions{Limit: listPage}
		for {
			list, err := cs.NetworkingV1().Ingresses(ns).List(ctx, opts)
			if err != nil {
				if ns == metav1.NamespaceAll {
					return nil, fmt.Errorf("listing the Ingresses: %w", err)
				}
				return nil, fmt.Errorf("listing the Ingresses of namespace %s: %w", ns, err)
			}
			all = append(all, list.Items...)
			if opts.Continue = list.Continue; opts.Continue == "" {
				break
			}
		}
	}
	return all, nil
}

// groupsOf makes the sites of ingresses (no API call): the secrets their tls entries name, with the hosts of each entry
// (an entry without hosts: its Ingress's rule hosts), and a secret of its own (secretNameFor) for each rule host served
// without TLS, by no tls entry of any Ingress read (nor under one of their wildcards). Sites without a name are left
// out: no certificate could be checked against them. Sorted by key.
func groupsOf(ingresses []networkingv1.Ingress) []*group {
	type id struct{ namespace, secret string }
	byID := map[id]*group{}
	add := func(ing *networkingv1.Ingress, secret string, names []string) {
		g := byID[id{ing.Namespace, secret}]
		if g == nil {
			g = &group{namespace: ing.Namespace, secret: secret}
			byID[id{ing.Namespace, secret}] = g
		}
		g.ingresses = append(g.ingresses, ing.Name)
		g.names = append(g.names, names...)
		g.certManager = g.certManager || asksCertManager(ing)
	}
	var withTLS []string
	for i := range ingresses {
		ing := &ingresses[i]
		for _, t := range ing.Spec.TLS {
			hosts := t.Hosts
			if len(hosts) == 0 {
				hosts = ruleHosts(ing)
			}
			names := inventory.SiteNames(hosts)
			withTLS = append(withTLS, names...)
			// A tls entry without a secret is served with the controller's default certificate: no site.
			if t.SecretName != "" && len(validation.IsDNS1123Subdomain(t.SecretName)) == 0 {
				add(ing, t.SecretName, names)
			}
		}
	}
	for i := range ingresses {
		ing := &ingresses[i]
		for _, host := range inventory.SiteNames(ruleHosts(ing)) {
			if !servedWithTLS(withTLS, host) {
				add(ing, secretNameFor(host), []string{host})
			}
		}
	}
	var groups []*group
	for _, g := range byID {
		g.ingresses = sortedUnique(g.ingresses)
		g.names = sortedUnique(g.names)
		if len(g.names) > 0 {
			groups = append(groups, g)
		}
	}
	slices.SortFunc(groups, func(a, b *group) int { return cmp.Compare(a.key(), b.key()) })
	return groups
}

func ruleHosts(ing *networkingv1.Ingress) []string {
	var hosts []string
	for _, r := range ing.Spec.Rules {
		if r.Host != "" {
			hosts = append(hosts, r.Host)
		}
	}
	return hosts
}

// servedWithTLS reports whether a tls entry serves host: the same name, or a wildcard for one label more.
func servedWithTLS(tlsNames []string, host string) bool {
	_, parent, _ := strings.Cut(host, ".")
	for _, n := range tlsNames {
		if n == host || (strings.HasPrefix(n, "*.") && !strings.HasPrefix(host, "*.") && n[2:] == parent) {
			return true
		}
	}
	return false
}

// secretNameFor is the secret made for a host served without TLS: the host with its dots as dashes and a leading "*" as
// "wildcard", lowercase, then "-tls", at most 253 characters (status.example.com → status-example-com-tls).
func secretNameFor(host string) string {
	name := strings.ToLower(host)
	if rest, ok := strings.CutPrefix(name, "*"); ok {
		name = "wildcard" + rest
	}
	name = strings.ReplaceAll(name, ".", "-")
	return name[:min(len(name), maxSecretName-len(tlsSuffix))] + tlsSuffix
}

// asksCertManager reports whether cert-manager issues the certificates of ing's tls entries: an issuer annotation, or
// the kubernetes.io/tls-acme annotation cert-manager also honours, when it reads as true ("true", "True", "1", ...).
func asksCertManager(ing *networkingv1.Ingress) bool {
	a := ing.Annotations
	_, issuer := a["cert-manager.io/issuer"]
	_, clusterIssuer := a["cert-manager.io/cluster-issuer"]
	acme, _ := strconv.ParseBool(a["kubernetes.io/tls-acme"])
	return issuer || clusterIssuer || acme
}

// managedByCertManager reports whether cert-manager wrote the secret (its cert-manager.io/ annotations).
func managedByCertManager(s *corev1.Secret) bool {
	if s == nil {
		return false
	}
	for k := range s.Annotations {
		if strings.HasPrefix(k, "cert-manager.io/") {
			return true
		}
	}
	return false
}

// deployerPrefixes are the label and annotation key prefixes of the deployment tools that sync what they deploy (Argo
// CD, Flux).
var deployerPrefixes = []string{"argocd.argoproj.io/", "kustomize.toolkit.fluxcd.io/", "helm.toolkit.fluxcd.io/"}

// deployedBy names the mark of another deployment tool on the secret ("" when none): an app.kubernetes.io/managed-by
// label naming another tool than the agent (Helm sets "Helm"), Helm's release annotation, or a label or annotation of
// Argo CD or Flux. Such a tool would put its own certificate back at its next sync.
func deployedBy(s *corev1.Secret) string {
	if s == nil {
		return ""
	}
	if v, ok := s.Labels[ManagedByLabel]; ok && v != ManagedBy {
		return fmt.Sprintf("label %s: %s", ManagedByLabel, v)
	}
	if _, ok := s.Annotations["meta.helm.sh/release-name"]; ok {
		return "annotation meta.helm.sh/release-name"
	}
	for _, m := range []struct {
		kind string
		keys map[string]string
	}{{"label", s.Labels}, {"annotation", s.Annotations}} {
		for _, k := range slices.Sorted(maps.Keys(m.keys)) {
			for _, prefix := range deployerPrefixes {
				if strings.HasPrefix(k, prefix) {
					return m.kind + " " + k
				}
			}
		}
	}
	return ""
}

// verdict is who manages a site's secret and why the agent may not write it (nil, nil: it may), from the group and the
// secret as read (nil: there is none yet).
func verdict(g *group, s *corev1.Secret) (owner *protocol.SiteOwner, blocked *protocol.SiteBlocked) {
	switch {
	case g.certManager || managedByCertManager(s):
		owner = ptr(protocol.OwnerCertManager)
	case s != nil && (len(s.OwnerReferences) > 0 || deployedBy(s) != ""):
		owner, blocked = ptr(protocol.OwnerOther), ptr(protocol.BlockedOwnedByOther)
	}
	if blocked == nil && s != nil {
		switch {
		case s.Type != corev1.SecretTypeTLS:
			blocked = ptr(protocol.BlockedSecretNotTLS)
		case s.Immutable != nil && *s.Immutable:
			blocked = ptr(protocol.BlockedSecretImmutable)
		}
	}
	return owner, blocked
}

// site is what the agent reports of g with its secret as read (nil: none, or unreadable): the facts of the
// certificate in its tls.crt, who manages it, why the agent may not write it.
func (g *group) site(secret *corev1.Secret, unreadable bool) protocol.Site {
	s := protocol.Site{
		SiteKey: g.key(),
		Kind:    protocol.SiteK8sIngress,
		Names:   g.names[:min(len(g.names), maxSiteNames)],
		Secret:  &protocol.SecretRef{Namespace: g.namespace, Name: g.secret, Ingress: g.ingresses[0]},
	}
	s.Owner, s.Blocked = verdict(g, secret)
	if unreadable && s.Blocked == nil {
		s.Blocked = ptr(protocol.BlockedUnreadable)
	}
	if secret != nil {
		if facts, err := inventory.CertFactsOf(secret.Data[corev1.TLSCertKey]); err == nil {
			s.Served = &facts
		}
	}
	return s
}

// getSecret reads a secret: nil (and no error) when there is none.
func getSecret(ctx context.Context, cs kubernetes.Interface, ns, name string) (*corev1.Secret, error) {
	s, err := cs.CoreV1().Secrets(ns).Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return s, nil
}

// clearData clears what a secret held (its key among it) in the agent's copy.
func clearData(s *corev1.Secret) {
	if s == nil {
		return
	}
	for _, v := range s.Data {
		clear(v)
	}
}

func sortedUnique(s []string) []string {
	s = slices.Clone(s)
	slices.Sort(s)
	return slices.Compact(s)
}

func ptr[T any](v T) *T { return &v }
