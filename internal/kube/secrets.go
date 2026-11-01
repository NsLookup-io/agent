package kube

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/nslookup-io/agent/internal/install"
	"github.com/nslookup-io/agent/internal/protocol"
)

const (
	// ManagedByLabel = ManagedBy marks what the agent made or wrote: the TLS secrets and its identity.
	ManagedByLabel = "app.kubernetes.io/managed-by"
	ManagedBy      = "nslookup-agent"
	// sha256Annotation names the certificate the agent wrote into a secret (the SHA-256 of its leaf).
	sha256Annotation = "nslookup.io/sha256"
	// apiTimeout bounds a read outside an install; applyTimeout an install.
	apiTimeout   = 30 * time.Second
	applyTimeout = time.Minute
)

var sha256Hex = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Installer writes the TLS secrets of the sites the agent read (agent.Installer). An install checks the bundle (the
// certificate the work names, its key, every name served from the secret, not expired), reads the Ingresses and the
// secret again (refusing what verdict refuses), and writes tls.crt (the certificate and its chain) and tls.key: into
// the secret there, keeping its other keys, labels and annotations, or into a new kubernetes.io/tls secret. Each
// secret it writes is labelled app.kubernetes.io/managed-by: nslookup-agent (a secret that label gives to another tool
// is never written) and annotated nslookup.io/sha256. Ingress controllers pick up a changed secret by themselves: there
// is nothing to reload.
type Installer struct {
	Client kubernetes.Interface
	// Namespaces are those it may write in; none: every namespace.
	Namespaces []string

	// now: nil = time.Now.
	now func() time.Time
}

func (k *Installer) clock() time.Time {
	if k.now == nil {
		return time.Now()
	}
	return k.now()
}

// secretOf is the secret a site names, when the agent may write in its namespace.
func (k *Installer) secretOf(site protocol.Site) (protocol.SecretRef, error) {
	if site.Kind != protocol.SiteK8sIngress || site.Secret == nil {
		return protocol.SecretRef{}, errors.New("this site is not a Kubernetes TLS secret")
	}
	if len(k.Namespaces) > 0 && !slices.Contains(k.Namespaces, site.Secret.Namespace) {
		return protocol.SecretRef{}, fmt.Errorf("this agent may not write in namespace %s", site.Secret.Namespace)
	}
	return *site.Secret, nil
}

// CanInstall says, before the bundle is fetched, why the agent cannot write the site's secret as w asks (nil: it may
// try): the site is no Kubernetes secret, it is in a namespace the agent may not write in, or w gives a site back.
func (k *Installer) CanInstall(site protocol.Site, w protocol.Work) error {
	if w.Action != protocol.ActionInstall {
		return errors.New("a Kubernetes secret has no certbot renewal to give back")
	}
	_, err := k.secretOf(site)
	return err
}

// DiskSHA is the SHA-256 of the leaf certificate in the site's secret (its tls.crt): "" when the secret does not exist
// yet (a host served without TLS) or holds no certificate.
func (k *Installer) DiskSHA(site protocol.Site) (string, error) {
	ref, err := k.secretOf(site)
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), apiTimeout)
	defer cancel()
	secret, err := getSecret(ctx, k.Client, ref.Namespace, ref.Name)
	if err != nil {
		return "", fmt.Errorf("reading the secret %s/%s: %w", ref.Namespace, ref.Name, err)
	}
	defer clearData(secret)
	if secret == nil {
		return "", nil
	}
	return install.LeafSHA(secret.Data[corev1.TLSCertKey]), nil
}

// Recorded is the SHA-256 the agent last wrote into the site's secret, by the secret's own record: its
// nslookup.io/sha256 annotation, on a secret labelled as the agent's; "" when there is none (or it cannot be read). The
// agent's state lives on an emptyDir in Kubernetes, gone with every new pod; the secret's record is not.
func (k *Installer) Recorded(site protocol.Site) string {
	ref, err := k.secretOf(site)
	if err != nil {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), apiTimeout)
	defer cancel()
	secret, err := getSecret(ctx, k.Client, ref.Namespace, ref.Name)
	if err != nil || secret == nil {
		return ""
	}
	defer clearData(secret)
	return recordOf(secret)
}

// recordOf is the SHA-256 the agent wrote into secret by its own record (its annotation, on a secret labelled as the
// agent's); "" when there is none.
func recordOf(secret *corev1.Secret) string {
	if secret == nil {
		return ""
	}
	sha := secret.Annotations[sha256Annotation]
	if secret.Labels[ManagedByLabel] != ManagedBy || !sha256Hex.MatchString(sha) {
		return ""
	}
	return sha
}

// Apply writes b into the site's secret and says how it went (steps checked, secret_written). A site whose Ingresses
// no longer use that secret as the agent read them, a bundle that fails the check and a secret the agent never writes
// are refused with nothing written. A release has nothing to give back here: a secret has no certbot renewal.
func (k *Installer) Apply(ctx context.Context, site protocol.Site, b protocol.Bundle, w protocol.Work) protocol.InstallResult {
	var o install.Outcome
	if w.Action != protocol.ActionInstall {
		o.Fail(protocol.StepCertbotRestored, "a Kubernetes secret has no certbot renewal to give back")
		return o.Result(false)
	}
	ref, err := k.secretOf(site)
	if err != nil {
		o.Fail(protocol.StepChecked, err.Error())
		return o.Result(false)
	}
	ctx, cancel := context.WithTimeout(ctx, applyTimeout)
	defer cancel()
	g, err := k.liveGroup(ctx, ref.Namespace, site.SiteKey)
	if err != nil {
		o.Fail(protocol.StepChecked, err.Error())
		return o.Result(false)
	}
	leaf, chain, key, err := install.CheckBundle(b, w.SHA256, g.names, k.clock())
	if err != nil {
		o.Fail(protocol.StepChecked, err.Error())
		return o.Result(false)
	}
	defer clear(key)
	o.OK(protocol.StepChecked, "")
	done, err := k.write(ctx, g, w.SHA256, append(leaf, chain...), key)
	if err != nil {
		o.Fail(protocol.StepSecretWritten, err.Error())
		return o.Result(false)
	}
	o.OK(protocol.StepSecretWritten, done)
	return o.Result(true)
}

// liveGroup reads the Ingresses of namespace ns again and finds the site with key siteKey among them: what the
// inventory said is not trusted for a write.
func (k *Installer) liveGroup(ctx context.Context, ns, siteKey string) (*group, error) {
	ingresses, err := listIngresses(ctx, k.Client, []string{ns})
	if err != nil {
		return nil, err
	}
	for _, g := range groupsOf(ingresses) {
		if g.key() == siteKey {
			return g, nil
		}
	}
	return nil, errors.New("the Ingresses no longer use this secret as the agent last read them; nothing was written (the next read reports the change)")
}

// write puts crt (the certificate and its chain) and key into g's secret, as read now: a new one when there is none,
// else the one there. A secret the agent never writes is refused. The write is made on the secret as read (its
// resourceVersion): when it was changed or made by someone else in between, it is read again once and the rules apply
// to what is there. It says what it did.
func (k *Installer) write(ctx context.Context, g *group, sha string, crt, key []byte) (string, error) {
	name := g.namespace + "/" + g.secret
	secrets := k.Client.CoreV1().Secrets(g.namespace)
	for again := false; ; again = true {
		secret, err := getSecret(ctx, k.Client, g.namespace, g.secret)
		if err != nil {
			return "", fmt.Errorf("nothing was written: the secret %s cannot be read: %w", name, err)
		}
		if why := refusal(g, secret); why != "" {
			clearData(secret)
			return "", errors.New("nothing was written: " + why)
		}
		var written *corev1.Secret
		created := secret == nil
		if created {
			secret = &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Namespace: g.namespace, Name: g.secret},
				Type:       corev1.SecretTypeTLS,
			}
			fill(secret, sha, crt, key)
			written, err = secrets.Create(ctx, secret, metav1.CreateOptions{})
		} else {
			fill(secret, sha, crt, key)
			written, err = secrets.Update(ctx, secret, metav1.UpdateOptions{})
		}
		clearData(secret)
		clearData(written)
		switch {
		case err == nil && created:
			return "created the secret " + name, nil
		case err == nil:
			return "updated the secret " + name, nil
		case (apierrors.IsAlreadyExists(err) || apierrors.IsConflict(err)) && !again:
			continue
		case apierrors.IsAlreadyExists(err) || apierrors.IsConflict(err):
			return "", fmt.Errorf("nothing was written: the secret %s was changed by someone else while the agent wrote it, twice", name)
		}
		return "", fmt.Errorf("writing the secret %s was refused: %v", name, err)
	}
}

// fill sets the certificate and key of secret (copies: the caller clears secret's data after the write) and marks it
// the agent's; its other keys, labels and annotations stay.
func fill(secret *corev1.Secret, sha string, crt, key []byte) {
	if secret.Data == nil {
		secret.Data = map[string][]byte{}
	}
	clear(secret.Data[corev1.TLSPrivateKeyKey])
	secret.Data[corev1.TLSCertKey] = bytes.Clone(crt)
	secret.Data[corev1.TLSPrivateKeyKey] = bytes.Clone(key)
	if secret.Labels == nil {
		secret.Labels = map[string]string{}
	}
	secret.Labels[ManagedByLabel] = ManagedBy
	if secret.Annotations == nil {
		secret.Annotations = map[string]string{}
	}
	secret.Annotations[sha256Annotation] = sha
}

// refusal says why the agent never writes g's secret as read (nil: there is none yet); "" when it may.
func refusal(g *group, s *corev1.Secret) string {
	owner, blocked := verdict(g, s)
	name := g.namespace + "/" + g.secret
	switch {
	case owner != nil && *owner == protocol.OwnerCertManager:
		return "cert-manager manages the secret " + name
	case blocked == nil:
		return ""
	case *blocked == protocol.BlockedOwnedByOther && len(s.OwnerReferences) > 0:
		return "another object owns the secret " + name + " (ownerReferences)"
	case *blocked == protocol.BlockedOwnedByOther:
		return "another tool deploys the secret " + name + " (" + deployedBy(s) + ")"
	case *blocked == protocol.BlockedSecretNotTLS:
		return fmt.Sprintf("the secret %s is of type %s, not kubernetes.io/tls", name, s.Type)
	case *blocked == protocol.BlockedSecretImmutable:
		return "the secret " + name + " is immutable"
	}
	return "the agent may not write the secret " + name
}
