package kube

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/nslookup-io/agent/internal/agent"
	"github.com/nslookup-io/agent/internal/protocol"
)

// The loop's "already installed" asks the ingress controllers too.
var _ agent.ServeChecker = (*Installer)(nil)

var ingressesResource = networkingv1.SchemeGroupVersion.WithResource("ingresses")

// withStatus gives ing the addresses its ingress controller lists in status.loadBalancer: IPs, else hostnames.
func withStatus(ing *networkingv1.Ingress, addresses ...string) *networkingv1.Ingress {
	ing.Status.LoadBalancer.Ingress = nil
	for _, a := range addresses {
		if net.ParseIP(a) != nil {
			ing.Status.LoadBalancer.Ingress = append(ing.Status.LoadBalancer.Ingress, networkingv1.IngressLoadBalancerIngress{IP: a})
		} else {
			ing.Status.LoadBalancer.Ingress = append(ing.Status.LoadBalancer.Ingress, networkingv1.IngressLoadBalancerIngress{Hostname: a})
		}
	}
	return ing
}

// listening sets the controller addresses of the Ingress ns/name in the fake cluster.
func listening(t *testing.T, cs *fake.Clientset, ns, name string, addresses ...string) {
	t.Helper()
	obj, err := cs.Tracker().Get(ingressesResource, ns, name)
	if err != nil {
		t.Fatal(err)
	}
	if err := cs.Tracker().Update(ingressesResource, withStatus(obj.(*networkingv1.Ingress).DeepCopy(), addresses...), ns); err != nil {
		t.Fatal(err)
	}
}

// serveTLS answers TLS handshakes on 127.0.0.1 with the certificate cert returns, and returns the port.
func serveTLS(t *testing.T, cert func() (*tls.Certificate, error)) int {
	t.Helper()
	l, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return cert() }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_ = conn.(*tls.Conn).Handshake()
			}()
		}
	}()
	return l.Addr().(*net.TCPAddr).Port
}

// controller is an ingress controller serving what the secret ns/name holds at each handshake; it returns its port.
func controller(t *testing.T, cs *fake.Clientset, ns, name string) int {
	return serveTLS(t, func() (*tls.Certificate, error) {
		obj, err := cs.Tracker().Get(corev1.SchemeGroupVersion.WithResource("secrets"), ns, name)
		if err != nil {
			return nil, err
		}
		s := obj.(*corev1.Secret)
		pair, err := tls.X509KeyPair(s.Data[corev1.TLSCertKey], s.Data[corev1.TLSPrivateKeyKey])
		return &pair, err
	})
}

// serving is a server that serves c whatever the secret holds (a controller that has not picked the secret up yet).
func serving(t *testing.T, c issued) int {
	pair, err := tls.X509KeyPair(append(bytes.Clone(c.leafPEM), c.chainPEM...), c.keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return serveTLS(t, func() (*tls.Certificate, error) { return &pair, nil })
}

func lastStep(r protocol.InstallResult) protocol.Step {
	if len(r.Steps) == 0 {
		return protocol.Step{}
	}
	return r.Steps[len(r.Steps)-1]
}

func detailOf(s protocol.Step) string {
	if s.Detail == nil {
		return ""
	}
	return *s.Detail
}

// shopListening is the fixture with both Ingresses of shop-tls served by a controller on 127.0.0.1.
func shopListening(t *testing.T) (fixture, protocol.Site, *Installer) {
	f := newFixture(t)
	listening(t, f.cs, "shop", "storefront", "127.0.0.1")
	listening(t, f.cs, "shop", "admin", "127.0.0.1")
	sites, k := readSites(t, f.cs)
	return f, sites["shop-tls"], k
}

func TestApplyAsksTheIngressControllerForTheNewCertificate(t *testing.T) {
	f, site, k := shopListening(t)
	k.tlsPort, k.serveWindow = controller(t, f.cs, "shop", "shop-tls"), 2*time.Second
	next := newCA(t).issue(t, site.Names...)
	r := k.Apply(context.Background(), site, next.bundle(), next.work(site.SiteKey))
	last := lastStep(r)
	if !r.OK || r.ServedLocally == nil || !*r.ServedLocally || r.Message != nil || len(r.Steps) != 3 || last.Name != protocol.StepCheckedLocally || !last.OK ||
		detailOf(last) != "the ingress controller serves the new certificate (3 names and addresses asked)" {
		t.Fatalf("%+v: %s", r, stepsOf(r))
	}
}

// A controller that picks the secret up later (Google's load balancer takes minutes) is not a failed install, and
// servedLocally stays empty: the server's own check from outside then speaks for the site.
func TestApplyLeavesServedLocallyEmptyWhileTheControllerServesAnother(t *testing.T) {
	f, site, k := shopListening(t)
	port := serving(t, f.shop)
	k.tlsPort, k.serveWindow = port, 500*time.Millisecond
	next := newCA(t).issue(t, site.Names...)
	r := k.Apply(context.Background(), site, next.bundle(), next.work(site.SiteKey))
	last := lastStep(r)
	want := fmt.Sprintf("admin.shop.example.test at 127.0.0.1:%d: the ingress controller serves another certificate", port)
	if !r.OK || r.ServedLocally != nil || r.Message != nil || last.Name != protocol.StepCheckedLocally || last.OK || detailOf(last) != want {
		t.Fatalf("%+v: %s", r, stepsOf(r))
	}
	if s := secretOf(t, f.cs, "shop", "shop-tls"); s.Annotations["nslookup.io/sha256"] != next.sha {
		t.Error("the secret was put back")
	}
}

func TestApplyAsksNothingWhenNoIngressListsItsControllersAddress(t *testing.T) {
	f := newFixture(t)
	sites, k := readSites(t, f.cs)
	site := sites["shop-tls"]
	next := newCA(t).issue(t, site.Names...)
	start := time.Now()
	r := k.Apply(context.Background(), site, next.bundle(), next.work(site.SiteKey))
	last := lastStep(r)
	if !r.OK || r.ServedLocally != nil || r.Message != nil || last.Name != protocol.StepCheckedLocally || last.OK ||
		detailOf(last) != "no Ingress using the secret lists the address of its ingress controller (status.loadBalancer); nothing was asked" {
		t.Fatalf("%+v: %s", r, stepsOf(r))
	}
	if waited := time.Since(start); waited > time.Second {
		t.Errorf("took %v", waited)
	}
}

// After the pod was replaced, the loop's "already installed" asks again (ServeChecker).
func TestCheckServedAsksTheIngressControllerAgain(t *testing.T) {
	f, site, k := shopListening(t)
	k.tlsPort = controller(t, f.cs, "shop", "shop-tls")
	if ok, detail := k.CheckServed(context.Background(), site, f.shop.sha); !ok || detail != "the ingress controller serves the new certificate (3 names and addresses asked)" {
		t.Errorf("%v %q", ok, detail)
	}
	next := newCA(t).issue(t, site.Names...)
	k.recheckWindow = 300 * time.Millisecond
	if ok, detail := k.CheckServed(context.Background(), site, next.sha); ok || !strings.Contains(detail, "the ingress controller serves another certificate") {
		t.Errorf("%v %q", ok, detail)
	}
}

func TestCheckServedSaysWhyItCannotAsk(t *testing.T) {
	f, site, k := shopListening(t)
	stale := site
	stale.SiteKey = "k8s_ingress|shop/gone|shop-tls"
	if ok, detail := k.CheckServed(context.Background(), stale, f.shop.sha); ok || !strings.Contains(detail, "no longer use this secret") {
		t.Errorf("%v %q", ok, detail)
	}
	k.Namespaces = []string{"web"}
	if ok, detail := k.CheckServed(context.Background(), site, f.shop.sha); ok || !strings.Contains(detail, "may not write in namespace shop") {
		t.Errorf("%v %q", ok, detail)
	}
}

// The addresses come from every Ingress using the secret: IPs and hostnames, each once, sorted, at most four; what is
// neither is left out.
func TestTheAddressesToAskAreTheIngressControllersOwn(t *testing.T) {
	a := withStatus(ingress("shop", "a", []networkingv1.IngressTLS{tlsEntry("shop-tls", "shop.example.test")}), "10.0.0.2", "lb.example.test", "10.0.0.1")
	b := withStatus(ingress("shop", "b", []networkingv1.IngressTLS{tlsEntry("shop-tls", "www.shop.example.test")}), "10.0.0.1", "2001:db8::1", "not an address!")
	groups := groupsOf([]networkingv1.Ingress{*a, *b})
	if len(groups) != 1 || strings.Join(groups[0].addresses, " ") != "10.0.0.1 10.0.0.2 2001:db8::1 lb.example.test" {
		t.Fatalf("%+v", groups)
	}
	withStatus(b, "10.0.0.1", "2001:db8::1", "10.0.0.3")
	if groups := groupsOf([]networkingv1.Ingress{*a, *b}); len(groups[0].addresses) != maxAddresses {
		t.Errorf("addresses %v", groups[0].addresses)
	}
}
