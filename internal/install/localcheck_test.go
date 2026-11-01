package install

import (
	"bytes"
	"context"
	"crypto/tls"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nslookup-io/agent/internal/inventory"
	"github.com/nslookup-io/agent/internal/protocol"
)

// tlsServer serves c on 127.0.0.1 and returns its port.
func tlsServer(t *testing.T, c issued) int {
	t.Helper()
	pair, err := tls.X509KeyPair(cat(c.leafPEM, c.chainPEM), c.keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	l, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{pair}})
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

func localSite(m *machine, old issued, ports ...int) protocol.Site {
	m.write("/etc/ssl/shop.pem", cat(old.leafPEM, old.chainPEM), 0o644)
	m.write("/etc/ssl/shop.key", old.keyPEM, 0o600)
	return m.site(inventory.Use{Kind: protocol.WebServerNginx, ConfigPath: "/etc/nginx/sites-enabled/shop", Names: []string{"*.shop.example", "shop.example"},
		CertPath: "/etc/ssl/shop.pem", KeyPath: "/etc/ssl/shop.key", Ports: ports})
}

func TestTheLocalCheckSaysWhetherThisMachineServesTheNewCertificate(t *testing.T) {
	m := newMachine(t, nginxOnItsOwn())
	next := m.ca.issue(t, "*.shop.example", "shop.example")
	site := localSite(m, m.ca.issue(t, "*.shop.example", "shop.example"), tlsServer(t, next))
	r := m.host.Apply(context.Background(), site, next.bundle(), installWork(site, next.sha))
	if !r.OK || steps(r) != "checked written tested reloaded checked_locally" || r.ServedLocally == nil || !*r.ServedLocally {
		t.Errorf("%s: %s, %v", steps(r), message(r), r.ServedLocally)
	}
}

// What this machine serves never undoes an install: a CDN or another listener can explain a miss.
func TestTheLocalCheckNeverRestores(t *testing.T) {
	m := newMachine(t, nginxOnItsOwn())
	old := m.ca.issue(t, "*.shop.example", "shop.example")
	next := m.ca.issue(t, "*.shop.example", "shop.example")
	site := localSite(m, old, tlsServer(t, old))
	r := m.host.Apply(context.Background(), site, next.bundle(), installWork(site, next.sha))
	if !r.OK || steps(r) != "checked written tested reloaded checked_locally!" || r.ServedLocally == nil || *r.ServedLocally ||
		!strings.Contains(detail(r, protocol.StepCheckedLocally), "another certificate") {
		t.Errorf("%s: %q, %v", steps(r), detail(r, protocol.StepCheckedLocally), r.ServedLocally)
	}
	if r.Message != nil {
		t.Errorf("message %q", *r.Message)
	}
	if !bytes.Equal(m.read("/etc/ssl/shop.key"), next.keyPEM) {
		t.Error("the files were put back")
	}
}

// switchingServer serves old for its first n handshakes and next after: a reload whose old workers still answer.
func switchingServer(t *testing.T, old, next issued, n int64) int {
	t.Helper()
	load := func(c issued) *tls.Certificate {
		pair, err := tls.X509KeyPair(cat(c.leafPEM, c.chainPEM), c.keyPEM)
		if err != nil {
			t.Fatal(err)
		}
		return &pair
	}
	oldPair, nextPair := load(old), load(next)
	var handshakes atomic.Int64
	l, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		if handshakes.Add(1) <= n {
			return oldPair, nil
		}
		return nextPair, nil
	}})
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

func TestTheLocalCheckWaitsForTheReloadedServer(t *testing.T) {
	m := newMachine(t, nginxOnItsOwn())
	old := m.ca.issue(t, "*.shop.example", "shop.example")
	next := m.ca.issue(t, "*.shop.example", "shop.example")
	site := localSite(m, old, switchingServer(t, old, next, 5))
	r := m.host.Apply(context.Background(), site, next.bundle(), installWork(site, next.sha))
	if !r.OK || steps(r) != "checked written tested reloaded checked_locally" || r.ServedLocally == nil || !*r.ServedLocally {
		t.Errorf("%s: %s, %v", steps(r), message(r), r.ServedLocally)
	}
}

func TestTheLocalCheckGivesUpAfterItsWindow(t *testing.T) {
	old := newCA(t).issue(t, "shop.example")
	next := newCA(t).issue(t, "shop.example")
	port := tlsServer(t, old)
	clock := new(fakeClock)
	ok, detail := checkLocally(context.Background(), []inventory.Use{{Names: []string{"shop.example"}, Ports: []int{port}}}, next.sha, fakeWait(clock))
	if ok || !strings.Contains(detail, "another certificate") {
		t.Errorf("%v %q", ok, detail)
	}
	if got := clock.now().Sub(time.Time{}); got < 4*time.Second || got > localWindow {
		t.Errorf("waited %v on the fake clock", got)
	}
}

func TestTheLocalCheckDoesNotWaitOnAClosedPort(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	clock := new(fakeClock)
	ok, detail := checkLocally(context.Background(), []inventory.Use{{Names: []string{"shop.example"}, Ports: []int{port}}}, "x", fakeWait(clock))
	if ok || detail == "" {
		t.Errorf("%v %q", ok, detail)
	}
	if clock.sleeps != silentRounds-1 {
		t.Errorf("%d sleeps", clock.sleeps)
	}
}

func TestTheLocalCheckEndsWhenItsContextDoes(t *testing.T) {
	old := newCA(t).issue(t, "shop.example")
	next := newCA(t).issue(t, "shop.example")
	port := tlsServer(t, old)
	ctx, cancel := context.WithCancel(context.Background())
	var sleeps int
	wait := localWait{now: time.Now, sleep: func(context.Context, time.Duration) { sleeps++; cancel() }}
	start := time.Now()
	ok, _ := checkLocally(ctx, []inventory.Use{{Names: []string{"shop.example"}, Ports: []int{port}}}, next.sha, wait)
	if ok || sleeps != 1 || time.Since(start) > time.Second {
		t.Errorf("%v, %d sleeps, %v", ok, sleeps, time.Since(start))
	}
}
