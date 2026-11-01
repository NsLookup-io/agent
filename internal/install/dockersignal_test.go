package install

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/nslookup-io/agent/internal/protocol"
)

// fakeDocker is the Docker Engine API on a unix socket: it records each request and answers with answers[container]
// (204 when none).
type fakeDocker struct {
	socket   string
	mu       sync.Mutex
	requests []string
	answers  map[string]func(w http.ResponseWriter)
}

func newFakeDocker(t *testing.T) *fakeDocker {
	t.Helper()
	// A short directory: a unix socket's path is limited to about 100 bytes.
	dir, err := os.MkdirTemp("", "dk")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	d := &fakeDocker{socket: filepath.Join(dir, "docker.sock"), answers: map[string]func(http.ResponseWriter){}}
	l, err := net.Listen("unix", d.socket)
	if err != nil {
		t.Fatal(err)
	}
	srv := &httptest.Server{Listener: l, Config: &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		d.mu.Lock()
		d.requests = append(d.requests, r.Method+" "+r.URL.RequestURI())
		var answer func(http.ResponseWriter)
		for name, a := range d.answers {
			if strings.HasPrefix(r.URL.Path, "/v1.41/containers/"+name+"/") {
				answer = a
			}
		}
		d.mu.Unlock()
		if answer != nil {
			answer(w)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})}}
	srv.Start()
	t.Cleanup(srv.Close)
	return d
}

func (d *fakeDocker) seen() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.requests...)
}

func refuse(status int, body string) func(http.ResponseWriter) {
	return func(w http.ResponseWriter) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		w.Write([]byte(body))
	}
}

func TestDockerReloadSignalsEveryContainer(t *testing.T) {
	m, f := folderMachine(t)
	d := newFakeDocker(t)
	f.Reload = &DockerReload{Containers: []string{"nginx", "mail.relay_1"}, Signal: "USR1", Socket: d.socket}
	c := m.ca.issue(t, "shop.example")
	r := f.Apply(context.Background(), folderWork("shop.example", c.sha), c.bundle())
	if !r.OK || steps(r) != "checked written hook_ran" || detail(r, protocol.StepHookRan) != "sent USR1 to nginx, mail.relay_1" {
		t.Fatalf("%s: %s / %s", steps(r), message(r), detail(r, protocol.StepHookRan))
	}
	want := []string{"POST /v1.41/containers/nginx/kill?signal=USR1", "POST /v1.41/containers/mail.relay_1/kill?signal=USR1"}
	if got := d.seen(); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("requests %q", got)
	}
}

func TestTheDefaultSignalIsHUP(t *testing.T) {
	m, f := folderMachine(t)
	d := newFakeDocker(t)
	f.Reload = &DockerReload{Containers: []string{"nginx"}, Socket: d.socket}
	c := m.ca.issue(t, "shop.example")
	if r := f.Apply(context.Background(), folderWork("shop.example", c.sha), c.bundle()); !r.OK {
		t.Fatalf("%s: %s", steps(r), message(r))
	}
	if got := d.seen(); len(got) != 1 || got[0] != "POST /v1.41/containers/nginx/kill?signal=HUP" {
		t.Errorf("requests %q", got)
	}
}

// Docker refusing one container fails the step with Docker's own message; the others are still signalled and the
// files stay.
func TestADockerRefusalIsAFailedStep(t *testing.T) {
	m, f := folderMachine(t)
	d := newFakeDocker(t)
	d.answers["nginx"] = refuse(http.StatusNotFound, `{"message":"No such container: nginx"}`)
	d.answers["mail"] = refuse(http.StatusConflict, "Container mail is not running\n")
	f.Reload = &DockerReload{Containers: []string{"nginx", "mail", "web"}, Signal: "HUP", Socket: d.socket}
	c := m.ca.issue(t, "shop.example")
	r := f.Apply(context.Background(), folderWork("shop.example", c.sha), c.bundle())
	want := "nginx: Docker answered 404: No such container: nginx; mail: Docker answered 409: Container mail is not running; sent HUP to web"
	if r.OK || steps(r) != "checked written hook_ran!" || detail(r, protocol.StepHookRan) != want || message(r) != want {
		t.Errorf("%s: %s", steps(r), detail(r, protocol.StepHookRan))
	}
	if len(d.seen()) != 3 {
		t.Errorf("requests %q", d.seen())
	}
	if !bytes.Equal(m.read("/certs/shop.example/privkey.pem"), c.keyPEM) {
		t.Error("the files did not stay")
	}
}

// Without the socket mounted (it is opt-in) the reload is skipped: the step says to reload by hand, and the install
// still counts.
func TestNoDockerSocketMountedSkipsTheReload(t *testing.T) {
	m, f := folderMachine(t)
	f.Reload = &DockerReload{Containers: []string{"nginx", "mail"}, Socket: filepath.Join(t.TempDir(), "docker.sock")}
	c := m.ca.issue(t, "shop.example")
	r := f.Apply(context.Background(), folderWork("shop.example", c.sha), c.bundle())
	if !r.OK || r.Message != nil || steps(r) != "checked written hook_ran!" || detail(r, protocol.StepHookRan) != "no Docker socket mounted; reload nginx, mail yourself" {
		t.Errorf("%s: %s / %s", steps(r), message(r), detail(r, protocol.StepHookRan))
	}
}

// A refused signal is owed and sent again by the next Apply of the same certificate (and only the signal); no socket
// mounted owes nothing.
func TestARefusedSignalIsSentAgain(t *testing.T) {
	m, f := folderMachine(t)
	d := newFakeDocker(t)
	d.answers["nginx"] = refuse(http.StatusConflict, `{"message":"Container nginx is restarting"}`)
	f.Reload = &DockerReload{Containers: []string{"nginx"}, Socket: d.socket}
	c := m.ca.issue(t, "shop.example")
	w := folderWork("shop.example", c.sha)
	if r := f.Apply(context.Background(), w, c.bundle()); r.OK || !f.ReloadOwed(w) {
		t.Fatalf("%s: %s", steps(r), message(r))
	}
	delete(d.answers, "nginx")
	if r := f.Apply(context.Background(), w, c.bundle()); !r.OK || steps(r) != "checked hook_ran" || f.ReloadOwed(w) {
		t.Errorf("%s: %s", steps(r), message(r))
	}
	if len(d.seen()) != 2 {
		t.Errorf("requests %q", d.seen())
	}

	f.Reload.Socket = filepath.Join(t.TempDir(), "docker.sock")
	next := m.ca.issue(t, "shop.example")
	if r := f.Apply(context.Background(), folderWork("shop.example", next.sha), next.bundle()); !r.OK || f.ReloadOwed(w) {
		t.Errorf("no socket: %s: %s", steps(r), message(r))
	}
}

// A socket nothing answers on is a failure, not a skip.
func TestADockerSocketNothingAnswersOn(t *testing.T) {
	m, f := folderMachine(t)
	dir, err := os.MkdirTemp("", "dk")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	socket := filepath.Join(dir, "docker.sock")
	l, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	l.(*net.UnixListener).SetUnlinkOnClose(false)
	l.Close()
	f.Reload = &DockerReload{Containers: []string{"nginx"}, Socket: socket}
	c := m.ca.issue(t, "shop.example")
	r := f.Apply(context.Background(), folderWork("shop.example", c.sha), c.bundle())
	if d := detail(r, protocol.StepHookRan); r.OK || !strings.HasPrefix(d, "nginx: the Docker socket did not answer: ") || strings.Contains(d, "http://") {
		t.Errorf("%s: %s", steps(r), d)
	}
}

// Only container names and the three reload signals are ever sent.
func TestOnlyContainerNamesAndReloadSignalsAreSent(t *testing.T) {
	for name, c := range map[string]struct {
		reload DockerReload
		want   string
	}{
		"a path":           {DockerReload{Containers: []string{"../../images/x"}}, `"../../images/x" is not a container name`},
		"a query":          {DockerReload{Containers: []string{"nginx?signal=KILL"}}, `"nginx?signal=KILL" is not a container name`},
		"a killing signal": {DockerReload{Containers: []string{"nginx"}, Signal: "KILL"}, "the agent sends HUP, USR1 or USR2, not KILL"},
	} {
		m, f := folderMachine(t)
		d := newFakeDocker(t)
		c.reload.Socket = d.socket
		f.Reload = &c.reload
		cert := m.ca.issue(t, "shop.example")
		r := f.Apply(context.Background(), folderWork("shop.example", cert.sha), cert.bundle())
		if r.OK || !strings.Contains(detail(r, protocol.StepHookRan), c.want) {
			t.Errorf("%s: %s: %s", name, steps(r), detail(r, protocol.StepHookRan))
		}
		if len(d.seen()) != 0 {
			t.Errorf("%s: requests %q", name, d.seen())
		}
	}
}
