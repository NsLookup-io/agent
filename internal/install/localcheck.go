package install

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/nslookup-io/agent/internal/inventory"
)

const (
	localAddress     = "127.0.0.1"
	handshakeTimeout = 5 * time.Second
	defaultTLSPort   = 443
	localWindow      = 5 * time.Second
	localInterval    = 250 * time.Millisecond
	silentRounds     = 3
	// wildcardLabel stands for the "*" of a wildcard name in the server name (SNI) asked for.
	wildcardLabel = "nslookup-agent-check"
)

// localWait is how long checkLocally waits for the reloaded server: a graceful reload keeps answering with the old
// certificate for a moment while the old workers finish. The zero value waits localWindow, asking every localInterval,
// on the real clock; tests give their own now and sleep.
type localWait struct {
	window, interval time.Duration
	now              func() time.Time
	sleep            func(ctx context.Context, d time.Duration)
}

func (w localWait) withDefaults() localWait {
	if w.window == 0 {
		w.window = localWindow
	}
	if w.interval == 0 {
		w.interval = localInterval
	}
	if w.now == nil {
		w.now = time.Now
	}
	if w.sleep == nil {
		w.sleep = func(ctx context.Context, d time.Duration) {
			t := time.NewTimer(d)
			defer t.Stop()
			select {
			case <-ctx.Done():
			case <-t.C:
			}
		}
	}
	return w
}

// ServeTarget is one question of a check: which certificate Address:Port serves for Name. A wildcard name is asked
// for with a label of the agent's own in place of its "*".
type ServeTarget struct {
	Address string
	Name    string
	Port    int
}

// speech is how a check says what it saw: who answers ("this machine"), what it asked ("names and ports") and how it
// names one target.
type speech struct {
	who, asked string
	target     func(ServeTarget) string
}

var thisMachine = speech{who: "this machine", asked: "names and ports", target: func(t ServeTarget) string {
	return fmt.Sprintf("%s on port %d", t.Name, t.Port)
}}

// checkLocally asks this machine (127.0.0.1) for each name of the uses, on each of their ports (443 when a use names
// none), and says whether every answer is the certificate sha. It asks again every interval until all of them serve it
// or the window since the call is over (the reload that came just before may still be answered by the old workers),
// then reports the last answer; a window never outlasts ctx. It gives up early when, for three rounds in a row, no
// name answered at all (nothing listens on this address: no point asking a closed port for the whole window). It only
// reports: a CDN in front or a listener on another address explains a miss, and the server's own check decides
// whether a site is live.
func checkLocally(ctx context.Context, uses []inventory.Use, sha string, wait localWait) (bool, string) {
	var targets []ServeTarget
	seen := map[ServeTarget]bool{}
	for _, u := range uses {
		ports := u.Ports
		if len(ports) == 0 {
			ports = []int{defaultTLSPort}
		}
		for _, n := range u.Names {
			for _, p := range ports {
				if t := (ServeTarget{localAddress, n, p}); !seen[t] {
					seen[t] = true
					targets = append(targets, t)
				}
			}
		}
	}
	if len(targets) == 0 {
		return false, "the site has no name to ask this machine for"
	}
	return servedAt(ctx, targets, sha, wait, thisMachine)
}

// ServedAt asks each target which certificate it serves, as the local check asks this machine (checkLocally: again
// every quarter second until all serve the certificate sha or window since the call is over, giving up early when none
// answered for three rounds), and says what it saw last; who names what answers ("the ingress controller"). It only
// reports.
func ServedAt(ctx context.Context, targets []ServeTarget, sha string, window time.Duration, who string) (bool, string) {
	if len(targets) == 0 {
		return false, "nothing was asked"
	}
	return servedAt(ctx, targets, sha, localWait{window: window}, speech{who: who, asked: "names and addresses", target: func(t ServeTarget) string {
		return t.Name + " at " + net.JoinHostPort(t.Address, strconv.Itoa(t.Port))
	}})
}

// servedAt asks targets (at least one) until all serve sha or wait's window is over.
func servedAt(ctx context.Context, targets []ServeTarget, sha string, wait localWait, say speech) (bool, string) {
	wait = wait.withDefaults()
	// The handshakes stop at the window's end too, so the check ends about window after the call whatever they do.
	ctx, cancel := context.WithTimeout(ctx, wait.window)
	defer cancel()
	deadline := wait.now().Add(wait.window)
	silent := 0
	for {
		ok, detail, answered := askOnce(ctx, targets, sha, say)
		if ok {
			return true, detail
		}
		if answered {
			silent = 0
		} else if silent++; silent >= silentRounds {
			return false, detail
		}
		if ctx.Err() != nil || !wait.now().Add(wait.interval).Before(deadline) {
			return false, detail
		}
		wait.sleep(ctx, wait.interval)
		if ctx.Err() != nil {
			return false, detail
		}
	}
}

// askOnce asks every target once: whether all serve sha, what to say of the first that does not, and whether any
// of them answered with a certificate.
func askOnce(ctx context.Context, targets []ServeTarget, sha string, say speech) (ok bool, detail string, answered bool) {
	for _, t := range targets {
		served, err := servedSHA(ctx, t)
		switch {
		case err != nil:
			if detail == "" {
				detail = fmt.Sprintf("%s: %v", say.target(t), err)
			}
		case served != sha:
			answered = true
			if detail == "" {
				detail = fmt.Sprintf("%s: %s serves another certificate", say.target(t), say.who)
			}
		default:
			answered = true
		}
	}
	if detail != "" {
		return false, detail, answered
	}
	return true, fmt.Sprintf("%s serves the new certificate (%d %s asked)", say.who, len(targets), say.asked), true
}

// servedSHA is the SHA-256 of the leaf certificate t's address serves for its name.
func servedSHA(ctx context.Context, t ServeTarget) (string, error) {
	name := t.Name
	if rest, ok := strings.CutPrefix(name, "*."); ok {
		name = wildcardLabel + "." + rest
	}
	ctx, cancel := context.WithTimeout(ctx, handshakeTimeout)
	defer cancel()
	d := tls.Dialer{Config: &tls.Config{
		ServerName: name,
		// The handshake only fetches the certificate the address serves, compared below by its SHA-256 (a stricter
		// check than a chain's); nothing is sent over the connection. Old protocol versions are accepted for the same
		// reason: the question is which certificate is served, not how well.
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10,
	}}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(t.Address, strconv.Itoa(t.Port)))
	if err != nil {
		return "", err
	}
	defer conn.Close()
	certs := conn.(*tls.Conn).ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return "", errors.New("no certificate was served")
	}
	sum := sha256.Sum256(certs[0].Raw)
	return hex.EncodeToString(sum[:]), nil
}
