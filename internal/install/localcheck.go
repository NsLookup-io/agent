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

type localTarget struct {
	name string
	port int
}

// checkLocally asks this machine (127.0.0.1) for each name of the uses, on each of their ports (443 when a use names
// none), and says whether every answer is the certificate sha. It asks again every interval until all of them serve it
// or the window since the call is over (the reload that came just before may still be answered by the old workers),
// then reports the last answer; a window never outlasts ctx. It gives up early when, for three rounds in a row, no
// name answered at all (nothing listens on this address: no point asking a closed port for the whole window). It only
// reports: a CDN in front or a listener on another address explains a miss, and the server's own check decides
// whether a site is live.
func checkLocally(ctx context.Context, uses []inventory.Use, sha string, wait localWait) (bool, string) {
	var targets []localTarget
	seen := map[localTarget]bool{}
	for _, u := range uses {
		ports := u.Ports
		if len(ports) == 0 {
			ports = []int{defaultTLSPort}
		}
		for _, n := range u.Names {
			if rest, ok := strings.CutPrefix(n, "*."); ok {
				n = wildcardLabel + "." + rest
			}
			for _, p := range ports {
				if t := (localTarget{n, p}); !seen[t] {
					seen[t] = true
					targets = append(targets, t)
				}
			}
		}
	}
	if len(targets) == 0 {
		return false, "the site has no name to ask this machine for"
	}
	wait = wait.withDefaults()
	// The handshakes stop at the window's end too, so the check ends about window after the call whatever they do.
	ctx, cancel := context.WithTimeout(ctx, wait.window)
	defer cancel()
	deadline := wait.now().Add(wait.window)
	silent := 0
	for {
		ok, detail, answered := askOnce(ctx, targets, sha)
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
func askOnce(ctx context.Context, targets []localTarget, sha string) (ok bool, detail string, answered bool) {
	for _, t := range targets {
		served, err := servedSHA(ctx, t.name, t.port)
		switch {
		case err != nil:
			if detail == "" {
				detail = fmt.Sprintf("%s on port %d: %v", t.name, t.port, err)
			}
		case served != sha:
			answered = true
			if detail == "" {
				detail = fmt.Sprintf("%s on port %d: this machine serves another certificate", t.name, t.port)
			}
		default:
			answered = true
		}
	}
	if detail != "" {
		return false, detail, answered
	}
	return true, fmt.Sprintf("this machine serves the new certificate (%d names and ports asked)", len(targets)), true
}

// servedSHA is the SHA-256 of the leaf certificate 127.0.0.1:port serves for name.
func servedSHA(ctx context.Context, name string, port int) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, handshakeTimeout)
	defer cancel()
	d := tls.Dialer{Config: &tls.Config{
		ServerName: name,
		// The handshake only fetches the certificate this machine serves, compared below by its SHA-256 (a stricter
		// check than a chain's); nothing is sent over the connection. Old protocol versions are accepted for the same
		// reason: the question is which certificate is served, not how well.
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10,
	}}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(localAddress, strconv.Itoa(port)))
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
