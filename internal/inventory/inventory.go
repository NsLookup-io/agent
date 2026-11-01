// Package inventory reads the sites of the web servers on this machine: nginx, Apache and HAProxy. A site is one
// certificate file with every name served from it, the configuration using it, its key and chain files, the facts of
// the certificate it holds and the tool renewing it today (certbot). Names served without HTTPS are a site too, so the
// portal can say why they cannot be taken over.
//
// It runs only the commands of its allowlist (exec.go), and reads the configuration files and certificate files the
// web servers name; it never reads a key. What it reports holds no configuration text and no key material: names,
// paths and certificate facts only.
package inventory

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"maps"
	"net"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/nslookup-io/agent/internal/protocol"
)

const (
	// maxSiteNames, maxHostName, maxPath and maxVersion are the server's limits.
	maxSiteNames = 100
	maxHostName  = 253
	maxPath      = 4096
	maxVersion   = 64
	// maxConfigFile: no configuration file read is larger.
	maxConfigFile = 16 << 20
	// maxIncludeDepth: includes nest no deeper, so a loop of includes ends.
	maxIncludeDepth = 16
)

// Options are what agent.yaml says about reading this machine.
type Options struct {
	// HAProxyConfigs are HAProxy configuration files, or directories of *.cfg files, read besides
	// /etc/haproxy/haproxy.cfg.
	HAProxyConfigs []string
}

// Inventory is what Read found.
type Inventory struct {
	// Sites are what the agent reports: one site per certificate file, with the names of every configuration using it
	// (of every web server), and one per configuration file for the names it serves without HTTPS.
	Sites []protocol.Site
	// Uses are, per site key, the configurations using the site's certificate file: installing on the site means
	// testing and reloading every web server among them. Never sent.
	Uses map[string][]Use
	// HAProxyFiles are the HAProxy configuration files read, in the order HAProxy is given them: its configuration test
	// checks these. Never sent.
	HAProxyFiles []string
	// Problems say what could not be read, in plain words, for the log. Never sent.
	Problems []string
}

// Wire is the inventory as the agent sends it.
func (inv Inventory) Wire() protocol.Inventory { return protocol.Inventory{Sites: inv.Sites} }

// Use is one configuration using a certificate file: an nginx server block, an Apache virtual host, or an HAProxy
// certificate (of a bind line's crt, a crt directory or a crt-list).
type Use struct {
	Kind protocol.WebServerKind
	// ConfigPath is the configuration file it is in.
	ConfigPath string
	// Names are the names it serves (with none in its configuration: the certificate's own).
	Names    []string
	CertPath string
	// KeyPath is where the key is: the certificate's own file when the configuration names no key file, "" when the
	// key is not in a file (an OpenSSL engine, a PKCS#11 token).
	KeyPath string
	// ChainPath is "" when the configuration names no chain file.
	ChainPath string
	// Ports are the TCP ports it serves HTTPS on, for a check on this machine; none when they are not known.
	Ports []int
}

// entry is one configuration as read, before entries sharing a certificate file become one site.
type entry struct {
	kind   protocol.WebServerKind
	config string
	names  []string
	// https: it serves the certificate in cert. Otherwise it serves its names without HTTPS and has no paths.
	https bool
	// servesMore: it serves hosts its names do not tell: its configuration names hosts the agent cannot list
	// (inexpressible), or it is a catch-all (an nginx default_server, the first Apache virtual host of an address).
	servesMore       bool
	cert, key, chain string
	ports            []int
}

// reader reads one machine; problems gathers what could not be read.
type reader struct {
	runner   Runner
	fsys     fs.FS
	problems []string
	// haproxyFiles are the HAProxy configuration files read.
	haproxyFiles []string
}

func (r *reader) note(format string, args ...any) {
	r.problems = append(r.problems, fmt.Sprintf(format, args...))
}

// Reader reads the sites of nginx, Apache and HAProxy on this machine, again and again (the agent reads them every 5
// minutes). A web server whose configuration cannot be read this time, even in part (a configuration being edited,
// an nginx -T that timed out), is reported as it was at its last read that worked: its sites must not disappear, or
// the server would pause their assignments as gone. Not for concurrent use.
type Reader struct {
	Runner Runner
	// FS is the machine's file system, rooted at /.
	FS      fs.FS
	Options Options

	// last are each web server's configurations at its last read that worked (in this process), and lastHAProxyFiles
	// the HAProxy configuration files of that read.
	last             map[protocol.WebServerKind][]entry
	lastHAProxyFiles []string
}

// Read reads the sites. A web server that is not installed is skipped. One that cannot be read is reported as at its
// last read that worked, and said in Problems; when it has none (it failed every read so far), Read fails, so the agent
// sends no list without its sites.
func (rd *Reader) Read(ctx context.Context) (Inventory, error) {
	if rd.last == nil {
		rd.last = map[protocol.WebServerKind][]entry{}
	}
	r := &reader{runner: rd.Runner, fsys: rd.FS}
	servers := []struct {
		kind protocol.WebServerKind
		name string
		read func(context.Context) (entries []entry, installed bool, err error)
	}{
		{protocol.WebServerNginx, "nginx", r.nginx},
		{protocol.WebServerApache, "Apache", r.apache},
		{protocol.WebServerHAProxy, "HAProxy", func(ctx context.Context) ([]entry, bool, error) {
			return r.haproxy(ctx, rd.Options.HAProxyConfigs)
		}},
	}
	var entries []entry
	var unread []string
	for _, s := range servers {
		found, installed, err := s.read(ctx)
		if ctx.Err() != nil {
			return Inventory{}, ctx.Err()
		}
		last, readBefore := rd.last[s.kind]
		switch {
		case !installed:
			delete(rd.last, s.kind)
			if s.kind == protocol.WebServerHAProxy {
				rd.lastHAProxyFiles = nil
			}
		case err == nil:
			rd.last[s.kind] = found
			if s.kind == protocol.WebServerHAProxy {
				rd.lastHAProxyFiles = r.haproxyFiles
			}
			entries = append(entries, found...)
		case readBefore:
			r.note("%s: %v; its sites are reported as at its last read", s.name, err)
			entries = append(entries, last...)
		default:
			r.note("%s: %v", s.name, err)
			unread = append(unread, s.name)
		}
	}
	if len(unread) > 0 {
		return Inventory{Problems: r.problems}, fmt.Errorf("the configuration of %s could not be read, and there is no earlier read of it to report", strings.Join(unread, " and "))
	}
	inv := r.assemble(entries)
	inv.HAProxyFiles = slices.Clone(rd.lastHAProxyFiles)
	return inv, nil
}

// Read reads the sites once: a Reader's first read, which fails when any web server installed cannot be read.
func Read(ctx context.Context, runner Runner, fsys fs.FS, opts Options) (Inventory, error) {
	return (&Reader{Runner: runner, FS: fsys, Options: opts}).Read(ctx)
}

// kindOrder is the precedence of web servers using one certificate file: the site is reported as the first's.
var kindOrder = map[protocol.WebServerKind]int{protocol.WebServerNginx: 0, protocol.WebServerApache: 1, protocol.WebServerHAProxy: 2}

// assemble makes the sites: entries sharing a certificate file become one site, whatever their web server; the names
// served without HTTPS become one site per configuration file, less the names some site serves with HTTPS (the
// port-80 server that redirects to HTTPS is no site of its own).
func (r *reader) assemble(entries []entry) Inventory {
	inv := Inventory{Uses: map[string][]Use{}}
	type plainKey struct {
		kind   protocol.WebServerKind
		config string
	}
	byCert := map[string][]entry{}
	plain := map[plainKey][]string{}
	for _, e := range entries {
		if !r.pathsOK(e) {
			continue
		}
		if e.https {
			byCert[e.cert] = append(byCert[e.cert], e)
		} else {
			k := plainKey{e.kind, e.config}
			plain[k] = append(plain[k], e.names...)
		}
	}
	secure := map[string]bool{}
	for _, cert := range slices.Sorted(maps.Keys(byCert)) {
		site, uses, names := r.site(cert, byCert[cert])
		for _, n := range names {
			secure[n] = true
		}
		inv.Sites = append(inv.Sites, site)
		inv.Uses[site.SiteKey] = uses
	}
	keys := slices.SortedFunc(maps.Keys(plain), func(a, b plainKey) int {
		return cmp.Or(strings.Compare(string(a.kind), string(b.kind)), strings.Compare(a.config, b.config))
	})
	for _, k := range keys {
		names := slices.DeleteFunc(sortedUnique(plain[k]), func(n string) bool { return secure[n] })
		if len(names) == 0 {
			continue
		}
		kind, config := protocol.SiteKind(k.kind), k.config
		inv.Sites = append(inv.Sites, protocol.Site{
			SiteKey:    SiteKey(kind, config, ""),
			Kind:       kind,
			Names:      r.capNames(names, config),
			ConfigPath: &config,
			Blocked:    ptr(protocol.BlockedNoHTTPS),
		})
	}
	slices.SortFunc(inv.Sites, func(a, b protocol.Site) int { return strings.Compare(a.SiteKey, b.SiteKey) })
	inv.Problems = r.problems
	return inv
}

// site is the one site of a certificate file and the configurations using it (group): the kind of the first by
// precedence (nginx, Apache, HAProxy), the first configuration file by name, every name (all returned; the site keeps
// the first 100), the key and chain of the first. It is blocked when a path holds a variable, when the certificate
// cannot be read, and when the configurations disagree on the key or the chain (an install must suit every one).
func (r *reader) site(cert string, group []entry) (protocol.Site, []Use, []string) {
	slices.SortStableFunc(group, func(a, b entry) int {
		return cmp.Or(cmp.Compare(kindOrder[a.kind], kindOrder[b.kind]), strings.Compare(a.config, b.config))
	})
	first := group[0]
	config := first.config
	for _, e := range group {
		config = min(config, e.config)
	}
	kind := protocol.SiteKind(first.kind)
	s := protocol.Site{
		SiteKey:    SiteKey(kind, config, cert),
		Kind:       kind,
		ConfigPath: &config,
		CertPath:   &cert,
		KeyPath:    optional(first.key),
		ChainPath:  optional(first.chain),
	}

	certVariable := strings.Contains(cert, "$")
	var readErr error
	var certNames []string
	trusted := false
	if !certVariable {
		leaf, err := certFacts(r.fsys, cert, time.Now())
		if err == nil {
			s.Served, certNames, trusted = &leaf.facts, siteNames(leaf.facts.Names), leaf.trusted
		}
		if len(leaf.odd) > 0 {
			r.note("the certificate in %s has %d names that are no host names, such as %q; they are not reported", cert, len(leaf.odd), leaf.odd[0])
		}
		readErr = err
	}

	var names []string
	uses := make([]Use, 0, len(group))
	variable, disagree, keyNotFile := certVariable, false, false
	for _, e := range group {
		variable = variable || strings.Contains(e.key, "$") || strings.Contains(e.chain, "$")
		disagree = disagree || e.key != first.key || e.chain != first.chain
		keyNotFile = keyNotFile || e.key == ""
		// A configuration naming no host is known by the names of the certificate it serves. One naming hosts the agent
		// cannot list (a regular expression, say), or catching every host no other serves, is known by them too, when that
		// certificate is one hosts rely on today (not self-signed, not expired): a certificate replacing it must cover at
		// least what it covers today. A snakeoil or expired certificate had nothing valid to lose, and its names (the
		// machine's own) are none a new certificate could cover.
		own := e.names
		switch {
		case len(own) == 0:
			own = certNames
		case e.servesMore && trusted:
			own = sortedUnique(append(slices.Clone(e.names), certNames...))
		}
		names = append(names, own...)
		uses = append(uses, Use{Kind: e.kind, ConfigPath: e.config, Names: slices.Clone(own), CertPath: e.cert, KeyPath: e.key, ChainPath: e.chain, Ports: slices.Clone(e.ports)})
	}
	names = sortedUnique(names)
	s.Names = r.capNames(names, config)

	switch {
	case variable:
		s.Blocked = ptr(protocol.BlockedPathVariable)
	case readErr != nil:
		s.Blocked = ptr(protocol.BlockedUnreadable)
		r.note("the certificate file %s cannot be read: %v", cert, readErr)
	case disagree:
		s.Blocked = ptr(protocol.BlockedUnreadable)
		r.note("the configurations using %s name different key or chain files; it cannot be installed until they name the same", cert)
	case keyNotFile:
		s.Blocked = ptr(protocol.BlockedUnreadable)
		r.note("the key of %s is not in a file; it cannot be installed", cert)
	}
	if !certVariable {
		if name := certbotName(r.fsys, cert); name != "" {
			s.Owner, s.CertbotName = ptr(protocol.OwnerCertbot), &name
		}
	}
	return s, uses, names
}

// capNames keeps the first 100 names (sorted), and says so when there were more.
func (r *reader) capNames(names []string, config string) []string {
	if len(names) <= maxSiteNames {
		return names
	}
	r.note("a site in %s serves %d names; the first %d are reported", config, len(names), maxSiteNames)
	return names[:maxSiteNames]
}

// pathsOK reports whether every path of e can be reported: absolute, valid UTF-8, at most 4096 characters, no control
// characters. An entry with one that cannot is left out (the server would refuse the whole inventory).
func (r *reader) pathsOK(e entry) bool {
	for i, p := range []string{e.config, e.cert, e.key, e.chain} {
		if p == "" && i > 0 {
			continue // no such file
		}
		if !strings.HasPrefix(p, "/") || !utf8.ValidString(p) || len(utf16.Encode([]rune(p))) > maxPath || hasControl(p) {
			r.note("%s: a configuration in %q names a path that cannot be reported (%q); it is left out", e.kind, e.config, p)
			return false
		}
	}
	return true
}

// SiteKey is a site's key: the first 32 hex characters of the SHA-256 of "<kind>|<configPath>|<certPath>" (certPath ""
// for the names a configuration file serves without HTTPS).
func SiteKey(kind protocol.SiteKind, configPath, certPath string) string {
	sum := sha256.Sum256([]byte(string(kind) + "|" + configPath + "|" + certPath))
	return hex.EncodeToString(sum[:16])
}

var siteNamePattern = regexp.MustCompile(`^(\*\.)?[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?(\.[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?)+$`)

// siteName is a name as a site reports it: lowercase with no trailing dot, a host name of two labels or more, or "*."
// and one. Anything else (a pattern such as www.example.*, a regular expression, "_", localhost, an IP address) is no
// name a certificate can cover, and is left out.
func siteName(raw string) (string, bool) {
	n := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(raw)), ".")
	if len(n) > maxHostName || !siteNamePattern.MatchString(n) || net.ParseIP(n) != nil {
		return "", false
	}
	return n, true
}

// inexpressible reports whether a name as configured stands for hosts the agent cannot list as names a certificate
// covers: a regular expression ("~"), a variable ("$"), a "?" wildcard, or a "*" that is not the whole first label
// (www.example.*, w*.example.test, *.*.example.test).
func inexpressible(raw string) bool {
	n := strings.TrimSpace(raw)
	switch {
	case strings.HasPrefix(n, "~"), strings.ContainsAny(n, "$?"):
		return true
	case strings.Contains(n, "*"):
		rest, ok := strings.CutPrefix(n, "*.")
		return !ok || strings.Contains(rest, "*")
	}
	return false
}

// SiteNames are the names among raw a site reports (a web server's or an Ingress's hosts), sorted, each once: lowercase
// with no trailing dot, a host name of two labels or more, or "*." and one; anything else is left out.
func SiteNames(raw []string) []string { return siteNames(raw) }

// siteNames are the names among raw a site reports, sorted, each once.
func siteNames(raw []string) []string {
	var names []string
	for _, n := range raw {
		if n, ok := siteName(n); ok {
			names = append(names, n)
		}
	}
	return sortedUnique(names)
}

var (
	nginxVersionPattern   = regexp.MustCompile(`nginx version: (?:nginx/)?(\S+)`)
	apacheVersionPattern  = regexp.MustCompile(`Server version: Apache/(\S+)`)
	haproxyVersionPattern = regexp.MustCompile(`HA-?Proxy version (\S+)`)
)

// WebServers are the web servers installed on this machine with their versions ("" when none was printed), from
// nginx -v, apachectl -v (or apache2ctl, httpd) and haproxy -v.
func WebServers(ctx context.Context, runner Runner) []protocol.WebServer {
	var servers []protocol.WebServer
	for _, w := range []struct {
		kind     protocol.WebServerKind
		commands []Command
		version  *regexp.Regexp
	}{
		{protocol.WebServerNginx, []Command{nginxVersion}, nginxVersionPattern},
		{protocol.WebServerApache, apacheVersions, apacheVersionPattern},
		{protocol.WebServerHAProxy, []Command{haproxyVersion}, haproxyVersionPattern},
	} {
		out, installed, _ := firstInstalled(ctx, runner, w.commands, w.version.Match)
		if !installed {
			continue
		}
		version := ""
		if m := w.version.FindSubmatch(out); m != nil {
			version = protocol.Clip(string(m[1]), maxVersion)
		}
		servers = append(servers, protocol.WebServer{Kind: w.kind, Version: version})
	}
	return servers
}

// hasControl: C0 and C1 control characters and DEL.
func hasControl(s string) bool {
	return strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 || (r >= 0x7f && r <= 0x9f) })
}

func sortedUnique[T cmp.Ordered](s []T) []T {
	s = slices.Clone(s)
	slices.Sort(s)
	return slices.Compact(s)
}

func ptr[T any](v T) *T { return &v }

// optional is nil for "".
func optional(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
