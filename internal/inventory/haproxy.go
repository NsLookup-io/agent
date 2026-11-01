package inventory

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"strconv"
	"strings"

	"github.com/nslookup-io/agent/internal/protocol"
)

// HAProxy: there is no command that prints its configuration, so the agent reads /etc/haproxy/haproxy.cfg and the
// files (or directories of *.cfg files) agent.yaml names, as HAProxy does when started with them (-f). A site is one
// certificate file of a "bind ... ssl" line: its crt files, every file of its crt directories (but those starting
// with a dot), every line of its crt-lists. Its names are the certificate's own (HAProxy picks the certificate by SNI).

const haproxyConfig = "/etc/haproxy/haproxy.cfg"

var haproxySections = map[string]bool{
	"global": true, "defaults": true, "frontend": true, "backend": true, "listen": true, "peers": true, "resolvers": true,
	"userlist": true, "mailers": true, "program": true, "http-errors": true, "ring": true, "cache": true, "fcgi-app": true,
	"crt-store": true, "log-forward": true, "traces": true,
}

// haproxyReserved are the endings of the files of a crt directory HAProxy does not load as certificates.
var haproxyReserved = []string{".key", ".ocsp", ".issuer", ".sctl"}

// haproxy reads HAProxy's sites; installed is false when HAProxy is not on this machine.
func (r *reader) haproxy(ctx context.Context, extra []string) ([]entry, bool, error) {
	if _, err := r.runner.Run(ctx, haproxyVersion); errors.Is(err, ErrNotInstalled) {
		if len(extra) > 0 {
			r.note("HAProxy: haproxy.configs is set in agent.yaml, but HAProxy is not installed")
		}
		return nil, false, nil
	}
	files, err := r.haproxyConfigs(extra)
	if err != nil {
		return nil, true, err
	}
	r.haproxyFiles = files
	h := &haproxyConf{r: r}
	var entries []entry
	for _, f := range files {
		found, err := h.file(f)
		if err != nil {
			return nil, true, fmt.Errorf("%s: %w", f, err)
		}
		entries = append(entries, found...)
	}
	return entries, true, nil
}

// haproxyConfigs are the configuration files read, in order: haproxy.cfg when it is there, then those agent.yaml names
// (a directory: its *.cfg files, sorted), each once. One that cannot be looked at is an error, never a file less.
func (r *reader) haproxyConfigs(extra []string) ([]string, error) {
	var files []string
	seen := map[string]bool{}
	add := func(f string) {
		if !seen[f] {
			seen[f] = true
			files = append(files, f)
		}
	}
	switch _, err := fs.Stat(r.fsys, fsPath(haproxyConfig)); {
	case err == nil:
		add(haproxyConfig)
	case !errors.Is(err, fs.ErrNotExist):
		return nil, err
	}
	for _, p := range extra {
		p = path.Clean(p)
		info, err := fs.Stat(r.fsys, fsPath(p))
		if err != nil {
			return nil, fmt.Errorf("%s (haproxy.configs in agent.yaml): %w", p, err)
		}
		if !info.IsDir() {
			add(p)
			continue
		}
		list, err := fs.ReadDir(r.fsys, fsPath(p))
		if err != nil {
			return nil, err
		}
		for _, d := range list {
			if !strings.HasSuffix(d.Name(), ".cfg") {
				continue
			}
			f := path.Join(p, d.Name())
			info, err := fs.Stat(r.fsys, fsPath(f))
			if err != nil {
				return nil, err
			}
			if !info.IsDir() {
				add(f)
			}
		}
	}
	return files, nil
}

// haproxyConf reads configuration files in order; crtBase (global crt-base) carries over from one to the next, as
// HAProxy reads them as one.
type haproxyConf struct {
	r       *reader
	crtBase string
}

func (h *haproxyConf) file(config string) ([]entry, error) {
	data, err := readFile(h.r.fsys, config, maxConfigFile)
	if err != nil {
		return nil, err
	}
	section := ""
	var entries []entry
	for i, line := range strings.Split(string(data), "\n") {
		words, err := haproxyWords(line)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", i+1, err)
		}
		switch {
		case len(words) == 0:
		case haproxySections[words[0]]:
			section = words[0]
		case section == "global" && words[0] == "crt-base" && len(words) > 1:
			h.crtBase = words[1]
		case (section == "frontend" || section == "listen") && words[0] == "bind" && len(words) > 1:
			found, err := h.bind(config, words[1], words[2:])
			if err != nil {
				return nil, fmt.Errorf("line %d: %w", i+1, err)
			}
			entries = append(entries, found...)
		}
	}
	return entries, nil
}

// bind reads a bind line: without "ssl" it serves no certificate; with it, an entry per certificate file.
func (h *haproxyConf) bind(config, addresses string, params []string) ([]entry, error) {
	var crts, lists []string
	ssl := false
	for i := 0; i < len(params); i++ {
		switch params[i] {
		case "ssl":
			ssl = true
		case "crt", "crt-list":
			if i+1 < len(params) {
				if params[i] == "crt" {
					crts = append(crts, params[i+1])
				} else {
					lists = append(lists, params[i+1])
				}
				i++
			}
		}
	}
	if !ssl {
		return nil, nil
	}
	ports := haproxyPorts(addresses)
	var entries []entry
	add := func(cert string) {
		// The key is beside the certificate (<file>.key) or in it.
		key := cert
		if isFile(h.r.fsys, cert+".key") {
			key = cert + ".key"
		}
		entries = append(entries, entry{kind: protocol.WebServerHAProxy, config: config, https: true, cert: cert, key: key, ports: ports})
	}
	for _, c := range crts {
		p, ok := h.crtPath(config, c)
		if !ok {
			continue
		}
		info, err := fs.Stat(h.r.fsys, fsPath(p))
		if err != nil || !info.IsDir() {
			add(p) // one that cannot be read is reported so
			continue
		}
		list, err := fs.ReadDir(h.r.fsys, fsPath(p))
		if err != nil {
			return nil, err
		}
		for _, d := range list {
			// HAProxy skips the files of a crt directory whose names start with a dot.
			if f := path.Join(p, d.Name()); !strings.HasPrefix(d.Name(), ".") && !reserved(d.Name()) && isFile(h.r.fsys, f) {
				add(f)
			}
		}
	}
	for _, l := range lists {
		p, ok := h.listPath(config, l)
		if !ok {
			continue
		}
		data, err := readFile(h.r.fsys, p, maxConfigFile)
		if err != nil {
			return nil, fmt.Errorf("crt-list %s: %w", p, err)
		}
		for _, line := range strings.Split(string(data), "\n") {
			words, err := haproxyWords(line)
			if err != nil {
				return nil, fmt.Errorf("crt-list %s: %w", p, err)
			}
			if len(words) == 0 {
				continue
			}
			if cert, ok := h.crtPath(config, words[0]); ok {
				add(cert)
			}
		}
	}
	return entries, nil
}

// crtPath is a crt path, or a certificate a crt-list names, as HAProxy resolves it: a relative one is relative to
// crt-base (else to /, the directory HAProxy runs in). A crt-store reference (@store/name) is no file: ok is false.
func (h *haproxyConf) crtPath(config, p string) (string, bool) {
	if strings.HasPrefix(p, "@") {
		h.r.note("HAProxy: %s names a certificate of a crt-store (%s); it is left out", config, p)
		return "", false
	}
	if !path.IsAbs(p) {
		p = path.Join("/", h.crtBase, p)
	}
	return path.Clean(p), true
}

// listPath is a crt-list path as HAProxy resolves it: a relative one is relative to the directory HAProxy runs in (/
// under systemd), never to crt-base (only the certificates the list names are). A crt-store reference is no file.
func (h *haproxyConf) listPath(config, p string) (string, bool) {
	if strings.HasPrefix(p, "@") {
		h.r.note("HAProxy: %s names a crt-list of a crt-store (%s); it is left out", config, p)
		return "", false
	}
	return path.Join("/", p), true
}

func reserved(name string) bool {
	for _, ext := range haproxyReserved {
		if strings.HasSuffix(name, ext) {
			return true
		}
	}
	return false
}

// haproxyPorts are the TCP ports of a bind line's addresses (:443, *:443, 192.0.2.1:443, :::443, ipv6@:443,
// :8443-8445 = its first); unix sockets and the like have none.
func haproxyPorts(addresses string) []int {
	var ports []int
	for _, a := range strings.Split(addresses, ",") {
		if family, rest, ok := strings.Cut(a, "@"); ok {
			switch family {
			case "ipv4", "ipv6", "tcp", "tcp4", "tcp6":
				a = rest
			default:
				continue
			}
		}
		i := strings.LastIndexByte(a, ':')
		if i < 0 {
			continue
		}
		p, _, _ := strings.Cut(a[i+1:], "-")
		if port, err := strconv.Atoi(p); err == nil && port > 0 && port < 65536 {
			ports = append(ports, port)
		}
	}
	return sortedUnique(ports)
}

// haproxyWords splits a configuration line as HAProxy does: words between spaces, "#" starting a comment, "..." and
// '...' quoting (a backslash escapes in "..."), a backslash escaping the next character.
func haproxyWords(line string) ([]string, error) {
	var words []string
	var b strings.Builder
	inWord := false
	end := func() {
		if inWord {
			words = append(words, b.String())
			b.Reset()
			inWord = false
		}
	}
	for i := 0; i < len(line); i++ {
		switch c := line[i]; {
		case c == '#':
			end()
			return words, nil
		case c == ' ' || c == '\t' || c == '\r':
			end()
		case c == '\\' && i+1 < len(line):
			i++
			b.WriteByte(line[i])
			inWord = true
		case c == '"' || c == '\'':
			inWord = true
			for i++; i < len(line) && line[i] != c; i++ {
				if c == '"' && line[i] == '\\' && i+1 < len(line) {
					i++
				}
				b.WriteByte(line[i])
			}
			if i >= len(line) {
				return nil, errors.New("a quote is not closed")
			}
		default:
			b.WriteByte(c)
			inWord = true
		}
	}
	end()
	return words, nil
}
