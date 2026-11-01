package inventory

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/nslookup-io/agent/internal/protocol"
)

// Apache: `apachectl -t -D DUMP_VHOSTS -D DUMP_RUN_CFG` names each virtual host's file and line, the ports it is on and
// the ServerRoot; the agent reads each <VirtualHost> block there, with the files it includes, for its names and its
// certificate, key and chain files.

var (
	apacheNameVhost = regexp.MustCompile(`^(\S+)\s+is a NameVirtualHost$`)
	apacheDefault   = regexp.MustCompile(`^\s+default server \S+ \((.+):(\d+)\)$`)
	apacheNamed     = regexp.MustCompile(`^\s+port (\d+|\*) namevhost \S+ \((.+):(\d+)\)$`)
	apacheSingle    = regexp.MustCompile(`^(\S+)\s+\S+ \((.+):(\d+)\)$`)
	apacheRoot      = regexp.MustCompile(`^ServerRoot: "(.*)"$`)
)

// maxIncludeFiles: one Include reads no more files.
const maxIncludeFiles = 1000

const apacheVhostsHeader = "VirtualHost configuration:"

// apache reads Apache's sites; installed is false when Apache is not on this machine.
func (r *reader) apache(ctx context.Context) ([]entry, bool, error) {
	out, installed, err := firstInstalled(ctx, r.runner, apacheDumps, func(out []byte) bool {
		return bytes.Contains(out, []byte(apacheVhostsHeader))
	})
	if !installed || err != nil {
		return nil, installed, err
	}
	refs, root := apacheVhostRefs(string(out))
	a := &apacheConf{r: r, root: root}
	if a.root == "" {
		a.root = "/"
	}
	var entries []entry
	for _, ref := range refs {
		if !path.IsAbs(ref.file) {
			// mod_macro names its virtual hosts "macro '<name>' (defined on line …)": no file to read.
			r.note("Apache: the virtual host defined by %s is not in a file of its own; it is left out", ref.file)
			continue
		}
		// One that cannot be read now (a file being edited, gone) fails the read: left out, its sites would look gone.
		found, err := a.vhost(ref)
		if err != nil {
			return nil, true, fmt.Errorf("the virtual host at %s:%d cannot be read: %w", ref.file, ref.line, err)
		}
		entries = append(entries, found...)
	}
	return entries, true, nil
}

// apacheVhostRef is a virtual host as the dump names it: where it starts and the ports it is on (0: any). catchAll: it
// is the first of an address and port (the default server, or the only one), which answers every name no other there
// serves.
type apacheVhostRef struct {
	file     string
	line     int
	ports    []int
	catchAll bool
}

// apacheVhostRefs reads the dump: each virtual host once, in the order first named, and the ServerRoot.
func apacheVhostRefs(dump string) (refs []apacheVhostRef, root string) {
	index := map[string]int{}
	add := func(file, line string, port int, catchAll bool) {
		key := file + ":" + line
		i, ok := index[key]
		if !ok {
			n, _ := strconv.Atoi(line)
			refs = append(refs, apacheVhostRef{file: file, line: n})
			i = len(refs) - 1
			index[key] = i
		}
		if port > 0 {
			refs[i].ports = append(refs[i].ports, port)
		}
		refs[i].catchAll = refs[i].catchAll || catchAll
	}
	current := 0
	for _, line := range strings.Split(dump, "\n") {
		line = strings.TrimRight(line, " \t\r")
		if m := apacheRoot.FindStringSubmatch(line); m != nil {
			root = m[1]
		} else if m := apacheNameVhost.FindStringSubmatch(line); m != nil {
			current = addressPort(m[1])
		} else if m := apacheDefault.FindStringSubmatch(line); m != nil {
			add(m[1], m[2], current, true)
		} else if m := apacheNamed.FindStringSubmatch(line); m != nil {
			port, _ := strconv.Atoi(m[1])
			add(m[2], m[3], port, false)
		} else if m := apacheSingle.FindStringSubmatch(line); m != nil {
			add(m[2], m[3], addressPort(m[1]), true)
		}
	}
	for i := range refs {
		refs[i].ports = sortedUnique(refs[i].ports)
	}
	return refs, root
}

// addressPort is the port of *:443, _default_:443, 192.0.2.10:443 or [2001:db8::1]:443; 0 when there is none.
func addressPort(addr string) int {
	i := strings.LastIndexByte(addr, ':')
	if i < 0 {
		return 0
	}
	port, err := strconv.Atoi(addr[i+1:])
	if err != nil || port < 1 || port > 65535 {
		return 0
	}
	return port
}

// apacheConf reads virtual hosts; root is the ServerRoot, which relative paths are relative to.
type apacheConf struct {
	r    *reader
	root string
}

// apacheVhost is what a <VirtualHost> block sets.
type apacheVhost struct {
	serverName  string
	aliases     []string
	sslEngine   bool
	certs, keys []string
	chain       string
}

func (a *apacheConf) vhost(ref apacheVhostRef) ([]entry, error) {
	data, err := readFile(a.r.fsys, ref.file, maxConfigFile)
	if err != nil {
		return nil, err
	}
	lines := apacheLines(string(data))
	start := slices.IndexFunc(lines, func(l apacheLine) bool { return l.first <= ref.line && ref.line <= l.last })
	if start < 0 || !apacheSection(lines[start].text, "<virtualhost") {
		return nil, errors.New("no <VirtualHost> starts on that line")
	}
	var v apacheVhost
	for _, l := range lines[start+1:] {
		if apacheSection(l.text, "</virtualhost") {
			return a.entries(ref, v), nil
		}
		if err := a.take(&v, l.text, 0); err != nil {
			return nil, err
		}
	}
	return nil, errors.New("its </VirtualHost> is missing")
}

// take reads one line of a virtual host (or of a file it includes).
func (a *apacheConf) take(v *apacheVhost, line string, depth int) error {
	args := apacheArgs(line)
	if len(args) < 2 {
		return nil
	}
	switch value := args[1]; strings.ToLower(args[0]) {
	case "servername":
		v.serverName = value
	case "serveralias":
		v.aliases = append(v.aliases, args[1:]...)
	case "sslengine":
		v.sslEngine = strings.EqualFold(value, "on")
	case "sslcertificatefile":
		v.certs = append(v.certs, value)
	case "sslcertificatekeyfile":
		v.keys = append(v.keys, value)
	case "sslcertificatechainfile":
		v.chain = value
	case "include", "includeoptional":
		return a.include(v, value, depth+1)
	}
	return nil
}

// include reads the files an Include names (a relative path is relative to ServerRoot) into the virtual host.
func (a *apacheConf) include(v *apacheVhost, pattern string, depth int) error {
	if depth > maxIncludeDepth {
		return errors.New("includes nest too deep")
	}
	if strings.Contains(pattern, "$") {
		a.r.note("Apache: an Include names a variable (%s); it is not read", pattern)
		return nil
	}
	files, err := a.files(a.path(pattern))
	if err != nil {
		return err
	}
	for _, f := range files {
		data, err := readFile(a.r.fsys, f, maxConfigFile)
		if err != nil {
			return err
		}
		for _, l := range apacheLines(string(data)) {
			if err := a.take(v, l.text, depth); err != nil {
				return err
			}
		}
	}
	return nil
}

// files are the files an Include names, in Apache's order: the file, the files a wildcard matches, every file under a
// directory. A name that is not there names none (IncludeOptional; Apache, which checked the configuration, found
// it); one that cannot be looked at is an error.
func (a *apacheConf) files(pattern string) ([]string, error) {
	matches := []string{pattern}
	if strings.ContainsAny(pattern, "*?[") {
		found, err := fs.Glob(a.r.fsys, fsPath(pattern))
		if err != nil {
			return nil, err
		}
		matches = matches[:0]
		for _, m := range found {
			matches = append(matches, "/"+m)
		}
	}
	var files []string
	for _, m := range matches {
		info, err := fs.Stat(a.r.fsys, fsPath(m))
		switch {
		case errors.Is(err, fs.ErrNotExist):
		case err != nil:
			return nil, err
		case !info.IsDir():
			files = append(files, m)
		default:
			err = fs.WalkDir(a.r.fsys, fsPath(m), func(p string, d fs.DirEntry, err error) error {
				if err == nil && !d.IsDir() {
					files = append(files, "/"+p)
				}
				return err
			})
			if err != nil {
				return nil, err
			}
		}
		if len(files) > maxIncludeFiles {
			return nil, fmt.Errorf("an Include names more than %d files", maxIncludeFiles)
		}
	}
	return files, nil
}

// entries are what a virtual host serves: an entry per certificate file (paired with the key files in order; with
// none, the key is in the certificate's file), or one for its names when it serves no HTTPS. It serves HTTPS with
// SSLEngine on, or on port 443 with a certificate.
func (a *apacheConf) entries(ref apacheVhostRef, v apacheVhost) []entry {
	names := siteNames(append([]string{apacheServerName(v.serverName)}, v.aliases...))
	if !v.sslEngine && (!slices.Contains(ref.ports, 443) || len(v.certs) == 0) {
		if len(names) == 0 {
			return nil
		}
		return []entry{{kind: protocol.WebServerApache, config: ref.file, names: names}}
	}
	if len(v.certs) == 0 {
		a.r.note("Apache: the virtual host at %s:%d takes its certificate from outside it; it is left out", ref.file, ref.line)
		return nil
	}
	odd := ref.catchAll || inexpressible(apacheServerName(v.serverName)) || slices.ContainsFunc(v.aliases, inexpressible)
	var entries []entry
	for i, c := range v.certs {
		if isURI(c) {
			a.r.note("Apache: the certificate of the virtual host at %s:%d is not in a file; it is left out", ref.file, ref.line)
			continue
		}
		e := entry{kind: protocol.WebServerApache, config: ref.file, names: names, https: true, servesMore: odd, cert: a.path(c), ports: ref.ports}
		e.key = e.cert
		if i < len(v.keys) {
			e.key = ""
			if !isURI(v.keys[i]) {
				e.key = a.path(v.keys[i])
			}
		}
		if v.chain != "" && !isURI(v.chain) {
			e.chain = a.path(v.chain)
		}
		entries = append(entries, e)
	}
	return entries
}

// path is p as Apache resolves it: a relative path is relative to ServerRoot.
func (a *apacheConf) path(p string) string {
	if !path.IsAbs(p) {
		p = path.Join(a.root, p)
	}
	return path.Clean(p)
}

// apacheServerName is the host of a ServerName ([scheme://]host[:port]).
func apacheServerName(s string) string {
	if _, rest, ok := strings.Cut(s, "://"); ok {
		s = rest
	}
	if i := strings.LastIndexByte(s, ':'); i >= 0 && !strings.Contains(s[i:], "]") {
		s = s[:i]
	}
	return s
}

// apacheLine is a line as Apache reads it, and the lines of the file it spans.
type apacheLine struct {
	text        string
	first, last int
}

// apacheLines are a configuration file's lines as Apache reads them: a line ending in a backslash goes on in the next;
// blank lines and comments are left out.
func apacheLines(text string) []apacheLine {
	raw := strings.Split(text, "\n")
	var lines []apacheLine
	for i := 0; i < len(raw); i++ {
		first := i + 1
		line := strings.TrimRight(raw[i], " \t\r")
		for strings.HasSuffix(line, "\\") && i+1 < len(raw) {
			i++
			line = line[:len(line)-1] + strings.TrimRight(raw[i], " \t\r")
		}
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, apacheLine{text: line, first: first, last: i + 1})
		}
	}
	return lines
}

// apacheSection reports whether line opens (or closes) the section named by tag ("<virtualhost", "</virtualhost").
func apacheSection(line, tag string) bool {
	if len(line) < len(tag) || !strings.EqualFold(line[:len(tag)], tag) {
		return false
	}
	rest := line[len(tag):]
	return rest == "" || rest[0] == '>' || rest[0] == ' ' || rest[0] == '\t'
}

// apacheArgs splits a directive into its words as Apache does: spaces between words, "..." or '...' around one (a
// backslash before the quote character keeps it).
func apacheArgs(line string) []string {
	var args []string
	for {
		line = strings.TrimLeft(line, " \t")
		if line == "" {
			return args
		}
		if q := line[0]; q == '"' || q == '\'' {
			var b strings.Builder
			i := 1
			for ; i < len(line) && line[i] != q; i++ {
				if line[i] == '\\' && i+1 < len(line) && line[i+1] == q {
					i++
				}
				b.WriteByte(line[i])
			}
			args = append(args, b.String())
			line = line[min(i+1, len(line)):]
			continue
		}
		end := strings.IndexAny(line, " \t")
		if end < 0 {
			end = len(line)
		}
		args = append(args, line[:end])
		line = line[end:]
	}
}
