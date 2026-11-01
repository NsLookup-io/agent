package inventory

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/nslookup-io/agent/internal/protocol"
)

// nginx: `nginx -T` prints every configuration file nginx read, each after a line "# configuration file <path>:", the
// main file first. include directives are expanded from those sections (the files nginx itself read, in its order),
// so a certificate set in an included snippet is found where nginx found it. Only the http servers are sites (a
// stream server has no names).

var nginxFileHeader = regexp.MustCompile(`^# configuration file (/.*):$`)

// maxBlockDepth: blocks nest no deeper.
const maxBlockDepth = 64

// nginx reads nginx's sites; installed is false when nginx is not on this machine.
func (r *reader) nginx(ctx context.Context) ([]entry, bool, error) {
	out, err := r.runner.Run(ctx, nginxDump)
	if errors.Is(err, ErrNotInstalled) {
		return nil, false, nil
	}
	if err != nil {
		return nil, true, err
	}
	entries, err := r.nginxSites(string(out))
	return entries, true, err
}

// nginxConf is nginx's configuration as nginx -T printed it.
type nginxConf struct {
	r *reader
	// files are the files' texts by path; main is the first, prefix its directory (relative paths are relative to it).
	files        map[string]string
	main, prefix string
	parsed       map[string][]ngxDirective
}

// ngxDirective is one directive: its name, its arguments and, when it has one, its block.
type ngxDirective struct {
	name     string
	args     []string
	hasBlock bool
	block    []ngxDirective
	// file is the configuration file it is in.
	file string
}

func (r *reader) nginxSites(dump string) ([]entry, error) {
	n := &nginxConf{r: r, files: map[string]string{}, parsed: map[string][]ngxDirective{}}
	current := ""
	var text strings.Builder
	flush := func() {
		if current != "" {
			n.files[current] = text.String()
		}
		text.Reset()
	}
	for _, line := range strings.Split(dump, "\n") {
		if m := nginxFileHeader.FindStringSubmatch(line); m != nil {
			flush()
			current = path.Clean(m[1])
			if n.main == "" {
				n.main = current
			}
			continue
		}
		if current != "" {
			text.WriteString(line)
			text.WriteByte('\n')
		}
	}
	flush()
	if n.main == "" {
		return nil, errors.New("nginx -T printed no configuration")
	}
	n.prefix = path.Dir(n.main)

	top, err := n.parse(n.main)
	if err == nil {
		top, err = n.expand(top, 0)
	}
	if err != nil {
		return nil, err
	}
	var entries []entry
	for _, h := range top {
		if h.name != "http" || !h.hasBlock {
			continue
		}
		body, err := n.expand(h.block, 0)
		if err != nil {
			return nil, err
		}
		var http nginxLevel
		var servers []ngxDirective
		for _, d := range body {
			if d.name == "server" && d.hasBlock {
				servers = append(servers, d)
			} else {
				http.take(d)
			}
		}
		type read struct {
			entries []entry
			listens map[string]bool
		}
		var all []read
		explicit := map[string]bool{}
		for _, s := range servers {
			found, listens, err := n.server(s, http)
			if err != nil {
				return nil, err
			}
			all = append(all, read{found, listens})
			for addr, marked := range listens {
				explicit[addr] = explicit[addr] || marked
			}
		}
		// Where no server says default_server, nginx's default server of an address and port is the first listening on
		// it: it catches every name no other server there serves.
		claimed := map[string]bool{}
		for _, r := range all {
			implicit := false
			for _, addr := range slices.Sorted(maps.Keys(r.listens)) {
				if !explicit[addr] && !claimed[addr] {
					claimed[addr], implicit = true, true
				}
			}
			for i := range r.entries {
				r.entries[i].servesMore = r.entries[i].servesMore || (implicit && r.entries[i].https)
			}
			entries = append(entries, r.entries...)
		}
	}
	return entries, nil
}

// nginxLevel is what an http or a server block sets about HTTPS.
type nginxLevel struct {
	certs, keys []string
	// ssl is the old "ssl on|off"; nil when not set.
	ssl *bool
}

func (l *nginxLevel) take(d ngxDirective) {
	if d.hasBlock || len(d.args) == 0 {
		return
	}
	switch d.name {
	case "ssl_certificate":
		l.certs = append(l.certs, d.args[0])
	case "ssl_certificate_key":
		l.keys = append(l.keys, d.args[0])
	case "ssl":
		l.ssl = ptr(d.args[0] == "on")
	}
}

// server reads one server block: an entry per certificate it serves (nginx pairs the certificates and keys in order),
// or one for its names when it serves no HTTPS. Its certificates are its own, else the http block's; it serves HTTPS
// on a listener with ssl or quic, on every listener with the old "ssl on", and on port 443 when it has a certificate.
// listens are the addresses (listenAddress) of its HTTPS listeners, each true when it says default_server there.
func (n *nginxConf) server(s ngxDirective, http nginxLevel) (_ []entry, listens map[string]bool, _ error) {
	body, err := n.expand(s.block, 0)
	if err != nil {
		return nil, nil, err
	}
	var own nginxLevel
	var names []string
	var listenArgs [][]string
	odd := false
	listens = map[string]bool{}
	for _, d := range body {
		switch {
		case d.hasBlock:
		case d.name == "listen" && len(d.args) > 0:
			listenArgs = append(listenArgs, d.args)
		case d.name == "server_name":
			names = append(names, nginxNames(d.args)...)
			odd = odd || slices.ContainsFunc(d.args, inexpressible)
		default:
			own.take(d)
		}
	}
	names = sortedUnique(names)
	certs, keys := own.certs, own.keys
	if len(certs) == 0 {
		certs = http.certs
	}
	if len(keys) == 0 {
		keys = http.keys
	}
	allHTTPS := sslOn(own.ssl, http.ssl)
	if len(listenArgs) == 0 {
		listenArgs = [][]string{{"80"}}
	}
	https := false
	var ports []int
	for _, l := range listenArgs {
		port, tcp := listenPort(l[0])
		quic := slices.Contains(l[1:], "quic")
		if !allHTTPS && !quic && !slices.Contains(l[1:], "ssl") && (port != 443 || len(certs) == 0) {
			continue
		}
		https = true
		// The default server of its address catches every name no other server there serves.
		marked := slices.Contains(l[1:], "default_server") || slices.Contains(l[1:], "default")
		odd = odd || marked
		addr := listenAddress(l[0], port)
		if quic {
			addr += "/udp"
		}
		listens[addr] = listens[addr] || marked
		// QUIC is UDP: no port for a TLS check.
		if tcp && !quic {
			ports = append(ports, port)
		}
	}
	if !https || len(certs) == 0 {
		if len(names) == 0 {
			return nil, listens, nil
		}
		return []entry{{kind: protocol.WebServerNginx, config: s.file, names: names}}, listens, nil
	}
	var entries []entry
	for i, c := range certs {
		cert, ok := n.file(c)
		if !ok {
			// Never quoted: such a value is the certificate itself.
			n.r.note("nginx: a server in %s has its certificate inside the configuration; it is left out", s.file)
			continue
		}
		e := entry{kind: protocol.WebServerNginx, config: s.file, names: names, https: true, servesMore: odd, cert: cert, ports: sortedUnique(ports)}
		if i < len(keys) {
			e.key, _ = n.file(keys[i])
		}
		entries = append(entries, e)
	}
	return entries, listens, nil
}

// listenAddress is the address and port a listen value binds, as nginx tells default servers apart: 443, *:443 and
// 0.0.0.0:443 are one ("*:443"), [::]:443 another, 192.0.2.1:443 another; a unix: socket is itself.
func listenAddress(value string, port int) string {
	if strings.HasPrefix(value, "unix:") {
		return value
	}
	host := "*"
	switch {
	case strings.HasPrefix(value, "["):
		if end := strings.IndexByte(value, ']'); end > 0 {
			host = value[:end+1]
		}
	case strings.Contains(value, ":"):
		host = value[:strings.LastIndexByte(value, ':')]
	default:
		if _, err := strconv.Atoi(value); err != nil {
			host = value // a host name or address alone, on port 80
		}
	}
	if host == "0.0.0.0" {
		host = "*"
	}
	return host + ":" + strconv.Itoa(port)
}

// sslOn is the old "ssl on": the server's own setting, else the http block's.
func sslOn(own, http *bool) bool {
	if own != nil {
		return *own
	}
	return http != nil && *http
}

// file is a certificate or key path as nginx resolves it (a relative one is relative to the main file's directory);
// ok is false when it is no file: data: (the PEM itself), engine: or store:.
func (n *nginxConf) file(p string) (string, bool) {
	if isURI(p) {
		return "", false
	}
	if !path.IsAbs(p) {
		p = path.Join(n.prefix, p)
	}
	return path.Clean(p), true
}

// isURI reports whether p names something other than a file ("data:...", "engine:...", "pkcs11:..."): a scheme
// before any slash.
func isURI(p string) bool {
	i := strings.IndexByte(p, ':')
	return i > 0 && !strings.Contains(p[:i], "/")
}

// nginxNames are the names of server_name values: exact names and *.name; .name is both name and *.name; regular
// expressions and the like are left out (siteName).
func nginxNames(args []string) []string {
	var names []string
	for _, a := range args {
		if strings.HasPrefix(a, "~") {
			continue
		}
		candidates := []string{a}
		if rest, ok := strings.CutPrefix(a, "."); ok {
			candidates = []string{rest, "*." + rest}
		}
		for _, c := range candidates {
			if name, ok := siteName(c); ok {
				names = append(names, name)
			}
		}
	}
	return names
}

// listenPort is the TCP port of a listen address: 443, *:443, 192.0.2.1:443, [::]:443, [::1] (80), localhost (80);
// tcp is false for a unix: socket or an address it cannot read.
func listenPort(addr string) (port int, tcp bool) {
	if strings.HasPrefix(addr, "unix:") {
		return 0, false
	}
	p := addr
	switch {
	case strings.HasPrefix(addr, "["):
		_, rest, ok := strings.Cut(addr, "]")
		if !ok {
			return 0, false
		}
		if rest == "" {
			return 80, true
		}
		p = strings.TrimPrefix(rest, ":")
	case strings.Contains(addr, ":"):
		p = addr[strings.LastIndexByte(addr, ':')+1:]
	default:
		if _, err := strconv.Atoi(addr); err != nil {
			return 80, true // a host name or address alone
		}
	}
	port, err := strconv.Atoi(p)
	if err != nil || port < 1 || port > 65535 {
		return 0, false
	}
	return port, true
}

// parse reads one of the files nginx -T printed (once).
func (n *nginxConf) parse(file string) ([]ngxDirective, error) {
	if ds, ok := n.parsed[file]; ok {
		return ds, nil
	}
	src, ok := n.files[file]
	if !ok {
		return nil, fmt.Errorf("%s is not in nginx -T's output", file)
	}
	p := &ngxParser{src: src, file: file, line: 1}
	ds, closed, err := p.block(0)
	if err == nil && closed {
		err = p.errorf(`unexpected "}"`)
	}
	if err != nil {
		return nil, err
	}
	n.parsed[file] = ds
	return ds, nil
}

// expand replaces the include directives of ds by the directives of the files they name, as nginx read them.
func (n *nginxConf) expand(ds []ngxDirective, depth int) ([]ngxDirective, error) {
	if depth > maxIncludeDepth {
		return nil, errors.New("includes nest too deep")
	}
	var out []ngxDirective
	for _, d := range ds {
		if d.name != "include" || d.hasBlock || len(d.args) != 1 {
			out = append(out, d)
			continue
		}
		for _, file := range n.included(d.args[0]) {
			sub, err := n.parse(file)
			if err == nil {
				sub, err = n.expand(sub, depth+1)
			}
			if err != nil {
				return nil, err
			}
			out = append(out, sub...)
		}
	}
	return out, nil
}

// included are the files an include pattern names, among those nginx read, in nginx's order (sorted).
func (n *nginxConf) included(pattern string) []string {
	if !path.IsAbs(pattern) {
		pattern = path.Join(n.prefix, pattern)
	}
	pattern = path.Clean(pattern)
	if !strings.ContainsAny(pattern, "*?[") {
		if _, ok := n.files[pattern]; ok {
			return []string{pattern}
		}
		return nil
	}
	var files []string
	for f := range n.files {
		if ok, _ := path.Match(pattern, f); ok {
			files = append(files, f)
		}
	}
	slices.Sort(files)
	return files
}

// ngxParser reads nginx's configuration syntax: words, ";" ending a directive, "{" and "}" around a block, "#"
// comments, '...' and "..." quoting, backslash escapes, "${name}" variables.
type ngxParser struct {
	src, file string
	pos, line int
}

func (p *ngxParser) errorf(format string, args ...any) error {
	return fmt.Errorf("%s:%d: %s", p.file, p.line, fmt.Sprintf(format, args...))
}

const ngxEOF, ngxWord = 0, 'w'

// block reads directives up to the end of the file or a "}" (closed).
func (p *ngxParser) block(depth int) (ds []ngxDirective, closed bool, err error) {
	if depth > maxBlockDepth {
		return nil, false, p.errorf("blocks nest too deep")
	}
	var words []string
	for {
		kind, word, err := p.token()
		if err != nil {
			return nil, false, err
		}
		switch kind {
		case ngxWord:
			words = append(words, word)
		case ';':
			if len(words) == 0 {
				return nil, false, p.errorf(`unexpected ";"`)
			}
			ds = append(ds, ngxDirective{name: words[0], args: words[1:], file: p.file})
			words = nil
		case '{':
			if len(words) == 0 {
				return nil, false, p.errorf(`unexpected "{"`)
			}
			d := ngxDirective{name: words[0], args: words[1:], hasBlock: true, file: p.file}
			if strings.HasSuffix(d.name, "_by_lua_block") {
				err = p.skipLua()
			} else {
				var inner bool
				d.block, inner, err = p.block(depth + 1)
				if err == nil && !inner {
					err = p.errorf(`unexpected end of file, expecting "}"`)
				}
			}
			if err != nil {
				return nil, false, err
			}
			ds = append(ds, d)
			words = nil
		case '}':
			if len(words) > 0 {
				return nil, false, p.errorf(`unexpected "}"`)
			}
			return ds, true, nil
		case ngxEOF:
			if len(words) > 0 {
				return nil, false, p.errorf(`unexpected end of file, expecting ";" or "}"`)
			}
			return ds, false, nil
		}
	}
}

// token is the next word, or ";", "{", "}", or ngxEOF.
func (p *ngxParser) token() (byte, string, error) {
	for p.pos < len(p.src) {
		switch c := p.src[p.pos]; c {
		case '\n':
			p.line++
			p.pos++
		case ' ', '\t', '\r':
			p.pos++
		case '#':
			for p.pos < len(p.src) && p.src[p.pos] != '\n' {
				p.pos++
			}
		case ';', '{', '}':
			p.pos++
			return c, "", nil
		case '"', '\'':
			word, err := p.quoted(c)
			return ngxWord, word, err
		default:
			return ngxWord, p.word(), nil
		}
	}
	return ngxEOF, "", nil
}

func (p *ngxParser) quoted(quote byte) (string, error) {
	start := p.line
	p.pos++
	var b strings.Builder
	for p.pos < len(p.src) {
		c := p.src[p.pos]
		p.pos++
		switch {
		case c == quote:
			return b.String(), nil
		case c == '\\' && p.pos < len(p.src):
			p.escape(&b)
		default:
			if c == '\n' {
				p.line++
			}
			b.WriteByte(c)
		}
	}
	return "", fmt.Errorf("%s:%d: a quote is not closed", p.file, start)
}

// word reads an unquoted word: it ends at a space, ";" or "{", except the "{" of "${name}".
func (p *ngxParser) word() string {
	var b strings.Builder
	variable := false
	for p.pos < len(p.src) {
		c := p.src[p.pos]
		if c == '{' && variable {
			b.WriteByte(c)
			p.pos++
			variable = false
			continue
		}
		if c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == ';' || c == '{' {
			break
		}
		p.pos++
		if c == '\\' && p.pos < len(p.src) {
			p.escape(&b)
			variable = false
			continue
		}
		variable = c == '$'
		b.WriteByte(c)
	}
	return b.String()
}

// escape writes the character after a backslash as nginx does: \" \' \\ \t \r \n are unescaped, anything else keeps
// its backslash.
func (p *ngxParser) escape(b *strings.Builder) {
	c := p.src[p.pos]
	p.pos++
	switch c {
	case '"', '\'', '\\':
		b.WriteByte(c)
	case 't':
		b.WriteByte('\t')
	case 'r':
		b.WriteByte('\r')
	case 'n':
		b.WriteByte('\n')
	default:
		if c == '\n' {
			p.line++
		}
		b.WriteByte('\\')
		b.WriteByte(c)
	}
}

// skipLua skips the Lua code of an *_by_lua_block (OpenResty) up to its closing brace: braces in Lua strings, long
// brackets and comments are not nginx's.
func (p *ngxParser) skipLua() error {
	start, depth := p.line, 1
	for p.pos < len(p.src) {
		c := p.src[p.pos]
		switch {
		case c == '\n':
			p.line++
			p.pos++
		case c == '{':
			depth++
			p.pos++
		case c == '}':
			depth--
			p.pos++
			if depth == 0 {
				return nil
			}
		case c == '"' || c == '\'':
			p.skipLuaString(c)
		case strings.HasPrefix(p.src[p.pos:], "--"):
			p.pos += 2
			if level := p.longBracket(); level >= 0 {
				p.skipLong(level)
			} else {
				for p.pos < len(p.src) && p.src[p.pos] != '\n' {
					p.pos++
				}
			}
		case c == '[' && p.longBracket() >= 0:
			p.skipLong(p.longBracket())
		default:
			p.pos++
		}
	}
	return fmt.Errorf("%s:%d: a Lua block is not closed", p.file, start)
}

func (p *ngxParser) skipLuaString(quote byte) {
	p.pos++
	for p.pos < len(p.src) {
		c := p.src[p.pos]
		p.pos++
		switch {
		case c == '\\' && p.pos < len(p.src):
			if p.src[p.pos] == '\n' {
				p.line++
			}
			p.pos++
		case c == '\n':
			p.line++
			return
		case c == quote:
			return
		}
	}
}

// longBracket is the level of the Lua long bracket opening at the current position ("[[" 0, "[==[" 2), or -1.
func (p *ngxParser) longBracket() int {
	if p.pos >= len(p.src) || p.src[p.pos] != '[' {
		return -1
	}
	i := p.pos + 1
	for i < len(p.src) && p.src[i] == '=' {
		i++
	}
	if i < len(p.src) && p.src[i] == '[' {
		return i - p.pos - 1
	}
	return -1
}

// skipLong skips a long bracket of the given level, to the end of the text when it is not closed.
func (p *ngxParser) skipLong(level int) {
	p.pos += level + 2
	closing := "]" + strings.Repeat("=", level) + "]"
	end := len(p.src)
	if i := strings.Index(p.src[p.pos:], closing); i >= 0 {
		end = p.pos + i + len(closing)
	}
	p.line += strings.Count(p.src[p.pos:end], "\n")
	p.pos = end
}
