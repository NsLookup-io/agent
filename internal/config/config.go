// Package config reads the agent's local configuration file (/etc/nslookup-agent/agent.yaml) and checks the values
// that also come from flags and the environment: the server's address, the agent's name, the Kubernetes namespaces,
// and a Docker agent's folder, containers and signal.
//
// The file (and a Docker agent's environment) is the only place the folder for certificates, the command run after
// writing one, the containers to signal and the HAProxy configuration files read come from: the server can never name
// a path or a command.
package config

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"unicode/utf16"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

const (
	// DefaultPath is where the agent looks for its configuration file.
	DefaultPath = "/etc/nslookup-agent/agent.yaml"
	// DefaultServer is the server an agent joins when none is given.
	DefaultServer = "https://agents.nslookup.io"
	// DefaultSignal is sent to docker.reloadContainers after a folder certificate is written.
	DefaultSignal = "HUP"
	// maxNameLength is the server's limit for an agent name (counted like the server counts it: UTF-16 units).
	maxNameLength = 100
	maxFileBytes  = 1 << 20
)

// Config is agent.yaml. Every field is optional.
type Config struct {
	// Server is the server's origin (checked with ServerOrigin); "" when not set.
	Server string
	// Name is the agent's name in the portal; "" when not set (the server then uses the code's name or the host name).
	Name    string
	Folder  Folder
	Docker  Docker
	HAProxy HAProxy
}

// Folder is where folder certificates are written, and what runs after one is.
type Folder struct {
	// Root is an absolute directory; each folder certificate is written to a directory of its own under it. "" = none.
	Root string
	// Hook is a command run after a folder certificate is written; "" = none.
	Hook string
}

// Docker names the containers signalled through the Docker socket after a folder certificate is written.
type Docker struct {
	ReloadContainers []string
	// Signal is the signal sent to them: HUP, USR1 or USR2.
	Signal string
}

// HAProxy names the HAProxy configuration read besides /etc/haproxy/haproxy.cfg (HAProxy has no command that prints
// it).
type HAProxy struct {
	// Configs are absolute paths of configuration files, or of directories of *.cfg files: what haproxy -f is given.
	Configs []string
}

// Default is the configuration when agent.yaml does not exist or sets nothing.
func Default() Config {
	return Config{Docker: Docker{Signal: DefaultSignal}}
}

var (
	containerName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)
	namespaceName = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`)
	// reloadSignals are the signals the agent sends to containers: the ones web servers and mail servers reload on.
	reloadSignals = []string{"HUP", "USR1", "USR2"}
)

// Load reads and checks the configuration file at path. A file that does not exist is an error wrapping
// fs.ErrNotExist (the caller decides whether that is fine). The file names the command the agent runs after writing a
// folder certificate, and the folder it writes in, so it is refused unless only the agent's user or root can change
// it: the file, and the directory it is in.
func Load(path string) (Config, error) { return load(path, os.Geteuid()) }

// load is Load for an agent running as the user uid.
func load(path string, uid int) (Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return Config{}, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return Config{}, err
	}
	if !info.Mode().IsRegular() {
		return Config{}, fmt.Errorf("%s is not a regular file", path)
	}
	if perm := info.Mode().Perm(); perm&0o022 != 0 {
		return Config{}, fmt.Errorf("%s can be changed by other users (mode %04o); it names commands the agent runs: run chmod 644 %s", path, perm, path)
	}
	if owner := ownerOf(info); owner != uid && owner != 0 {
		return Config{}, fmt.Errorf("%s belongs to user %d, not to root or the user the agent runs as (%d); it names commands the agent runs: run chown root %s",
			path, owner, uid, path)
	}
	if err := checkDirectories(path, uid); err != nil {
		return Config{}, err
	}
	data, err := io.ReadAll(io.LimitReader(f, maxFileBytes+1))
	if err != nil {
		return Config{}, err
	}
	if len(data) > maxFileBytes {
		return Config{}, fmt.Errorf("%s is larger than %d bytes", path, maxFileBytes)
	}
	cfg, err := Parse(data)
	if err != nil {
		return Config{}, fmt.Errorf("%s: %w", path, err)
	}
	return cfg, nil
}

// checkDirectories checks the directory of path, and of the file it really is (links followed), can be changed by root
// or the user uid only: whoever can change a directory can put another file in place of agent.yaml.
func checkDirectories(path string, uid int) error {
	files := []string{path}
	if real, err := filepath.EvalSymlinks(path); err == nil && real != path {
		files = append(files, real)
	}
	for _, file := range files {
		dir := filepath.Dir(file)
		info, err := os.Stat(dir)
		if err != nil {
			return err
		}
		perm, owner := info.Mode().Perm(), ownerOf(info)
		if perm&0o022 != 0 || (owner != uid && owner != 0) {
			return fmt.Errorf("%s, the directory of %s, can be changed by other users (owner %d, mode %04o); it names commands the agent runs: "+
				"keep agent.yaml in a directory only root can change, such as /etc/nslookup-agent (run chown root %s and chmod go-w %s)",
				dir, file, owner, perm, dir, dir)
		}
	}
	return nil
}

// ownerOf is the user owning a file; -1 when it cannot be told.
func ownerOf(info fs.FileInfo) int {
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		return int(st.Uid)
	}
	return -1
}

// Parse reads agent.yaml's text. An error names the line and the field.
func Parse(data []byte) (Config, error) {
	cfg := Default()
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return Config{}, fmt.Errorf("not valid YAML: %w", err)
	}
	if len(doc.Content) == 0 || isNull(doc.Content[0]) {
		return cfg, nil
	}
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode {
		return Config{}, at(root, "the file must be a mapping of fields (server, name, folder, docker, haproxy)")
	}
	err := fields(root, "", map[string]func(*yaml.Node) error{
		"server": func(v *yaml.Node) error {
			s, ok, err := text(v, "server")
			if !ok {
				return err
			}
			origin, err := ServerOrigin(s)
			if err != nil {
				return at(v, "server: %v", err)
			}
			cfg.Server = origin
			return nil
		},
		"name": func(v *yaml.Node) error {
			s, ok, err := text(v, "name")
			if !ok {
				return err
			}
			if cfg.Name, err = AgentName(s); err != nil {
				return at(v, "name: %v", err)
			}
			return nil
		},
		"folder": func(v *yaml.Node) error {
			return section(v, "folder", map[string]func(*yaml.Node) error{
				"root": func(v *yaml.Node) error {
					s, ok, err := text(v, "folder.root")
					if !ok {
						return err
					}
					if cfg.Folder.Root, err = FolderRoot(s); err != nil {
						return at(v, "folder.root %v", err)
					}
					return nil
				},
				"hook": func(v *yaml.Node) error {
					s, ok, err := text(v, "folder.hook")
					if !ok {
						return err
					}
					if hasControl(s) {
						return at(v, "folder.hook must be one line")
					}
					cfg.Folder.Hook = s
					return nil
				},
			})
		},
		"docker": func(v *yaml.Node) error {
			return section(v, "docker", map[string]func(*yaml.Node) error{
				"reloadContainers": func(v *yaml.Node) error {
					if isNull(v) {
						return nil
					}
					if v.Kind != yaml.SequenceNode {
						return at(v, "docker.reloadContainers must be a list of container names")
					}
					for i, item := range v.Content {
						field := fmt.Sprintf("docker.reloadContainers[%d]", i)
						s, ok, err := text(item, field)
						if err != nil {
							return err
						}
						if !ok || !containerName.MatchString(s) {
							return at(item, "%s: %q is not a container name", field, s)
						}
						cfg.Docker.ReloadContainers = append(cfg.Docker.ReloadContainers, s)
					}
					return nil
				},
				"signal": func(v *yaml.Node) error {
					s, ok, err := text(v, "docker.signal")
					if !ok {
						return err
					}
					if cfg.Docker.Signal, err = ReloadSignal(s); err != nil {
						return at(v, "docker.signal: %v", err)
					}
					return nil
				},
			})
		},
		"haproxy": func(v *yaml.Node) error {
			return section(v, "haproxy", map[string]func(*yaml.Node) error{
				"configs": func(v *yaml.Node) error {
					if isNull(v) {
						return nil
					}
					if v.Kind != yaml.SequenceNode {
						return at(v, "haproxy.configs must be a list of absolute paths")
					}
					for i, item := range v.Content {
						field := fmt.Sprintf("haproxy.configs[%d]", i)
						s, ok, err := text(item, field)
						if err != nil {
							return err
						}
						if !ok || !filepath.IsAbs(s) || hasControl(s) || filepath.Clean(s) == "/" {
							return at(item, "%s must be an absolute path to a file or directory other than /", field)
						}
						cfg.HAProxy.Configs = append(cfg.HAProxy.Configs, filepath.Clean(s))
					}
					return nil
				},
			})
		},
	})
	if err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// fields walks a mapping: each known key once, through its reader; an unknown key or one set twice is an error.
func fields(m *yaml.Node, prefix string, readers map[string]func(*yaml.Node) error) error {
	seen := map[string]bool{}
	for i := 0; i+1 < len(m.Content); i += 2 {
		key, value := m.Content[i], m.Content[i+1]
		name := prefix + key.Value
		read, known := readers[key.Value]
		if key.Kind != yaml.ScalarNode || !known {
			return at(key, "unknown field %q", name)
		}
		if seen[key.Value] {
			return at(key, "%q is set twice", name)
		}
		seen[key.Value] = true
		if err := read(value); err != nil {
			return err
		}
	}
	return nil
}

// section reads a nested mapping such as folder: or docker:; empty (null) is fine.
func section(v *yaml.Node, name string, readers map[string]func(*yaml.Node) error) error {
	if isNull(v) {
		return nil
	}
	if v.Kind != yaml.MappingNode {
		return at(v, "%s must be a mapping of fields", name)
	}
	return fields(v, name+".", readers)
}

// text reads a text value, trimmed: ok is false when it is null or blank (not set), and err says when it is not text.
func text(v *yaml.Node, field string) (s string, ok bool, err error) {
	if isNull(v) {
		return "", false, nil
	}
	if v.Kind != yaml.ScalarNode {
		return "", false, at(v, "%s must be text", field)
	}
	if v.Tag != "!!str" {
		return "", false, at(v, "%s must be text (put it in quotes)", field)
	}
	s = strings.TrimSpace(v.Value)
	return s, s != "", nil
}

func isNull(v *yaml.Node) bool { return v.Kind == yaml.ScalarNode && v.Tag == "!!null" }

func at(v *yaml.Node, format string, args ...any) error {
	return fmt.Errorf("line %d: %s", v.Line, fmt.Sprintf(format, args...))
}

// hasControl: C0 control characters (line breaks, tabs, NUL) and DEL.
func hasControl(s string) bool {
	return strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f })
}

// ServerOrigin checks a server address and returns its origin (scheme://host[:port], lowercase): https:// with a
// host, no user name or password, no path (a lone "/" is fine), query or fragment. http:// is accepted only for
// localhost, 127.0.0.1 and [::1], for testing on one machine.
func ServerOrigin(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	const want = "must be an origin such as " + DefaultServer
	switch {
	case raw == "":
		return "", errors.New("is empty; it " + want)
	case hasControl(raw):
		return "", errors.New("holds a control character; it " + want)
	case strings.ContainsAny(raw, "?#"):
		return "", errors.New(want + ", with no query or fragment")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Opaque != "" || u.Host == "" || strings.HasSuffix(u.Host, ":") {
		return "", errors.New(want)
	}
	if u.User != nil {
		return "", errors.New(want + ", with no user name or password")
	}
	if (u.Path != "" && u.Path != "/") || u.RawPath != "" {
		return "", errors.New(want + ", with no path")
	}
	host := strings.ToLower(u.Hostname())
	switch {
	case u.Scheme == "https":
	case u.Scheme == "http" && (host == "localhost" || host == "127.0.0.1" || host == "::1"):
	default:
		return "", errors.New("must use https:// (http:// only for localhost, 127.0.0.1 and [::1])")
	}
	if p := u.Port(); p != "" {
		if n, err := strconv.Atoi(p); err != nil || n < 1 || n > 65535 {
			return "", errors.New(want + ", with a port from 1 to 65535")
		}
	}
	return u.Scheme + "://" + strings.ToLower(u.Host), nil
}

// AgentName checks a name for the agent the way the server does: trimmed, at most 100 characters, no control
// characters. "" means none.
func AgentName(raw string) (string, error) {
	name := strings.TrimSpace(raw)
	if !utf8.ValidString(name) {
		return "", errors.New("is not valid UTF-8")
	}
	if strings.ContainsFunc(name, func(r rune) bool { return r < 0x20 || (r >= 0x7f && r <= 0x9f) }) {
		return "", errors.New("must not hold control characters")
	}
	if n := len(utf16.Encode([]rune(name))); n > maxNameLength {
		return "", fmt.Errorf("must be at most %d characters", maxNameLength)
	}
	return name, nil
}

// FolderRoot checks the directory folder certificates are written in (agent.yaml folder.root, NSL_FOLDER_ROOT) and
// returns it cleaned: an absolute path other than /, one line.
func FolderRoot(raw string) (string, error) {
	root := strings.TrimSpace(raw)
	if !filepath.IsAbs(root) || hasControl(root) || filepath.Clean(root) == "/" {
		return "", errors.New("must be an absolute path to a directory other than /")
	}
	return filepath.Clean(root), nil
}

// ReloadSignal checks the signal sent to the reload containers (agent.yaml docker.signal, NSL_RELOAD_SIGNAL): HUP,
// USR1 or USR2, in any case, with or without SIG; "" is HUP.
func ReloadSignal(raw string) (string, error) {
	signal := strings.ToUpper(strings.TrimSpace(raw))
	if signal == "" {
		return DefaultSignal, nil
	}
	if name := strings.TrimPrefix(signal, "SIG"); slices.Contains(reloadSignals, name) {
		return name, nil
	}
	return "", fmt.Errorf("%s is not a signal the agent sends: HUP, USR1 or USR2", signal)
}

// ContainerNames reads a comma-separated list of Docker container names or ids (NSL_RELOAD_CONTAINER; spaces and
// empty entries ignored, each named once); nil when none.
func ContainerNames(raw string) ([]string, error) {
	var list []string
	for _, part := range strings.Split(raw, ",") {
		name := strings.TrimSpace(part)
		if name == "" || slices.Contains(list, name) {
			continue
		}
		if !containerName.MatchString(name) {
			return nil, fmt.Errorf("%q is not a container name", name)
		}
		list = append(list, name)
	}
	return list, nil
}

// Namespaces reads a comma-separated list of Kubernetes namespaces (spaces and empty entries ignored, each named
// once); nil means every namespace.
func Namespaces(raw string) ([]string, error) {
	var list []string
	seen := map[string]bool{}
	for _, part := range strings.Split(raw, ",") {
		ns := strings.TrimSpace(part)
		if ns == "" || seen[ns] {
			continue
		}
		if !namespaceName.MatchString(ns) {
			return nil, fmt.Errorf("%q is not a Kubernetes namespace name (lowercase letters, digits and -, at most 63)", ns)
		}
		seen[ns] = true
		list = append(list, ns)
	}
	return list, nil
}
