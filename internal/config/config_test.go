package config

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestParseAFullFile(t *testing.T) {
	cfg, err := Parse([]byte(`
# nslookup.io agent
server: https://agents.example.test
name: "web-1 — front"
folder:
  root: /etc/ssl/nslookup/
  hook: systemctl reload postfix
docker:
  reloadContainers: [nginx, mail.relay_1]
  signal: usr1
haproxy:
  configs: [/etc/haproxy/conf.d/, /opt/edge/haproxy.cfg]
`))
	if err != nil {
		t.Fatal(err)
	}
	want := Config{
		Server:  "https://agents.example.test",
		Name:    "web-1 — front",
		Folder:  Folder{Root: "/etc/ssl/nslookup", Hook: "systemctl reload postfix"},
		Docker:  Docker{ReloadContainers: []string{"nginx", "mail.relay_1"}, Signal: "USR1"},
		HAProxy: HAProxy{Configs: []string{"/etc/haproxy/conf.d", "/opt/edge/haproxy.cfg"}},
	}
	if !reflect.DeepEqual(cfg, want) {
		t.Errorf("got %+v\nwant %+v", cfg, want)
	}
}

func TestDefaults(t *testing.T) {
	for name, text := range map[string]string{
		"an empty file":       "",
		"only a comment":      "# nothing set\n",
		"empty sections":      "folder:\ndocker:\nhaproxy:\n",
		"null values":         "server: ~\nname:\nfolder:\n  root: null\ndocker:\n  signal:\n",
		"an empty mapping":    "{}",
		"a document start":    "---\n",
		"a blank server line": "server: ''\n",
	} {
		cfg, err := Parse([]byte(text))
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if !reflect.DeepEqual(cfg, Default()) {
			t.Errorf("%s: %+v, want the defaults %+v", name, cfg, Default())
		}
	}
	if Default().Docker.Signal != "HUP" || Default().Server != "" {
		t.Errorf("defaults %+v", Default())
	}
}

func TestParseErrorsNameTheField(t *testing.T) {
	cases := []struct {
		name, text, want string
	}{
		{"an unknown field", "servr: https://agents.example.test\n", `line 1: unknown field "servr"`},
		{"an unknown folder field", "folder:\n  rooot: /srv\n", `line 2: unknown field "folder.rooot"`},
		{"an unknown docker field", "docker:\n  reload: [nginx]\n", `line 2: unknown field "docker.reload"`},
		{"a server that is not https", "server: http://agents.example.test\n", "line 1: server: "},
		{"a server with a path", "server: https://agents.example.test/agent/v1\n", "line 1: server: "},
		{"a server that is a list", "server: [a]\n", "line 1: server must be text"},
		{"a name with a line break", "name: \"web\\n1\"\n", "line 1: name: "},
		{"a name of 101 characters", "name: " + strings.Repeat("a", 101) + "\n", "line 1: name: "},
		{"a name that is a number", "name: 12\n", "line 1: name must be text"},
		{"folder that is text", "folder: /srv\n", "line 1: folder must be a mapping"},
		{"a relative folder.root", "folder:\n  root: certs\n", "line 2: folder.root must be an absolute path"},
		{"folder.root /", "folder:\n  root: /\n", "line 2: folder.root must be an absolute path"},
		{"a two-line folder.hook", "folder:\n  hook: |\n    a\n    b\n", "line 2: folder.hook must be one line"},
		{"reloadContainers as text", "docker:\n  reloadContainers: nginx\n", "line 2: docker.reloadContainers must be a list"},
		{"a container name with a slash", "docker:\n  reloadContainers: [nginx, ../x]\n", "line 2: docker.reloadContainers[1]"},
		{"a container name that is a list", "docker:\n  reloadContainers: [[a]]\n", "line 2: docker.reloadContainers[0] must be text"},
		{"a signal with a space", "docker:\n  signal: HUP now\n", "line 2: docker.signal"},
		{"a signal that does not reload", "docker:\n  signal: KILL\n", "line 2: docker.signal: KILL is not a signal the agent sends: HUP, USR1 or USR2"},
		{"a signal number", "docker:\n  signal: '9'\n", "line 2: docker.signal: 9 is not a signal the agent sends"},
		{"an unknown haproxy field", "haproxy:\n  config: /etc/haproxy/a.cfg\n", `line 2: unknown field "haproxy.config"`},
		{"haproxy.configs as text", "haproxy:\n  configs: /etc/haproxy/a.cfg\n", "line 2: haproxy.configs must be a list"},
		{"a relative haproxy config", "haproxy:\n  configs: [/etc/a.cfg, a.cfg]\n", "line 2: haproxy.configs[1] must be an absolute path"},
		{"/ as an haproxy config", "haproxy:\n  configs: [/]\n", "line 2: haproxy.configs[0] must be an absolute path"},
		{"an empty haproxy config", "haproxy:\n  configs: ['']\n", "line 2: haproxy.configs[0] must be an absolute path"},
		{"a field set twice", "name: a\nname: b\n", `line 2: "name" is set twice`},
		{"a list at the top", "- server\n", "line 1: the file must be a mapping"},
		{"broken YAML", "server: [\n", "not valid YAML"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg, err := Parse([]byte(c.text))
			if err == nil {
				t.Fatalf("parsed %+v", cfg)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("error %q does not contain %q", err, c.want)
			}
		})
	}
}

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.yaml")
	if err := os.WriteFile(path, []byte("name: web-1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil || cfg.Name != "web-1" || cfg.Docker.Signal != "HUP" {
		t.Fatalf("got %+v, %v", cfg, err)
	}

	if _, err := Load(filepath.Join(dir, "missing.yaml")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("a missing file: %v, want fs.ErrNotExist", err)
	}

	if err := os.WriteFile(path, []byte("folder:\n  root: certs\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), path+": line 2: folder.root") {
		t.Errorf("an error names the file, the line and the field: %v", err)
	}

	// It names the commands the agent runs, so only its owner may change it.
	for _, mode := range []os.FileMode{0o666, 0o664, 0o646} {
		if err := os.WriteFile(path, []byte("name: web-1\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "other users") {
			t.Errorf("mode %04o: %v, want a refusal", mode, err)
		}
	}
}

// agent.yaml names the command the agent runs after writing a folder certificate and the folder it writes in: the
// file and its directory must be the agent's user's or root's, and only theirs to change.
func TestLoadRefusesAFileOrDirectoryOthersCanChange(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.yaml")
	if err := os.WriteFile(path, []byte("folder:\n  hook: systemctl reload postfix\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := load(path, os.Getuid()); err != nil {
		t.Fatalf("the agent's own file: %v", err)
	}
	if os.Getuid() != 0 {
		// Owned by the test's user, read by an agent running as another user (not root).
		if _, err := load(path, os.Getuid()+1); err == nil || !strings.Contains(err.Error(), "belongs to user") || !strings.Contains(err.Error(), "chown root "+path) {
			t.Errorf("another user's file: %v", err)
		}
	}

	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := load(path, os.Getuid()); err == nil || !strings.Contains(err.Error(), dir+", the directory of "+path+", can be changed by other users") {
		t.Errorf("a directory others can change: %v", err)
	}
	if err := os.Chmod(dir, 0o1777); err != nil {
		t.Fatal(err)
	}
	if _, err := load(path, os.Getuid()); err == nil || !strings.Contains(err.Error(), "can be changed by other users") {
		t.Errorf("a sticky directory others can write in: %v", err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}

	// Through a link, the directory the file really is in counts too.
	linked := filepath.Join(t.TempDir(), "agent.yaml")
	if err := os.Symlink(path, linked); err != nil {
		t.Fatal(err)
	}
	if _, err := load(linked, os.Getuid()); err != nil {
		t.Errorf("a link: %v", err)
	}
	if err := os.Chmod(dir, 0o775); err != nil {
		t.Fatal(err)
	}
	real, err := filepath.EvalSymlinks(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := load(linked, os.Getuid()); err == nil || !strings.Contains(err.Error(), filepath.Dir(real)+", the directory of "+real) {
		t.Errorf("a link into a directory others can change: %v", err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
}

func TestReloadSignal(t *testing.T) {
	for raw, want := range map[string]string{"HUP": "HUP", " usr1 ": "USR1", "SIGUSR2": "USR2", "sighup": "HUP", "": "HUP"} {
		if got, err := ReloadSignal(raw); got != want || err != nil {
			t.Errorf("%q: %q, %v", raw, got, err)
		}
	}
	for _, raw := range []string{"KILL", "TERM", "SIGKILL", "9", "HUP USR1"} {
		if got, err := ReloadSignal(raw); err == nil {
			t.Errorf("%q: %q", raw, got)
		}
	}
}

func TestContainerNames(t *testing.T) {
	got, err := ContainerNames(" nginx, mail.relay_1,,nginx , 3f2b8c1e7a4d ")
	if err != nil || !reflect.DeepEqual(got, []string{"nginx", "mail.relay_1", "3f2b8c1e7a4d"}) {
		t.Errorf("%q, %v", got, err)
	}
	for _, raw := range []string{"../images", "nginx;rm", "-nginx", strings.Repeat("a", 129)} {
		if got, err := ContainerNames(raw); err == nil {
			t.Errorf("%q: %q", raw, got)
		}
	}
	if got, err := ContainerNames(" , "); got != nil || err != nil {
		t.Errorf("none: %q, %v", got, err)
	}
}

func TestFolderRoot(t *testing.T) {
	if got, err := FolderRoot(" /srv/certs/ "); got != "/srv/certs" || err != nil {
		t.Errorf("%q, %v", got, err)
	}
	for _, raw := range []string{"certs", "/", "//", "/srv/\ncerts", ""} {
		if got, err := FolderRoot(raw); err == nil {
			t.Errorf("%q: %q", raw, got)
		}
	}
}

func TestServerOrigin(t *testing.T) {
	good := map[string]string{
		"https://agents.nslookup.io":         "https://agents.nslookup.io",
		"https://agents.example.test/":       "https://agents.example.test",
		"  https://agents.example.test  ":    "https://agents.example.test",
		"HTTPS://Agents.Example.Test":        "https://agents.example.test",
		"https://agents.example.test:8443":   "https://agents.example.test:8443",
		"http://localhost:3020":              "http://localhost:3020",
		"http://127.0.0.1:3020":              "http://127.0.0.1:3020",
		"http://[::1]:3020":                  "http://[::1]:3020",
		"https://[2001:db8::1]":              "https://[2001:db8::1]",
		"https://192.0.2.10":                 "https://192.0.2.10",
		"http://LOCALHOST":                   "http://localhost",
		"https://xn--bcher-kva.example.test": "https://xn--bcher-kva.example.test",
	}
	for raw, want := range good {
		got, err := ServerOrigin(raw)
		if err != nil || got != want {
			t.Errorf("ServerOrigin(%q) = %q, %v; want %q", raw, got, err, want)
		}
	}
	for _, raw := range []string{
		"",
		"agents.example.test",
		"http://agents.example.test",
		"http://10.0.0.1",
		"http://localhost.example.test",
		"ftp://agents.example.test",
		"https://agents.example.test/agent/v1",
		"https://agents.example.test//",
		"https://agents.example.test?x=1",
		"https://agents.example.test?",
		"https://agents.example.test#top",
		"https://user:pass@agents.example.test",
		"https://user@agents.example.test",
		"https://",
		"https:agents.example.test",
		"https://agents.example.test:0",
		"https://agents.example.test:99999",
		"https://agents.example.test:",
		"https://agents.exam\nple.test",
		"https://agents.example.test\x7f",
		"https://agents example.test",
		"//agents.example.test",
	} {
		if got, err := ServerOrigin(raw); err == nil {
			t.Errorf("ServerOrigin(%q) = %q, want an error", raw, got)
		}
	}
	if _, err := ServerOrigin("http://agents.example.test"); err == nil || !strings.Contains(err.Error(), "https://") {
		t.Errorf("the refusal says what is allowed: %v", err)
	}
}

func TestAgentName(t *testing.T) {
	for raw, want := range map[string]string{
		"web-1":                        "web-1",
		"  web-1  ":                    "web-1",
		"-rf":                          "-rf",
		"":                             "",
		"   ":                          "",
		"web 1 — front":                "web 1 — front",
		strings.Repeat("é", 100):       strings.Repeat("é", 100),
		strings.Repeat("a", 100) + " ": strings.Repeat("a", 100),
	} {
		got, err := AgentName(raw)
		if err != nil || got != want {
			t.Errorf("AgentName(%q) = %q, %v; want %q", raw, got, err, want)
		}
	}
	for _, raw := range []string{strings.Repeat("a", 101), "web\n1", "web\t1", "a\x7fb", "a\u0085b", "\xff", strings.Repeat("😀", 51)} {
		if got, err := AgentName(raw); err == nil {
			t.Errorf("AgentName(%q) = %q, want an error", raw, got)
		}
	}
}

func TestNamespaces(t *testing.T) {
	for raw, want := range map[string][]string{
		"":                      nil,
		" , ":                   nil,
		"web":                   {"web"},
		"web, shop ,web,,a-1":   {"web", "shop", "a-1"},
		strings.Repeat("a", 63): {strings.Repeat("a", 63)},
	} {
		got, err := Namespaces(raw)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Errorf("Namespaces(%q) = %q, %v; want %q", raw, got, err, want)
		}
	}
	for _, raw := range []string{"Web", "web_1", "-web", "web-", "web.shop", strings.Repeat("a", 64), "web shop", "a,../b"} {
		if got, err := Namespaces(raw); err == nil {
			t.Errorf("Namespaces(%q) = %q, want an error", raw, got)
		}
	}
}
