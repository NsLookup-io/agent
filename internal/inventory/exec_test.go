package inventory

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nslookup-io/agent/internal/protocol"
)

// program writes an executable shell script named name into dir.
func program(t *testing.T, dir, name, script string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"+script), 0o755); err != nil {
		t.Fatal(err)
	}
}

func TestSystemRunnerRunsTheProgramWithItsOutputInOrder(t *testing.T) {
	dir := t.TempDir()
	program(t, dir, "nginx", `[ "$1" = "-T" ] || exit 9
echo "nginx: the configuration file /etc/nginx/nginx.conf syntax is ok" >&2
echo "# configuration file /etc/nginx/nginx.conf:"
echo "LC_ALL=$LC_ALL PATH=$PATH HOME=$HOME AGENT_SECRET=$AGENT_SECRET" >&2
`)
	// Nothing of the agent's own environment reaches a command: PATH and LC_ALL only.
	t.Setenv("AGENT_SECRET", "leaked")
	t.Setenv("HOME", "/root")
	out, err := SystemRunner{Dirs: []string{dir}}.Run(context.Background(), nginxDump)
	if err != nil {
		t.Fatal(err)
	}
	want := "nginx: the configuration file /etc/nginx/nginx.conf syntax is ok\n# configuration file /etc/nginx/nginx.conf:\n" +
		"LC_ALL=C PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin HOME= AGENT_SECRET=\n"
	if string(out) != want {
		t.Errorf("output %q, want %q", out, want)
	}
}

func TestSystemRunnerLooksInPathThenTheSbinDirectories(t *testing.T) {
	dir := t.TempDir()
	program(t, dir, "haproxy", "echo HAProxy version 2.8.5\n")
	t.Setenv("PATH", "relative/dir"+string(os.PathListSeparator)+dir)
	out, err := SystemRunner{}.Run(context.Background(), haproxyVersion)
	if err != nil || string(out) != "HAProxy version 2.8.5\n" {
		t.Errorf("%q, %v", out, err)
	}
	if got := (SystemRunner{}).dirs(); !strings.HasSuffix(strings.Join(got, ":"), dir+":/usr/sbin:/usr/local/sbin:/sbin") {
		t.Errorf("directories %q", got)
	}
}

func TestAProgramThatIsNotThereIsNotInstalled(t *testing.T) {
	dir := t.TempDir()
	// Not executable, a directory, or only in a relative directory: none counts.
	if err := os.WriteFile(filepath.Join(dir, "nginx"), []byte("#!/bin/sh\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "apachectl"), 0o755); err != nil {
		t.Fatal(err)
	}
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	relative, err := filepath.Rel(wd, dir)
	if err != nil {
		t.Fatal(err)
	}
	program(t, dir, "haproxy", "echo HAProxy\n")
	r := SystemRunner{Dirs: []string{dir, relative}}
	for _, c := range []Command{nginxVersion, apacheVersions[0], apacheVersions[2]} {
		if _, err := r.Run(context.Background(), c); !errors.Is(err, ErrNotInstalled) {
			t.Errorf("%s: %v", c, err)
		}
	}
	if _, err := (SystemRunner{Dirs: []string{relative}}).Run(context.Background(), haproxyVersion); !errors.Is(err, ErrNotInstalled) {
		t.Errorf("a relative directory: %v", err)
	}
	if _, err := r.Run(context.Background(), Command{}); err == nil || errors.Is(err, ErrNotInstalled) {
		t.Errorf("no command: %v", err)
	}
}

func TestSystemRunnerFailures(t *testing.T) {
	dir := t.TempDir()
	program(t, dir, "nginx", `echo "nginx: [emerg] unknown directive \"sll_certificate\" in /etc/nginx/sites-enabled/a:3" >&2
echo "nginx: configuration file /etc/nginx/nginx.conf test failed" >&2
exit 1
`)
	program(t, dir, "apachectl", "exec sleep 5\n")
	program(t, dir, "haproxy", "i=0; while [ $i -lt 2000 ]; do echo 0123456789abcdef0123456789abcdef; i=$((i+1)); done\n")
	r := SystemRunner{Dirs: []string{dir}, Timeout: 10 * time.Second, MaxOutput: 1000}

	out, err := r.Run(context.Background(), nginxDump)
	if err == nil || !strings.Contains(err.Error(), "nginx -T failed (exit status 1): nginx: [emerg] unknown directive") ||
		!strings.Contains(err.Error(), "; nginx: configuration file /etc/nginx/nginx.conf test failed") || len(out) == 0 {
		t.Errorf("exit 1: %q, %v", out, err)
	}
	if _, err := r.Run(context.Background(), haproxyVersion); err == nil || !strings.Contains(err.Error(), "more than 1000 bytes") {
		t.Errorf("too much output: %v", err)
	}
	start := time.Now()
	hang := SystemRunner{Dirs: []string{dir}, Timeout: 500 * time.Millisecond}
	if _, err := hang.Run(context.Background(), apacheVersions[0]); err == nil || !strings.Contains(err.Error(), "did not finish within 500ms") {
		t.Errorf("a program that hangs: %v", err)
	}
	if time.Since(start) > 4*time.Second {
		t.Errorf("it waited %s", time.Since(start))
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := r.Run(ctx, apacheVersions[0]); !errors.Is(err, context.Canceled) {
		t.Errorf("a cancelled run: %v", err)
	}
}

// recordingRunner answers every command it knows (by its text) and records what it was asked to run; every other program
// is not installed.
type recordingRunner struct {
	answers map[string]fakeRun
	ran     []string
}

func (r *recordingRunner) Run(_ context.Context, c Command) ([]byte, error) {
	r.ran = append(r.ran, c.String())
	a, ok := r.answers[c.String()]
	if !ok {
		return nil, fmt.Errorf("%s: %w", c.argv[0], ErrNotInstalled)
	}
	return []byte(a.out), a.err
}

func TestConfigurationTests(t *testing.T) {
	failed := errors.New("apachectl -t failed (exit status 1): AH00526: Syntax error")
	for name, c := range map[string]struct {
		kind    protocol.WebServerKind
		configs []string
		answers map[string]fakeRun
		ran     []string
		err     string
	}{
		"nginx": {kind: protocol.WebServerNginx, answers: map[string]fakeRun{"nginx -t": {}}, ran: []string{"nginx -t"}},
		// The first program installed decides: a failing test is not run again with the next one.
		"Apache fails": {kind: protocol.WebServerApache, answers: map[string]fakeRun{"apachectl -t": {err: failed}, "apache2ctl -t": {}},
			ran: []string{"apachectl -t"}, err: "AH00526"},
		"Apache on Debian": {kind: protocol.WebServerApache, answers: map[string]fakeRun{"apache2ctl -t": {}}, ran: []string{"apachectl -t", "apache2ctl -t"}},
		"Apache as httpd":  {kind: protocol.WebServerApache, answers: map[string]fakeRun{"httpd -t": {}}, ran: []string{"apachectl -t", "apache2ctl -t", "httpd -t"}},
		"HAProxy": {kind: protocol.WebServerHAProxy, configs: []string{"/etc/haproxy/haproxy.cfg", "/etc/haproxy/extra/edge.cfg"},
			answers: map[string]fakeRun{"haproxy -c -f /etc/haproxy/haproxy.cfg -f /etc/haproxy/extra/edge.cfg": {}},
			ran:     []string{"haproxy -c -f /etc/haproxy/haproxy.cfg -f /etc/haproxy/extra/edge.cfg"}},
		"HAProxy without its files": {kind: protocol.WebServerHAProxy, err: "no HAProxy configuration file"},
		"HAProxy with a path that is no file of the inventory": {kind: protocol.WebServerHAProxy, configs: []string{"-d"},
			err: "not a configuration file"},
		"not installed": {kind: protocol.WebServerNginx, ran: []string{"nginx -t"}, err: "nginx: not installed"},
	} {
		r := &recordingRunner{answers: c.answers}
		err := ConfigTest(context.Background(), r, c.kind, c.configs)
		if c.err == "" && err != nil || c.err != "" && (err == nil || !strings.Contains(err.Error(), c.err)) {
			t.Errorf("%s: %v", name, err)
		}
		if strings.Join(r.ran, "|") != strings.Join(c.ran, "|") {
			t.Errorf("%s: ran %q, want %q", name, r.ran, c.ran)
		}
	}
}

func TestReloads(t *testing.T) {
	active := fakeRun{out: "active\n"}
	inactive := fakeRun{out: "inactive\n", err: errors.New("exit status 3")}
	for name, c := range map[string]struct {
		kind    protocol.WebServerKind
		answers map[string]fakeRun
		ran     []string
		err     string
	}{
		"nginx under systemd": {kind: protocol.WebServerNginx,
			answers: map[string]fakeRun{"systemctl is-active nginx": active, "systemctl reload nginx": {}},
			ran:     []string{"systemctl is-active nginx", "systemctl reload nginx"}},
		"nginx on its own": {kind: protocol.WebServerNginx,
			answers: map[string]fakeRun{"systemctl is-active nginx": inactive, "nginx -s reload": {}},
			ran:     []string{"systemctl is-active nginx", "nginx -s reload"}},
		"no systemd": {kind: protocol.WebServerNginx, answers: map[string]fakeRun{"nginx -s reload": {}},
			ran: []string{"systemctl is-active nginx", "nginx -s reload"}},
		"Apache as httpd": {kind: protocol.WebServerApache,
			answers: map[string]fakeRun{"systemctl is-active apache2": inactive, "systemctl is-active httpd": active, "systemctl reload httpd": {}},
			ran:     []string{"systemctl is-active apache2", "systemctl is-active httpd", "systemctl reload httpd"}},
		"Apache on its own": {kind: protocol.WebServerApache,
			answers: map[string]fakeRun{"systemctl is-active apache2": inactive, "systemctl is-active httpd": inactive, "apache2ctl -k graceful": {}},
			ran:     []string{"systemctl is-active apache2", "systemctl is-active httpd", "apachectl -k graceful", "apache2ctl -k graceful"}},
		"a failed reload": {kind: protocol.WebServerHAProxy,
			answers: map[string]fakeRun{"systemctl is-active haproxy": active, "systemctl reload haproxy": {err: errors.New("Job for haproxy.service failed")}},
			ran:     []string{"systemctl is-active haproxy", "systemctl reload haproxy"}, err: "Job for haproxy.service failed"},
		"HAProxy without systemd": {kind: protocol.WebServerHAProxy, answers: map[string]fakeRun{"systemctl is-active haproxy": inactive},
			ran: []string{"systemctl is-active haproxy"}, err: "only through systemd"},
	} {
		r := &recordingRunner{answers: c.answers}
		err := Reload(context.Background(), r, c.kind)
		if c.err == "" && err != nil || c.err != "" && (err == nil || !strings.Contains(err.Error(), c.err)) {
			t.Errorf("%s: %v", name, err)
		}
		if strings.Join(r.ran, "|") != strings.Join(c.ran, "|") {
			t.Errorf("%s: ran %q, want %q", name, r.ran, c.ran)
		}
	}
}

// The folder hook is agent.yaml's folder.hook run with /bin/sh: the minimal environment plus the folder and the name,
// shown as "the folder hook" (never its text), and 60 s at most.
func TestTheFolderHook(t *testing.T) {
	t.Setenv("AGENT_SECRET", "leaked")
	t.Setenv("HOME", "/root")
	hook := FolderHook(`printf '%s|%s|%s|%s|%s|%s' "$NSL_FOLDER" "$NSL_CERTIFICATE" "$PATH" "$LC_ALL" "$HOME" "$AGENT_SECRET"; echo; echo "said on stderr" >&2`,
		"/etc/ssl/nslookup/mail.example", "mail.example")
	if hook.String() != "the folder hook" || hook.timeout != time.Minute {
		t.Errorf("%q, %s", hook, hook.timeout)
	}
	// Found by its absolute path, whatever the directories searched.
	out, err := SystemRunner{Dirs: []string{}}.Run(context.Background(), hook)
	want := "/etc/ssl/nslookup/mail.example|mail.example|/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin|C||\nsaid on stderr\n"
	if err != nil || string(out) != want {
		t.Errorf("%q, %v; want %q", out, err, want)
	}

	failing := FolderHook(`echo "postfix/postfix-script: fatal: the Postfix mail system is not running" >&2; exit 1`, "/x", "x")
	if _, err := (SystemRunner{}).Run(context.Background(), failing); err == nil ||
		err.Error() != "the folder hook failed (exit status 1): postfix/postfix-script: fatal: the Postfix mail system is not running" {
		t.Errorf("a failing hook: %v", err)
	}
	// The runner's own limit, when set, counts first (so a test need not wait a minute).
	hang := FolderHook("exec sleep 5", "/x", "x")
	if _, err := (SystemRunner{Timeout: 300 * time.Millisecond}).Run(context.Background(), hang); err == nil ||
		err.Error() != "the folder hook did not finish within 300ms" {
		t.Errorf("a hook that hangs: %v", err)
	}
}
