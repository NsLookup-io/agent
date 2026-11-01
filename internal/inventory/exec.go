package inventory

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/nslookup-io/agent/internal/protocol"
)

// Command is one command of the agent's allowlist. Its fields are this package's own: nothing outside it (and nothing
// the server sends) can make one, so the agent runs these commands and no other.
type Command struct {
	argv []string
	// env is added to the minimal environment; timeout replaces the runner's 30 s; label is how the command shows
	// (in errors too) instead of its arguments.
	env     []string
	timeout time.Duration
	label   string
}

func (c Command) String() string {
	if c.label != "" {
		return c.label
	}
	return strings.Join(c.argv, " ")
}

const folderHookTimeout = time.Minute

// FolderHook is the command agent.yaml's folder.hook names, run with /bin/sh -c after a folder certificate is written:
// the minimal environment plus NSL_FOLDER (the folder's absolute path) and NSL_CERTIFICATE (its name), at most a
// minute. It is the one command not written here: it comes from the agent's local configuration file (which only root
// or the agent's user can change), never from the server. It shows as "the folder hook", never its text.
func FolderHook(hook, folder, certificate string) Command {
	return Command{
		argv:    []string{"/bin/sh", "-c", hook},
		env:     []string{"NSL_FOLDER=" + folder, "NSL_CERTIFICATE=" + certificate},
		timeout: folderHookTimeout,
		label:   "the folder hook",
	}
}

// The allowlist. The commands that read print and change nothing; installing a certificate also tests a web server's
// configuration and reloads it (ConfigTest, Reload).
var (
	// nginxDump tests nginx's configuration and prints every file of it.
	nginxDump    = Command{argv: []string{"nginx", "-T"}}
	nginxVersion = Command{argv: []string{"nginx", "-v"}}
	// apacheDumps print Apache's virtual hosts (DUMP_VHOSTS) and its ServerRoot (DUMP_RUN_CFG), which relative paths
	// are relative to: apachectl, Debian's apache2ctl, then the httpd binary itself (-S is the same two dumps).
	apacheDumps = []Command{
		{argv: []string{"apachectl", "-t", "-D", "DUMP_VHOSTS", "-D", "DUMP_RUN_CFG"}},
		{argv: []string{"apache2ctl", "-t", "-D", "DUMP_VHOSTS", "-D", "DUMP_RUN_CFG"}},
		{argv: []string{"httpd", "-S"}},
	}
	apacheVersions = []Command{
		{argv: []string{"apachectl", "-v"}},
		{argv: []string{"apache2ctl", "-v"}},
		{argv: []string{"httpd", "-v"}},
	}
	haproxyVersion = Command{argv: []string{"haproxy", "-v"}}

	nginxTest   = Command{argv: []string{"nginx", "-t"}}
	nginxReload = Command{argv: []string{"nginx", "-s", "reload"}}
	// apacheTests and apacheReloads: apachectl, Debian's apache2ctl, then the httpd binary itself.
	apacheTests = []Command{
		{argv: []string{"apachectl", "-t"}},
		{argv: []string{"apache2ctl", "-t"}},
		{argv: []string{"httpd", "-t"}},
	}
	apacheReloads = []Command{
		{argv: []string{"apachectl", "-k", "graceful"}},
		{argv: []string{"apache2ctl", "-k", "graceful"}},
		{argv: []string{"httpd", "-k", "graceful"}},
	}
	// systemdUnits are the units each web server may run as, in the order looked at: systemctl is-active and
	// systemctl reload are run for these units only.
	systemdUnits = map[protocol.WebServerKind][]string{
		protocol.WebServerNginx:   {"nginx"},
		protocol.WebServerApache:  {"apache2", "httpd"},
		protocol.WebServerHAProxy: {"haproxy"},
	}
)

// ErrNotInstalled is a command whose program is not on this machine: its web server is not installed.
var ErrNotInstalled = errors.New("not installed")

// Runner runs a command of the allowlist and returns what it printed, standard output and standard error together in
// the order printed. A program that is not there is ErrNotInstalled; a program that fails is an error, with what it
// printed.
type Runner interface {
	Run(ctx context.Context, c Command) ([]byte, error)
}

const (
	defaultTimeout   = 30 * time.Second
	defaultMaxOutput = 16 << 20
	// commandPath is the PATH every command runs with: the agent's own environment never reaches a command.
	commandPath = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
)

// sbinDirs are searched after $PATH: a service's PATH may lack them, and the web servers live there.
var sbinDirs = []string{"/usr/sbin", "/usr/local/sbin", "/sbin"}

// SystemRunner runs commands on this machine: no shell, the program looked up in the absolute directories of $PATH and
// then /usr/sbin, /usr/local/sbin and /sbin (a program named by its absolute path is that file), an environment of
// PATH (the standard directories) and LC_ALL=C only (plus what the command adds), at most 30 s each (unless the
// command has its own limit), at most 16 MB of output.
type SystemRunner struct {
	// Dirs replaces the directories searched; nil = $PATH, then the sbin directories.
	Dirs []string
	// Timeout: 0 = the command's own limit, else 30 s.
	Timeout time.Duration
	// MaxOutput in bytes: 0 = 16 MB; a program printing more fails.
	MaxOutput int
}

func (r SystemRunner) Run(ctx context.Context, c Command) ([]byte, error) {
	if len(c.argv) == 0 {
		return nil, errors.New("no command")
	}
	program, err := r.lookPath(c.argv[0])
	if err != nil {
		return nil, err
	}
	timeout := cmp.Or(r.Timeout, c.timeout, defaultTimeout)
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(runCtx, program, c.argv[1:]...)
	out := &cappedBuffer{max: cmp.Or(r.MaxOutput, defaultMaxOutput)}
	// One writer for both: one pipe, so the lines keep their order.
	cmd.Stdout, cmd.Stderr = out, out
	cmd.Env = append([]string{"PATH=" + commandPath, "LC_ALL=C"}, c.env...)
	// A child that keeps the pipe open (a script's background process) cannot hold the run past its time.
	cmd.WaitDelay = time.Second
	err = cmd.Run()
	switch {
	case ctx.Err() != nil:
		return nil, ctx.Err()
	case runCtx.Err() != nil:
		return nil, fmt.Errorf("%s did not finish within %s", c, timeout)
	case out.over:
		return nil, fmt.Errorf("%s printed more than %d bytes", c, out.max)
	case err != nil:
		return out.buf.Bytes(), fmt.Errorf("%s failed (%v): %s", c, err, lastLines(out.buf.Bytes()))
	}
	return out.buf.Bytes(), nil
}

func (r SystemRunner) dirs() []string {
	if r.Dirs != nil {
		return r.Dirs
	}
	return append(filepath.SplitList(os.Getenv("PATH")), sbinDirs...)
}

// lookPath finds name in the absolute directories searched (a relative one, such as ".", never counts), or is name when
// it is an absolute path: a regular file someone may execute.
func (r SystemRunner) lookPath(name string) (string, error) {
	executable := func(p string) bool {
		info, err := os.Stat(p)
		return err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0o111 != 0
	}
	if filepath.IsAbs(name) {
		if executable(name) {
			return name, nil
		}
		return "", fmt.Errorf("%s: %w", name, ErrNotInstalled)
	}
	for _, dir := range r.dirs() {
		if !filepath.IsAbs(dir) {
			continue
		}
		if p := filepath.Join(dir, name); executable(p) {
			return p, nil
		}
	}
	return "", fmt.Errorf("%s: %w", name, ErrNotInstalled)
}

// cappedBuffer keeps what a program prints up to max bytes; past that it refuses the write, which ends the program's
// output (its pipe is closed).
type cappedBuffer struct {
	buf  bytes.Buffer
	max  int
	over bool
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	if b.buf.Len()+len(p) > b.max {
		b.over = true
		return 0, errors.New("too much output")
	}
	return b.buf.Write(p)
}

// lastLines are the last three lines printed that are not blank, at most 500 characters: what a failing tool says
// last (nginx and Apache name the error, then that the test failed).
func lastLines(out []byte) string {
	var lines []string
	for _, line := range strings.Split(string(out), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			lines = append(lines, line)
		}
	}
	text := strings.Join(lines[max(0, len(lines)-3):], "; ")
	if utf8.RuneCountInString(text) > 500 {
		text = string([]rune(text)[:500]) + "…"
	}
	return cmp.Or(text, "nothing printed")
}

// ConfigTest tests kind's configuration: nginx -t, apachectl -t (or apache2ctl -t, or httpd -t), or haproxy -c with
// haproxyConfigs, the configuration files the inventory read (absolute paths). The error says what the tool printed.
func ConfigTest(ctx context.Context, runner Runner, kind protocol.WebServerKind, haproxyConfigs []string) error {
	switch kind {
	case protocol.WebServerNginx:
		return runFirst(ctx, runner, []Command{nginxTest}, "nginx")
	case protocol.WebServerApache:
		return runFirst(ctx, runner, apacheTests, "Apache")
	case protocol.WebServerHAProxy:
		if len(haproxyConfigs) == 0 {
			return errors.New("no HAProxy configuration file is known to test")
		}
		argv := []string{"haproxy", "-c"}
		for _, f := range haproxyConfigs {
			if !path.IsAbs(f) || path.Clean(f) != f || hasControl(f) {
				return fmt.Errorf("%q is not a configuration file the agent read", f)
			}
			argv = append(argv, "-f", f)
		}
		return runFirst(ctx, runner, []Command{{argv: argv}}, "HAProxy")
	}
	return fmt.Errorf("the agent cannot test the configuration of %q", kind)
}

// Reload makes kind load its certificates again: systemctl reload <unit> when its unit is active (nginx; apache2 or
// httpd; haproxy), else its own reload (nginx -s reload; apachectl -k graceful, or apache2ctl, or httpd). HAProxy is
// reloaded through systemd only.
func Reload(ctx context.Context, runner Runner, kind protocol.WebServerKind) error {
	units, known := systemdUnits[kind]
	if !known {
		return fmt.Errorf("the agent cannot reload %q", kind)
	}
	for _, unit := range units {
		// systemctl is-active exits 0 only when the unit is active; no systemctl at all is no unit active.
		if _, err := runner.Run(ctx, Command{argv: []string{"systemctl", "is-active", unit}}); err == nil {
			_, err = runner.Run(ctx, Command{argv: []string{"systemctl", "reload", unit}})
			return err
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}
	switch kind {
	case protocol.WebServerNginx:
		return runFirst(ctx, runner, []Command{nginxReload}, "nginx")
	case protocol.WebServerApache:
		return runFirst(ctx, runner, apacheReloads, "Apache")
	}
	return errors.New("HAProxy is not running as the systemd unit haproxy, and the agent reloads HAProxy only through systemd")
}

// runFirst runs the first of the commands that is installed: its answer decides (a failing test is not run again
// with the next program).
func runFirst(ctx context.Context, runner Runner, commands []Command, what string) error {
	for _, c := range commands {
		_, err := runner.Run(ctx, c)
		if !errors.Is(err, ErrNotInstalled) {
			return err
		}
	}
	return fmt.Errorf("%s: %w", what, ErrNotInstalled)
}

// firstInstalled runs the commands in order and returns the first answer of one that is installed and does not fail;
// installed says whether any of them was installed, err is the last failure when none answered.
func firstInstalled(ctx context.Context, runner Runner, commands []Command, ok func([]byte) bool) (out []byte, installed bool, err error) {
	for _, c := range commands {
		printed, runErr := runner.Run(ctx, c)
		if errors.Is(runErr, ErrNotInstalled) {
			continue
		}
		installed = true
		if runErr == nil && !ok(printed) {
			runErr = fmt.Errorf("%s printed nothing usable", c)
		}
		if runErr == nil {
			return printed, true, nil
		}
		err = runErr
	}
	return nil, installed, err
}
