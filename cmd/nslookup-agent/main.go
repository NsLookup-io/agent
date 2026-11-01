// Command nslookup-agent is the nslookup.io agent: it joins nslookup.io once with a join code from the portal, then
// runs, reporting the sites on this machine and installing the certificates nslookup.io Certificate Autopilot renews
// for them.
package main

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"syscall"

	"k8s.io/client-go/kubernetes"

	"github.com/nslookup-io/agent/internal/agent"
	"github.com/nslookup-io/agent/internal/client"
	"github.com/nslookup-io/agent/internal/config"
	"github.com/nslookup-io/agent/internal/identity"
	"github.com/nslookup-io/agent/internal/install"
	"github.com/nslookup-io/agent/internal/inventory"
	"github.com/nslookup-io/agent/internal/kube"
	"github.com/nslookup-io/agent/internal/protocol"
	"github.com/nslookup-io/agent/internal/state"
	"github.com/nslookup-io/agent/internal/version"
)

// defaultStateDir holds what the agent keeps between runs: its identity (identity/; in Kubernetes a Secret instead),
// what it installed (installed.json), the files it replaced (previous/), its take-overs from certbot (certbot/) and an
// install under way (pending.json).
const defaultStateDir = "/var/lib/nslookup-agent"

// defaultDockerFolder is where a Docker agent writes folder certificates: the folder mounted into its container.
const defaultDockerFolder = "/certs"

const usage = `Usage:
  nslookup-agent join <code> [flags]   join nslookup.io with a join code from the portal (once)
  nslookup-agent run [flags]           run: heartbeats, the sites on this machine, installs
  nslookup-agent inventory [flags]     print what this agent reports about this machine
  nslookup-agent version               print the agent's version

Flags:
  --server <url>       the nslookup.io server, an https:// origin (default ` + config.DefaultServer + `;
                       environment NSL_SERVER; http:// only for localhost, to test on one machine)
  --config <path>      the configuration file (default ` + config.DefaultPath + `)
  --mode <mode>        host, docker or kubernetes (environment NSL_MODE, which the Docker image sets
                       to docker; default host)
  --name <name>        the agent's name in the portal (environment NSL_NAME; default: the name given
                       with the join code, else the host name)
  --namespaces <list>  kubernetes mode: the namespaces whose Ingresses it reads and whose TLS secrets it
                       may write, comma-separated (environment NSL_NAMESPACES; default: every namespace)
  --join <code>        run only: join first when this agent has not joined yet (environment NSL_JOIN)

Every flag takes its value as --flag=value or as --flag value; either way a value that starts with a dash is
the value, as in --name=-web. A flag counts before its environment variable, and both before agent.yaml.
join takes the code from NSL_JOIN when none is given.

Kubernetes mode connects with the pod's service account (outside the cluster: KUBECONFIG) and keeps its
identity in the Secret ` + kube.IdentitySecret + ` of its own namespace (POD_NAMESPACE).

Docker mode also reads, before agent.yaml's folder.root, docker.reloadContainers and docker.signal:
  NSL_FOLDER_ROOT       the folder certificates are written in (default ` + defaultDockerFolder + `)
  NSL_RELOAD_CONTAINER  the containers signalled after a certificate is written, comma-separated
                        (through ` + install.DockerSocket + `, when it is mounted)
  NSL_RELOAD_SIGNAL     HUP, USR1 or USR2 (default HUP)
`

// cli is one run of the command, with what it reads from its surroundings.
type cli struct {
	getenv         func(string) string
	stdout, stderr io.Writer
	stateDir       string
	// configPath is where agent.yaml is read from when --config is not given (a missing file is fine there).
	configPath string
	// runner runs the web servers' own commands and root is this machine's file system: what a host agent reads.
	// rootDir is the same file system's directory, where an agent installs; root or dirOwner (the agent's own user)
	// must own every directory it writes in. dockerSocket is the Docker socket a Docker agent signals containers
	// through.
	runner       inventory.Runner
	root         fs.FS
	rootDir      string
	dirOwner     int
	dockerSocket string
	// kube connects a Kubernetes agent to its cluster: the client and the agent's own namespace.
	kube func() (kubernetes.Interface, string, error)
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	c := &cli{
		getenv: os.Getenv, stdout: os.Stdout, stderr: os.Stderr, stateDir: defaultStateDir, configPath: config.DefaultPath,
		runner: inventory.SystemRunner{}, root: inventory.HostFS("/"), rootDir: "/", dirOwner: os.Geteuid(), dockerSocket: install.DockerSocket,
		kube: func() (kubernetes.Interface, string, error) { return kube.Connect(os.Getenv) },
	}
	code := c.main(ctx, os.Args[1:])
	stop()
	os.Exit(code)
}

// Exit codes.
const (
	exitOK    = 0
	exitError = 1
	exitUsage = 2
)

func (c *cli) main(ctx context.Context, args []string) int {
	if len(args) == 0 {
		fmt.Fprint(c.stderr, usage)
		return exitUsage
	}
	switch cmd := args[0]; cmd {
	case "join":
		return c.join(ctx, args[1:])
	case "run":
		return c.run(ctx, args[1:])
	case "inventory":
		return c.inventory(ctx, args[1:])
	case "version":
		fmt.Fprintf(c.stdout, "nslookup-agent %s\n", version.Version)
		return exitOK
	case "help", "-h", "-help", "--help":
		fmt.Fprint(c.stdout, usage)
		return exitOK
	default:
		return c.usageError(fmt.Errorf("unknown command %q", cmd))
	}
}

func (c *cli) usageError(err error) int {
	fmt.Fprintf(c.stderr, "nslookup-agent: %v\nRun nslookup-agent help for the commands and flags.\n", err)
	return exitUsage
}

func (c *cli) fail(format string, args ...any) int {
	fmt.Fprintf(c.stderr, "nslookup-agent: "+format+"\n", args...)
	return exitError
}

// options are the flags as given.
type options struct {
	values map[string]*string
	set    map[string]bool
}

func (o options) value(name string) string { return *o.values[name] }

// parseFlags reads cmd's flags (run also takes --join) wherever they stand among its arguments, which it returns.
func parseFlags(cmd string, args []string) (options, []string, error) {
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	o := options{values: map[string]*string{}, set: map[string]bool{}}
	names := []string{"server", "config", "mode", "name", "namespaces"}
	if cmd == "run" {
		names = append(names, "join")
	}
	for _, name := range names {
		o.values[name] = fs.String(name, "", "")
	}
	var positional []string
	for {
		if err := fs.Parse(args); err != nil {
			return o, nil, err
		}
		rest := fs.Args()
		if len(rest) == 0 {
			break
		}
		// After "--" every argument is an argument.
		if len(rest) < len(args) && args[len(args)-len(rest)-1] == "--" {
			positional = append(positional, rest...)
			break
		}
		positional = append(positional, rest[0])
		args = rest[1:]
	}
	fs.Visit(func(f *flag.Flag) { o.set[f.Name] = true })
	return o, positional, nil
}

// settings are the flags, the environment and agent.yaml together, checked.
type settings struct {
	// server is the origin given by --server, NSL_SERVER or agent.yaml; "" when none was.
	server     string
	name       *string
	kind       protocol.AgentKind
	namespaces []string
	// join is the join code of --join or NSL_JOIN, trimmed; "" when none.
	join string
	// folderRoot is where folder certificates are written ("" = folder mode is not set up); reloadContainers and
	// reloadSignal are what a Docker agent signals after writing one.
	folderRoot       string
	reloadContainers []string
	reloadSignal     string
	cfg              config.Config
}

// pick is a flag's value when it was given, else its environment variable's when that is not blank.
func (c *cli) pick(o options, name, env string) (value, from string, ok bool) {
	if o.set[name] {
		return o.value(name), "--" + name, true
	}
	if v := c.getenv(env); strings.TrimSpace(v) != "" {
		return v, env, true
	}
	return "", "", false
}

func (c *cli) resolve(o options) (settings, error) {
	var s settings
	path := c.configPath
	if o.set["config"] {
		path = o.value("config")
	}
	cfg, err := config.Load(path)
	switch {
	case err == nil:
	case errors.Is(err, fs.ErrNotExist) && !o.set["config"]:
		cfg = config.Default()
	default:
		return s, err
	}
	s.cfg = cfg

	s.server = cfg.Server
	if raw, from, ok := c.pick(o, "server", "NSL_SERVER"); ok {
		if s.server, err = config.ServerOrigin(raw); err != nil {
			return s, fmt.Errorf("%s %w", from, err)
		}
	}
	name := cfg.Name
	if raw, from, ok := c.pick(o, "name", "NSL_NAME"); ok {
		if name, err = config.AgentName(raw); err != nil {
			return s, fmt.Errorf("%s %w", from, err)
		}
	}
	if name != "" {
		s.name = &name
	}
	mode, from := "host", "--mode"
	if raw, f, ok := c.pick(o, "mode", "NSL_MODE"); ok {
		mode, from = strings.TrimSpace(raw), f
	}
	switch protocol.AgentKind(mode) {
	case protocol.KindHost, protocol.KindDocker, protocol.KindKubernetes:
		s.kind = protocol.AgentKind(mode)
	default:
		return s, fmt.Errorf("%s must be host, docker or kubernetes", from)
	}
	if raw, from, ok := c.pick(o, "namespaces", "NSL_NAMESPACES"); ok {
		if s.namespaces, err = config.Namespaces(raw); err != nil {
			return s, fmt.Errorf("%s: %w", from, err)
		}
		if len(s.namespaces) > 0 && s.kind != protocol.KindKubernetes {
			return s, fmt.Errorf("%s is for --mode kubernetes only", from)
		}
	}
	if o.values["join"] != nil {
		if raw, _, ok := c.pick(o, "join", "NSL_JOIN"); ok {
			s.join = strings.TrimSpace(raw)
		}
	}
	if err := c.resolveFolder(&s); err != nil {
		return s, err
	}
	return s, nil
}

// resolveFolder sets where folder certificates are written and what a Docker agent signals after writing one: a
// Docker agent's environment first, then agent.yaml; a Docker agent writes in /certs by default.
func (c *cli) resolveFolder(s *settings) error {
	s.folderRoot, s.reloadContainers, s.reloadSignal = s.cfg.Folder.Root, s.cfg.Docker.ReloadContainers, s.cfg.Docker.Signal
	for _, env := range []string{"NSL_FOLDER_ROOT", "NSL_RELOAD_CONTAINER", "NSL_RELOAD_SIGNAL"} {
		raw := c.getenv(env)
		if strings.TrimSpace(raw) == "" {
			continue
		}
		if s.kind != protocol.KindDocker {
			return fmt.Errorf("%s is for --mode docker only", env)
		}
		var err error
		switch env {
		case "NSL_FOLDER_ROOT":
			if s.folderRoot, err = config.FolderRoot(raw); err != nil {
				return fmt.Errorf("%s %w", env, err)
			}
		case "NSL_RELOAD_CONTAINER":
			s.reloadContainers, err = config.ContainerNames(raw)
		case "NSL_RELOAD_SIGNAL":
			s.reloadSignal, err = config.ReloadSignal(raw)
		}
		if err != nil {
			return fmt.Errorf("%s: %w", env, err)
		}
	}
	if s.kind == protocol.KindDocker && s.folderRoot == "" {
		s.folderRoot = defaultDockerFolder
	}
	return nil
}

// parse reads a command's flags and settings; code is the exit code when it failed (or help was asked for).
func (c *cli) parse(cmd string, args []string) (s settings, positional []string, code int, ok bool) {
	o, positional, err := parseFlags(cmd, args)
	if errors.Is(err, flag.ErrHelp) {
		fmt.Fprint(c.stdout, usage)
		return s, nil, exitOK, false
	}
	if err == nil {
		s, err = c.resolve(o)
	}
	if err != nil {
		return s, nil, c.usageError(err), false
	}
	return s, positional, exitOK, true
}

func (c *cli) logger() *slog.Logger {
	return slog.New(slog.NewTextHandler(c.stderr, nil))
}

func (c *cli) join(ctx context.Context, args []string) int {
	s, positional, code, ok := c.parse("join", args)
	if !ok {
		return code
	}
	var joinCode string
	switch len(positional) {
	case 0:
		joinCode = strings.TrimSpace(c.getenv("NSL_JOIN"))
	case 1:
		joinCode = positional[0]
	default:
		return c.usageError(errors.New("join takes one join code"))
	}
	if strings.TrimSpace(joinCode) == "" {
		return c.usageError(errors.New("join needs a join code: nslookup-agent join <code> (create one in the portal)"))
	}
	if err := c.checkOwnDirs(s); err != nil {
		return c.fail("%v", err)
	}
	p, err := c.parts(s)
	if err != nil {
		return c.fail("%v", err)
	}
	id, err := agent.Join(ctx, p.store, cmp.Or(s.server, config.DefaultServer), joinCode, s.kind, s.name, p.facts(ctx))
	if err != nil {
		return c.joinFailed(err, p)
	}
	fmt.Fprintf(c.stdout, "Joined %s as agent %s. Start it with: nslookup-agent run\n", id.Server, id.AgentID)
	return exitOK
}

func (c *cli) joinFailed(err error, p parts) int {
	var already *agent.AlreadyJoinedError
	var refused *client.APIError
	switch {
	case errors.As(err, &already):
		return c.fail("%v; remove %s to join again", err, p.storeName)
	case errors.Is(err, client.ErrBadServerSignature):
		return c.fail("the join answer did not prove it came from nslookup.io (is a proxy changing it?); nothing was stored")
	case errors.As(err, &refused) && refused.Code == "agent_limit_reached":
		return c.fail("your organization already has as many agents as it may have; remove one in the portal, then join again")
	}
	return c.fail("joining failed: %v", err)
}

func (c *cli) run(ctx context.Context, args []string) int {
	s, positional, code, ok := c.parse("run", args)
	if !ok {
		return code
	}
	if len(positional) > 0 {
		return c.usageError(errors.New("run takes no arguments (the join code goes in --join or NSL_JOIN)"))
	}
	log := c.logger()
	if err := c.checkOwnDirs(s); err != nil {
		return c.fail("%v", err)
	}
	if err := os.MkdirAll(c.stateDir, 0o700); err != nil {
		return c.fail("%v", err)
	}
	lock, err := state.Lock(c.stateDir)
	var running *state.RunningError
	switch {
	case errors.As(err, &running) && s.kind == protocol.KindHost:
		return c.fail("%v; the service runs it: systemctl status nslookup-agent", err)
	case err != nil:
		return c.fail("%v", err)
	}
	defer lock.Close()
	p, err := c.parts(s)
	if err != nil {
		return c.fail("%v", err)
	}
	id, err := p.store.Load()
	switch {
	case errors.Is(err, identity.ErrNotFound):
		if s.join == "" {
			return c.fail("this agent has not joined yet: run nslookup-agent join <code>, or set NSL_JOIN")
		}
		if id, err = agent.Join(ctx, p.store, cmp.Or(s.server, config.DefaultServer), s.join, s.kind, s.name, p.facts(ctx)); err != nil {
			return c.joinFailed(err, p)
		}
		log.Info("joined nslookup.io", "agent", id.AgentID, "server", id.Server)
	case err != nil:
		return c.fail("%v", err)
	case s.join != "":
		log.Info("already joined; the join code is not used", "agent", id.AgentID)
	}
	if s.server != "" && s.server != id.Server {
		return c.fail("this agent joined %s, not %s; remove %s and join again to move it", id.Server, s.server, p.storeName)
	}

	log.Info("running", "agent", id.AgentID, "server", id.Server, "mode", string(s.kind), "version", version.Version)
	switch {
	case s.kind == protocol.KindHost && len(s.reloadContainers) > 0:
		log.Warn("docker.reloadContainers is for a Docker agent; on a server the agent runs folder.hook after writing a folder certificate")
	case s.kind == protocol.KindDocker && s.cfg.Folder.Hook != "":
		log.Warn("folder.hook is for an agent on a server; a Docker agent signals docker.reloadContainers (NSL_RELOAD_CONTAINER) instead")
	}
	ledger := agent.FileLedger{Path: filepath.Join(c.stateDir, "installed.json")}
	if p.recover != nil {
		recoverInstall(ctx, p.recover, ledger, log)
	}
	cl := client.New(id.Server, id)
	// The server keys it trusts change when the server rolls its signing key over: kept in the identity.
	cl.SaveKeys, cl.Log = p.store.SaveServerKeys, log
	loop := &agent.Loop{
		Client:     cl,
		Inventory:  p.inventory,
		Facts:      p.facts,
		Installer:  p.installer,
		Folder:     p.folder,
		Ledger:     ledger,
		Log:        log,
		RemoveHint: p.removeHint,
		Owned:      p.owned,
	}
	if err := loop.Run(ctx); err != nil {
		return c.fail("%v", err)
	}
	return exitOK
}

func (c *cli) inventory(ctx context.Context, args []string) int {
	s, positional, code, ok := c.parse("inventory", args)
	if !ok {
		return code
	}
	if len(positional) > 0 {
		return c.usageError(errors.New("inventory takes no arguments"))
	}
	p, err := c.parts(s)
	if err != nil {
		return c.fail("%v", err)
	}
	facts := p.facts(ctx)
	inv, err := p.inventory(ctx)
	if err != nil {
		return c.fail("%v", err)
	}
	out, err := json.MarshalIndent(struct {
		Facts     protocol.AgentFacts `json:"facts"`
		Inventory protocol.Inventory  `json:"inventory"`
	}{facts, inv}, "", "  ")
	if err != nil {
		return c.fail("%v", err)
	}
	fmt.Fprintf(c.stdout, "%s\n", out)
	return exitOK
}

// checkOwnDirs checks, on a server and in Docker, that only root (or the agent's own user) can change the state
// directory, its subdirectories (identity/, previous/, certbot/, blocked/, reload-owed/) and every directory above them:
// what is kept there drives what the agent writes as root. A
// Kubernetes agent keeps its identity in a Secret and its state on an emptyDir that only its own pod uses.
func (c *cli) checkOwnDirs(s settings) error {
	if s.kind == protocol.KindKubernetes {
		return nil
	}
	dirs := []string{c.stateDir}
	for _, sub := range []string{"identity", "previous", "certbot", "blocked", "reload-owed"} {
		dirs = append(dirs, filepath.Join(c.stateDir, sub))
	}
	return state.Check(c.rootDir, c.dirOwner, dirs...)
}

// parts is what the agent uses in its mode: where it keeps its identity (storeName says where, in plain words), how it
// reads this machine, how it installs on sites and writes folder certificates, how it finishes an install it was
// stopped in, how it is removed (the hint a removed agent logs).
type parts struct {
	store      identity.Store
	storeName  string
	inventory  func(context.Context) (protocol.Inventory, error)
	facts      func(context.Context) protocol.AgentFacts
	installer  agent.Installer
	folder     agent.FolderInstaller
	recover    func(context.Context) (*install.Recovered, error)
	removeHint string
	// owned names the sites this machine says the agent installed on (Kubernetes: secrets carrying its record), as of
	// the last inventory read; nil when the mode has no such record.
	owned func() []string
}

// parts are the parts of an agent of s's kind; a Kubernetes agent's fail when it cannot connect to its cluster.
func (c *cli) parts(s settings) (parts, error) {
	files := identity.FileStore{Dir: filepath.Join(c.stateDir, "identity")}
	p := parts{
		store:     files,
		storeName: files.Dir,
		facts:     func(context.Context) protocol.AgentFacts { return machineFacts(os.ReadFile, os.Hostname) },
	}
	// Only the identity goes: certbot/ and previous/ are what gives sites back to certbot and rolls back.
	then := fmt.Sprintf(", then delete %s only (keep %s and %s: they give sites back to certbot and roll back)",
		filepath.Join(c.stateDir, "identity"), filepath.Join(c.stateDir, "certbot"), filepath.Join(c.stateDir, "previous"))
	switch s.kind {
	case protocol.KindHost:
		p.facts = func(ctx context.Context) protocol.AgentFacts {
			f := machineFacts(os.ReadFile, os.Hostname)
			f.WebServers = inventory.WebServers(ctx, c.runner)
			return f
		}
		host := &install.Host{Root: c.rootDir, StateDir: c.stateDir, Runner: c.runner, Log: c.logger(), DirOwner: c.dirOwner}
		p.inventory = c.hostInventory(s.cfg.HAProxy.Configs, host)
		// Folder mode only when agent.yaml sets folder.root; folder work says how to set it up otherwise.
		folder := &install.Folder{Host: host, Root: s.folderRoot, Hook: s.cfg.Folder.Hook}
		p.installer, p.folder, p.recover = host, folder, folder.RecoverPending
		p.removeHint = "systemctl disable --now nslookup-agent" + then
	case protocol.KindDocker:
		// A container sees no web server: a Docker agent writes folder certificates only.
		p.inventory = func(context.Context) (protocol.Inventory, error) { return protocol.Inventory{}, nil }
		host := &install.Host{Root: c.rootDir, StateDir: c.stateDir, Log: c.logger(), DirOwner: c.dirOwner}
		folder := &install.Folder{Host: host, Root: s.folderRoot,
			Reload: &install.DockerReload{Containers: s.reloadContainers, Signal: s.reloadSignal, Socket: c.dockerSocket}}
		p.folder, p.recover = folder, folder.RecoverPending
		p.removeHint = "docker rm -f nslookup-agent" + then
	case protocol.KindKubernetes:
		cs, ns, err := c.kube()
		if err != nil {
			return p, fmt.Errorf("connecting to the cluster: %w", err)
		}
		namespaces := s.namespaces
		p.facts = func(ctx context.Context) protocol.AgentFacts {
			f := machineFacts(os.ReadFile, os.Hostname)
			f.Kubernetes = kube.Facts(ctx, cs, namespaces)
			return f
		}
		var owned []string
		p.inventory = func(ctx context.Context) (protocol.Inventory, error) {
			inv, o, err := kube.ReadInventory(ctx, cs, namespaces)
			if err == nil {
				owned = o
			}
			return inv, err
		}
		p.owned = func() []string { return owned }
		p.installer = &kube.Installer{Client: cs, Namespaces: namespaces}
		store := kube.SecretStore{Client: cs, Namespace: ns}
		p.store, p.storeName = store, "the secret "+store.String()
		// The TLS secrets it wrote stay; its identity is a Secret the chart does not remove.
		p.removeHint = fmt.Sprintf("helm uninstall nslookup-agent -n %s, then kubectl delete secret %s -n %s", ns, kube.IdentitySecret, ns)
	}
	return p, nil
}

// hostInventory reads the sites of the web servers on this machine, every read with the same reader: a web server that
// fails a read is reported as at its last read that worked. What could not be read is logged, again only when it
// changed (the sites are read every 5 minutes). Each read is handed to host, which installs on its sites.
func (c *cli) hostInventory(haproxyConfigs []string, host *install.Host) func(context.Context) (protocol.Inventory, error) {
	log := c.logger()
	reader := &inventory.Reader{Runner: c.runner, FS: c.root, Options: inventory.Options{HAProxyConfigs: haproxyConfigs}}
	var said []string
	return func(ctx context.Context) (protocol.Inventory, error) {
		inv, err := reader.Read(ctx)
		if !slices.Equal(inv.Problems, said) {
			for _, problem := range inv.Problems {
				log.Warn("part of the web server configuration was not read", "problem", problem)
			}
			said = inv.Problems
		}
		if err != nil {
			return protocol.Inventory{}, err
		}
		host.SetInventory(inv)
		return inv.Wire(), nil
	}
}

// recoverInstall finishes or undoes an install the agent was stopped in (killed between writing a site's files and
// reloading its web server), and queues its result for the first heartbeat.
func recoverInstall(ctx context.Context, recover func(context.Context) (*install.Recovered, error), ledger agent.Ledger, log *slog.Logger) {
	rec, err := recover(ctx)
	switch {
	case err != nil:
		log.Error("an install the agent was stopped in could not be finished or undone", "error", err)
		return
	case rec == nil:
		return
	case rec.Result.OK:
		log.Info("finished an install the agent was stopped in", "assignment", rec.AssignmentID, "sha256", rec.Result.SHA256)
	case rec.ReloadOwed:
		var why string
		if rec.Result.Message != nil {
			why = *rec.Result.Message
		}
		log.Warn("the new files of an install the agent was stopped in are in place, but reloading what uses them failed; the next work for it reloads again",
			"assignment", rec.AssignmentID, "sha256", rec.Result.SHA256, "error", why)
	default:
		log.Warn("undid an install the agent was stopped in; the previous files are back", "assignment", rec.AssignmentID, "sha256", rec.Result.SHA256)
	}
	if err := agent.AddResult(ledger, rec.AssignmentID, rec.Result, rec.Installed); err != nil {
		log.Warn("the result of an install the agent was stopped in cannot be saved; it is not reported", "assignment", rec.AssignmentID, "error", err)
	}
}

// machineFacts describes this machine within the server's limits.
func machineFacts(readFile func(string) ([]byte, error), hostname func() (string, error)) protocol.AgentFacts {
	host, _ := hostname()
	return protocol.AgentFacts{
		OS:           protocol.Clip(runtime.GOOS, 64),
		OSVersion:    protocol.Clip(osVersion(readFile), 128),
		Arch:         protocol.Clip(runtime.GOARCH, 32),
		Hostname:     protocol.Clip(host, 253),
		AgentVersion: version.Version,
	}
}

// osVersion is PRETTY_NAME from os-release (else NAME and VERSION_ID); "" when there is none.
func osVersion(readFile func(string) ([]byte, error)) string {
	var data []byte
	for _, path := range []string{"/etc/os-release", "/usr/lib/os-release"} {
		if b, err := readFile(path); err == nil {
			data = b
			break
		}
	}
	fields := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok || strings.HasPrefix(key, "#") {
			continue
		}
		if unquoted, err := strconv.Unquote(value); err == nil && strings.HasPrefix(value, `"`) {
			value = unquoted
		} else if len(value) >= 2 && (value[0] == '"' || value[0] == '\'') && value[len(value)-1] == value[0] {
			value = value[1 : len(value)-1]
		}
		fields[key] = protocol.Clip(value, 128)
	}
	if fields["PRETTY_NAME"] != "" {
		return fields["PRETTY_NAME"]
	}
	return strings.TrimSpace(fields["NAME"] + " " + fields["VERSION_ID"])
}
