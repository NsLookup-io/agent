# nslookup.io agent

The nslookup.io agent runs on your own servers: on a Linux host, in Docker or in Kubernetes. It tells nslookup.io which
sites it finds there, and installs the certificates that nslookup.io Certificate Autopilot renews for them.

How it talks to nslookup.io:

- It joins once with a one-use join code from the portal. The code's secret never leaves the machine: it only proves
  the join and checks the answer.
- Every request it sends is signed with its own key, and every answer it gets is checked against the server key it
  pinned when it joined. When nslookup.io rolls that key over, its heartbeat answers, signed with a key the agent
  trusts, name the new key ahead of time; the agent then trusts it too and keeps it with its identity. An agent that
  was offline through a whole rollover must join again.
- It stops working only when nslookup.io removed it in the portal and says so in an answer it signed: an unsigned
  "removed" answer (from a proxy, say) is a failure like any other, and the agent tries again.
- A certificate's private key arrives sealed to a key that exists only on that machine.

What it never does: run a command or write a path that nslookup.io names (commands are a fixed list inside the agent,
paths come only from what the agent read on the machine or from its own `agent.yaml`), edit a web server's
configuration or an Ingress, send a private key anywhere, decode a key other than the one it installs, send
configuration text, or touch a Kubernetes secret that cert-manager or another tool manages. (When it installs, the
key file it replaces is copied as it is into `/var/lib/nslookup-agent/previous/`, readable by root only, so that it
can be put back.)

## Status

Version 1. The protocol between the agent and nslookup.io (`/agent/v1`) stays the same within version 1. Report
problems as issues, and vulnerabilities as [SECURITY.md](SECURITY.md) says.

## Install

The portal (Integrations, Install agent) shows the command for your machine with a fresh join code in it (`nsj_…`,
one use, valid for an hour); these are the same commands. Add the server (`--server=`, `NSL_SERVER`, `server`) only
when it is not `https://agents.nslookup.io`. What the agent reads, what it sends and what it never does is described
under [What it reads on a server](#what-it-reads-on-a-server),
[What it does when it installs on a server](#what-it-does-when-it-installs-on-a-server),
[Folder certificates](#folder-certificates) and [In Kubernetes](#in-kubernetes).

### On a Linux server

```sh
curl -fsSL https://github.com/nslookup-io/agent/releases/latest/download/install.sh | sudo sh -s -- --join <code> --name=<name>
```

`install.sh` (a file of every release) runs on Linux on amd64 or arm64, as root, and:

1. downloads the release archive for this machine and `checksums.txt` from the same release (the latest, or the one
   in `NSL_VERSION`, as in `sudo NSL_VERSION=1.2.0 sh -s -- …`) and checks the archive's SHA-256; a mismatch installs
   nothing;
2. installs `/usr/local/bin/nslookup-agent` and the systemd unit `/etc/systemd/system/nslookup-agent.service`, and
   creates `/var/lib/nslookup-agent` (0700) and `/etc/nslookup-agent` (0755);
3. joins with the code, once; the agent gets the code only in its environment (`NSL_JOIN`), never on its command line;
4. enables and restarts the service `nslookup-agent`.

Its flags are `--join <code>`, `--join-file <path>` (with `--remove-join-file` to delete that file once the agent has
joined), `--name` and `--server`, each as `--flag=value` or `--flag value`, and `--dry-run`, which prints what it would
do and changes nothing. Without `--join` or `--join-file` it asks for the code on the terminal, and what you paste is
not shown.

**`--join <code>` is visible to other users of the machine while the install runs** (in the process list, as an
argument of `sudo` and `sh`) **and is kept in sudo's log.** A join code is used once and expires after an hour, but
until the agent has used it, whoever has it can join a machine of their own to your organization. On a shared server,
leave `--join` out and paste the code when asked:

```sh
curl -fsSL https://github.com/nslookup-io/agent/releases/latest/download/install.sh | sudo sh -s -- --name=<name>
```

or put the code in a file of root's that only root can read and give that file:

```sh
sudo install -m 600 /dev/null /root/nslookup-join    # then write the code into it: sudoedit /root/nslookup-join
curl -fsSL https://github.com/nslookup-io/agent/releases/latest/download/install.sh | sudo sh -s -- --join-file /root/nslookup-join --remove-join-file --name=<name>
```

The file must belong to root, neither its group nor other users may read or change it, it must have no other name
(hard link), and every folder from its own up to `/` must belong to root and be writable by root only (as `/root` is,
and `/tmp` is not). `--remove-join-file` deletes it only while that path is still the file the code was read from.
Behind a proxy, give the script the proxy through sudo
(`sudo HTTPS_PROXY=http://proxy.example.test:3128 sh -s -- …`) and the service with `systemctl edit nslookup-agent`:

```ini
[Service]
Environment=HTTPS_PROXY=http://proxy.example.test:3128
```

The service runs as root: it writes certificate files wherever the web server configuration names them and reloads
the web servers. Its unit sets `NoNewPrivileges=yes` and nothing that limits where it may write
(`ProtectSystem=`, `ProtectHome=`) or hides `/tmp` (`PrivateTmp=`, which a hook or a web server's reload may use).

Without the script: each release also has `.deb` and `.rpm` packages and the archives, which install the same files.
Then `sudo /usr/local/bin/nslookup-agent join <code>` and `sudo systemctl enable --now nslookup-agent`.

To update, run the same command without `--join` (the server keeps its identity), or install the newer package. To
uninstall, `sudo systemctl disable --now nslookup-agent`, delete `/usr/local/bin/nslookup-agent` and the unit, and
of `/var/lib/nslookup-agent` delete only `identity/` (`certbot/` and `previous/` give sites back to certbot and roll
back).

### In Docker

```sh
docker run -d --name nslookup-agent --restart unless-stopped \
  -v /etc/ssl/nslookup:/certs \
  -v nslookup-agent:/var/lib/nslookup-agent \
  -e NSL_JOIN=<code> ghcr.io/nslookup-io/agent:1
# optional, to reload your nginx container after an install (gives the agent root on this host):
#   -v /var/run/docker.sock:/var/run/docker.sock -e NSL_RELOAD_CONTAINER=nginx
```

Add `-e NSL_NAME=<name>` to name it. `-e NSL_JOIN=<code>` keeps the code in your shell history and shows it in the
process list while `docker run` runs; prefer a file of yours that only you can read, with `--env-file`:

```sh
install -m 600 /dev/null nslookup-agent.env          # then write NSL_JOIN=<code> into it
docker run -d --name nslookup-agent --restart unless-stopped \
  -v /etc/ssl/nslookup:/certs \
  -v nslookup-agent:/var/lib/nslookup-agent \
  --env-file nslookup-agent.env ghcr.io/nslookup-io/agent:1
rm nslookup-agent.env                                # once the agent has joined
```

The image runs `nslookup-agent run` in Docker mode (`NSL_MODE=docker`): it writes
the certificates you add to it in the portal under `/certs` ([Folder certificates](#folder-certificates)). The volume
`nslookup-agent` keeps its identity: to update, `docker pull ghcr.io/nslookup-io/agent:1`, `docker rm -f
nslookup-agent` and the same `docker run` (the join code is not used again).

The image runs as root, because the folder mounted at `/certs` normally belongs to root and the agent writes only in
folders that root or its own user owns and no one else can change. To run it as another user, give it a certificate
folder and a state folder of that user:

```sh
sudo install -d -o 1000 -g 1000 -m 0750 /srv/nslookup/certs /srv/nslookup/state
docker run -d --name nslookup-agent --restart unless-stopped --user 1000:1000 \
  -v /srv/nslookup/certs:/certs -v /srv/nslookup/state:/var/lib/nslookup-agent \
  -e NSL_JOIN=<code> ghcr.io/nslookup-io/agent:1
```

With the Docker socket, that user also needs the socket's group (`--group-add <its gid>`).

### In Kubernetes

```sh
helm install nslookup-agent oci://ghcr.io/nslookup-io/charts/agent -n nslookup-agent --create-namespace \
  --set-string joinCode=<code> --set-string name=<name>
```

| Value | |
|-------|--|
| `joinCode` | the join code, used once (give it with `--set-string`) |
| `existingJoinSecret` | instead (preferred): a Secret of yours in the release namespace whose key `joinCode` holds the code |
| `name` | the agent's name in the portal |
| `server` | the server, when it is not `https://agents.nslookup.io` |
| `namespaces` | only these namespaces, as in `--set "namespaces={shop,blog}"` (default: every namespace) |
| `image.repository`, `image.tag` | `ghcr.io/nslookup-io/agent`, the chart's version |
| `resources` | requests 10m CPU and 32 MiB, limit 128 MiB |

`--set-string joinCode=<code>` keeps the code in your shell history and in the release's stored values; prefer a
Secret of your own, made from a file holding the code:

```sh
kubectl create namespace nslookup-agent
kubectl create secret generic nslookup-agent-join -n nslookup-agent --from-file=joinCode=./join-code
helm install nslookup-agent oci://ghcr.io/nslookup-io/charts/agent -n nslookup-agent \
  --set existingJoinSecret=nslookup-agent-join --set-string name=<name>
```

The chart installs one Deployment (one replica, `Recreate`) running the agent with `--mode=kubernetes` as user 65532,
with a read-only root file system, no capabilities, no privilege escalation and the `RuntimeDefault` seccomp profile,
and its ServiceAccount. Its RBAC is Ingresses `get`, `list`, `watch` and Secrets `get`, `create`, `update`, `patch`,
nothing else: a ClusterRole, or with `namespaces` a Role in each of them. Then, unless its own namespace is one of them,
a Role there lets it read and update its identity Secret `nslookup-agent-identity` and create Secrets (Kubernetes cannot
limit a create to one name). The join code goes into a Secret of the release; once joined, the agent keeps its own
identity Secret and the code is not used again. Besides nslookup.io, the agent connects to port 443 of the addresses
your Ingresses list for their ingress controller, after each install (below): allow that if a NetworkPolicy limits
its egress.

To update, `helm upgrade nslookup-agent oci://ghcr.io/nslookup-io/charts/agent -n nslookup-agent --reuse-values`. To
uninstall, `helm uninstall nslookup-agent -n nslookup-agent`, then `kubectl delete secret nslookup-agent-identity -n
nslookup-agent`; the TLS secrets it wrote stay as they are.

### Verifying a release

Releases are built by this repository's release workflow from a tag. `checksums.txt` (which lists every archive,
package and `install.sh`), the image and the Helm chart are signed with [cosign](https://github.com/sigstore/cosign),
keyless, as that workflow. Verifying needs cosign 3.0 or later: the signatures are Sigstore bundles
(`.sigstore.json`), the format cosign reads by default only from 3.0 on. With `checksums.txt`,
`checksums.txt.sigstore.json` and the files you downloaded in one folder:

```sh
cosign verify-blob \
  --certificate-identity https://github.com/nslookup-io/agent/.github/workflows/release.yml@refs/tags/v1.2.0 \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --bundle checksums.txt.sigstore.json checksums.txt
sha256sum --check --ignore-missing checksums.txt
```

The image and the chart:

```sh
cosign verify ghcr.io/nslookup-io/agent:1.2.0 \
  --certificate-identity https://github.com/nslookup-io/agent/.github/workflows/release.yml@refs/tags/v1.2.0 \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
cosign verify ghcr.io/nslookup-io/charts/agent:1.2.0 \
  --certificate-identity https://github.com/nslookup-io/agent/.github/workflows/release.yml@refs/tags/v1.2.0 \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Each archive has an SBOM next to it (`<archive>.sbom.json`), and the image carries one as an attestation.

## Usage

```sh
nslookup-agent join <code>    # once, with a join code from the portal
nslookup-agent run            # what the service runs: heartbeats, the sites on this machine, installs
nslookup-agent inventory      # print what the agent reports about this machine
nslookup-agent version
```

| Flag | Environment | |
|------|-------------|--|
| `--server <url>` | `NSL_SERVER` | the server, an `https://` origin (default `https://agents.nslookup.io`) |
| `--name <name>` | `NSL_NAME` | the agent's name in the portal (default: the name given with the join code, else the host name) |
| `--mode <mode>` | `NSL_MODE` | `host` (default), `docker` or `kubernetes` (the Docker image sets `NSL_MODE=docker`) |
| `--namespaces <list>` | `NSL_NAMESPACES` | Kubernetes only: the namespaces whose Ingresses it reads and whose TLS secrets it may write, comma-separated (default: all) |
| `--join <code>` | `NSL_JOIN` | `run` only: join first when the agent has not joined yet (how Docker and the Helm chart start it) |
| `--config <path>` | | the configuration file (default `/etc/nslookup-agent/agent.yaml`) |
| | `NSL_FOLDER_ROOT` | Docker only: the folder certificates are written in (default `/certs`) |
| | `NSL_RELOAD_CONTAINER` | Docker only: the containers signalled after one is written, comma-separated |
| | `NSL_RELOAD_SIGNAL` | Docker only: `HUP` (default), `USR1` or `USR2` |

Every flag takes its value as `--flag=value` or as `--flag value`; either way a value that starts with a dash is the
value, as in `--name=-web`. A flag counts before its environment variable, and both before `agent.yaml`. A pasted join
code is trimmed of spaces and line breaks.

The agent keeps its identity (its private keys, the server key it pinned when it joined and the server keys it trusts
since) in `/var/lib/nslookup-agent/identity/`, readable by its owner only (in Kubernetes: a Secret, below). On a server
and in Docker it starts only when `/var/lib/nslookup-agent`, its `identity/` and every directory above them are
directories (not links) that belong to root (or to the user the agent runs as) and that only their owner can change:
what it keeps there decides what it writes as root. It reads its own files there without following links, and a symbolic
link anywhere on the path of the state directory, its subdirectories (`identity/`, `previous/`, `certbot/`, `blocked/`,
`reload-owed/`) or the directories above them stops it at start, naming the link. Only one `nslookup-agent run` uses a
state directory at a time (it holds `agent.lock` there): a second one, such as a run by hand beside the service, exits
at once and names the one that runs. `join` never replaces an identity that is there: remove that directory to join
again. An agent removed in the portal stops working and waits to be uninstalled, logging how (then and once a day); it
deletes nothing on its own. Uninstalling it, delete only `identity/` and keep `/var/lib/nslookup-agent/certbot/` and
`previous/`: they give sites back to certbot and roll back.

### What it reads on a server

On a Linux host the agent reads the sites of nginx, Apache and HAProxy. It runs only `nginx -T`, `nginx -v`, `apachectl
-t -D DUMP_VHOSTS -D DUMP_RUN_CFG` (or `apache2ctl`, or `httpd -S`), `apachectl -v` (or `apache2ctl`, `httpd`) and
`haproxy -v`, and reads the configuration files they name, `/etc/haproxy/haproxy.cfg` and the certificate files. It
sends, per certificate file, the names served from it, the paths of the configuration, certificate, key and chain files
and the certificate's facts (issuer, names, serial, expiry, SHA-256). A server block or virtual host with HTTPS that
names hosts the agent cannot list (a regular expression, a variable, a `?` or a `*` other than a whole first label, as
in `www.example.*`) is reported with the names of the certificate it serves as well, when that certificate is one hosts
rely on today (not self-signed, not expired), so a certificate that replaces it must cover at least what it covers
today; a snakeoil or expired certificate adds nothing. So is a catch-all, which answers the names no other one serves:
an nginx server whose HTTPS `listen` says `default_server` (where none does, the first server listening on that address
and port), and the first Apache virtual host of an address and port. Reading the sites, it never opens a key file and
never decodes a key: a file that holds the key and the certificate together (HAProxy's) is read whole, but only its
certificate is decoded and the bytes read are cleared. It never sends configuration text. `nslookup-agent inventory`
prints what it would send. A machine with more sites than nslookup.io takes in one report (500 sites, 3.5 MiB) leaves
out the certificates' own names first, then sites, but never a site that nslookup.io assigns certificates to (named by
its work, remembered for 30 days, and in Kubernetes every secret that carries the agent's annotation). Such a list is
sent only once nslookup.io has named its work since the agent started: until then a heartbeat carries only its hash.

**What it does not see.** The agent asks each web server for its configuration with a fixed command line (`nginx -T`,
`apachectl -t -D DUMP_VHOSTS -D DUMP_RUN_CFG`, `haproxy`'s default file and the `haproxy.configs` of `agent.yaml`), so
a web server that was started with a configuration file of another path (`nginx -c`, `httpd -f`, `haproxy -f` elsewhere)
is not seen through its running command: its sites do not appear. Point the agent at such a server's configuration
through a folder certificate or, for HAProxy, `haproxy.configs`.

Every command runs without a shell, with only `PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin`
and `LC_ALL=C` in its environment.

### What it does when it installs on a server

nslookup.io names a site only by its key; the paths are the ones the agent read on the machine, and the agent never
edits a web server's configuration. For each certificate it installs on a site, the agent:

1. checks the certificate is the one nslookup.io named (its SHA-256), matches its key, covers every name of the site
   and has not expired;
2. writes the files the configuration names, in the format each one expects: nginx's `ssl_certificate` and HAProxy's
   `crt` get the certificate with its chain, Apache's `SSLCertificateFile` too unless the virtual host has an
   `SSLCertificateChainFile` (which then gets the chain), and a file that holds the key today (HAProxy's one file)
   gets the key first. Each file is written to a temporary file in the same directory and renamed into place, keeping
   its owner, group and mode; a key file never gets a wider mode than it had, nor wider than `0640`. When the
   configurations using one file expect different files, or a key file is also used by another site, nothing is
   written; a chain file other sites share is left as it is when it already holds the new chain, and otherwise nothing
   is written either.

   How it reaches the files: it walks from `/` to each file's directory one name at a time. Every directory it passes
   through, including `/`, must be owned by root (or by the user the agent runs as, when that is not root) and writable
   by its owner only (no group or other write, no sticky bit, so not `/tmp`), or nothing is written; the refusal names
   who may own them, for example "which a user other than root or the agent's user (uid 1000) can change". A symbolic
   link on the way is followed only when it sits in such a directory (so only root, or the agent's own user, could have
   made it), at most 40 of them. The directory it reaches is kept open, and every read, write, rename and restore of
   that install happens in it, so the path is never looked up again; a file is never opened through a link (certbot's
   links, below, are replaced as links). Users other than root and the agent's own user therefore cannot redirect what
   the agent writes by swapping a file, a directory or a link along the path. For this reason a certificate folder
   that a user other than root (or the agent's own user) can write is refused: a web server's own user (for example
   `www-data`) must not own the folder the agent writes into. Make the folder root's (or the agent's), readable by that
   user;
3. keeps the files it replaces in `/var/lib/nslookup-agent/previous/<site>/` (the last two sets) and notes the install
   in `/var/lib/nslookup-agent/pending.json` until it is done;
4. tests the configuration of every web server using the file: `nginx -t`, `apachectl -t` (or `apache2ctl -t`,
   `httpd -t`), `haproxy -c -f <each HAProxy configuration file it read>`. A failure puts the previous files back;
   nothing is reloaded;
5. reloads each of them: `systemctl reload <unit>` when `systemctl is-active <unit>` says the unit runs (units
   `nginx`, `apache2`, `httpd` and `haproxy` only), else `nginx -s reload` or `apachectl -k graceful` (or
   `apache2ctl`, `httpd`); HAProxy only through systemd. A failure puts the previous files back and reloads again;
6. asks this machine (`127.0.0.1`, each name of the site, its ports) whether it serves the new certificate, and says
   so; this never undoes the install.

An agent stopped half way finishes or undoes the install when it starts again (`pending.json`). An install is never
cut short by the service stopping. Previous files that cannot be put back (their directory was made read-only
meanwhile, say) hold up only their own site (`/var/lib/nslookup-agent/blocked/`): each install on that site tries
again first, and after three failed tries they are set aside, the result says where they are kept, and the site can
be installed on again.

**certbot.** A site whose files are certbot's (`/etc/letsencrypt/live/<name>/`) is taken over only after you confirm
it in the portal. The agent then moves `/etc/letsencrypt/renewal/<name>.conf` to `<name>.conf.nslookup-disabled`
(certbot skips it), replaces the links in `live/<name>/` that the site uses with real files and records what it did
in `/var/lib/nslookup-agent/certbot/<name>.json`. Giving the site back to certbot (in the portal) moves the renewal
file back and makes the links again, then tests and reloads. A certbot certificate that several sites use goes back
to certbot only when no other site that Autopilot still renews uses it (until then the give-back fails and says
which site); then every link the agent replaced under that name is made again. No other certbot file, and no other
name, is touched.

### Folder certificates

A Docker agent, and an agent on a server whose `agent.yaml` sets `folder.root`, also take certificates you add to the
agent in the portal (for what it cannot read the configuration of: a web server in another container, Postfix, Dovecot,
a Java application). Each goes into a folder of its own under the root (`/certs` in Docker: mount a folder there), named
by nslookup.io but kept to lowercase letters, digits, dots and dashes, without a leading dot or dash and at most 64
characters, so it can never leave the root nor read as an option. The folder holds `fullchain.pem` (the certificate and
its chain), `cert.pem`, `chain.pem` and `privkey.pem`. They are checked and written as on a site (above): the same walk,
a temporary file renamed into place, owner, group and mode kept, a key never wider than it was nor than `0640`; a new
folder gets `0750`, a new file `0644` and a new key `0600`. The files replaced are kept in
`/var/lib/nslookup-agent/previous/folder-<name>/` (the last two sets). Then it reloads what uses them:

- on a server, `agent.yaml`'s `folder.hook`, run with `/bin/sh -c`, the same environment as every command plus
  `NSL_FOLDER` (the folder's path) and `NSL_CERTIFICATE` (its name), for at most a minute. A hook that fails is
  reported with the last lines it printed (never the command itself);
- in Docker, a signal to each container named in `NSL_RELOAD_CONTAINER` (or `docker.reloadContainers`):
  `POST /containers/<name>/kill?signal=<HUP|USR1|USR2>` through `/var/run/docker.sock`, nothing else. Mount the socket
  (`-v /var/run/docker.sock:/var/run/docker.sock`) only if you want this: it gives the agent root on the host. Without
  it the portal says to reload those containers yourself.

When the reload fails (or the agent is stopped while it runs) the files stay and the reload is owed
(`/var/lib/nslookup-agent/reload-owed/<name>`): the next time nslookup.io sends that certificate (after Try again in
the portal) the agent only reloads. A folder the agent may not use (missing, a link, or one another user can change,
such as a mounted folder owned by your own user) is reported to the portal with the reason.

### In Kubernetes

A Kubernetes agent reads the cluster's Ingresses (`networking.k8s.io/v1`), in every namespace or only in those of
`--namespaces`, and the TLS secrets their `tls` entries name, each with a `get` (it never lists secrets). It sends, per
secret, every name of every Ingress using it (Ingresses sharing a secret are one site), the namespace, the secret, the
first Ingress and the facts of the certificate in its `tls.crt`; it never sends, logs or keeps a `tls.key`. A host an
Ingress serves without TLS is a site too: taking it over creates the secret named after the host, its dots as dashes
and a leading `*` as `wildcard`, then `-tls` (`status.example.com` gets `status-example-com-tls`), which you then add
to the Ingress's `tls` section. The agent never edits an Ingress.

For each certificate it installs, it checks it as on a server (step 1 above, every name of every Ingress using the
secret), reads the Ingresses and the secret again, and writes `tls.crt` (the certificate and its chain) and `tls.key`,
keeping the secret's other keys, labels and annotations, and labels it `app.kubernetes.io/managed-by: nslookup-agent`
and annotates it `nslookup.io/sha256` (a secret that already names another tool in that label is never written,
below). That annotation is also its record of what it installed, kept with the secret rather than in the pod: a
certificate changed by hand afterwards is reported to the portal and not overwritten, also after the agent's pod was
replaced. It writes the secret as it read it (its `resourceVersion`): one changed meanwhile is read again once. Ingress
controllers pick up a changed secret by themselves, so nothing is reloaded.

Then it asks the ingress controller whether it serves the new certificate, and says so; this never undoes the install.
It connects to the addresses the Ingresses using the secret list for their controller (`status.loadBalancer`: each
entry's IP, else its host name, at most four), on port 443, once for each name, and compares the certificate it gets
with the new one, again every quarter second for up to 15 seconds (nginx and Traefik pick a secret up within seconds).
The addresses come from your cluster, never from nslookup.io. When it does not see the new certificate (a controller
that picks secrets up later, such as Google's own load balancer, which takes minutes; one that does not answer from
inside the cluster; an Ingress that lists no address), it says what it saw and the portal goes by nslookup.io's own
check from the internet. After the agent's pod was replaced, the one "already installed" report of a certificate that
is in its secret asks again, for up to 3 seconds.

It never writes, and the portal says why (the portal reads the signs below; the agent cannot read cert-manager's own
`Certificate` objects, which would need more rights than it has):

- a secret cert-manager manages: one with a `cert-manager.io/` annotation, or used by an Ingress with
  `cert-manager.io/issuer`, `cert-manager.io/cluster-issuer` or a true `kubernetes.io/tls-acme` (`"true"`, `"1"`, ...);
- a secret another object owns (`ownerReferences`) or another deployment tool deploys, since it would put its own
  certificate back: an `app.kubernetes.io/managed-by` label other than `nslookup-agent` (Helm sets `Helm`), Helm's
  `meta.helm.sh/release-name` annotation, or a label or annotation starting with `argocd.argoproj.io/`,
  `kustomize.toolkit.fluxcd.io/` or `helm.toolkit.fluxcd.io/`;
- a secret of another type than `kubernetes.io/tls`, or an immutable one.

One case it cannot see: a cert-manager `Certificate` whose secret does not exist yet and whose Ingress does not carry
one of the `cert-manager.io/` annotations above. The agent treats that host as one without TLS and, if you take it
over, creates the secret; cert-manager then finds a secret it did not make and may overwrite it. If cert-manager
manages a host, annotate the Ingress (`cert-manager.io/cluster-issuer` or `cert-manager.io/issuer`) before you use
Autopilot on it.

It connects with its pod's service account (outside the cluster: `KUBECONFIG`) and needs Ingresses `get`, `list`,
`watch` and Secrets `get`, `create`, `update`, `patch`, nothing else. Its identity is the Secret
`nslookup-agent-identity` in its own namespace (`POD_NAMESPACE`), created once when it joins and never replaced: delete
it to join again. Removing the agent leaves the TLS secrets it wrote as they are.

### agent.yaml

Every field is optional. The folder, the hook command, the containers and the HAProxy files come only from this file
(and a Docker agent's environment), never from the server, so the agent refuses the file unless it and the directory
it is in belong to root (or the user the agent runs as) and only their owner can change them.

```yaml
server: https://agents.nslookup.io
name: web-1
folder:
  root: /etc/ssl/nslookup          # folder certificates are written under it, one directory each
  hook: systemctl reload postfix   # runs after one is written
docker:
  reloadContainers: [nginx]        # signalled through the Docker socket after one is written
  signal: HUP                      # the default
haproxy:
  configs: [/etc/haproxy/conf.d]   # read besides /etc/haproxy/haproxy.cfg: files, or directories of *.cfg files
```

## Building

Go 1.24 or later.

```sh
make test    # go test ./...
make lint    # go vet ./...
make build
sh scripts/check-chart.sh                         # the Helm chart (needs helm)
sh scripts/test-install.sh                        # install.sh, with stubs: no network, no root
docker build --build-arg VERSION=1.2.3 -t nslookup-agent .
```

A tag `v<version>` releases it (`.github/workflows/release.yml`, `.goreleaser.yaml`): the workflow runs the tests in
a job of its own, without write permissions, then builds, signs and publishes.

Before a release:

- Run `goreleaser check` and `goreleaser release --snapshot --clean`, and push a tag to a fork first.
- A pre-release tag (`v1.0.0-rc.1`) counts as older than its version (`1.0.0`): a server whose minimum agent version
  is `1.0.0` sends such an agent no work. Test a release candidate against a server whose minimum is below it.
- Install it for real with `install.sh` on Debian or Ubuntu and on Rocky Linux with SELinux enforcing, and check the
  image and `checksums.txt` with `cosign` exactly as above.

## Security

See [SECURITY.md](SECURITY.md) to report a vulnerability.

## License

Apache License 2.0, see [LICENSE](LICENSE).
