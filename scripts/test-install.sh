#!/bin/sh
# Tests install.sh without a network, without root and without changing this machine: uname, id, curl and
# systemctl are stubs, and so are install, mv and the agent's join, which must never run here (a call is logged and
# fails); stat reports root as the owner when STUB_ROOT is set. Covers the --dry-run plan, both forms of every
# flag, the refusals, the join code from --join, from --join-file and from the terminal (with python3: install.sh runs
# on a pseudo-terminal, or without any terminal), and a download whose checksum does not match. The join code must
# never be printed, echoed on the terminal or passed on a command line.
#
# Run from anywhere: sh scripts/test-install.sh (INSTALL_SH=dash runs install.sh with dash; default /bin/sh)
set -eu

script=$(cd "$(dirname "$0")/.." && pwd)/install.sh
code=nsj_installtest0123456789abcdef
shell=$(command -v "${INSTALL_SH:-sh}")

tmp=$(mktemp -d)
tmp=$(cd -P "$tmp" && pwd -P)
joins=
trap 'rm -rf "$tmp" ${joins:+"$joins"}' EXIT
trap 'exit 1' INT TERM

failures=0
fail() {
	printf 'FAIL: %s\n' "$*" >&2
	failures=$((failures + 1))
}

stubs=$tmp/bin
mkdir "$stubs"
cat >"$stubs/uname" <<'EOF'
#!/bin/sh
case ${1-} in
-m) echo "${STUB_ARCH:-x86_64}" ;;
*) echo "${STUB_OS:-Linux}" ;;
esac
EOF
cat >"$stubs/id" <<'EOF'
#!/bin/sh
echo "${STUB_UID:-0}"
EOF
# curl: -o FILE gets $STUB_FILES/<the URL's last part>; -w prints $STUB_LATEST. Each URL is logged.
cat >"$stubs/curl" <<'EOF'
#!/bin/sh
out= write= url=
while [ $# -gt 0 ]; do
	case $1 in
	-o) out=$2; shift ;;
	-w) write=$2; shift ;;
	--proto | --retry | --connect-timeout | --max-time) shift ;;
	-*) ;;
	*) url=$1 ;;
	esac
	shift
done
echo "curl $url" >>"$STUB_LOG"
if [ -n "$write" ]; then
	printf '%s' "$STUB_LATEST"
	exit 0
fi
[ -f "$STUB_FILES/${url##*/}" ] || exit 22
cat "$STUB_FILES/${url##*/}" >"$out"
EOF
for cmd in systemctl install mv; do
	printf '#!/bin/sh\necho "%s $*" >>"$STUB_LOG"\nexit 1\n' "$cmd" >"$stubs/$cmd"
done
# stat: as it is, but its first field (install.sh asks for the owner first) is root (uid 0) when STUB_ROOT=all, or
# for a folder when STUB_ROOT=dirs: a test cannot make root's files.
cat >"$stubs/stat" <<'EOF'
#!/bin/sh
for last; do :; done
case ${STUB_ROOT-} in
all) ;;
dirs) [ -d "${last-}" ] || exec "$STUB_REAL_STAT" "$@" ;;
*) exec "$STUB_REAL_STAT" "$@" ;;
esac
out=$("$STUB_REAL_STAT" "$@") || exit $?
printf '%s\n' "$out" | sed 's/^[0-9][0-9]*/0/'
EOF
chmod +x "$stubs"/*

# term.py none OUT COMMAND...: COMMAND with no terminal at all (a new session), its output in OUT.
# term.py tty OUT TRANSCRIPT TYPED COMMAND...: COMMAND on a pseudo-terminal of its own, with stdin not the terminal (as
# in curl ... | sudo sh); TYPED and a line break are typed once the terminal asks for the join code; what the terminal
# showed goes to TRANSCRIPT, the output to OUT.
cat >"$tmp/term.py" <<'EOF'
import os, pty, select, subprocess, sys, time

def code(status):
    return os.WEXITSTATUS(status) if os.WIFEXITED(status) else 128 + os.WTERMSIG(status)

def none(out, argv):
    with open(out, 'wb') as f:
        p = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=f, stderr=subprocess.STDOUT, start_new_session=True)
        try:
            return p.wait(timeout=60)
        except subprocess.TimeoutExpired:
            p.kill()
            return 124

def tty(out, transcript, typed, argv):
    pid, fd = pty.fork()
    if pid == 0:
        os.dup2(0, 9)  # the terminal stays open, as under the user's shell
        null = os.open(os.devnull, os.O_RDONLY)
        o = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        os.dup2(null, 0)
        os.dup2(o, 1)
        os.dup2(o, 2)
        os.execvp(argv[0], argv)
    seen, sent, status = b'', False, None
    deadline = time.time() + 60
    while status is None and time.time() < deadline:
        if select.select([fd], [], [], 0.05)[0]:
            try:
                seen += os.read(fd, 4096)
            except OSError:
                time.sleep(0.05)
        if not sent and b'Paste the join code' in seen:
            os.write(fd, typed.encode() + b'\n')
            sent = True
        done, st = os.waitpid(pid, os.WNOHANG)
        if done:
            status = st
    if status is None:
        os.kill(pid, 9)
        os.waitpid(pid, 0)
        result = 124
    else:
        result = code(status)
    while select.select([fd], [], [], 0.1)[0]:
        try:
            data = os.read(fd, 4096)
        except OSError:
            break
        if not data:
            break
        seen += data
    with open(transcript, 'wb') as f:
        f.write(seen)
    return result

if sys.argv[1] == 'none':
    sys.exit(none(sys.argv[2], sys.argv[3:]))
sys.exit(tty(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5:]))
EOF
python=$(command -v python3 || true)

# Only the stubs: no curl.
nocurl=$tmp/nocurl
mkdir "$nocurl"
cp "$stubs/uname" "$stubs/id" "$stubs/systemctl" "$nocurl/"

# The release files the curl stub serves: an archive and a checksums.txt that does not match it.
files=$tmp/files
mkdir "$files" "$tmp/archive"
printf '#!/bin/sh\necho "agent $*" >>"$STUB_LOG"\n' >"$tmp/archive/nslookup-agent"
printf '[Service]\n' >"$tmp/archive/nslookup-agent.service"
for v in 1.2.3 9.8.7; do
	(cd "$tmp/archive" && tar -czf "$files/nslookup-agent_${v}_linux_amd64.tar.gz" nslookup-agent nslookup-agent.service)
done
printf '%064d  nslookup-agent_1.2.3_linux_amd64.tar.gz\n%064d  nslookup-agent_9.8.7_linux_amd64.tar.gz\n' 0 0 >"$files/checksums.txt"

export STUB_LOG="$tmp/log" STUB_FILES="$files" STUB_LATEST=https://github.com/nslookup-io/agent/releases/tag/v9.8.7
export STUB_REAL_STAT="$(command -v stat)"

# run WHAT ENV... -- ARGS...: install.sh with PATH starting with the stubs. With terminal=none it runs without a
# terminal, with terminal=tty on a terminal where $typed is typed when it asks (both need python3).
terminal=
typed=
run() {
	what=$1
	shift
	envs=
	while [ $# -gt 0 ] && [ "$1" != -- ]; do
		envs="$envs $1"
		shift
	done
	[ $# -gt 0 ] && shift
	: >"$tmp/log"
	: >"$tmp/transcript"
	status=0
	# Each word of $envs is one VAR=value.
	set -- env PATH="${STUB_PATH:-$stubs:$PATH}" $envs "$shell" "$script" "$@"
	case $terminal in
	'') "$@" >"$tmp/out" 2>&1 || status=$? ;;
	none) "$python" "$tmp/term.py" none "$tmp/out" "$@" || status=$? ;;
	tty) "$python" "$tmp/term.py" tty "$tmp/out" "$tmp/transcript" "$typed" "$@" || status=$? ;;
	esac
	if grep -q "$code" "$tmp/out" "$tmp/log" "$tmp/transcript"; then
		fail "$what: the join code was printed, shown on the terminal or passed on a command line"
	fi
}

# has WHAT TEXT: the output holds TEXT.
has() {
	grep -qF -- "$2" "$tmp/out" || fail "$1: the output does not say: $2
$(sed 's/^/  | /' "$tmp/out")"
}

# exits WHAT STATUS
exits() {
	[ "$status" = "$2" ] || fail "$1: exit status $status, want $2
$(sed 's/^/  | /' "$tmp/out")"
}

# nothing_ran WHAT: no download, no install, no systemctl, no join.
nothing_ran() {
	if [ -s "$tmp/log" ]; then
		fail "$1: it ran: $(cat "$tmp/log")"
	fi
}

release=https://github.com/nslookup-io/agent/releases/download

## --dry-run: the plan, and nothing done.

run "dry run" NSL_VERSION=1.2.3 -- --dry-run --join="$code" --name web-1 --server=https://agents.example.test
exits "dry run" 0
has "dry run" "Dry run: nothing is downloaded or changed."
has "dry run" "This machine: Linux amd64."
has "dry run" "Would download $release/v1.2.3/checksums.txt"
has "dry run" "Would download $release/v1.2.3/nslookup-agent_1.2.3_linux_amd64.tar.gz"
has "dry run" "Would install /usr/local/bin/nslookup-agent (0755) and /etc/systemd/system/nslookup-agent.service (0644)"
has "dry run" "Would create /var/lib/nslookup-agent (0700) and /etc/nslookup-agent (0755)"
has "dry run" "Would run: /usr/local/bin/nslookup-agent join --name=web-1 --server=https://agents.example.test (with the join code in its environment, NSL_JOIN)"
has "dry run" "Would run: systemctl daemon-reload; systemctl enable nslookup-agent; systemctl restart nslookup-agent"
nothing_ran "dry run"

# The other form of each flag, a value starting with a dash, arm64, a version with a v, and not root.
run "dry run, arm64" STUB_ARCH=aarch64 STUB_UID=1000 NSL_VERSION=v2.0.0-rc.1 -- --join "$code" --name=-web --server https://agents.example.test --dry-run
exits "dry run, arm64" 0
has "dry run, arm64" "This machine: Linux arm64."
has "dry run, arm64" "Not root: the real run needs root (sudo)."
has "dry run, arm64" "Would download $release/v2.0.0-rc.1/nslookup-agent_2.0.0-rc.1_linux_arm64.tar.gz"
has "dry run, arm64" "join --name=-web --server=https://agents.example.test (with"
nothing_ran "dry run, arm64"

# The latest release, found when it runs.
run "dry run, latest" -- --dry-run --join "$code"
exits "dry run, latest" 0
has "dry run, latest" "Would find the latest release: https://github.com/nslookup-io/agent/releases/latest"
has "dry run, latest" "Would run: /usr/local/bin/nslookup-agent join (with the join code in its environment, NSL_JOIN)"
nothing_ran "dry run, latest"

## Refusals, each before anything runs.

run "macOS" STUB_OS=Darwin -- --join "$code"
exits "macOS" 1
has "macOS" "this script installs the agent on Linux only, not on Darwin"
nothing_ran "macOS"

run "32-bit ARM" STUB_ARCH=armv7l -- --join "$code"
exits "32-bit ARM" 1
has "32-bit ARM" "there is no agent for armv7l"
nothing_ran "32-bit ARM"

run "not root" STUB_UID=1000 -- --join "$code"
exits "not root" 1
has "not root" "run it as root"
nothing_ran "not root"

STUB_PATH=$nocurl
run "no curl" -- --join "$code" --dry-run
STUB_PATH=
exits "no curl" 1
has "no curl" "curl is missing"
nothing_ran "no curl"

run "--join and --join-file" -- --join "$code" --join-file /etc/nslookup-agent/join
exits "--join and --join-file" 1
has "--join and --join-file" "give the join code with --join or with --join-file, not both"

run "an empty --join-file" -- --join-file=
exits "an empty --join-file" 1
has "an empty --join-file" "--join-file needs a path"

run "--remove-join-file alone" -- --join "$code" --remove-join-file
exits "--remove-join-file alone" 1
has "--remove-join-file alone" "--remove-join-file goes with --join-file"

run "an empty --join" NSL_VERSION=1.2.3 -- --join=" "
exits "an empty --join" 1
has "an empty --join" "the join code from --join is empty"
nothing_ran "an empty --join"

run "a flag without its value" -- --name web-1 --join
exits "a flag without its value" 1
has "a flag without its value" "--join needs a value"

run "a misspelt flag" -- --jion="$code"
exits "a misspelt flag" 1
has "a misspelt flag" "unknown flag --jion"
nothing_ran "a misspelt flag"

run "the code alone" -- "$code"
exits "the code alone" 1
has "the code alone" "unexpected argument; give the join code as --join <code>"

run "a bad version" NSL_VERSION=latest -- --join "$code"
exits "a bad version" 1
has "a bad version" "NSL_VERSION must be a release version"
nothing_ran "a bad version"

## A download whose checksum does not match: nothing is installed.

run "checksum mismatch" NSL_VERSION=1.2.3 -- --join "$code"
exits "checksum mismatch" 1
has "checksum mismatch" "checksum mismatch: nslookup-agent_1.2.3_linux_amd64.tar.gz has SHA-256"
has "checksum mismatch" "checksums.txt says 0000000000000000000000000000000000000000000000000000000000000000; nothing was installed"
expect="curl $release/v1.2.3/checksums.txt
curl $release/v1.2.3/nslookup-agent_1.2.3_linux_amd64.tar.gz"
[ "$(cat "$tmp/log")" = "$expect" ] || fail "checksum mismatch: it ran more than the two downloads: $(cat "$tmp/log")"

# The latest release: both files come from it.
run "latest, checksum mismatch" -- --join "$code"
exits "latest, checksum mismatch" 1
has "latest, checksum mismatch" "Downloading the agent 9.8.7 for linux/amd64"
expect="curl https://github.com/nslookup-io/agent/releases/latest
curl $release/v9.8.7/checksums.txt
curl $release/v9.8.7/nslookup-agent_9.8.7_linux_amd64.tar.gz"
[ "$(cat "$tmp/log")" = "$expect" ] || fail "latest: want the latest release's two downloads, got: $(cat "$tmp/log")"

# checksums.txt without a line for the archive.
printf '%064d  something-else.tar.gz\n' 0 >"$files/checksums.txt"
run "no checksum line" NSL_VERSION=1.2.3 -- --join "$code"
exits "no checksum line" 1
has "no checksum line" "checksums.txt of 1.2.3 has no line for nslookup-agent_1.2.3_linux_amd64.tar.gz; nothing was installed"

## The join code from --join: its length (never the code) is said, so a paste can be checked.

printf '%064d  nslookup-agent_1.2.3_linux_amd64.tar.gz\n%064d  nslookup-agent_9.8.7_linux_amd64.tar.gz\n' 0 0 >"$files/checksums.txt"
run "--join" NSL_VERSION=1.2.3 -- --join "$code"
has "--join" "Join code: from --join (${#code} characters)"

## The join code from a file: root's, readable by root only, one name, in folders only root can change; read once,
## trimmed; deleted only after a join.

# private_chain DIR: no folder from DIR up to / can be written by its group or others, or is sticky (install.sh's rule
# for the folders of a join file, owners aside, which the stat stub makes root).
private_chain() {
	d=$(cd -P -- "$1" && pwd -P) || return 1
	while :; do
		case $(/bin/ls -ld -- "$d" | awk '{ print $1 }') in
		d????[!w]??[!w][!tT]*) ;;
		*) return 1 ;;
		esac
		[ "$d" != / ] || return 0
		d=${d%/*}
		[ -n "$d" ] || d=/
	done
}
# The join files go where their folders pass: the temporary folder (not under /tmp, which anyone can write in), else
# the home folder.
for base in "$tmp" "${HOME-}"; do
	if [ -n "$base" ] && private_chain "$base"; then
		joins=$(mktemp -d "$base/nslookup-join-test.XXXXXX")
		joins=$(cd -P "$joins" && pwd -P)
		break
	fi
done

if [ -z "$joins" ]; then
	echo "skipped: the join file checks need a folder that only its owner can change (not under /tmp)" >&2
else
	(
		umask 077
		printf '  %s\n\n' "$code" >"$joins/good"
		printf '\n' >"$joins/empty"
		printf '%s\n' "$code" >"$joins/linked"
		ln "$joins/linked" "$joins/linked-too"
		mkdir "$joins/shared" "$joins/open" "$joins/sticky"
		printf '%s\n' "$code" >"$joins/shared/join"
		printf '%s\n' "$code" >"$joins/open/join"
		printf '%s\n' "$code" >"$joins/sticky/join"
		chmod 0770 "$joins/shared"
		chmod 0703 "$joins/open"
		chmod 1700 "$joins/sticky"
	)
	(umask 022 && printf '%s\n' "$code" >"$joins/readable")
	ln -s "$joins/good" "$joins/link"

	STUB_ROOT=all
	export STUB_ROOT
	run "--join-file, dry run" NSL_VERSION=1.2.3 -- --dry-run --join-file "$joins/good" --remove-join-file --name web-1
	exits "--join-file, dry run" 0
	has "--join-file, dry run" "Join code: from the file $joins/good (${#code} characters)"
	has "--join-file, dry run" "Would run: /usr/local/bin/nslookup-agent join --name=web-1 (with the join code in its environment, NSL_JOIN)"
	has "--join-file, dry run" "Would delete $joins/good once the agent has joined, if it is still the file read"
	nothing_ran "--join-file, dry run"
	[ -f "$joins/good" ] || fail "--join-file, dry run: the file was deleted"

	# A relative path, through a link to its folder: the folders checked are the real ones.
	ln -s "$joins" "$tmp/joins-link"
	here=$(pwd)
	cd "$tmp"
	run "--join-file, relative" NSL_VERSION=1.2.3 -- --dry-run --join-file joins-link/good
	cd "$here"
	exits "--join-file, relative" 0
	has "--join-file, relative" "Join code: from the file joins-link/good (${#code} characters)"

	# Not joined (the checksum fails first): the file stays.
	run "--join-file=, checksum mismatch" NSL_VERSION=1.2.3 -- --join-file="$joins/good" --remove-join-file
	exits "--join-file=, checksum mismatch" 1
	has "--join-file=, checksum mismatch" "Join code: from the file $joins/good (${#code} characters)"
	has "--join-file=, checksum mismatch" "checksum mismatch"
	[ -f "$joins/good" ] || fail "--join-file=, checksum mismatch: the file was deleted though the agent did not join"

	run "a readable join file" NSL_VERSION=1.2.3 -- --join-file "$joins/readable"
	exits "a readable join file" 1
	has "a readable join file" "$joins/readable can be read or changed by users other than root (chmod 600 $joins/readable)"
	nothing_ran "a readable join file"

	run "a join file with two names" NSL_VERSION=1.2.3 -- --join-file "$joins/linked"
	exits "a join file with two names" 1
	has "a join file with two names" "$joins/linked has other names (hard links): give a file of its own"
	nothing_ran "a join file with two names"

	run "a join file in a group's folder" NSL_VERSION=1.2.3 -- --join-file "$joins/shared/join"
	exits "a join file in a group's folder" 1
	has "a join file in a group's folder" "$joins/shared can be changed by users other than root: put the join file in a folder only root can change, e.g. /root"
	nothing_ran "a join file in a group's folder"

	run "a join file in a folder others can write in" NSL_VERSION=1.2.3 -- --join-file "$joins/open/join"
	exits "a join file in a folder others can write in" 1
	has "a join file in a folder others can write in" "$joins/open can be changed by users other than root: put the join file in a folder only root can change, e.g. /root"
	nothing_ran "a join file in a folder others can write in"

	run "a join file in a sticky folder" NSL_VERSION=1.2.3 -- --join-file "$joins/sticky/join"
	exits "a join file in a sticky folder" 1
	has "a join file in a sticky folder" "$joins/sticky can be changed by users other than root: put the join file in a folder only root can change, e.g. /root"
	nothing_ran "a join file in a sticky folder"

	run "a join file behind a link" NSL_VERSION=1.2.3 -- --join-file "$joins/link"
	exits "a join file behind a link" 1
	has "a join file behind a link" "$joins/link is a symbolic link"
	nothing_ran "a join file behind a link"

	run "a missing join file" NSL_VERSION=1.2.3 -- --join-file "$joins/missing"
	exits "a missing join file" 1
	has "a missing join file" "$joins/missing is not a file"
	nothing_ran "a missing join file"

	run "an empty join file" NSL_VERSION=1.2.3 -- --join-file "$joins/empty"
	exits "an empty join file" 1
	has "an empty join file" "the join code from the file $joins/empty is empty"
	nothing_ran "an empty join file"

	STUB_ROOT=dirs
	run "a join file of another user" NSL_VERSION=1.2.3 -- --join-file "$joins/good"
	exits "a join file of another user" 1
	has "a join file of another user" "$joins/good must belong to root (chown root $joins/good)"
	nothing_ran "a join file of another user"

	STUB_ROOT=
	run "a folder of another user" NSL_VERSION=1.2.3 -- --join-file "$joins/good"
	exits "a folder of another user" 1
	has "a folder of another user" "$joins can be changed by users other than root: put the join file in a folder only root can change, e.g. /root"
	nothing_ran "a folder of another user"
fi

## The join code from the terminal, when neither --join nor --join-file is given.

if [ -z "$python" ]; then
	echo "skipped: the terminal checks need python3" >&2
else
	terminal=none
	run "no terminal" NSL_VERSION=1.2.3 -- --name web-1
	exits "no terminal" 1
	has "no terminal" "no join code: pass --join <code> or --join-file <path> (there is no terminal to ask on)"
	nothing_ran "no terminal"

	terminal=tty
	typed="  $code "
	run "the terminal" NSL_VERSION=1.2.3 -- --name web-1
	exits "the terminal" 1
	grep -qF "Paste the join code from the portal:" "$tmp/transcript" ||
		fail "the terminal: it did not ask for the join code: $(cat "$tmp/transcript")"
	has "the terminal" "Join code: from this terminal (${#code} characters)"
	has "the terminal" "checksum mismatch"

	typed=
	run "nothing pasted" NSL_VERSION=1.2.3 -- --name web-1
	exits "nothing pasted" 1
	has "nothing pasted" "the join code from this terminal is empty"
	nothing_ran "nothing pasted"

	typed=$code
	run "a dry run does not ask" NSL_VERSION=1.2.3 -- --dry-run
	exits "a dry run does not ask" 0
	has "a dry run does not ask" "Would ask for the join code on this terminal (what you paste is not shown)"
	if grep -qF "Paste the join code" "$tmp/transcript"; then
		fail "a dry run does not ask: it asked"
	fi
	terminal=
	typed=
fi

## The join code reaches the agent only through its environment (it is never on a command line): every other use of
## $join in install.sh sets it or tests whether it is empty. (A join cannot run here, so this is read, not run.)

uses=$(grep -nE '\$\{?join([^e_]|$)' "$script" | grep -vE '^[0-9]+:[[:space:]]*join=' | grep -vF '[ -z "$join' |
	grep -vF '[ -n "$join' | grep -vF 'NSL_JOIN=$join "$bin" "$@"' || true)
[ -z "$uses" ] || fail "install.sh uses the join code other than in NSL_JOIN: $uses"
join_at=$(grep -nF 'NSL_JOIN=$join "$bin" "$@"' "$script" | cut -d: -f1)
[ -n "$join_at" ] || fail "install.sh must join with the code in NSL_JOIN"
# The join file is deleted once, after the join, and only while its path is still the file read (a join cannot run
# here, so this is read, not run): same_join_file compares the device and inode remembered from the descriptor.
rm_at=$(grep -nF 'rm -f -- "$join_path"' "$script" | cut -d: -f1)
if [ "$(printf '%s\n' "$rm_at" | grep -c .)" != 1 ] || [ "${rm_at:-0}" -le "${join_at:-0}" ]; then
	fail "install.sh must delete the join file once, after the join"
elif [ "$(sed -n "$((rm_at - 1))p" "$script" | tr -d '\t')" != 'if same_join_file; then' ]; then
	fail "install.sh must delete the join file only after same_join_file"
fi
same=$(awk '/^same_join_file\(\) \{$/ { on = 1; next } on && /^\}$/ { exit } on' "$script")
case $same in
*'[ ! -L "$join_path" ]'*'"$4 $5" = "$join_id"'*) ;;
*) fail "same_join_file must refuse a link and compare the device and inode: $same" ;;
esac
# The file is opened once, and checked and read through that descriptor.
grep -qF 'exec 4<"$join_path"' "$script" || fail "install.sh must open the join file once, as descriptor 4"
grep -qF 'join=$(cat <&4)' "$script" || fail "install.sh must read the join code from descriptor 4"
grep -qF 'set -- $(fd_facts)' "$script" || fail "install.sh must check the join file's owner, mode and links on descriptor 4"
if grep -nE 'cat [^|<]*\$join_(file|path)' "$script"; then
	fail "install.sh must not read the join file by its path"
fi

## Every download is HTTPS only (redirects too), TLS 1.2 or later, and time-limited.

fetch=$(awk '/^fetch\(\) \{$/ { on = 1; next } on && /^\}$/ { exit } on' "$script")
for want in "--proto '=https'" "--tlsv1.2" "--max-time "; do
	case $fetch in
	*"$want"*) ;;
	*) fail "fetch must use $want: $fetch" ;;
	esac
done

if [ "$failures" -gt 0 ]; then
	printf '%d check(s) failed\n' "$failures" >&2
	exit 1
fi
echo "install.sh checks passed"
