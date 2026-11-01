#!/bin/sh
# Installs the nslookup.io agent on a Linux server, or updates it. Run it as root:
#
#   curl -fsSL https://github.com/nslookup-io/agent/releases/latest/download/install.sh | sudo sh -s -- --join <code>
#
# Flags, each as --flag=value or as --flag value:
#   --join <code>        the join code from the portal
#   --join-file <path>   the file holding the join code instead (root's, readable by root only, in a folder only
#                        root can change, such as /root)
#   --remove-join-file   delete that file once the agent has joined
#   --name <name>        the agent's name in the portal (default: the name given with the join code, else the host name)
#   --server <url>       the nslookup.io server, when it is not https://agents.nslookup.io
#   --dry-run            print what it would do; nothing is downloaded or changed
#
# Without --join or --join-file it asks for the join code on the terminal, and what you paste is not shown. A server
# that has joined needs no code: then it only updates the agent.
#
# --join <code> is visible to other users of this machine while the install runs (in the process list) and is kept in
# sudo's log. On a shared server, run it without --join and paste the code when asked, or use --join-file. (In
# Docker, prefer --env-file to -e NSL_JOIN=; with Helm, existingJoinSecret to joinCode: see the README.)
#
# NSL_VERSION=1.2.0 installs that release instead of the latest.
#
# What it does: it downloads the agent's archive for this machine (amd64 or arm64) and checksums.txt from the same
# release on GitHub, checks the archive's SHA-256, installs /usr/local/bin/nslookup-agent and the systemd unit
# /etc/systemd/system/nslookup-agent.service, creates /var/lib/nslookup-agent and /etc/nslookup-agent, joins with the
# code (once; the agent gets it only in its environment, as NSL_JOIN), then enables and restarts the service
# nslookup-agent.
#
# Everything runs inside main, so a shell reading this script from a pipe has read all of it before anything runs.

set -eu

repo=https://github.com/nslookup-io/agent
bin=/usr/local/bin/nslookup-agent
unit=/etc/systemd/system/nslookup-agent.service
state=/var/lib/nslookup-agent
conf=/etc/nslookup-agent

say() {
	printf '%s\n' "$*"
}

die() {
	printf 'nslookup-agent install: %s\n' "$*" >&2
	exit 1
}

# fetch [curl arguments]: an HTTPS download (redirects too) that fails on an HTTP error and gives up after 5 minutes.
fetch() {
	curl --proto '=https' --tlsv1.2 -fsSL --retry 3 --connect-timeout 20 --max-time 300 "$@"
}

# cleanup: on the way out, the terminal shows what is typed again and the downloads are deleted.
cleanup() {
	if [ -n "$tty_saved" ]; then
		stty "$tty_saved" </dev/tty 2>/dev/null || :
		printf '\n' >/dev/tty 2>/dev/null || :
	fi
	[ -z "$tmp" ] || rm -rf "$tmp"
}

main() {
	join=
	join_given=
	join_file=
	join_file_given=
	remove_join_file=
	name=
	server=
	named=
	served=
	dry_run=
	tmp=
	tty_saved=
	trap cleanup EXIT
	trap 'exit 1' HUP INT TERM
	while [ $# -gt 0 ]; do
		case $1 in
		--join=*) join=${1#*=} join_given=1 ;;
		--join-file=*) join_file=${1#*=} join_file_given=1 ;;
		--name=*) name=${1#*=} named=1 ;;
		--server=*) server=${1#*=} served=1 ;;
		--join | --join-file | --name | --server)
			[ $# -ge 2 ] || die "$1 needs a value"
			case $1 in
			--join) join=$2 join_given=1 ;;
			--join-file) join_file=$2 join_file_given=1 ;;
			--name) name=$2 named=1 ;;
			--server) server=$2 served=1 ;;
			esac
			shift
			;;
		--remove-join-file) remove_join_file=1 ;;
		--dry-run) dry_run=1 ;;
		-h | --help)
			say "Usage: install.sh [--join <code> | --join-file <path> [--remove-join-file]] [--name <name>] [--server <url>] [--dry-run]"
			say "Without --join or --join-file it asks for the join code on the terminal. See $repo#install"
			return 0
			;;
		# Never the value: it could be a join code typed after a misspelt flag.
		-*) die "unknown flag ${1%%=*} (the flags are --join, --join-file, --remove-join-file, --name, --server and --dry-run)" ;;
		*) die "unexpected argument; give the join code as --join <code>, or leave it out to be asked for it" ;;
		esac
		shift
	done
	[ -z "$join_file_given" ] || [ -n "$join_file" ] || die "--join-file needs a path"
	[ -z "$join_given" ] || [ -z "$join_file" ] || die "give the join code with --join or with --join-file, not both"
	[ -z "$remove_join_file" ] || [ -n "$join_file" ] || die "--remove-join-file goes with --join-file"
	[ -z "$dry_run" ] || say "Dry run: nothing is downloaded or changed."

	os=$(uname -s)
	[ "$os" = Linux ] || die "this script installs the agent on Linux only, not on $os; for Docker and Kubernetes see $repo#install"
	machine=$(uname -m)
	case $machine in
	x86_64 | amd64) arch=amd64 ;;
	aarch64 | arm64) arch=arm64 ;;
	*) die "there is no agent for $machine; there is one for x86_64 (amd64) and aarch64 (arm64)" ;;
	esac
	if [ "$(id -u)" != 0 ] && [ -z "$dry_run" ]; then
		die "run it as root: curl -fsSL $repo/releases/latest/download/install.sh | sudo sh -s -- <the same flags>"
	fi
	command -v curl >/dev/null 2>&1 || die "curl is missing: install it (apt-get install curl, or dnf install curl), then run this again"
	if command -v sha256sum >/dev/null 2>&1; then
		sum=sha256sum
	elif command -v shasum >/dev/null 2>&1; then
		sum="shasum -a 256"
	else
		die "sha256sum is missing (it checks the download): install coreutils, then run this again"
	fi
	command -v systemctl >/dev/null 2>&1 || die "systemd was not found: this script runs the agent as a systemd service; see $repo#install"

	version=${NSL_VERSION:-}
	version=${version#v}
	if [ -n "$version" ]; then
		valid_version "$version" || die "NSL_VERSION must be a release version, such as 1.2.0"
	fi

	# The join code, unless this server has joined before: from --join, from --join-file, or asked for on the terminal
	# (a dry run does not ask). It is said how long it is, never what it is.
	joined=
	[ -f "$state/identity/agent.json" ] && joined=1
	from=
	if [ -z "$joined" ]; then
		if [ -n "$join_file" ]; then
			read_join_file
			from="the file $join_file"
		elif [ -n "$join_given" ]; then
			from=--join
		elif [ -z "$dry_run" ]; then
			ask_join_code
			from="this terminal"
		fi
	fi
	if [ -n "$from" ]; then
		join=${join#"${join%%[![:space:]]*}"}
		join=${join%"${join##*[![:space:]]}"}
		[ -n "$join" ] || die "the join code from $from is empty"
		say "Join code: from $from (${#join} characters)"
	fi

	if [ -n "$dry_run" ]; then
		show_plan
		return 0
	fi

	if [ -z "$version" ]; then
		latest=$(fetch -o /dev/null -w '%{url_effective}' "$repo/releases/latest") ||
			die "could not reach $repo/releases/latest"
		case $latest in
		"$repo"/releases/tag/v*) version=${latest##*/v} ;;
		*) die "could not find the latest release at $repo/releases" ;;
		esac
		valid_version "$version" || die "the latest release, $latest, is not named like a release"
	fi
	base=$repo/releases/download/v$version
	archive=nslookup-agent_${version}_linux_${arch}.tar.gz

	tmp=$(mktemp -d)

	say "Downloading the agent $version for linux/$arch from $base"
	fetch -o "$tmp/checksums.txt" "$base/checksums.txt" || die "could not download $base/checksums.txt"
	fetch -o "$tmp/$archive" "$base/$archive" || die "could not download $base/$archive"
	want=$(awk -v f="$archive" '$2 == f || $2 == "*" f { print $1; exit }' "$tmp/checksums.txt")
	[ -n "$want" ] || die "checksums.txt of $version has no line for $archive; nothing was installed"
	got=$($sum "$tmp/$archive" | awk '{ print $1 }')
	[ "$got" = "$want" ] || die "checksum mismatch: $archive has SHA-256 $got, checksums.txt says $want; nothing was installed"
	say "Checked its SHA-256 against checksums.txt: $got"

	mkdir "$tmp/files"
	tar -xzf "$tmp/$archive" -C "$tmp/files" nslookup-agent nslookup-agent.service ||
		die "$archive does not hold nslookup-agent and nslookup-agent.service; nothing was installed"

	# Each file is written next to its place, then renamed into it: a running agent keeps its old binary meanwhile.
	install -m 0755 -o root -g root "$tmp/files/nslookup-agent" "$bin.new"
	mv -f "$bin.new" "$bin"
	install -m 0644 -o root -g root "$tmp/files/nslookup-agent.service" "$unit.new"
	mv -f "$unit.new" "$unit"
	install -d -m 0700 -o root -g root "$state"
	install -d -m 0755 -o root -g root "$conf"
	say "Installed $bin ($("$bin" version </dev/null)) and $unit"
	systemctl daemon-reload </dev/null

	if [ -n "$joined" ]; then
		say "This server has joined nslookup.io before: it keeps its identity ($state/identity)."
		[ -z "$join_given$join_file$named$served" ] || say "(The join code, --name and --server are used only to join.)"
	else
		set -- join
		[ -z "$named" ] || set -- "$@" "--name=$name"
		[ -z "$served" ] || set -- "$@" "--server=$server"
		NSL_JOIN=$join "$bin" "$@" </dev/null ||
			die "joining failed (above); the agent is installed but not started. Create a new join code in the portal, then run this again with it."
		if [ -n "$remove_join_file" ]; then
			if same_join_file; then
				rm -f -- "$join_path"
				say "Deleted $join_file"
			else
				say "Left $join_file as it is: it is no longer the file the join code was read from"
			fi
		fi
	fi

	systemctl enable --quiet nslookup-agent </dev/null
	systemctl restart nslookup-agent </dev/null
	say "The agent runs: systemctl status nslookup-agent, and its log: journalctl -u nslookup-agent"
}

# read_join_file: the join code from $join_file. Every folder from the file's own up to / must belong to root and be
# writable by root only (not sticky, as /tmp is), so no other user can swap the file or a folder on the way; the file
# must not be a link. It is opened once, as descriptor 4, and that open file must be a regular file of root's that no
# other user can read or change and that has no other name (hard link); the code is read from it. Its device and inode
# are kept in $join_id and its real path in $join_path, for same_join_file.
read_join_file() {
	if stat -c %u / >/dev/null 2>&1; then
		stat_style=gnu
	else
		stat_style=bsd
	fi
	case $join_file in
	*/*) parent=${join_file%/*} ;;
	*) parent=. ;;
	esac
	dir=$(CDPATH='' cd -P -- "${parent:-/}" 2>/dev/null && pwd -P) || die "$join_file is not a file"
	join_path=${dir%/}/${join_file##*/}
	d=$dir
	while :; do
		set -- $(file_facts "$d")
		[ $# = 5 ] || die "could not check the folder $d"
		# Root's, not sticky, and writable by root only.
		case $1:$2 in
		0:[1357]??? | 0:*[2367]? | 0:*[2367]) safe= ;;
		0:*) safe=1 ;;
		*) safe= ;;
		esac
		[ -n "$safe" ] ||
			die "$d can be changed by users other than root: put the join file in a folder only root can change, e.g. /root"
		[ "$d" != / ] || break
		d=${d%/*}
		d=${d:-/}
	done
	[ ! -L "$join_path" ] || die "$join_file is a symbolic link: give the file itself"
	[ -f "$join_path" ] || die "$join_file is not a file"
	exec 4<"$join_path"
	[ -f /dev/fd/4 ] || die "$join_file is not a file"
	set -- $(fd_facts)
	[ $# = 5 ] || die "could not check $join_file"
	[ "$1" = 0 ] || die "$join_file must belong to root (chown root $join_file)"
	case $2 in
	*00) ;;
	*) die "$join_file can be read or changed by users other than root (chmod 600 $join_file)" ;;
	esac
	[ "$3" = 1 ] || die "$join_file has other names (hard links): give a file of its own"
	join_id="$4 $5"
	join=$(cat <&4) || die "could not read $join_file"
	exec 4<&-
}

# file_facts PATH: "<owner uid> <mode, octal> <links> <device> <inode>" of PATH, following a link.
file_facts() {
	if [ "$stat_style" = gnu ]; then
		stat -L -c '%u %a %h %d %i' -- "$1"
	else
		stat -L -f '%u %Mp%Lp %l %d %i' -- "$1"
	fi
}

# fd_facts: file_facts of the file open as descriptor 4 (GNU stat through /dev/fd, BSD stat on its standard input).
fd_facts() {
	if [ "$stat_style" = gnu ]; then
		stat -L -c '%u %a %h %d %i' /dev/fd/4
	else
		stat -f '%u %Mp%Lp %l %d %i' <&4
	fi
}

# same_join_file: $join_path is still the file the join code was read from: not a link, the same device and inode.
same_join_file() {
	[ ! -L "$join_path" ] && [ -f "$join_path" ] || return 1
	set -- $(file_facts "$join_path")
	[ $# = 5 ] && [ "$4 $5" = "$join_id" ]
}

# ask_join_code: the join code, pasted on the terminal (even when this script comes through a pipe) and not shown.
ask_join_code() {
	if ! (: </dev/tty) 2>/dev/null; then
		die "no join code: pass --join <code> or --join-file <path> (there is no terminal to ask on)"
	fi
	exec 3<>/dev/tty
	tty_saved=$(stty -g <&3)
	stty -echo <&3
	printf 'Paste the join code from the portal: ' >&3
	IFS= read -r join <&3 || :
	stty "$tty_saved" <&3
	tty_saved=
	printf '\n' >&3
	exec 3>&-
}

# valid_version VERSION: x.y.z, maybe with a suffix such as -rc.1.
valid_version() {
	case $1 in
	*[!0-9A-Za-z.-]*) return 1 ;;
	[0-9]*.[0-9]*.[0-9]*) return 0 ;;
	*) return 1 ;;
	esac
}

# show_plan: what main would do, from what it has checked so far.
show_plan() {
	say "This machine: Linux $arch."
	[ "$(id -u)" = 0 ] || say "Not root: the real run needs root (sudo)."
	if [ -n "$version" ]; then
		base=$repo/releases/download/v$version
		archive=nslookup-agent_${version}_linux_${arch}.tar.gz
		say "Would install the release $version."
	else
		base="$repo/releases/download/v<version>"
		archive="nslookup-agent_<version>_linux_${arch}.tar.gz"
		say "Would find the latest release: $repo/releases/latest"
	fi
	say "Would download $base/checksums.txt"
	say "Would download $base/$archive"
	say "Would check the archive's SHA-256 against checksums.txt (with $sum)"
	say "Would install $bin (0755) and $unit (0644)"
	say "Would create $state (0700) and $conf (0755)"
	if [ -n "$joined" ]; then
		say "Would not join: this server has joined before and keeps its identity ($state/identity)"
	else
		[ -n "$from" ] || say "Would ask for the join code on this terminal (what you paste is not shown)"
		args=
		[ -z "$named" ] || args="$args --name=$name"
		[ -z "$served" ] || args="$args --server=$server"
		say "Would run: $bin join$args (with the join code in its environment, NSL_JOIN)"
		[ -z "$remove_join_file" ] || say "Would delete $join_file once the agent has joined, if it is still the file read"
	fi
	say "Would run: systemctl daemon-reload; systemctl enable nslookup-agent; systemctl restart nslookup-agent"
}

main "$@"
