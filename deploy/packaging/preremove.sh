#!/bin/sh
# Before the .deb or .rpm is removed (not upgraded: dpkg passes "remove", rpm 0 packages left): the agent stops. What
# it keeps in /var/lib/nslookup-agent stays; certbot/ and previous/ give sites back to certbot and roll back.
case "${1-}" in
remove | 0)
	if [ -d /run/systemd/system ]; then
		systemctl disable --now nslookup-agent >/dev/null 2>&1 || :
	fi
	;;
esac
