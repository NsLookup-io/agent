#!/bin/sh
# After the .deb or .rpm is installed or upgraded: systemd reads the unit again, and an agent that runs restarts on
# the new binary. A first install starts nothing: join first (nslookup-agent join <code>), then
# systemctl enable --now nslookup-agent.
if [ -d /run/systemd/system ]; then
	systemctl daemon-reload >/dev/null 2>&1 || :
	if systemctl is-active --quiet nslookup-agent; then
		systemctl restart nslookup-agent || :
	fi
fi
