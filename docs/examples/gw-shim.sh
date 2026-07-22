#!/bin/sh
# gw (macOS shim) — run greasewood's gw CLI inside the node VM, from the Mac.
#
# Install (see docs/macos.md):
#   install -m 755 gw-shim.sh /opt/homebrew/bin/gw
#
# Then `gw watch`, `gw diagnose gp2`, … just work in a Mac terminal. Commands
# run as root inside the VM, so no sudo needed on the Mac — and typing
# `sudo gw …` out of habit works too: limactl instances are per-user, so the
# shim drops back to your user for the Lima leg and stays root only inside.
set -eu

VM="${GW_VM:-greasewood-node}"

if [ "$(id -u)" = 0 ] && [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != root ]; then
    exec sudo -u "$SUDO_USER" -- "$0" "$@"
fi

limactl list --format '{{.Status}}' "$VM" 2>/dev/null | grep -q '^Running$' \
    || { echo "gw: node VM '$VM' is not running — start it with: gw-mac" >&2; exit 1; }

exec limactl shell "$VM" -- sudo gw "$@"
