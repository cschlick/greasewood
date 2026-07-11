#!/usr/bin/env bash
#
# greasewood uninstaller — removes ALL greasewood state from this host, WITHOUT
# needing the `gw` binary (use this when gw was already removed, or a `gw purge`
# won't run). It mirrors what `gw purge` does; prefer `gw purge` when gw is still
# installed (it's config-aware).
#
# SURGICAL: touches only greasewood's own artifacts — gw-* interfaces,
# greasewood_* nftables tables, the door routing table (51820), the greasewood@
# systemd units, /etc/greasewood_*.toml, /var/lib/greasewood_*, /opt/greasewood.
# It never touches your OTHER WireGuard (an old wg0 hub-and-spoke, /etc/wireguard,
# Tailscale, …) or anything else.
#
# Usage:  sudo ./scripts/uninstall.sh        (prompts)
#         sudo ./scripts/uninstall.sh -y     (no prompt)
set -u

[ "$(id -u)" = 0 ] || { echo "run as root: sudo bash $0"; exit 1; }
[ "$(uname -s)" = "Linux" ] || { echo "greasewood is Linux-only"; exit 1; }

yes=0
case "${1:-}" in -y|--yes) yes=1;; esac
if [ "$yes" -ne 1 ]; then
    printf 'Remove ALL greasewood state from this host? [y/N] '
    read -r a; case "$a" in y|Y) ;; *) echo "aborted."; exit 1;; esac
fi

removed() { echo "  - $*"; }

echo "service:"
systemctl stop 'greasewood@*.service' 2>/dev/null
for u in $(systemctl list-units --all --plain --no-legend 'greasewood@*.service' 2>/dev/null | awk '{print $1}'); do
    systemctl disable "$u" 2>/dev/null && removed "disabled $u"
done
rm -f  /etc/systemd/system/*.wants/greasewood@*.service
rm -f  /etc/systemd/system/greasewood@.service
rm -rf /etc/systemd/system/greasewood@*.service.d
systemctl daemon-reload
systemctl reset-failed 'greasewood@*' 2>/dev/null
removed "systemd units"

echo "wireguard interfaces (gw-* only):"
for i in $(ip -o link show type wireguard 2>/dev/null | awk -F': ' '{print $2}' | cut -d@ -f1 | grep '^gw-'); do
    ip link del "$i" && removed "deleted $i"
done

echo "door isolation routing (table 51820):"
while ip -6 rule list 2>/dev/null | grep -q 51820; do ip -6 rule del table 51820 2>/dev/null || break; done
ip -6 route flush table 51820 2>/dev/null

if command -v nft >/dev/null 2>&1; then
    echo "nftables (greasewood_* tables):"
    for t in $(nft list tables inet 2>/dev/null | awk '/greasewood_/{print $3}'); do
        nft delete table inet "$t" && removed "deleted table inet $t"
    done
fi

echo "/etc/hosts managed block:"
if grep -q '# BEGIN greasewood ' /etc/hosts 2>/dev/null; then
    cp -a /etc/hosts /etc/hosts.gw-uninstall.bak
    # temp in /etc (never /tmp), and `cat >` rewrites in place so /etc/hosts
    # keeps its inode + perms.
    sed '/# BEGIN greasewood /,/# END greasewood /d' /etc/hosts > /etc/hosts.gwtmp \
        && cat /etc/hosts.gwtmp > /etc/hosts
    rm -f /etc/hosts.gwtmp
    removed "removed greasewood block (backup: /etc/hosts.gw-uninstall.bak)"
fi

echo "files:"
rm -f  /etc/greasewood_*.toml 2>/dev/null
rm -rf /var/lib/greasewood_*  2>/dev/null
rm -f  /usr/local/bin/gw
rm -rf /opt/greasewood
removed "configs, /var/lib/greasewood_*, /opt/greasewood, /usr/local/bin/gw"

echo
echo "done — greasewood fully removed. Your other WireGuard was left untouched."
echo "a source checkout (if you did a --dev install) is yours to delete: rm -rf ~/greasewood"
echo "if this host was a mesh node, also revoke it from the anchor:  sudo gw revoke <hostname>"
