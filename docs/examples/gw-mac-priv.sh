#!/bin/sh
# gw-mac-priv — the root half of gw-mac: exactly the two operations that need
# root on macOS (the overlay route, the managed /etc/hosts block), factored out
# so a scoped NOPASSWD sudoers rule can cover them and nothing else.
#
# `sudo gw-mac install-autostart` installs this root-owned at
# /usr/local/libexec/gw-mac-priv — deliberately OUTSIDE the user-writable brew
# prefix, so the sudoers rule can't be hijacked by rewriting the helper.
# Self-contained on purpose: pinned PATH, no sourcing, args validated.
set -eu
PATH=/usr/bin:/bin:/usr/sbin:/sbin; export PATH

[ "$(id -u)" = 0 ] || { echo "gw-mac-priv: must run as root" >&2; exit 1; }

# IPv6 prefixes/addresses only — nothing shell-active gets past this.
net_ok() { case "${1:-}" in ""|*[!0-9a-fA-F:/.%]*) return 1 ;; *) return 0 ;; esac; }

case "${1:-}" in
route-add)
    net_ok "${2:-}" && net_ok "${3:-}" || { echo "usage: gw-mac-priv route-add <prefix> <gateway>" >&2; exit 2; }
    route -n delete -inet6 "$2" >/dev/null 2>&1 || true
    route -n add -inet6 "$2" "$3" >/dev/null
    [ -f /etc/hosts.pre-greasewood ] || cp /etc/hosts /etc/hosts.pre-greasewood
    ;;
route-del)
    net_ok "${2:-}" || { echo "usage: gw-mac-priv route-del <prefix>" >&2; exit 2; }
    route -n delete -inet6 "$2" >/dev/null 2>&1 || true
    ;;
hosts-sync)
    # stdin: the VM's managed hosts block, BEGIN/END markers included
    # (empty input = remove the block).
    python3 -c '
import re, sys
block = sys.stdin.read().rstrip("\n")
hosts = open("/etc/hosts").read()
new = re.sub(r"\n*# BEGIN greasewood.*?# END greasewood[^\n]*\n?", "\n", hosts, flags=re.S).rstrip("\n") + "\n"
if block:
    new += "\n" + block + "\n"
open("/etc/hosts", "w").write(new)
'
    ;;
*)
    echo "usage: gw-mac-priv {route-add <prefix> <gw> | route-del <prefix> | hosts-sync}" >&2
    exit 2
    ;;
esac
