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

# IPv6 prefixes/addresses, with an optional %scope (a link-local gateway is
# scoped to an interface, e.g. fe80::1%bridge101) — nothing shell-active gets
# past this: hex/:/./ for the address, alphanumerics only for the scope.
net_ok() {
    case "${1:-}" in ""|*%*%*) return 1 ;; esac
    addr=${1%%\%*}; scope=${1#"$addr"}; scope=${scope#%}
    case "$addr" in ""|*[!0-9a-fA-F:/.]*) return 1 ;; esac
    case "$scope" in *[!0-9a-zA-Z]*) return 1 ;; *) return 0 ;; esac
}

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
transfer-add)
    # Give the Mac its side of the gw-mac transfer net (see gw-mac-net.sh):
    # the source macOS picks for mesh-bound traffic, so the VM's replies route
    # back over the vzNAT link instead of a default route that may point at
    # the host-blind bridged link. $2 = host interface, $3 = address.
    case "${2:-}" in ""|*[!0-9a-zA-Z]*) echo "usage: gw-mac-priv transfer-add <iface> <addr>" >&2; exit 2 ;; esac
    net_ok "${3:-}" || { echo "usage: gw-mac-priv transfer-add <iface> <addr>" >&2; exit 2; }
    ifconfig "$2" inet6 2>/dev/null | grep -q " $3 " || ifconfig "$2" inet6 "$3" prefixlen 64 alias
    ;;
hosts-sync)
    # stdin: the VM's managed hosts block, BEGIN/END markers included
    # (empty input = remove the block).  Use awk, not python3, so this works on
    # a fresh Mac that doesn't have Xcode command-line tools installed yet.
    new=$(mktemp)
    cat > "$new"
    awk -v newfile="$new" '
        BEGIN { n=0; while ((getline line < newfile) > 0) block[n++] = line }
        /^# BEGIN greasewood/ { skip=1; next }
        /^# END greasewood/ { skip=0; next }
        !skip { out[++m] = $0 }
        END {
            for (i = 1; i <= m; i++) print out[i]
            if (n > 0) {
                print ""
                for (i = 0; i < n; i++) print block[i]
            }
        }
    ' /etc/hosts > /etc/hosts.new
    mv /etc/hosts.new /etc/hosts
    rm -f "$new"
    ;;
*)
    echo "usage: gw-mac-priv {route-add <prefix> <gw> | route-del <prefix> | transfer-add <iface> <addr> | hosts-sync}" >&2
    exit 2
    ;;
esac
