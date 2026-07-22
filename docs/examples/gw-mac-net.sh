#!/bin/sh
# gw-mac — bring the greasewood node VM up and route this Mac into the overlay.
#
# Install as a command (see docs/macos.md):
#   install -m 755 gw-mac-net.sh /opt/homebrew/bin/gw-mac
#
#   gw-mac [up]      start VM if stopped, route the mesh /64, sync mesh names
#   gw-mac down      remove the route, stop the VM
#   gw-mac status    one-line state of VM + route
#
# `up` is idempotent and only asks for sudo when something actually needs
# changing — after a Mac reboot or VM restart, `gw-mac` is the one command.
# Requires the gw-mac-gateway unit inside the VM (NAT66 + forwarding).
set -eu

CMD="${1:-up}"
VM="${2:-greasewood-node}"

guest() { limactl shell "$VM" -- sh -c "$1"; }
vm_running() { limactl list --format '{{.Status}}' "$VM" 2>/dev/null | grep -q '^Running$'; }

mesh_info() {
    GWIF=$(guest 'ls /sys/class/net | grep "^gw-" | head -1' || true)
    [ -n "$GWIF" ] || { echo "no gw-* interface in $VM — node not joined?" >&2; exit 1; }
    OVERLAY=$(guest "ip -6 -o addr show dev $GWIF scope global" | awk '{print $4}' | cut -d/ -f1 | head -1)
    PREFIX=$(python3 -c 'import ipaddress,sys; print(ipaddress.IPv6Interface(sys.argv[1]).network)' "$OVERLAY/64")
    VMADDR=$(guest 'ip -6 -o addr show dev lima0 scope global' | awk '{print $4}' | cut -d/ -f1 | head -1)
    [ -n "$VMADDR" ] || { echo "VM has no vzNAT IPv6 on lima0 — networks: [vzNAT] missing?" >&2; exit 1; }
}

route_ok() { netstat -rn -f inet6 | awk -v p="$PREFIX" -v g="$VMADDR" '$1==p && $2==g' | grep -q .; }

case "$CMD" in
up)
    vm_running || { echo "starting $VM…"; limactl start --tty=false "$VM"; }
    mesh_info
    if route_ok; then
        echo "route: $PREFIX via $VMADDR — already in place"
    else
        echo "route: $PREFIX via $VM ($VMADDR) — sudo may prompt"
        sudo sh -c "
            route -n delete -inet6 '$PREFIX' >/dev/null 2>&1 || true
            route -n add -inet6 '$PREFIX' '$VMADDR' >/dev/null
            [ -f /etc/hosts.pre-greasewood ] || cp /etc/hosts /etc/hosts.pre-greasewood
        "
    fi
    BLOCK=$(guest 'sed -n "/^# BEGIN greasewood/,/^# END greasewood/p" /etc/hosts')
    CUR=$(sed -n "/^# BEGIN greasewood/,/^# END greasewood/p" /etc/hosts)
    if [ "$BLOCK" = "$CUR" ]; then
        echo "names: already in sync"
    else
        printf '%s\n' "$BLOCK" | sudo python3 -c '
import re, sys
block = sys.stdin.read().rstrip("\n")
hosts = open("/etc/hosts").read()
new = re.sub(r"\n*# BEGIN greasewood.*?# END greasewood[^\n]*\n?", "\n", hosts, flags=re.S).rstrip("\n") + "\n"
if block:
    new += "\n" + block + "\n"
open("/etc/hosts", "w").write(new)
'
        echo "names: synced to /etc/hosts"
    fi
    echo "up — overlay addresses and mesh names work from macOS"
    ;;
down)
    if vm_running; then
        mesh_info
        sudo route -n delete -inet6 "$PREFIX" >/dev/null 2>&1 || true
    fi
    limactl stop "$VM"
    ;;
status)
    vm_running || { echo "$VM: stopped (gw-mac up)"; exit 0; }
    mesh_info
    if route_ok; then R="routed via $VMADDR"; else R="NOT routed — run gw-mac up"; fi
    echo "$VM: running · $PREFIX $R"
    ;;
*)
    echo "usage: gw-mac [up|down|status] [vm-name]" >&2
    exit 2
    ;;
esac
