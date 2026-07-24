#!/bin/sh
# gw-mac — bring the greasewood node VM up and route this Mac into the overlay.
#
# Install as a command (see docs/macos.md):
#   install -m 755 gw-mac-net.sh /opt/homebrew/bin/gw-mac
#   # or: brew install cschlick/tap/greasewood
#
#   gw-mac [up]      create the VM on first run; afterwards: start VM if
#                    stopped, route the mesh /64, sync mesh names
#   gw-mac down      remove the route, stop the VM
#   gw-mac status    one-line state of VM + route
#   sudo gw-mac install-autostart    root helper + scoped sudoers rule, so
#                    `brew services start greasewood` reconciles headlessly
#   sudo gw-mac uninstall-autostart  remove both again
#
# `up` is idempotent and only touches root state when something actually
# drifted — after a Mac reboot or VM restart, `gw-mac` is the one command
# (or let `brew services` run it on a timer and never think about it).
# Requires the gw-mac-gateway unit inside the VM (NAT66 + forwarding);
# installed automatically when gw-mac creates the VM.
set -eu

CMD="${1:-up}"
VM="${2:-greasewood-node}"
PRIV=/usr/local/libexec/gw-mac-priv

guest() { limactl shell "$VM" -- sh -c "$1"; }
vm_running() { limactl list --format '{{.Status}}' "$VM" 2>/dev/null | grep -q '^Running$'; }
vm_exists() { limactl list --format '{{.Name}}' 2>/dev/null | grep -qx "$VM"; }

# The VM recipe + gateway files travel with this script: Homebrew links us into
# <prefix>/bin and the files into <prefix>/share/greasewood; a hand-installed
# copy finds them next to itself (the docs/examples layout).
find_share() {
    for d in "$(dirname "$0")/../share/greasewood" "$(dirname "$0")"; do
        [ -f "$d/greasewood-node.yaml" ] && SHARE="$d" && return 0
    done
    return 1
}

# Root operations (route, /etc/hosts) go through gw-mac-priv: passwordless via
# the sudoers rule once install-autostart has run; interactive sudo otherwise.
priv() {
    if [ -x "$PRIV" ]; then
        sudo -n "$PRIV" "$@"
    elif [ -t 0 ]; then
        find_share || { echo "gw-mac: gw-mac-priv.sh not found near $0" >&2; exit 1; }
        sudo sh "$SHARE/gw-mac-priv.sh" "$@"        # may prompt for a password
    else
        echo "gw-mac: root needed but no terminal for sudo — run once: sudo gw-mac install-autostart" >&2
        exit 1
    fi
}

# NAT66 + forwarding inside the VM — `up`'s routing is dead without it.
# Works on both recipes: systemd unit on Debian, OpenRC script on Alpine.
install_gateway() {
    limactl cp "$SHARE/gw-mac-gateway.nft" "$SHARE/gw-mac-gateway.sysctl.conf" \
               "$SHARE/gw-mac-gateway.service" "$SHARE/gw-mac-gateway.initd" "$VM:/tmp/"
    if limactl shell "$VM" -- sh -c 'command -v systemctl' >/dev/null 2>&1; then
        limactl shell "$VM" -- sudo sh -c '
            mv /tmp/gw-mac-gateway.nft /etc/ &&
            mv /tmp/gw-mac-gateway.sysctl.conf /etc/sysctl.d/99-gw-mac-gateway.conf &&
            mv /tmp/gw-mac-gateway.service /etc/systemd/system/ &&
            rm -f /tmp/gw-mac-gateway.initd &&
            chown root:root /etc/gw-mac-gateway.nft /etc/sysctl.d/99-gw-mac-gateway.conf \
                            /etc/systemd/system/gw-mac-gateway.service &&
            sysctl --system >/dev/null && systemctl daemon-reload &&
            systemctl enable --now gw-mac-gateway'
    else
        limactl shell "$VM" -- sudo sh -c '
            mv /tmp/gw-mac-gateway.nft /etc/ &&
            mv /tmp/gw-mac-gateway.sysctl.conf /etc/sysctl.d/99-gw-mac-gateway.conf &&
            mv /tmp/gw-mac-gateway.initd /etc/init.d/gw-mac-gateway &&
            rm -f /tmp/gw-mac-gateway.service &&
            chown root:root /etc/gw-mac-gateway.nft /etc/sysctl.d/99-gw-mac-gateway.conf \
                            /etc/init.d/gw-mac-gateway &&
            chmod 755 /etc/init.d/gw-mac-gateway &&
            sysctl -p /etc/sysctl.d/99-gw-mac-gateway.conf >/dev/null &&
            rc-update -q add sysctl boot 2>/dev/null || true &&
            rc-update add gw-mac-gateway default &&
            rc-service gw-mac-gateway start'
    fi
}

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
    if ! vm_exists; then
        [ -t 0 ] || { echo "gw-mac: VM '$VM' doesn't exist — run gw-mac in a terminal to create it" >&2; exit 1; }
        find_share || { echo "gw-mac: VM '$VM' doesn't exist and greasewood-node.yaml isn't installed next to this script" >&2; exit 1; }
        echo "first run — creating $VM from $SHARE/greasewood-node.yaml (downloads a Debian image)…"
        limactl start --tty=false --name="$VM" "$SHARE/greasewood-node.yaml"
        install_gateway
        cat <<EOF
$VM created — it hasn't joined a mesh yet:
  on your anchor:  sudo gw invite --hostname $VM
  then here:       gw join <token>
then run gw-mac again to route this Mac into the overlay.
EOF
        exit 0
    fi
    vm_running || { echo "starting $VM…"; limactl start --tty=false "$VM"; }
    mesh_info
    if route_ok; then
        echo "route: $PREFIX via $VMADDR — already in place"
    else
        echo "route: $PREFIX via $VM ($VMADDR)"
        priv route-add "$PREFIX" "$VMADDR"
    fi
    BLOCK=$(guest 'sed -n "/^# BEGIN greasewood/,/^# END greasewood/p" /etc/hosts')
    CUR=$(sed -n "/^# BEGIN greasewood/,/^# END greasewood/p" /etc/hosts)
    if [ "$BLOCK" = "$CUR" ]; then
        echo "names: already in sync"
    else
        printf '%s\n' "$BLOCK" | priv hosts-sync
        echo "names: synced to /etc/hosts"
    fi
    echo "up — overlay addresses and mesh names work from macOS"
    ;;
down)
    if vm_running; then
        mesh_info
        priv route-del "$PREFIX" || true
    fi
    limactl stop "$VM"
    ;;
status)
    vm_running || { echo "$VM: stopped (gw-mac up)"; exit 0; }
    mesh_info
    if route_ok; then R="routed via $VMADDR"; else R="NOT routed — run gw-mac up"; fi
    echo "$VM: running · $PREFIX $R"
    ;;
install-autostart)
    [ "$(id -u)" = 0 ] || { echo "run with sudo: sudo gw-mac install-autostart" >&2; exit 1; }
    U="${SUDO_USER:-}"
    { [ -n "$U" ] && [ "$U" != root ]; } || { echo "run via sudo from your own user — the sudoers rule needs your username" >&2; exit 1; }
    find_share || { echo "gw-mac: gw-mac-priv.sh not found near $0" >&2; exit 1; }
    mkdir -p /usr/local/libexec
    # Root-owned, outside the user-writable brew prefix — the sudoers rule
    # below must point at something the user can't rewrite.
    install -o root -g wheel -m 755 "$SHARE/gw-mac-priv.sh" "$PRIV"
    printf '%s ALL=(root) NOPASSWD: %s\n' "$U" "$PRIV" > /etc/sudoers.d/gw-mac
    chmod 440 /etc/sudoers.d/gw-mac
    visudo -c >/dev/null || { rm -f /etc/sudoers.d/gw-mac; echo "sudoers validation failed — rolled back" >&2; exit 1; }
    cat <<EOF
installed: $PRIV + /etc/sudoers.d/gw-mac (NOPASSWD, that helper only, for $U)
next:      brew services start greasewood
           (runs 'gw-mac up' every 2 minutes at login — reboot, VM restarts,
            and name changes all reconcile on their own)
EOF
    ;;
uninstall-autostart)
    [ "$(id -u)" = 0 ] || { echo "run with sudo: sudo gw-mac uninstall-autostart" >&2; exit 1; }
    rm -f /etc/sudoers.d/gw-mac "$PRIV"
    echo "removed. If the service is running: brew services stop greasewood"
    ;;
*)
    echo "usage: gw-mac [up|down|status|install-autostart|uninstall-autostart] [vm-name]" >&2
    exit 2
    ;;
esac
