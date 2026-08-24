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
# installed automatically when gw-mac creates the VM, along with the gw-mac-lan
# seal (closes the VM's non-mesh interfaces — see gw-mac-lan.nft).
set -eu

CMD="${1:-up}"
VM="${2:-greasewood-node}"
PRIV=/usr/local/libexec/gw-mac-priv

# The gw-mac "transfer net": a fixed ULA for exactly the Mac↔VM hop over the
# vzNAT link. The VM side is the mesh route's next hop; the Mac side is what
# macOS sources mesh-bound traffic from (RFC 6724 prefers an on-interface,
# prefix-matching source over the en0 GUA) — which is what makes the VM's
# replies route back over the vzNAT link. Without it the Mac sources from its
# GUA, and a VM whose default route points elsewhere (a bridged VM's does —
# the bridged RA wins) sends replies out a link that is host-blind: Apple's
# bridged vmnet carries no host↔guest traffic, so whole-Mac routing dies.
# vmnet's own NAT66 fd… ULA used to fill this role by accident; it is not
# guaranteed (adding a second network rebuilds the shared bridge without it).
TRANSFER_VM=fd6d:6163::2
TRANSFER_MAC=fd6d:6163::1

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
    elif [ -t 2 ]; then
        # Terminal check on stderr, NOT stdin: hosts-sync pipes the hosts
        # block into stdin by design, so fd 0 is never a tty for exactly the
        # op that made this matter. sudo prompts on /dev/tty regardless.
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
               "$SHARE/gw-mac-gateway.service" "$SHARE/gw-mac-gateway.initd" \
               "$SHARE/gw-mac-gateway.network.conf" "$VM:/tmp/"
    if limactl shell "$VM" -- sh -c 'command -v systemctl' >/dev/null 2>&1; then
        limactl shell "$VM" -- sudo sh -c '
            mv /tmp/gw-mac-gateway.nft /etc/ &&
            mv /tmp/gw-mac-gateway.sysctl.conf /etc/sysctl.d/99-gw-mac-gateway.conf &&
            mv /tmp/gw-mac-gateway.service /etc/systemd/system/ &&
            rm -f /tmp/gw-mac-gateway.initd &&
            chown root:root /etc/gw-mac-gateway.nft /etc/sysctl.d/99-gw-mac-gateway.conf \
                            /etc/systemd/system/gw-mac-gateway.service &&
            sysctl --system >/dev/null &&
            NETFILE=$(networkctl status lima0 2>/dev/null | grep "Network File:" \
                      | tr -d " " | cut -d: -f2) &&
            if [ -n "$NETFILE" ]; then
                DROPIN="/etc/systemd/network/$(basename "$NETFILE").d"
                mkdir -p "$DROPIN"
                mv /tmp/gw-mac-gateway.network.conf "$DROPIN/gw-mac-gateway.conf"
                chown root:root "$DROPIN/gw-mac-gateway.conf"
                networkctl reload 2>/dev/null || true
            else
                rm -f /tmp/gw-mac-gateway.network.conf
            fi &&
            systemctl daemon-reload &&
            systemctl enable --now gw-mac-gateway'
    else
        limactl shell "$VM" -- sudo sh -c '
            mv /tmp/gw-mac-gateway.nft /etc/ &&
            mv /tmp/gw-mac-gateway.sysctl.conf /etc/sysctl.d/99-gw-mac-gateway.conf &&
            mv /tmp/gw-mac-gateway.initd /etc/init.d/gw-mac-gateway &&
            rm -f /tmp/gw-mac-gateway.service /tmp/gw-mac-gateway.network.conf &&
            chown root:root /etc/gw-mac-gateway.nft /etc/sysctl.d/99-gw-mac-gateway.conf \
                            /etc/init.d/gw-mac-gateway &&
            chmod 755 /etc/init.d/gw-mac-gateway &&
            sysctl -p /etc/sysctl.d/99-gw-mac-gateway.conf >/dev/null &&
            rc-update -q add sysctl boot 2>/dev/null || true &&
            rc-update add gw-mac-gateway default &&
            rc-service gw-mac-gateway start'
    fi
}

# Seal the VM's non-mesh interfaces (see gw-mac-lan.nft). Installed whenever
# gw-mac creates a VM, and retro-fitted by `up` to a VM that predates it — the
# exposure it closes only appears once the VM is given a real NIC, but a seal
# that arrives with the NIC would be a seal you have to remember.
#
# The ruleset has to name the node's WireGuard port, which isn't knowable at VM
# creation (nothing has joined a mesh yet), so it ships defaulting to 51900 and
# we substitute the configured port whenever one exists.
install_lanfilter() {
    limactl cp "$SHARE/gw-mac-lan.nft" "$SHARE/gw-mac-lan.service" \
               "$SHARE/gw-mac-lan.initd" "$VM:/tmp/"
    limactl shell "$VM" -- sudo sh -c '
        PORT=$(grep -h "^ *listen_port" /etc/greasewood_*.toml 2>/dev/null \
               | head -1 | tr -dc "0-9")
        [ -n "$PORT" ] && sed -i "s/^define wg_port = .*/define wg_port = $PORT/" \
                              /tmp/gw-mac-lan.nft
        mv /tmp/gw-mac-lan.nft /etc/ && chown root:root /etc/gw-mac-lan.nft
        if command -v systemctl >/dev/null 2>&1; then
            mv /tmp/gw-mac-lan.service /etc/systemd/system/
            rm -f /tmp/gw-mac-lan.initd
            chown root:root /etc/systemd/system/gw-mac-lan.service
            systemctl daemon-reload && systemctl enable --now gw-mac-lan
        else
            mv /tmp/gw-mac-lan.initd /etc/init.d/gw-mac-lan
            rm -f /tmp/gw-mac-lan.service
            chown root:root /etc/init.d/gw-mac-lan
            chmod 755 /etc/init.d/gw-mac-lan
            rc-update add gw-mac-lan default && rc-service gw-mac-lan start
        fi'
}

# Has the seal been installed in this VM yet?
lanfilter_present() {
    limactl shell "$VM" -- sh -c '[ -f /etc/gw-mac-lan.nft ]' >/dev/null 2>&1
}

mesh_info() {
    GWIF=$(guest 'ls /sys/class/net | grep "^gw-" | head -1' || true)
    [ -n "$GWIF" ] || { echo "no gw-* interface in $VM — node not joined?" >&2; exit 1; }
    OVERLAY=$(guest "ip -6 -o addr show dev $GWIF scope global" | awk '{print $4}' | cut -d/ -f1 | head -1)
    # Compute the /64 prefix without python3 so this works on a fresh Mac
    # without Xcode command-line tools installed.
    PREFIX=$(printf '%s' "$OVERLAY" | awk -F: 'NF>=4 {printf "%s:%s:%s:%s::/64\n", $1, $2, $3, $4}')
    guest 'ip link show dev lima0' >/dev/null 2>&1 || { echo "VM has no lima0 — networks: [vzNAT] missing from the recipe?" >&2; exit 1; }
    # Next hop for the mesh route: the VM's transfer address (see TRANSFER_VM
    # at the top). `up` ensures it exists on both ends before routing; status/
    # down only compare against it.
    VMADDR=$TRANSFER_VM
}

# Idempotently give both ends of the vzNAT link their transfer address (see
# TRANSFER_VM/TRANSFER_MAC at the top). The VM side also lands at boot via the
# gw-mac-gateway unit; doing it here too covers VMs whose installed unit
# predates it. The Mac side cannot persist (macOS addresses die with the VM's
# bridge), so the reconciler is its home.
ensure_transfer() {
    guest "ip -6 -o addr show dev lima0 | grep -q \" $TRANSFER_VM/\"" || \
        guest "sudo ip -6 addr replace $TRANSFER_VM/64 dev lima0"
    VMV4=$(guest 'ip -4 -o addr show dev lima0 scope global' | awk '{print $4}' | cut -d/ -f1 | head -1)
    [ -n "$VMV4" ] || { echo "VM has no v4 on lima0 — networks: [vzNAT] missing from the recipe?" >&2; exit 1; }
    HOSTIF=$(route -n get "$VMV4" 2>/dev/null | awk '/interface:/{print $2}')
    [ -n "$HOSTIF" ] || { echo "no host route to the VM's vzNAT address ($VMV4) — is the VM running?" >&2; exit 1; }
    ifconfig "$HOSTIF" inet6 2>/dev/null | grep -q " $TRANSFER_MAC " || \
        priv transfer-add "$HOSTIF" "$TRANSFER_MAC"
}

route_ok() { netstat -rn -f inet6 | awk -v p="$PREFIX" -v g="$VMADDR" '$1==p && $2==g' | grep -q .; }

# After a Mac sleep/wake the Lima VM's clock jumps and the greasewood daemon can
# get wedged on stale liveness stamps.  Restart the service if it isn't active,
# and clear those stamps so the watchdog gives it time to recover.
ensure_daemon() {
    limactl shell "$VM" -- sh -c '
        if command -v systemctl >/dev/null 2>&1 && [ -f /etc/systemd/system/greasewood@.service ]; then
            if ! systemctl is-active --quiet greasewood@home 2>/dev/null; then
                rm -f /var/lib/greasewood_home/last_sync /var/lib/greasewood_home/last_reconcile
                systemctl restart greasewood@home
            fi
        elif [ -f /etc/init.d/greasewood.home ]; then
            if ! rc-service greasewood.home status 2>/dev/null | grep -q started; then
                rm -f /var/lib/greasewood_home/last_sync /var/lib/greasewood_home/last_reconcile
                rc-service greasewood.home restart
            fi
        fi
    '
}

case "$CMD" in
up)
    if ! vm_exists; then
        [ -t 0 ] || { echo "gw-mac: VM '$VM' doesn't exist — run gw-mac in a terminal to create it" >&2; exit 1; }
        find_share || { echo "gw-mac: VM '$VM' doesn't exist and greasewood-node.yaml isn't installed next to this script" >&2; exit 1; }
        echo "first run — creating $VM from $SHARE/greasewood-node.yaml (downloads a Debian image)…"
        limactl start --tty=false --name="$VM" "$SHARE/greasewood-node.yaml"
        install_gateway
        install_lanfilter
        # The node should carry the MAC's name, not the VM's — same default the
        # gw shim applies at join time.
        MACHOST=$( (hostname -s 2>/dev/null || scutil --get LocalHostName) \
                   | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9-]//g')
        : "${MACHOST:=$VM}"
        cat <<EOF
$VM created — it hasn't joined a mesh yet:
  on your anchor:  sudo gw invite --hostname $MACHOST    # pinned (recommended)
  then here:       gw join <token>
(a plain 'gw invite' works too — join then claims '$MACHOST', this Mac's name)
then run gw-mac again to route this Mac into the overlay.
EOF
        exit 0
    fi
    # ${VM} braced: macOS /bin/sh (bash 3.2) parses a bare $VM followed by a
    # multibyte char as part of the variable name — unbound under set -u.
    vm_running || { echo "starting ${VM}…"; limactl start --tty=false "$VM"; }
    # A VM created before the seal existed gets it here, once. Cheap to test,
    # and it means the protection arrives through the command people already run.
    if ! lanfilter_present && find_share; then
        echo "sealing ${VM}'s non-mesh interfaces (gw-mac-lan)…"
        install_lanfilter
    fi
    ensure_daemon
    ensure_transfer
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
    # Validate OUR file only (-f). A global `visudo -c` audits every file in
    # sudoers.d and fails on unrelated ones — e.g. Lima's, which is 0444 on
    # purpose (limactl refuses a rule file it cannot read back; sudo's runtime
    # accepts 0444, only the audit is stricter).
    visudo -c -f /etc/sudoers.d/gw-mac >/dev/null || { rm -f /etc/sudoers.d/gw-mac; echo "sudoers validation failed — rolled back" >&2; exit 1; }
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
