"""
greasewood.wg — WireGuard interface management via subprocess.

Design rule (§implementation note): granular per-peer `wg set peer ...` /
`wg set peer ... remove` operations against the live interface only.
Never wg-quick down/up; never edit a .conf file and re-apply — those are
all-or-nothing interface bounces that tear down every live tunnel.
`wg set` gives us per-peer surgery, which is what the reconcile loop requires.

Interface and address setup use `ip`; that happens once at startup, not in
the hot reconcile loop.

Audit-context rule: contexts are CALLER-supplied (audit.context at the call
site — reconcile/invite/join/startup know who and why); this module only
records. The exceptions set their own because no caller adds meaning:
rename_interface and the door isolation routing.
"""
from __future__ import annotations

import logging
import os
import subprocess
import time

from . import audit
from . import platform as gwplat
from dataclasses import dataclass
from pathlib import Path

log = logging.getLogger(__name__)


def _run(*args: str, check: bool = True,
         env: "dict | None" = None,
         input: "str | None" = None) -> subprocess.CompletedProcess:
    # Every ip/wg mutation greasewood makes passes through here, so this is the
    # one place that records the data-plane command trail (greasewood.audit).
    # `env` overrides the child environment (macOS wireguard-go needs
    # WG_TUN_NAME_FILE); `input` feeds stdin (used to hand `wg` a key via
    # /dev/stdin — see _wg_set). Neither reaches the audit trail, so a key is
    # never recorded.
    t0 = time.monotonic()
    try:
        r = subprocess.run(list(args), capture_output=True, text=True, check=check,
                           env=env, input=input)
        audit.record_command(args, r.returncode, int((time.monotonic() - t0) * 1000),
                             r.stdout, r.stderr)
        return r
    except subprocess.CalledProcessError as e:
        # A command that had to succeed (check=True) didn't → a real failure.
        audit.record_command(args, e.returncode, int((time.monotonic() - t0) * 1000),
                             e.stdout or "", e.stderr or "", failed=True)
        if e.stderr:
            log.error("command failed: %s\nstderr: %s", " ".join(args), e.stderr.strip())
        raise


# ---------------------------------------------------------------------------
# macOS backend: logical names ↔ utun devices
#
# greasewood's interface names (gw-<mesh>, gw-door) are LOGICAL everywhere in
# the codebase. On Linux the kernel accepts them as literal device names. On
# macOS a WireGuard interface is a dynamically numbered utunN run by
# wireguard-go (userspace — macOS has no kernel WireGuard), so we keep the
# standard wg-quick convention: wireguard-go writes the utun name it got into
# /var/run/wireguard/<logical>.name (via WG_TUN_NAME_FILE), and its UAPI
# socket lives at /var/run/wireguard/<utunN>.sock. Resolution = read the name
# file, confirm the socket is alive. `wg`/`wg show` work unchanged against the
# resolved utun. Deleting the socket makes wireguard-go exit (that IS the
# teardown, again per wg-quick).
# ---------------------------------------------------------------------------

_WG_RUN_DIR = Path("/var/run/wireguard")


def _namefile(iface: str) -> Path:
    return _WG_RUN_DIR / f"{iface}.name"


def resolve_iface(iface: str) -> "str | None":
    """The OS device for a logical interface name. Linux: identity (the kernel
    device IS the logical name). macOS: the utunN recorded in the name file,
    or None when the interface isn't up (no file, or its wireguard-go died)."""
    if gwplat.IS_LINUX:
        return iface
    if iface.startswith("utun"):
        return iface                      # already an OS device name
    try:
        dev = _namefile(iface).read_text().split()[0]
    except (OSError, IndexError):
        return None
    if dev and (_WG_RUN_DIR / f"{dev}.sock").exists():
        return dev
    return None


def _spawn_wireguard_go(iface: str) -> str:
    """Start a wireguard-go instance for a logical interface (macOS) and return
    the utunN it claimed. wireguard-go daemonizes itself; it exits when its
    UAPI socket is removed (see destroy_interface)."""
    _WG_RUN_DIR.mkdir(parents=True, exist_ok=True)
    namefile = _namefile(iface)
    try:
        namefile.unlink()
    except OSError:
        pass
    env = dict(os.environ, WG_TUN_NAME_FILE=str(namefile))
    r = _run("wireguard-go", "utun", check=False, env=env)
    if r.returncode != 0:
        raise RuntimeError(
            f"wireguard-go failed to start for {iface}: "
            f"{(r.stderr or '').strip() or r.returncode}. Is it installed? "
            f"(brew install wireguard-go wireguard-tools)")
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        dev = resolve_iface(iface)
        if dev:
            log.info("created WireGuard interface %s (%s, wireguard-go)", iface, dev)
            return dev
        time.sleep(0.1)
    raise RuntimeError(f"wireguard-go started for {iface} but {namefile} never "
                       f"appeared — check wireguard-go's syslog output")


# --- tiny per-OS primitives (address / link / route), so the interface and
# --- door setup below read identically on both platforms -------------------

def _create_wg_iface(iface: str) -> str:
    """Create the WireGuard interface; returns the OS device name."""
    if gwplat.IS_MACOS:
        return _spawn_wireguard_go(iface)
    _run("ip", "link", "add", iface, "type", "wireguard")
    log.info("created WireGuard interface %s", iface)
    return iface


def _add_overlay_addr(dev: str, addr: str) -> None:
    """Assign an overlay /128 to the device (idempotent — checks first)."""
    if gwplat.IS_MACOS:
        r = _run("ifconfig", dev, check=False)
        if addr not in (r.stdout or ""):
            _run("ifconfig", dev, "inet6", addr, "prefixlen", "128", "alias")
        return
    r = _run("ip", "-6", "addr", "show", "dev", dev, check=False)
    if addr not in r.stdout:
        _run("ip", "-6", "addr", "add", f"{addr}/128", "dev", dev)


def _link_up(dev: str) -> subprocess.CompletedProcess:
    if gwplat.IS_MACOS:
        return _run("ifconfig", dev, "up", check=False)
    return _run("ip", "link", "set", dev, "up", check=False)


def _route_replace(dev: str, addr: str) -> None:
    """Host route for a peer's /128 via the mesh device (replace semantics)."""
    if gwplat.IS_MACOS:
        # macOS `route add` errors on an existing route; delete-then-add gives
        # replace semantics. -q keeps the routing socket chatter out of stderr.
        _run("route", "-q", "-n", "delete", "-inet6", f"{addr}/128", check=False)
        _run("route", "-q", "-n", "add", "-inet6", f"{addr}/128",
             "-interface", dev)
        return
    _run("ip", "-6", "route", "replace", f"{addr}/128", "dev", dev)


def _macos_self_route(addr: str) -> None:
    """Make the node's OWN overlay address locally deliverable on macOS. Linux
    auto-adds a local (loopback) delivery route when an address is assigned to
    an interface; macOS doesn't for a utun, so without this a node can't reach
    its own overlay /128 — breaking gw watch's self-latency row and any local
    client that dials the node via its overlay address. A host route via lo0
    fixes it. Best-effort (check=False): peer traffic never flows through this
    route (inbound is wireguard-go delivery; outbound uses peers' own /128s),
    so if it doesn't take, only self-delivery is affected — never the mesh."""
    _run("route", "-q", "-n", "delete", "-inet6", f"{addr}/128", check=False)
    _run("route", "-q", "-n", "add", "-inet6", f"{addr}/128",
         "-interface", "lo0", check=False)


def _route_del(dev: str, addr: str) -> None:
    if gwplat.IS_MACOS:
        _run("route", "-q", "-n", "delete", "-inet6", f"{addr}/128", check=False)
        return
    _run("ip", "-6", "route", "del", f"{addr}/128", "dev", dev, check=False)


def _wg_set(*args: str, key: str) -> None:
    """`wg set …` where a private-key/preshared-key path is given as the literal
    "/dev/stdin", with the key fed on stdin. greasewood (an unconfined Python
    process) reads the key and hands it to `wg` over stdin, so `wg` never needs
    read access to a key FILE. Recent AppArmor profiles for `wg` (Ubuntu 24.04+)
    confine it to a small whitelist and DENY reading keys from /tmp — and would
    deny /var/lib/greasewood_* too — which broke enrollment and interface
    bring-up; /dev/stdin sidesteps the path check entirely. One key per call
    (stdin is consumed once), so private-key and preshared-key go in separate
    `wg set` invocations. (Works with wireguard-go's `wg` on macOS too.)"""
    _run("wg", "set", *args, input=key.strip() + "\n")


def ensure_interface(
    iface: str,
    overlay_addr: str,
    listen_port: int,
    wg_key_path: Path,
) -> None:
    """
    Create and configure the WireGuard interface if it does not already exist.
    Idempotent — safe to call on every daemon start.
    """
    dev = resolve_iface(iface) if interface_exists(iface) else None
    if dev is None:
        dev = _create_wg_iface(iface)

    # Set private key + listen port (idempotent). On macOS the userspace bind
    # happens HERE (wg set listen-port), so this is where EADDRINUSE surfaces;
    # on Linux the kernel binds at link-up below. The key is fed on stdin via
    # /dev/stdin, never as a file path wg must open (see _wg_set) — check=False
    # + input, since we need the return code for the EADDRINUSE branch.
    r = _run("wg", "set", dev, "private-key", "/dev/stdin",
             "listen-port", str(listen_port), check=False,
             input=Path(wg_key_path).read_text().strip() + "\n")
    if r.returncode != 0:
        if "in use" in (r.stderr or "").lower():
            _raise_port_in_use(iface, listen_port, exclude=dev)
        raise subprocess.CalledProcessError(
            r.returncode, ["wg", "set", dev, "..."], r.stdout, r.stderr)

    _add_overlay_addr(dev, overlay_addr)
    if gwplat.IS_MACOS:
        _macos_self_route(overlay_addr)

    # Bringing a WireGuard interface up binds its listen-port (Linux kernel WG);
    # EADDRINUSE here means ANOTHER wg interface already holds this UDP port —
    # a leftover mesh whose config is gone but whose kernel interface lingers,
    # so port allocation (which scans configs) couldn't see it. Turn the raw
    # RTNETLINK crash into an actionable message naming the culprit.
    r = _link_up(dev)
    if r.returncode != 0:
        if "Address already in use" in (r.stderr or ""):
            _raise_port_in_use(iface, listen_port, exclude=dev)
        raise subprocess.CalledProcessError(r.returncode,
                                            ["link-up", dev],
                                            r.stdout, r.stderr)
    log.info("interface %s up, addr %s, port %d", iface, overlay_addr, listen_port)


def _raise_port_in_use(iface: str, listen_port: int, exclude: str) -> None:
    holder = _wg_iface_on_port(listen_port, exclude=exclude)
    who = (f"WireGuard interface {holder!r}" if holder
           else "another WireGuard interface")
    remedy = (f"rm /var/run/wireguard/{holder or '<utunN>'}.sock"
              if gwplat.IS_MACOS else f"sudo ip link del {holder or '<iface>'}")
    raise PortInUse(
        f"can't bring up {iface}: UDP port {listen_port} is already used "
        f"by {who} — a leftover from a previous mesh on this host. Remove "
        f"it ({remedy}) or give this mesh a different port "
        f"(create/join --listen-port). 'wg show interfaces' lists them.")


class PortInUse(RuntimeError):
    """A mesh's listen-port is held by a leftover WireGuard interface."""


def _wg_iface_on_port(port: int, exclude: str = "") -> "str | None":
    """The name of the WireGuard interface currently listening on `port`, if any
    (other than `exclude`). Best-effort — parses `wg show <iface> listen-port`."""
    return next((name for name, p in wg_interface_ports().items()
                 if p == port and name != exclude), None)


def wg_interface_ports() -> dict:
    """Map of {wg_interface_name: listen_port} for every live WireGuard
    interface — so port allocation can avoid a port a leftover interface holds,
    not just one a config claims."""
    out = {}
    r = _run("wg", "show", "interfaces", check=False)
    if r.returncode != 0:
        return out
    for name in r.stdout.split():
        p = _run("wg", "show", name, "listen-port", check=False)
        if p.returncode == 0 and p.stdout.strip().isdigit():
            out[name] = int(p.stdout.strip())
    return out


def nft_load(script: str) -> None:
    """Apply an nft ruleset document atomically via `nft -f -`. Used ONLY for
    greasewood's own `table inet greasewood` (port enforcement) — the one place
    greasewood writes firewall state, and only when --enforce-ports is set."""
    t0 = time.monotonic()
    try:
        r = subprocess.run(["nft", "-f", "-"], input=script,
                           capture_output=True, text=True, check=True)
        audit.record_command(("nft", "-f", "-"), r.returncode,
                             int((time.monotonic() - t0) * 1000), r.stdout, r.stderr)
    except subprocess.CalledProcessError as e:
        audit.record_command(("nft", "-f", "-"), e.returncode,
                             int((time.monotonic() - t0) * 1000),
                             e.stdout or "", e.stderr or "", failed=True)
        if e.stderr:
            log.error("nft -f failed: %s", e.stderr.strip())
        raise


def nft_delete_table(table: str) -> None:
    """Remove one of our own inet tables (idempotent — a missing table is fine)."""
    _run("nft", "delete", "table", "inet", table, check=False)


def nft_table_exists(table: str) -> bool:
    """True if our inet table is present in the LIVE ruleset. Read-only, so it
    goes straight to `nft` (not audited like a mutation). Lets the port enforcer
    notice its table was wiped out from under it (e.g. an operator's `nft -f`
    that begins with `flush ruleset`) and re-assert it."""
    r = subprocess.run(["nft", "list", "table", "inet", table],
                       capture_output=True, text=True)
    return r.returncode == 0


def interface_exists(iface: str) -> bool:
    """True if `iface` currently exists. Read-only (`show`), so it lands at
    DEBUG in the audit trail, not the durable log."""
    if gwplat.IS_MACOS:
        dev = resolve_iface(iface)
        return (dev is not None
                and _run("ifconfig", dev, check=False).returncode == 0)
    return _run("ip", "link", "show", iface, check=False).returncode == 0


def format_endpoint(host: str, port: "int") -> str:
    """Format a wg endpoint, bracketing IPv6. `host` is a bare address (a ':' in
    it means IPv6). v4 → 'host:port'; v6 → '[host]:port'. The underlay may be
    either family; only the overlay is IPv6-only."""
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


def endpoint_family(endpoint: str) -> int:
    """4 or 6 for an already-formatted endpoint ('host:port' / '[v6]:port')."""
    return 6 if endpoint.startswith("[") else 4


def set_peer(
    iface: str,
    wg_pub_b64: str,
    allowed_ip: str,
    endpoint: str | None = None,
    keepalive: int = 25,
) -> None:
    """
    Add or update a single WireGuard peer. Idempotent.
    allowed_ip is the peer's overlay address (will be installed as /128).
    endpoint is "host:port" (v4) or "[v6]:port", or None (peer must initiate).
    """
    dev = resolve_iface(iface) or iface
    cmd = [
        "wg", "set", dev,
        "peer", wg_pub_b64,
        "allowed-ips", f"{allowed_ip}/128",
        "persistent-keepalive", str(keepalive),
    ]
    if endpoint:
        cmd += ["endpoint", endpoint]
    _run(*cmd)
    # wg set configures the peer but does NOT install a kernel route; do it explicitly.
    _route_replace(dev, allowed_ip)
    log.debug("set peer ...%s  endpoint=%s  allowed=%s/128", wg_pub_b64[-8:], endpoint, allowed_ip)


def remove_peer(iface: str, wg_pub_b64: str, allowed_ip: str | None = None) -> None:
    """Remove a single WireGuard peer from the live interface."""
    dev = resolve_iface(iface) or iface
    _run("wg", "set", dev, "peer", wg_pub_b64, "remove")
    if allowed_ip:
        _route_del(dev, allowed_ip)
    log.debug("removed peer ...%s", wg_pub_b64[-8:])


@dataclass
class LivePeer:
    wg_pub_b64: str
    endpoint: str      # empty string if none/unknown
    allowed_ips: str
    latest_handshake: int = 0   # unix epoch seconds; 0 = never handshaked
    rx_bytes: int = 0
    tx_bytes: int = 0
    keepalive: int = 0          # persistent-keepalive secs (0 = off)


def destroy_interface(iface: str) -> None:
    """Tear down a WireGuard interface if it exists. Idempotent. On macOS,
    removing the UAPI socket is the documented way to make wireguard-go exit
    (the utun disappears with it); the name file goes too."""
    if gwplat.IS_MACOS:
        dev = resolve_iface(iface)
        if dev:
            try:
                (_WG_RUN_DIR / f"{dev}.sock").unlink()
                log.info("destroyed interface %s (%s: removed UAPI socket, "
                         "wireguard-go exits)", iface, dev)
            except OSError:
                pass
        try:
            _namefile(iface).unlink()
        except OSError:
            pass
        return
    r = _run("ip", "link", "show", iface, check=False)
    if r.returncode == 0:
        _run("ip", "link", "del", iface, check=False)
        log.info("destroyed interface %s", iface)


def rename_interface(old: str, new: str) -> None:
    """Rename a live WireGuard interface (peers/keys ride along; routes bound
    to the device survive the rename). Linux: brief data-plane blip (the link
    must be down for the kernel to accept a new name). macOS: the OS device is
    an unrenameable utunN — but greasewood's name is LOGICAL, held in our name
    file, so the rename is a file move with no data-plane blip at all."""
    from . import audit
    with audit.context(f"rename-mesh: interface {old} -> {new}"):
        if gwplat.IS_MACOS:
            os.replace(_namefile(old), _namefile(new))
            log.info("renamed logical interface %s -> %s (same utun)", old, new)
            return
        _run("ip", "link", "set", old, "down")
        _run("ip", "link", "set", old, "name", new)
        _run("ip", "link", "set", new, "up")


def setup_door_routing() -> None:
    """
    One-time idempotent setup of the door subnet's policy routing.
    Call from create and from gw-run (anchor role) to survive reboots.

    Isolation mechanism: packets sourced from GUEST_DOOR_IP consult DOOR_TABLE,
    which contains only a blackhole default.  This prevents a joining node from
    reaching the mesh even if the anchor has IPv6 forwarding enabled.

    The rule is scoped to GUEST_DOOR_IP, NOT the full DOOR_SUBNET — ANCHOR_DOOR_IP
    must NOT match or the enroll daemon's TCP replies are blackholed too.
    WireGuard's allowed-ips already enforces that only GUEST_DOOR_IP can inject
    packets into the anchor via gw-door; the policy rule adds a second layer for
    forwarded traffic only.

    macOS: there is no source-scoped policy routing without pf — and none is
    needed. The blackhole's job is to stop the guest TRANSITING the anchor into
    the mesh, and the primary mechanism for that is that the anchor is not a
    router: greasewood never enables IP forwarding, and it's off by default.
    So on macOS this ASSERTS forwarding is off (net.inet6.ip6.forwarding) and
    warns loudly if something else turned it on — the same guarantee, without
    pf. (The guest still can't spoof: WireGuard allowed-ips. The third layer,
    locking the anchor's own ports, is the packet-filter layer on BOTH OSes —
    nftables on Linux, the future pf backend on macOS.)
    """
    from .door import GUEST_DOOR_IP, DOOR_TABLE, DOOR_RULE_PRIO
    from . import audit

    if gwplat.IS_MACOS:
        _assert_no_forwarding()
        return

    with audit.context("door: isolation routing"):
        # Blackhole default in the door table
        r = _run("ip", "-6", "route", "show", "table", str(DOOR_TABLE), check=False)
        if "blackhole" not in r.stdout:
            _run("ip", "-6", "route", "add", "blackhole", "default",
                 "table", str(DOOR_TABLE), check=False)
            log.info("door routing: blackhole default in table %d", DOOR_TABLE)

        # Source rule: packets FROM GUEST_DOOR_IP → DOOR_TABLE.
        # Do NOT use the full /64 — ANCHOR_DOOR_IP is in that range and must route normally.
        r = _run("ip", "-6", "rule", "show", check=False)
        if str(DOOR_TABLE) not in r.stdout or GUEST_DOOR_IP not in r.stdout:
            _run("ip", "-6", "rule", "add",
                 "from", GUEST_DOOR_IP,
                 "lookup", str(DOOR_TABLE),
                 "priority", str(DOOR_RULE_PRIO),
                 check=False)
        log.info("door routing: source rule for %s → table %d", GUEST_DOOR_IP, DOOR_TABLE)


def _assert_no_forwarding() -> None:
    """macOS door isolation: the guest can't transit the anchor because the
    anchor doesn't forward. Verify that's actually true and warn LOUDLY if some
    other software enabled it (Internet Sharing, a VPN server, ...). Called at
    door setup and re-checked opportunistically — cheap (one sysctl read)."""
    r = _run("sysctl", "-n", "net.inet6.ip6.forwarding", check=False)
    if r.returncode == 0 and (r.stdout or "").strip() not in ("0", ""):
        log.warning(
            "IPv6 forwarding is ENABLED on this Mac (net.inet6.ip6.forwarding=%s) "
            "— something other than greasewood turned it on (Internet Sharing?). "
            "The enrollment door's isolation assumes this host does not route: "
            "with forwarding on, a joining node could reach the mesh through the "
            "anchor during its invite window. Disable it "
            "(sudo sysctl -w net.inet6.ip6.forwarding=0) or close the door "
            "before inviting.", (r.stdout or "").strip())
    else:
        log.info("door isolation: IPv6 forwarding is off (anchor is not a router)")


def teardown_door_routing() -> None:
    """Undo setup_door_routing — remove the source rule and the blackhole route
    in the door table. Idempotent (each step is check=False, a no-op if absent).
    `gw purge` calls this so a torn-down anchor leaves no policy-routing residue.
    Removes ALL rules pointing at DOOR_TABLE, not just the current GUEST_DOOR_IP,
    so a stale rule from an older install is cleaned up too. macOS: nothing to
    undo (setup only asserted forwarding-off)."""
    from .door import GUEST_DOOR_IP, DOOR_TABLE
    from . import audit

    if gwplat.IS_MACOS:
        return

    with audit.context("door: remove isolation routing"):
        # Delete any ip rule feeding the door table (loop: there may be more than
        # one from repeated setups; `rule del` removes one match at a time). No
        # priority in the match, so a rule from an older install with a different
        # priority is still removed.
        for _ in range(8):
            r = _run("ip", "-6", "rule", "show", check=False)
            if str(DOOR_TABLE) not in (r.stdout or ""):
                break
            _run("ip", "-6", "rule", "del",
                 "from", GUEST_DOOR_IP, "lookup", str(DOOR_TABLE), check=False)
        # Flush the blackhole default from the door table.
        _run("ip", "-6", "route", "flush", "table", str(DOOR_TABLE), check=False)
        log.info("door routing: removed source rule + table %d", DOOR_TABLE)


def ensure_anchor_door_interface(
    door_key_path: Path,
    guest_pub_b64: str,
    psk_b64: str,
    door_port: "int | None" = None,
) -> None:
    """
    Bring up the anchor's gw-door interface for one enrollment window.
    Destroys any existing gw-door first so each invite gets a clean start.
    """
    from .door import ANCHOR_DOOR_IP, GUEST_DOOR_IP, DOOR_IFACE, DOOR_PORT
    door_port = DOOR_PORT if door_port is None else door_port

    destroy_interface(DOOR_IFACE)

    dev = _create_wg_iface(DOOR_IFACE)
    _wg_set(dev,
            "private-key", "/dev/stdin",
            "listen-port", str(door_port),
            key=Path(door_key_path).read_text())

    _wg_set(dev,
            "peer", guest_pub_b64,
            "preshared-key", "/dev/stdin",
            "allowed-ips", f"{GUEST_DOOR_IP}/128",
            key=psk_b64)

    _add_overlay_addr(dev, ANCHOR_DOOR_IP)
    _link_up(dev)
    _route_replace(dev, GUEST_DOOR_IP)
    log.info("anchor door interface %s up on port %d", DOOR_IFACE, door_port)


def ensure_node_door_interface(
    guest_priv_bytes: bytes,
    anchor_door_pub_b64: str,
    psk_b64: str,
    anchor_host: str,
    door_port: "int | None" = None,
) -> None:
    """
    Bring up the node's transient gw-door interface for the enrollment dance.
    """
    import base64
    from .door import ANCHOR_DOOR_IP, GUEST_DOOR_IP, DOOR_IFACE, DOOR_PORT
    door_port = DOOR_PORT if door_port is None else door_port

    destroy_interface(DOOR_IFACE)

    dev = _create_wg_iface(DOOR_IFACE)

    guest_priv_b64 = base64.b64encode(guest_priv_bytes).decode()
    _wg_set(dev,
            "private-key", "/dev/stdin",
            "listen-port", str(door_port),
            key=guest_priv_b64)
    _wg_set(dev,
            "peer", anchor_door_pub_b64,
            "preshared-key", "/dev/stdin",
            "endpoint", format_endpoint(anchor_host, door_port),
            "allowed-ips", f"{ANCHOR_DOOR_IP}/128",
            "persistent-keepalive", "5",
            key=psk_b64)

    _add_overlay_addr(dev, GUEST_DOOR_IP)
    _link_up(dev)
    _route_replace(dev, ANCHOR_DOOR_IP)
    log.info("node door interface %s up → [%s]:%d", DOOR_IFACE, anchor_host, door_port)


def get_peers(iface: str) -> "dict[str, LivePeer] | None":
    """
    Currently installed peers from `wg show <iface> dump`, or None if the dump
    FAILED (vs an empty dict, which means the interface has no peers). The
    distinction matters to the reconcile loop: acting on a misread of "no peers"
    would skip every removal. First line is the interface; subsequent lines are
    peers, tab-separated: pubkey, preshared-key, endpoint, allowed-ips,
    latest-handshake, rx-bytes, tx-bytes, persistent-keepalive.
    """
    dev = resolve_iface(iface)
    if dev is None:                       # macOS: interface not up → no peers readable
        return None
    r = _run("wg", "show", dev, "dump", check=False)
    if r.returncode != 0:
        return None
    peers: dict[str, LivePeer] = {}
    lines = r.stdout.strip().splitlines()
    for line in lines[1:]:  # skip interface line
        parts = line.split("\t")
        if len(parts) < 4:
            continue
        pub, _preshared, endpoint, allowed_ips, *rest = parts

        def _int(i: int) -> int:
            try:
                return int(rest[i])
            except (IndexError, ValueError):
                return 0

        peers[pub] = LivePeer(
            wg_pub_b64=pub,
            endpoint=endpoint if endpoint != "(none)" else "",
            allowed_ips=allowed_ips,
            latest_handshake=_int(0),
            rx_bytes=_int(1),
            tx_bytes=_int(2),
            keepalive=_int(3),      # "off" → 0 (via _int's ValueError guard)
        )
    return peers
