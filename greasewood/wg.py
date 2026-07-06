"""
greasewood.wg — WireGuard interface management via subprocess.

Design rule (§implementation note): granular per-peer `wg set peer ...` /
`wg set peer ... remove` operations against the live interface only.
Never wg-quick down/up; never edit a .conf file and re-apply — those are
all-or-nothing interface bounces that tear down every live tunnel.
`wg set` gives us per-peer surgery, which is what the reconcile loop requires.

Interface and address setup use `ip`; that happens once at startup, not in
the hot reconcile loop.
"""
from __future__ import annotations

import contextlib
import logging
import os
import subprocess
import tempfile
import time

from . import audit
from dataclasses import dataclass
from pathlib import Path

log = logging.getLogger(__name__)


def _run(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    # Every ip/wg mutation greasewood makes passes through here, so this is the
    # one place that records the data-plane command trail (greasewood.audit).
    t0 = time.monotonic()
    try:
        r = subprocess.run(list(args), capture_output=True, text=True, check=check)
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
    r = _run("ip", "link", "show", iface, check=False)
    if r.returncode != 0:
        _run("ip", "link", "add", iface, "type", "wireguard")
        log.info("created WireGuard interface %s", iface)

    # Set private key + listen port (idempotent)
    _run("wg", "set", iface, "private-key", str(wg_key_path), "listen-port", str(listen_port))

    # Add overlay /128 address if not already present
    r = _run("ip", "-6", "addr", "show", "dev", iface, check=False)
    if overlay_addr not in r.stdout:
        _run("ip", "-6", "addr", "add", f"{overlay_addr}/128", "dev", iface)

    # Bringing a WireGuard interface up binds its listen-port; EADDRINUSE here
    # means ANOTHER wg interface already holds this UDP port — a leftover mesh
    # whose config is gone but whose kernel interface lingers, so port
    # allocation (which scans configs) couldn't see it. Turn the raw RTNETLINK
    # crash into an actionable message naming the culprit.
    r = _run("ip", "link", "set", iface, "up", check=False)
    if r.returncode != 0:
        if "Address already in use" in (r.stderr or ""):
            holder = _wg_iface_on_port(listen_port, exclude=iface)
            who = (f"WireGuard interface {holder!r}" if holder
                   else "another WireGuard interface")
            raise PortInUse(
                f"can't bring up {iface}: UDP port {listen_port} is already used "
                f"by {who} — a leftover from a previous mesh on this host. Remove "
                f"it (sudo ip link del {holder or '<iface>'}) or give this mesh a "
                f"different port (create/join --listen-port). "
                f"'wg show interfaces' lists them.")
        raise subprocess.CalledProcessError(r.returncode,
                                            ["ip", "link", "set", iface, "up"],
                                            r.stdout, r.stderr)
    log.info("interface %s up, addr %s, port %d", iface, overlay_addr, listen_port)


class PortInUse(RuntimeError):
    """A mesh's listen-port is held by a leftover WireGuard interface."""


def _wg_iface_on_port(port: int, exclude: str = "") -> "str | None":
    """The name of the WireGuard interface currently listening on `port`, if any
    (other than `exclude`). Best-effort — parses `wg show <iface> listen-port`."""
    r = _run("wg", "show", "interfaces", check=False)
    if r.returncode != 0:
        return None
    for name in r.stdout.split():
        if name == exclude:
            continue
        p = _run("wg", "show", name, "listen-port", check=False)
        if p.returncode == 0 and p.stdout.strip() == str(port):
            return name
    return None


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


def interface_exists(iface: str) -> bool:
    """True if `iface` currently exists. Read-only (`show`), so it lands at
    DEBUG in the audit trail, not the durable log."""
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
    cmd = [
        "wg", "set", iface,
        "peer", wg_pub_b64,
        "allowed-ips", f"{allowed_ip}/128",
        "persistent-keepalive", str(keepalive),
    ]
    if endpoint:
        cmd += ["endpoint", endpoint]
    _run(*cmd)
    # wg set configures the peer but does NOT install a kernel route; do it explicitly.
    _run("ip", "-6", "route", "replace", f"{allowed_ip}/128", "dev", iface)
    log.debug("set peer ...%s  endpoint=%s  allowed=%s/128", wg_pub_b64[-8:], endpoint, allowed_ip)


def remove_peer(iface: str, wg_pub_b64: str, allowed_ip: str | None = None) -> None:
    """Remove a single WireGuard peer from the live interface."""
    _run("wg", "set", iface, "peer", wg_pub_b64, "remove")
    if allowed_ip:
        _run("ip", "-6", "route", "del", f"{allowed_ip}/128", "dev", iface, check=False)
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
    """Tear down a WireGuard interface if it exists. Idempotent."""
    r = _run("ip", "link", "show", iface, check=False)
    if r.returncode == 0:
        _run("ip", "link", "del", iface, check=False)
        log.info("destroyed interface %s", iface)


def rename_interface(old: str, new: str) -> None:
    """Rename a live WireGuard interface (peers/keys ride along; routes bound
    to the device survive the rename). Brief data-plane blip: the link must be
    down for the kernel to accept a new name."""
    from . import audit
    with audit.context(f"rename-mesh: interface {old} -> {new}"):
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
    """
    from .door import GUEST_DOOR_IP, DOOR_TABLE, DOOR_RULE_PRIO
    from . import audit

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

    _run("ip", "link", "add", DOOR_IFACE, "type", "wireguard")
    _run("wg", "set", DOOR_IFACE,
         "private-key", str(door_key_path),
         "listen-port", str(door_port))

    with _temp_key_file(psk_b64) as psk_path:
        _run("wg", "set", DOOR_IFACE,
             "peer", guest_pub_b64,
             "preshared-key", psk_path,
             "allowed-ips", f"{GUEST_DOOR_IP}/128")

    _run("ip", "-6", "addr", "add", f"{ANCHOR_DOOR_IP}/128", "dev", DOOR_IFACE)
    _run("ip", "link", "set", DOOR_IFACE, "up")
    _run("ip", "-6", "route", "replace", f"{GUEST_DOOR_IP}/128", "dev", DOOR_IFACE)
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

    _run("ip", "link", "add", DOOR_IFACE, "type", "wireguard")

    guest_priv_b64 = base64.b64encode(guest_priv_bytes).decode()
    with _temp_key_file(guest_priv_b64) as key_path, _temp_key_file(psk_b64) as psk_path:
        _run("wg", "set", DOOR_IFACE,
             "private-key", key_path,
             "listen-port", str(door_port))
        _run("wg", "set", DOOR_IFACE,
             "peer", anchor_door_pub_b64,
             "preshared-key", psk_path,
             "endpoint", format_endpoint(anchor_host, door_port),
             "allowed-ips", f"{ANCHOR_DOOR_IP}/128",
             "persistent-keepalive", "5")

    _run("ip", "-6", "addr", "add", f"{GUEST_DOOR_IP}/128", "dev", DOOR_IFACE)
    _run("ip", "link", "set", DOOR_IFACE, "up")
    _run("ip", "-6", "route", "replace", f"{ANCHOR_DOOR_IP}/128", "dev", DOOR_IFACE)
    log.info("node door interface %s up → [%s]:%d", DOOR_IFACE, anchor_host, door_port)


@contextlib.contextmanager
def _temp_key_file(b64_key: str):
    """Write a base64 WireGuard key to a mode-0600 temp file, yield its path."""
    fd, path = tempfile.mkstemp()
    try:
        os.write(fd, b64_key.encode() + b"\n")
        os.close(fd)
        os.chmod(path, 0o600)
        yield path
    finally:
        try:
            os.unlink(path)
        except Exception:
            pass


def get_peers(iface: str) -> dict[str, LivePeer]:
    """
    Return currently installed peers from `wg show <iface> dump`.
    First line is the interface; subsequent lines are peers. Tab-separated:
    pubkey, preshared-key, endpoint, allowed-ips, latest-handshake,
    rx-bytes, tx-bytes, persistent-keepalive.
    """
    r = _run("wg", "show", iface, "dump", check=False)
    if r.returncode != 0:
        return {}
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
