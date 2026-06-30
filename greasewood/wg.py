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
from dataclasses import dataclass
from pathlib import Path

log = logging.getLogger(__name__)


def _run(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    log.debug("$ %s", " ".join(args))
    try:
        return subprocess.run(list(args), capture_output=True, text=True, check=check)
    except subprocess.CalledProcessError as e:
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

    _run("ip", "link", "set", iface, "up")
    log.info("interface %s up, addr %s, port %d", iface, overlay_addr, listen_port)


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
    endpoint is "[v6addr]:port" or None (peer must initiate if missing).
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


def destroy_interface(iface: str) -> None:
    """Tear down a WireGuard interface if it exists. Idempotent."""
    r = _run("ip", "link", "show", iface, check=False)
    if r.returncode == 0:
        _run("ip", "link", "del", iface, check=False)
        log.info("destroyed interface %s", iface)


def setup_door_routing() -> None:
    """
    One-time idempotent setup of the door subnet's policy routing.
    Call from setup-hub and from gw-run (hub role) to survive reboots.

    Isolation mechanism: packets sourced from DOOR_SUBNET consult DOOR_TABLE,
    which contains only a blackhole default.  The kernel's local table (priority 0)
    is checked first, so the enroll daemon's address (HUB_DOOR_IP, a local addr)
    is still reachable from the door.  Mesh addresses are not local and hit the
    blackhole — the door subnet is a dead end for everything except the enroll RPC.
    """
    from .door import DOOR_SUBNET, DOOR_TABLE, DOOR_RULE_PRIO

    # Blackhole default in the door table
    r = _run("ip", "-6", "route", "show", "table", str(DOOR_TABLE), check=False)
    if "blackhole" not in r.stdout:
        _run("ip", "-6", "route", "add", "blackhole", "default",
             "table", str(DOOR_TABLE), check=False)
        log.info("door routing: blackhole default in table %d", DOOR_TABLE)

    # Source rule: packets from DOOR_SUBNET → DOOR_TABLE
    r = _run("ip", "-6", "rule", "show", check=False)
    if str(DOOR_TABLE) not in r.stdout or DOOR_SUBNET not in r.stdout:
        _run("ip", "-6", "rule", "add",
             "from", DOOR_SUBNET,
             "lookup", str(DOOR_TABLE),
             "priority", str(DOOR_RULE_PRIO),
             check=False)
        log.info("door routing: source rule for %s → table %d", DOOR_SUBNET, DOOR_TABLE)


def ensure_hub_door_interface(
    door_key_path: Path,
    guest_pub_b64: str,
    psk_b64: str,
) -> None:
    """
    Bring up the hub's gw-door interface for one enrollment window.
    Destroys any existing gw-door first so each mint gets a clean start.
    """
    from .door import HUB_DOOR_IP, GUEST_DOOR_IP, DOOR_IFACE, DOOR_PORT

    destroy_interface(DOOR_IFACE)

    _run("ip", "link", "add", DOOR_IFACE, "type", "wireguard")
    _run("wg", "set", DOOR_IFACE,
         "private-key", str(door_key_path),
         "listen-port", str(DOOR_PORT))

    with _temp_key_file(psk_b64) as psk_path:
        _run("wg", "set", DOOR_IFACE,
             "peer", guest_pub_b64,
             "preshared-key", psk_path,
             "allowed-ips", f"{GUEST_DOOR_IP}/128")

    _run("ip", "-6", "addr", "add", f"{HUB_DOOR_IP}/128", "dev", DOOR_IFACE)
    _run("ip", "link", "set", DOOR_IFACE, "up")
    _run("ip", "-6", "route", "replace", f"{GUEST_DOOR_IP}/128", "dev", DOOR_IFACE)
    log.info("hub door interface %s up on port %d", DOOR_IFACE, DOOR_PORT)


def ensure_node_door_interface(
    guest_priv_bytes: bytes,
    hub_door_pub_b64: str,
    psk_b64: str,
    hub_host: str,
) -> None:
    """
    Bring up the node's transient gw-door interface for the enrollment dance.
    """
    import base64
    from .door import HUB_DOOR_IP, GUEST_DOOR_IP, DOOR_IFACE, DOOR_PORT

    destroy_interface(DOOR_IFACE)

    _run("ip", "link", "add", DOOR_IFACE, "type", "wireguard")

    guest_priv_b64 = base64.b64encode(guest_priv_bytes).decode()
    with _temp_key_file(guest_priv_b64) as key_path, _temp_key_file(psk_b64) as psk_path:
        _run("wg", "set", DOOR_IFACE, "private-key", key_path)
        _run("wg", "set", DOOR_IFACE,
             "peer", hub_door_pub_b64,
             "preshared-key", psk_path,
             "endpoint", f"[{hub_host}]:{DOOR_PORT}",
             "allowed-ips", f"{HUB_DOOR_IP}/128",
             "persistent-keepalive", "5")

    _run("ip", "-6", "addr", "add", f"{GUEST_DOOR_IP}/128", "dev", DOOR_IFACE)
    _run("ip", "link", "set", DOOR_IFACE, "up")
    _run("ip", "-6", "route", "replace", f"{HUB_DOOR_IP}/128", "dev", DOOR_IFACE)
    log.info("node door interface %s up → [%s]:%d", DOOR_IFACE, hub_host, DOOR_PORT)


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
    First line is the interface; subsequent lines are peers.
    Tab-separated: pubkey, preshared-key, endpoint, allowed-ips, ...
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
        pub, _preshared, endpoint, allowed_ips, *_ = parts
        peers[pub] = LivePeer(
            wg_pub_b64=pub,
            endpoint=endpoint if endpoint != "(none)" else "",
            allowed_ips=allowed_ips,
        )
    return peers
