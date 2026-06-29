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

import logging
import subprocess
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
    log.debug("set peer ...%s  endpoint=%s  allowed=%s/128", wg_pub_b64[-8:], endpoint, allowed_ip)


def remove_peer(iface: str, wg_pub_b64: str) -> None:
    """Remove a single WireGuard peer from the live interface."""
    _run("wg", "set", iface, "peer", wg_pub_b64, "remove")
    log.debug("removed peer ...%s", wg_pub_b64[-8:])


@dataclass
class LivePeer:
    wg_pub_b64: str
    endpoint: str      # empty string if none/unknown
    allowed_ips: str


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
