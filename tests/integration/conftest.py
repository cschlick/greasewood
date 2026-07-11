"""
Integration test fixtures for greasewood.

Topology
--------
  Podman network (IPv6 ULA fd52:ba5e::/64) — underlay
  WireGuard overlay (fd8d:e5c1:db1a::/48) — greasewood mesh

Prerequisites
-------------
  - podman 4+
  - WireGuard kernel module loaded on the host (Linux 5.6+ has it built in)

Run
---
  pytest tests/integration/ -v
  pytest tests/integration/ -v --tb=short
"""
from __future__ import annotations

import hashlib
import ipaddress
import subprocess
import threading
import time
import uuid
from pathlib import Path

import pytest

from .helpers import container_addr, container_ipv6, pexec, podman, wait_for_control_plane


def _ep(addr: str, port: int) -> str:
    """Format an underlay endpoint, bracketing IPv6 (v4 has no brackets)."""
    return f"[{addr}]:{port}" if ":" in addr else f"{addr}:{port}"

IMAGE_TAG = "greasewood-test:latest"
PROJECT_ROOT = Path(__file__).parent.parent.parent
_NETWORK_SUBNET = "fd52:ba5e::/64"


# ---------------------------------------------------------------------------
# Session-scoped: image, network, anchor node
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def gw_image():
    """Build the greasewood container image once per session (via the configured
    engine — podman by default, docker when GW_CONTAINER_ENGINE=docker)."""
    from .helpers import ENGINE
    # Build from Containerfile explicitly: podman auto-detects that name, but
    # `docker build` only looks for "Dockerfile" — so name it for both engines.
    subprocess.run(
        [ENGINE, "build", "-f", str(PROJECT_ROOT / "Containerfile"),
         "-t", IMAGE_TAG, str(PROJECT_ROOT)],
        check=True,
    )
    return IMAGE_TAG


@pytest.fixture(scope="session")
def gw_network():
    """Ephemeral IPv6-enabled Podman bridge network."""
    name = f"gw-test-{uuid.uuid4().hex[:8]}"
    podman("network", "create", "--ipv6", "--subnet", _NETWORK_SUBNET, name)
    yield name
    podman("network", "rm", "-f", name, check=False)


@pytest.fixture(scope="session")
def gw_anchor(gw_image, gw_network):
    """
    Start the anchor container, run create, launch daemon.

    The control plane binds only to the overlay address + loopback (never the
    underlay), so it is not reachable from the host. Tests query it from inside
    the anchor container over loopback via helpers.anchor_get(cid, path).

    Yields a dict:
      cid        — container ID (also the handle for control-plane queries)
      ipv6       — underlay IPv6 address (fd52:ba5e::.../64)
      ca_pub     — CA public key hex
      overlay    — overlay address (fd8d:e5c1:db1a::/48 prefix)
    """
    cid = None
    try:
        r = podman(
            "run", "-d", "--privileged",
            "--network", gw_network,
            "--sysctl", "net.ipv6.conf.all.disable_ipv6=0",
            gw_image, "sleep", "infinity",
        )
        cid = r.stdout.strip()
        time.sleep(1)  # wait for network address assignment

        ipv6 = container_addr(cid, gw_network)
        assert ipv6, "anchor container got no underlay address"

        pexec(cid, "gw", "create", "testmesh",
              "--hostname", "anchor",
              "--endpoint", _ep(ipv6, 51900))

        overlay = pexec(cid, "sh", "-c", "cat /var/lib/greasewood_*/id_pub.hex").stdout.strip()
        ca_pub = pexec(cid, "sh", "-c", "cat /var/lib/greasewood_*/ca.pub").stdout.strip()
        overlay_addr = overlay_addr_from_id_pub(overlay)

        podman("exec", "-d", cid, "sh", "-c", "gw run >> /tmp/gw.log 2>&1")

        assert wait_for_control_plane(cid, timeout=20), \
            "anchor daemon did not start — check /tmp/gw.log in the container"

        yield {
            "cid": cid,
            "ipv6": ipv6,
            "ca_pub": ca_pub,
            "overlay": overlay_addr,
        }
    finally:
        if cid:
            podman("rm", "-f", cid, check=False)


# ---------------------------------------------------------------------------
# Function-scoped: node factory
# ---------------------------------------------------------------------------

def overlay_addr_from_id_pub(id_pub_hex: str,
                             prefix: str = "fd8d:e5c1:db1a:7::") -> str:
    """Derive a node's overlay address from its id_pub (matches keys.py). The
    prefix defaults to the fleet default but can be overridden for a mesh set up
    with a custom --overlay-prefix."""
    pfx = ipaddress.IPv6Address(prefix.split("/")[0]).packed[:8]
    digest = hashlib.blake2s(bytes.fromhex(id_pub_hex)).digest()
    return str(ipaddress.IPv6Address(pfx + digest[:8]))


def make_anchor(gw_image, gw_network, *, ttl="24h", hostname="anchor") -> dict:
    """Spin up a DEDICATED anchor container (own CA) — for tests that must not
    pollute the shared session `gw_anchor` (revoke, short-TTL renewal, etc.) or that
    need a second anchor. Same shape as the gw_anchor fixture. CALLER owns cleanup."""
    cid = podman(
        "run", "-d", "--privileged", "--network", gw_network,
        "--sysctl", "net.ipv6.conf.all.disable_ipv6=0",
        gw_image, "sleep", "infinity",
    ).stdout.strip()
    time.sleep(1)
    ipv6 = container_addr(cid, gw_network)
    assert ipv6, "anchor container got no underlay address"
    pexec(cid, "gw", "create", f"{hostname}mesh", "--hostname", hostname,
          "--endpoint", _ep(ipv6, 51900), "--credential-ttl", ttl)
    id_pub = pexec(cid, "sh", "-c", "cat /var/lib/greasewood_*/id_pub.hex").stdout.strip()
    ca_pub = pexec(cid, "sh", "-c", "cat /var/lib/greasewood_*/ca.pub").stdout.strip()
    podman("exec", "-d", cid, "sh", "-c", "gw run >> /tmp/gw.log 2>&1")
    assert wait_for_control_plane(cid, timeout=20), "dedicated anchor daemon did not start"
    return {"cid": cid, "ipv6": ipv6, "ca_pub": ca_pub,
            "overlay": overlay_addr_from_id_pub(id_pub)}


# The enrollment door is a single slot (one window, one guest key, one peer).
# Concurrent callers — the stress tests grow the mesh from many threads — must
# serialize the invite→join critical section, exactly like a real provisioner.
_ENROLL_LOCK = threading.Lock()


def _extract_token(text: str) -> str:
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("gw1."):
            return s
    raise AssertionError(f"no join token in invite output:\n{text}")


def _wait_iface_gone(cid: str, iface: str, timeout: int = 20) -> bool:
    """Block until `iface` no longer exists in the container."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if pexec(cid, "ip", "link", "show", iface, check=False).returncode != 0:
            return True
        time.sleep(0.5)
    return False


def door_enroll_via(anchor_cid: str, anchor_ipv6: str, node_cid: str, node_ipv6: str, *,
                    hostname: str | None = None, caps: str | None = None,
                    roles: str | None = None,
                    invite_hostname: str | None = None,
                    check: bool = True):
    """
    Run one `gw invite` (on anchor_cid) → `gw join` (on node_cid) door enrollment.
    `anchor_ipv6` is the anchor's underlay address (the door endpoint). Generalized
    over the anchor so a test can enroll via a successor anchor, not just the original one.
    `invite_hostname` pins the name at invite (`gw invite --hostname`), which
    overrides any node-side `--hostname` and locks rename.
    Returns the `gw join` CompletedProcess.
    """
    # caps/roles are decided by the anchor at invite (no self-assertion);
    # hostname remains a node-side join flag.
    join_extra = []
    if hostname is not None:
        join_extra += ["--hostname", hostname]
    invite_extra = []
    if caps is not None:
        invite_extra += ["--caps", caps]
    if roles is not None:
        invite_extra += ["--roles", roles]
    if invite_hostname is not None:
        invite_extra += ["--hostname", invite_hostname]

    with _ENROLL_LOCK:
        # invite --endpoint takes a BARE address; the door port is fixed and the
        # token carries only the host.
        res = pexec(anchor_cid, "gw", "invite", "--endpoint", anchor_ipv6, *invite_extra)
        token = _extract_token(res.stdout + "\n" + res.stderr)

        j = pexec(node_cid, "gw", "join", token,
                  "--endpoint", _ep(node_ipv6, 51900), *join_extra, check=False)
        if check:
            assert j.returncode == 0, (
                f"gw join failed (rc={j.returncode}):\n"
                f"stdout: {j.stdout}\nstderr: {j.stderr}"
            )

        if j.returncode == 0:
            # On success the anchor closes the window and destroys gw-door; wait for
            # that before releasing the lock so the next invite doesn't race it.
            assert _wait_iface_gone(anchor_cid, "gw-door"), \
                "anchor did not tear down gw-door after enrollment"
        else:
            # A failed attempt deliberately leaves the door open for retries.
            # Force-close it for test isolation: drop the window file and let
            # the DoorWatcher tear the interface down.
            pexec(anchor_cid, "sh", "-c", "rm -f /var/lib/greasewood_*/door_window.json",
                  check=False)
            _wait_iface_gone(anchor_cid, "gw-door")
    return j


def door_enroll(gw_anchor, node_cid: str, node_ipv6: str, *,
                hostname: str | None = None, caps: str | None = None,
                roles: str | None = None,
                invite_hostname: str | None = None,
                check: bool = True):
    """Enroll an existing node container via the anchor (see door_enroll_via).
    `hostname`/`caps`/`roles` are passed only when given, so omitting
    them exercises join's "keep existing config" behavior. `invite_hostname` pins
    the name at the anchor; `roles` sets the node's roles at invite."""
    return door_enroll_via(
        gw_anchor["cid"], gw_anchor["ipv6"], node_cid, node_ipv6,
        hostname=hostname, caps=caps, roles=roles,
        invite_hostname=invite_hostname, check=check,
    )


def bring_up_node(gw_image, gw_network, gw_anchor, hostname: str | None = None,
                  caps: str | None = None, roles: str | None = None,
                  invite_hostname: str | None = None,
                  run_args: "list[str] | None" = None) -> dict:
    """
    Create, enroll (via the door), and start a single node container.

    Enrollment uses the real `gw invite` / `gw join` flow — the only supported
    path (see door_enroll). Container creation and `gw run` stay parallel; only
    the door section serializes. `caps` (abilities, e.g. "tls") and `roles`
    (e.g. "prod,web") are granted by the anchor at `gw invite` — the joiner can't
    self-assert either.

    Returns {cid, hostname, overlay, id_pub}. The CALLER owns cleanup.
    """
    hostname = hostname or f"node-{uuid.uuid4().hex[:6]}"
    r = podman(
        "run", "-d", "--privileged",
        "--network", gw_network,
        "--sysctl", "net.ipv6.conf.all.disable_ipv6=0",
        gw_image, "sleep", "infinity",
    )
    cid = r.stdout.strip()
    time.sleep(1)  # wait for network address assignment

    ipv6 = container_addr(cid, gw_network)
    door_enroll(gw_anchor, cid, ipv6, hostname=hostname, caps=caps, roles=roles,
                invite_hostname=invite_hostname)

    id_pub = pexec(cid, "sh", "-c", "cat /var/lib/greasewood_*/id_pub.hex").stdout.strip()
    run_cmd = "gw -v run " + " ".join(run_args or []) + " >> /tmp/gw.log 2>&1"
    podman("exec", "-d", cid, "sh", "-c", run_cmd)

    return {
        "cid": cid,
        "hostname": hostname,
        "overlay": overlay_addr_from_id_pub(id_pub),
        "id_pub": id_pub,
    }


@pytest.fixture
def gw_node(gw_image, gw_network, gw_anchor):
    """
    Start a node container, enroll it into the mesh, launch daemon.

    Yields a dict:
      cid        — container ID
      hostname   — unique hostname for this node
      overlay    — overlay address (fd8d:e5c1:db1a::... prefix)
      id_pub     — node identity public key (hex)
    """
    node = None
    try:
        node = bring_up_node(gw_image, gw_network, gw_anchor)
        yield node
    finally:
        if node:
            podman("rm", "-f", node["cid"], check=False)
