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

from .helpers import container_ipv6, pexec, podman, wait_for_http

IMAGE_TAG = "greasewood-test:latest"
PROJECT_ROOT = Path(__file__).parent.parent.parent
_NETWORK_SUBNET = "fd52:ba5e::/64"


# ---------------------------------------------------------------------------
# Session-scoped: image, network, root node
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def gw_image():
    """Build the greasewood container image once per session."""
    subprocess.run(
        ["podman", "build", "-t", IMAGE_TAG, str(PROJECT_ROOT)],
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


def _free_tcp_port() -> int:
    """Grab an ephemeral TCP port the kernel says is free, then release it."""
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.fixture(scope="session")
def gw_root(gw_image, gw_network):
    """
    Start the hub container, run setup-hub, launch daemon.

    The host has no route onto the Podman IPv6 bridge, so the control plane
    port is published to host loopback for the pytest driver. Node containers,
    which DO share the bridge, talk to the root over the container-network
    address. Hence two URLs.

    Yields a dict:
      cid        — container ID
      ipv6       — underlay IPv6 address (fd52:ba5e::.../64)
      url        — host-reachable control plane URL (published, 127.0.0.1:PORT)
      net_url    — container-network control plane URL (http://[fd52:...]:7946)
      ca_pub     — CA public key hex
      overlay    — overlay address (fd8d:e5c1:db1a::/48 prefix)
    """
    cid = None
    try:
        host_port = _free_tcp_port()
        r = podman(
            "run", "-d", "--privileged",
            "--network", gw_network,
            "-p", f"127.0.0.1:{host_port}:7946",
            "--sysctl", "net.ipv6.conf.all.disable_ipv6=0",
            gw_image, "sleep", "infinity",
        )
        cid = r.stdout.strip()
        time.sleep(1)  # wait for network address assignment

        ipv6 = container_ipv6(cid, gw_network)
        assert ipv6, "root container got no IPv6 address"

        pexec(cid, "gw", "setup-hub",
              "--hostname", "root",
              "--endpoint", f"[{ipv6}]:51820")

        ca_pub = pexec(cid, "cat", "/var/lib/greasewood/ca.pub").stdout.strip()
        overlay = pexec(cid, "cat", "/var/lib/greasewood/id_pub.hex").stdout.strip()

        # Derive overlay addr (same formula as keys.py)
        overlay_addr = overlay_addr_from_id_pub(overlay)

        podman("exec", "-d", cid, "sh", "-c", "gw run >> /tmp/gw.log 2>&1")

        url = f"http://127.0.0.1:{host_port}"          # host → published
        net_url = f"http://[{ipv6}]:7946"              # container → bridge
        assert wait_for_http(f"{url}/health", timeout=20), \
            "root daemon did not start — check /tmp/gw.log in the container"

        yield {
            "cid": cid,
            "ipv6": ipv6,
            "url": url,
            "net_url": net_url,
            "ca_pub": ca_pub,
            "overlay": overlay_addr,
        }
    finally:
        if cid:
            podman("rm", "-f", cid, check=False)


# ---------------------------------------------------------------------------
# Function-scoped: node factory
# ---------------------------------------------------------------------------

def overlay_addr_from_id_pub(id_pub_hex: str) -> str:
    """Derive a node's fd8d:: overlay address from its id_pub (matches keys.py)."""
    prefix = bytes([0xfd, 0x8d, 0xe5, 0xc1, 0xdb, 0x1a, 0x00, 0x07])
    digest = hashlib.blake2s(bytes.fromhex(id_pub_hex)).digest()
    return str(ipaddress.IPv6Address(prefix + digest[:8]))


# The enrollment door is a single slot (one window, one guest key, one peer).
# Concurrent callers — the stress tests grow the mesh from many threads — must
# serialize the mint→join critical section, exactly like a real provisioner.
_ENROLL_LOCK = threading.Lock()


def _extract_token(text: str) -> str:
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("gw1."):
            return s
    raise AssertionError(f"no join token in mint output:\n{text}")


def _wait_iface_gone(cid: str, iface: str, timeout: int = 20) -> bool:
    """Block until `iface` no longer exists in the container."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if pexec(cid, "ip", "link", "show", iface, check=False).returncode != 0:
            return True
        time.sleep(0.5)
    return False


def door_enroll_via(hub_cid: str, hub_ipv6: str, node_cid: str, node_ipv6: str, *,
                    hostname: str | None = None, caps: str | None = None,
                    check: bool = True):
    """
    Run one `gw mint` (on hub_cid) → `gw join` (on node_cid) door enrollment.
    `hub_ipv6` is the hub's underlay address (the door endpoint). Generalized
    over the hub so a test can enroll via a successor hub, not just the root.
    Returns the `gw join` CompletedProcess.
    """
    extra = []
    if hostname is not None:
        extra += ["--hostname", hostname]
    if caps is not None:
        extra += ["--caps", caps]

    with _ENROLL_LOCK:
        # mint --endpoint takes a BARE address; the door port is fixed and the
        # token carries only the host.
        mint = pexec(hub_cid, "gw", "mint", "--endpoint", hub_ipv6)
        token = _extract_token(mint.stdout + "\n" + mint.stderr)

        j = pexec(node_cid, "gw", "join", token,
                  "--endpoint", f"[{node_ipv6}]:51820", *extra, check=False)
        if check:
            assert j.returncode == 0, (
                f"gw join failed (rc={j.returncode}):\n"
                f"stdout: {j.stdout}\nstderr: {j.stderr}"
            )

        # Wait for the hub to close the window and destroy its gw-door before
        # releasing the lock, so the next mint doesn't race the teardown.
        assert _wait_iface_gone(hub_cid, "gw-door"), \
            "hub did not tear down gw-door after enrollment"
    return j


def door_enroll(gw_root, node_cid: str, node_ipv6: str, *,
                hostname: str | None = None, caps: str | None = None,
                check: bool = True):
    """Enroll an existing node container via the root hub (see door_enroll_via).
    `hostname`/`caps` are passed only when given, so omitting them exercises
    join's "keep existing config" behavior."""
    return door_enroll_via(
        gw_root["cid"], gw_root["ipv6"], node_cid, node_ipv6,
        hostname=hostname, caps=caps, check=check,
    )


def bring_up_node(gw_image, gw_network, gw_root, hostname: str | None = None,
                  caps: str | None = None) -> dict:
    """
    Create, enroll (via the door), and start a single node container.

    Enrollment uses the real `gw mint` / `gw join` flow — the only supported
    path (see door_enroll). Container creation and `gw run` stay parallel; only
    the door section serializes. `caps` (e.g. "mesh,tls") is passed to join.

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

    ipv6 = container_ipv6(cid, gw_network)
    door_enroll(gw_root, cid, ipv6, hostname=hostname, caps=caps)

    id_pub = pexec(cid, "cat", "/var/lib/greasewood/id_pub.hex").stdout.strip()
    podman("exec", "-d", cid, "sh", "-c", "gw -v run >> /tmp/gw.log 2>&1")

    return {
        "cid": cid,
        "hostname": hostname,
        "overlay": overlay_addr_from_id_pub(id_pub),
        "id_pub": id_pub,
    }


@pytest.fixture
def gw_node(gw_image, gw_network, gw_root):
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
        node = bring_up_node(gw_image, gw_network, gw_root)
        yield node
    finally:
        if node:
            podman("rm", "-f", node["cid"], check=False)
