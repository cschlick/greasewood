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
import os
import subprocess
import tempfile
import time
import urllib.request
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


def bring_up_node(gw_image, gw_network, gw_root, hostname: str | None = None) -> dict:
    """
    Create, enroll, and start a single node container.

    This is the reusable core behind the `gw_node` fixture; the stress tests
    call it directly (often from many threads at once) to grow the mesh.
    Safe to run concurrently: each node has a unique id_pub, so `gw issue`
    only ever writes per-node files (nodes/<id_pub>.json) on the root — no
    shared-file race.

    Returns a dict {cid, hostname, overlay, id_pub}. The CALLER owns cleanup
    (`podman rm -f cid`).
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
    # The node (a container on the bridge) reaches the root over the
    # container-network URL; the pytest driver (host) uses the published one.
    net_url = gw_root["net_url"]
    host_url = gw_root["url"]

    cfg = f"""[node]
hostname = "{hostname}"
data_dir = "/var/lib/greasewood"
role = "node"
inbound = "yes"
caps = ["mesh"]
endpoints = ["[{ipv6}]:51820"]

[network]
interface = "gw0"
listen_port = 51820
seeds = ["{net_url}"]
root_url = "{net_url}"

[ca]
trusted_pubs = ["{gw_root['ca_pub']}"]
"""
    _copy_text_to_container(cfg, cid, "/etc/greasewood.toml")

    # Generate node identity + WireGuard keypair
    pexec(cid, "gw", "init-node")
    id_pub = pexec(cid, "cat", "/var/lib/greasewood/id_pub.hex").stdout.strip()
    wg_pub = pexec(cid, "cat", "/var/lib/greasewood/wg_pub.b64").stdout.strip()

    # Pre-seed local directory with root's current directory so the node
    # can reconcile root as a peer immediately on first startup (otherwise
    # it would have to wait up to 20 s for the first sync cycle). Fetched
    # from the host via the published URL.
    root_dir = urllib.request.urlopen(f"{host_url}/directory").read()
    _copy_bytes_to_container(root_dir, cid, "/var/lib/greasewood/directory.json")

    # Issue credential from root container (outputs JSON to stdout)
    r = pexec(
        gw_root["cid"], "gw", "issue",
        "--id-pub", id_pub,
        "--wg-pub", wg_pub,
        "--hostname", hostname,
        "--caps", "mesh",
    )
    _copy_text_to_container(r.stdout, cid, "/tmp/cred.json")

    # Install credential — merges node's NodeRecord into the pre-seeded directory
    pexec(cid, "gw", "install-cred", "/tmp/cred.json")

    # Start daemon
    podman("exec", "-d", cid, "sh", "-c", "gw run >> /tmp/gw.log 2>&1")

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


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _copy_text_to_container(text: str, cid: str, path: str) -> None:
    with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
        f.write(text)
        tmp = f.name
    try:
        podman("cp", tmp, f"{cid}:{path}")
    finally:
        os.unlink(tmp)


def _copy_bytes_to_container(data: bytes, cid: str, path: str) -> None:
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(data)
        tmp = f.name
    try:
        podman("cp", tmp, f"{cid}:{path}")
    finally:
        os.unlink(tmp)
