"""
Integration tests for the greasewood mesh.

Each test uses real WireGuard interfaces inside privileged Podman containers.

Run:
  pytest tests/integration/ -v
"""
import json
import urllib.request

import pytest

from .helpers import wait_for_hostname, wait_for_ping

pytestmark = pytest.mark.integration


# ---------------------------------------------------------------------------
# Root-only tests (no node needed)
# ---------------------------------------------------------------------------

def test_root_health(gw_root):
    resp = urllib.request.urlopen(f"{gw_root['url']}/health")
    assert resp.status == 200


def test_root_in_own_directory(gw_root):
    resp = urllib.request.urlopen(f"{gw_root['url']}/directory")
    data = json.loads(resp.read())
    hostnames = {r["hostname"] for r in data}
    assert "root" in hostnames


# ---------------------------------------------------------------------------
# Node enrollment tests
# ---------------------------------------------------------------------------

def test_node_appears_in_root_directory(gw_root, gw_node):
    """Node pushes its NodeRecord to root on startup — should appear within seconds."""
    assert wait_for_hostname(gw_root["url"], gw_node["hostname"], timeout=20), \
        f"{gw_node['hostname']} never appeared in root directory"


def test_root_overlay_addr_in_directory(gw_root):
    """Root's NodeRecord contains a valid fd8d:: overlay address."""
    resp = urllib.request.urlopen(f"{gw_root['url']}/directory")
    data = json.loads(resp.read())
    root_record = next(r for r in data if r["hostname"] == "root")
    assert root_record["addr"].startswith("fd8d:e5c1:db1a:")


# ---------------------------------------------------------------------------
# WireGuard connectivity tests
# ---------------------------------------------------------------------------

def test_root_pings_node(gw_root, gw_node):
    """Root can ping the node's overlay address after enrollment."""
    assert wait_for_ping(gw_root["cid"], gw_node["overlay"], timeout=30), \
        f"root → node ping failed (target: {gw_node['overlay']})"


def test_node_pings_root(gw_root, gw_node):
    """Node can ping root's overlay address."""
    assert wait_for_ping(gw_node["cid"], gw_root["overlay"], timeout=30), \
        f"node → root ping failed (target: {gw_root['overlay']})"


def test_two_nodes_ping_each_other(gw_root, gw_node, tmp_path, gw_image, gw_network):
    """Two independent nodes can reach each other via the overlay."""
    # Spin up a second node using the same fixture logic directly
    import os, tempfile, time, urllib.request, uuid, hashlib, ipaddress
    from .helpers import container_ipv6, pexec, podman
    from .conftest import _copy_bytes_to_container, _copy_text_to_container

    hostname2 = f"node-{uuid.uuid4().hex[:6]}"
    cid2 = None
    try:
        r = podman(
            "run", "-d", "--privileged",
            "--network", gw_network,
            "--sysctl", "net.ipv6.conf.all.disable_ipv6=0",
            gw_image, "sleep", "infinity",
        )
        cid2 = r.stdout.strip()
        time.sleep(1)

        ipv6_2 = container_ipv6(cid2, gw_network)
        root_url = gw_root["url"]

        cfg = f"""[node]
hostname = "{hostname2}"
data_dir = "/var/lib/greasewood"
role = "node"
inbound = "yes"
caps = ["mesh"]
endpoints = ["[{ipv6_2}]:51820"]

[network]
interface = "greasewood0"
listen_port = 51820
seeds = ["{root_url}"]
root_url = "{root_url}"

[ca]
trusted_pubs = ["{gw_root['ca_pub']}"]
"""
        _copy_text_to_container(cfg, cid2, "/etc/greasewood.toml")
        pexec(cid2, "gw", "init-node")
        id_pub2 = pexec(cid2, "cat", "/var/lib/greasewood/id_pub.hex").stdout.strip()
        wg_pub2 = pexec(cid2, "cat", "/var/lib/greasewood/wg_pub.b64").stdout.strip()

        root_dir = urllib.request.urlopen(f"{root_url}/directory").read()
        _copy_bytes_to_container(root_dir, cid2, "/var/lib/greasewood/directory.json")

        r = pexec(
            gw_root["cid"], "gw", "issue",
            "--id-pub", id_pub2, "--wg-pub", wg_pub2,
            "--hostname", hostname2, "--caps", "mesh",
        )
        _copy_text_to_container(r.stdout, cid2, "/tmp/cred.json")
        pexec(cid2, "gw", "install-cred", "/tmp/cred.json")

        prefix = bytes([0xfd, 0x8d, 0xe5, 0xc1, 0xdb, 0x1a, 0x00, 0x07])
        digest = hashlib.blake2s(bytes.fromhex(id_pub2)).digest()
        overlay2 = str(ipaddress.IPv6Address(prefix + digest[:8]))

        podman("exec", "-d", cid2, "sh", "-c", "gw run >> /tmp/gw.log 2>&1")

        # Both nodes need to know about each other — wait for root to have both
        assert wait_for_hostname(root_url, hostname2, timeout=20)

        # node1 → node2
        assert wait_for_ping(gw_node["cid"], overlay2, timeout=30), \
            f"node1 → node2 ping failed"
        # node2 → node1
        assert wait_for_ping(cid2, gw_node["overlay"], timeout=30), \
            f"node2 → node1 ping failed"
    finally:
        if cid2:
            podman("rm", "-f", cid2, check=False)
