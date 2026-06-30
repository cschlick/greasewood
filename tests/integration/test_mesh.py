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
    # addr is anchored in the signed credential, not a top-level record field.
    assert root_record["cred"]["addr"].startswith("fd8d:e5c1:db1a:")


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


def test_two_nodes_ping_each_other(gw_root, gw_node, gw_image, gw_network):
    """Two independent nodes can reach each other via the overlay."""
    from .helpers import podman
    from .conftest import bring_up_node

    node2 = None
    try:
        node2 = bring_up_node(gw_image, gw_network, gw_root)

        # Both nodes need to know about each other — wait for root to have both
        assert wait_for_hostname(gw_root["url"], node2["hostname"], timeout=20)

        # node1 → node2
        assert wait_for_ping(gw_node["cid"], node2["overlay"], timeout=30), \
            "node1 → node2 ping failed"
        # node2 → node1
        assert wait_for_ping(node2["cid"], gw_node["overlay"], timeout=30), \
            "node2 → node1 ping failed"
    finally:
        if node2:
            podman("rm", "-f", node2["cid"], check=False)
