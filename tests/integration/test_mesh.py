"""
Integration tests for the greasewood mesh.

Each test uses real WireGuard interfaces inside privileged Podman containers.

Run:
  pytest tests/integration/ -v
"""
import time

import pytest

from .helpers import (
    container_ipv6, directory_hostnames, directory_records, hub_get, podman,
    wait_for_hostname, wait_for_ping,
)

pytestmark = pytest.mark.integration


# ---------------------------------------------------------------------------
# Root-only tests (no node needed). Control plane is queried from inside the
# hub container over loopback — it's not reachable from the host by design.
# ---------------------------------------------------------------------------

def test_hub_health(gw_hub):
    assert "ok" in hub_get(gw_hub["cid"], "/health")


def test_hub_in_own_directory(gw_hub):
    assert "hub" in directory_hostnames(gw_hub["cid"])


# ---------------------------------------------------------------------------
# Node enrollment tests
# ---------------------------------------------------------------------------

def test_node_appears_in_root_directory(gw_hub, gw_node):
    """Node pushes its NodeRecord to root on startup — should appear within seconds."""
    assert wait_for_hostname(gw_hub["cid"], gw_node["hostname"], timeout=20), \
        f"{gw_node['hostname']} never appeared in root directory"


def test_hub_overlay_addr_in_directory(gw_hub):
    """Root's NodeRecord contains a valid fd8d:: overlay address."""
    data = directory_records(gw_hub["cid"])
    hub_record = next(r for r in data if r["hostname"] == "hub")
    # addr is anchored in the signed credential, not a top-level record field.
    assert hub_record["cred"]["addr"].startswith("fd8d:e5c1:db1a:")


def test_duplicate_hostname_refused(gw_hub, gw_image, gw_network):
    """The hub refuses to enroll a second node with a name already in use."""
    from .conftest import bring_up_node, door_enroll_via

    node = c2 = None
    try:
        node = bring_up_node(gw_image, gw_network, gw_hub, hostname="dupename")
        c2 = podman(
            "run", "-d", "--privileged", "--network", gw_network,
            "--sysctl", "net.ipv6.conf.all.disable_ipv6=0",
            gw_image, "sleep", "infinity",
        ).stdout.strip()
        time.sleep(1)
        ipv6 = container_ipv6(c2, gw_network)
        j = door_enroll_via(gw_hub["cid"], gw_hub["ipv6"], c2, ipv6,
                            hostname="dupename", check=False)
        assert j.returncode != 0, "join should fail for a duplicate hostname"
        assert "already in use" in (j.stdout + j.stderr).lower(), \
            f"unexpected message:\n{j.stdout}\n{j.stderr}"
    finally:
        for cid in (node["cid"] if node else None, c2):
            if cid:
                podman("rm", "-f", cid, check=False)


def test_rejoin_reuses_keys_and_preserves_config(gw_hub, gw_image, gw_network):
    """
    Re-joining an already-enrolled node with a fresh token is a credential
    refresh: it reuses the node's keys (same id_pub → same overlay address),
    preserves the existing hostname when --hostname is omitted, and announces
    the re-enrollment.
    """
    from .helpers import container_ipv6, pexec, podman
    from .conftest import bring_up_node, door_enroll

    node = None
    try:
        node = bring_up_node(gw_image, gw_network, gw_hub, hostname="alpha")
        id_pub_before = node["id_pub"]
        ipv6 = container_ipv6(node["cid"], gw_network)

        # Re-join with a new token and NO --hostname/--caps.
        rj = door_enroll(gw_hub, node["cid"], ipv6)

        # 1. Announces the re-enrollment (notice goes to the log on stderr).
        assert "re-enrolling existing node" in rj.stderr, \
            f"no re-enrollment notice:\n{rj.stderr}"

        # 2. Keys reused — same id_pub, hence same overlay address.
        id_pub_after = pexec(
            node["cid"], "cat", "/var/lib/greasewood/id_pub.hex"
        ).stdout.strip()
        assert id_pub_after == id_pub_before, "re-join changed the node's identity"

        # 3. Prior hostname preserved (not reset to user@hostname).
        cfg = pexec(node["cid"], "cat", "/etc/greasewood.toml").stdout
        assert 'hostname = "alpha"' in cfg, f"hostname not preserved:\n{cfg}"
    finally:
        if node:
            podman("rm", "-f", node["cid"], check=False)


# ---------------------------------------------------------------------------
# WireGuard connectivity tests
# ---------------------------------------------------------------------------

def test_hub_pings_node(gw_hub, gw_node):
    """Root can ping the node's overlay address after enrollment."""
    assert wait_for_ping(gw_hub["cid"], gw_node["overlay"], timeout=30), \
        f"root → node ping failed (target: {gw_node['overlay']})"


def test_node_pings_root(gw_hub, gw_node):
    """Node can ping root's overlay address."""
    assert wait_for_ping(gw_node["cid"], gw_hub["overlay"], timeout=30), \
        f"node → root ping failed (target: {gw_hub['overlay']})"


def test_two_nodes_ping_each_other(gw_hub, gw_node, gw_image, gw_network):
    """Two independent nodes can reach each other via the overlay."""
    from .helpers import podman
    from .conftest import bring_up_node

    node2 = None
    try:
        node2 = bring_up_node(gw_image, gw_network, gw_hub)

        # Both nodes need to know about each other — wait for root to have both
        assert wait_for_hostname(gw_hub["cid"], node2["hostname"], timeout=20)

        # node1 → node2
        assert wait_for_ping(gw_node["cid"], node2["overlay"], timeout=30), \
            "node1 → node2 ping failed"
        # node2 → node1
        assert wait_for_ping(node2["cid"], gw_node["overlay"], timeout=30), \
            "node2 → node1 ping failed"
    finally:
        if node2:
            podman("rm", "-f", node2["cid"], check=False)
