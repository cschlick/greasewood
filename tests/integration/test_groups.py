"""
Integration test: segmentation groups (group:<name> cap tags).

Nodes peer only within a shared group; the hub (group:* by default) reaches every
segment. Exercises the positive (same-group link forms), the negative
(cross-group link never forms), and hub-reaches-all. Dedicated hub so the shared
session hub isn't polluted.
"""
import time

import pytest

from .conftest import bring_up_node, make_hub
from .helpers import ping_once, podman, wait_for_ping

pytestmark = pytest.mark.integration


def test_groups_segment_the_mesh(gw_image, gw_network):
    cids = []
    try:
        hub = make_hub(gw_image, gw_network, hostname="grouphub")
        cids.append(hub["cid"])
        a = bring_up_node(gw_image, gw_network, hub,
                          hostname="prod-a", caps="mesh,group:prod")
        cids.append(a["cid"])
        c = bring_up_node(gw_image, gw_network, hub,
                          hostname="prod-c", caps="mesh,group:prod")
        cids.append(c["cid"])
        b = bring_up_node(gw_image, gw_network, hub,
                          hostname="dev-b", caps="mesh,group:dev")
        cids.append(b["cid"])

        # The hub carries group:*, so every node reaches it regardless of group.
        for n in (a, c, b):
            assert wait_for_ping(n["cid"], hub["overlay"], timeout=40), \
                f"{n['hostname']} can't reach the hub"

        # Same group (prod) → A and C form a direct link.
        assert wait_for_ping(a["cid"], c["overlay"], timeout=40), \
            "same-group nodes should peer"

        # Different groups → A (prod) and B (dev) must never link.
        time.sleep(15)
        for _ in range(3):
            assert not ping_once(a["cid"], b["overlay"], timeout=2), \
                "different-group nodes must not peer (segmentation)"
            time.sleep(2)
    finally:
        for cid in cids:
            podman("rm", "-f", cid, check=False)
