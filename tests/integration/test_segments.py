"""
Integration test: segments (segment:<name> tags).

Nodes peer only within a shared segment; the anchor (segment:* by default) reaches
every segment. Exercises the positive (same-segment link forms), the negative
(cross-segment link never forms), and anchor-reaches-all. Dedicated anchor so the
shared session anchor isn't polluted.
"""
import time

import pytest

from .conftest import bring_up_node, make_anchor
from .helpers import ping_once, podman, wait_for_ping

pytestmark = pytest.mark.integration


def test_segments_partition_the_mesh(gw_image, gw_network):
    cids = []
    try:
        anchor = make_anchor(gw_image, gw_network, hostname="seganchor")
        cids.append(anchor["cid"])
        a = bring_up_node(gw_image, gw_network, anchor,
                          hostname="prod-a", segments="prod")
        cids.append(a["cid"])
        c = bring_up_node(gw_image, gw_network, anchor,
                          hostname="prod-c", segments="prod")
        cids.append(c["cid"])
        b = bring_up_node(gw_image, gw_network, anchor,
                          hostname="dev-b", segments="dev")
        cids.append(b["cid"])

        # The anchor carries segment:*, so every node reaches it regardless.
        for n in (a, c, b):
            assert wait_for_ping(n["cid"], anchor["overlay"], timeout=40), \
                f"{n['hostname']} can't reach the anchor"

        # Same segment (prod) → A and C form a direct link.
        assert wait_for_ping(a["cid"], c["overlay"], timeout=40), \
            "same-segment nodes should peer"

        # Different segments → A (prod) and B (dev) must never link.
        time.sleep(15)
        for _ in range(3):
            assert not ping_once(a["cid"], b["overlay"], timeout=2), \
                "different-segment nodes must not peer (segmentation)"
            time.sleep(2)
    finally:
        for cid in cids:
            podman("rm", "-f", cid, check=False)
