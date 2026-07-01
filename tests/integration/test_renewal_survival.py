"""
Integration test: a running mesh stays fully linked PAST one credential TTL.

This is the positive counterpart to test_expiry_teardown (where a *stopped* node
falls out) and the end-to-end version of security-review finding #1: renewed
credentials must be re-published to the hub so peers (which pull from the hub)
see the fresh expiry and DON'T evict a healthy node. With a 1-minute TTL, if
renewal→publish→sync→reconcile weren't working, peers would evict each other at
~60s. We wait well past that and assert everyone is still peered.
"""
import time

import pytest

from .conftest import bring_up_node, make_hub
from .helpers import podman, wg_peer_count, wait_for_peer_count

pytestmark = pytest.mark.integration


def test_running_mesh_survives_past_one_ttl(gw_image, gw_network):
    cids = []
    try:
        hub = make_hub(gw_image, gw_network, ttl="1m", hostname="ttlhub")
        cids.append(hub["cid"])
        a = bring_up_node(gw_image, gw_network, hub, hostname="alpha")
        cids.append(a["cid"])
        b = bring_up_node(gw_image, gw_network, hub, hostname="bravo")
        cids.append(b["cid"])

        # Full mesh: alpha peers with hub AND bravo = 2 peers.
        assert wait_for_peer_count(a["cid"], 2, timeout=60) >= 2, \
            "alpha never reached 2 peers (hub + bravo)"

        # Wait past one full 60s TTL (with margin). Nothing is stopped, so if
        # renewal is propagating, the original credentials get refreshed before
        # they lapse and no one is evicted. A non-propagating bug would drop
        # peers around the 60s mark.
        time.sleep(95)

        assert wg_peer_count(a["cid"]) >= 2, (
            "alpha lost a peer past one TTL — renewed credentials aren't "
            f"propagating (only {wg_peer_count(a['cid'])} peers left)"
        )
        # And the hub still holds both nodes.
        assert wg_peer_count(hub["cid"]) >= 2, \
            f"hub lost a peer past one TTL ({wg_peer_count(hub['cid'])} peers)"
    finally:
        for cid in cids:
            podman("rm", "-f", cid, check=False)
