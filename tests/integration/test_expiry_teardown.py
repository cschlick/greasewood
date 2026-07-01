"""
Integration test: expiry-driven peer teardown (milestone 4).

greasewood's revocation model is "stop renewing → the node falls out fleet-wide
when its credential lapses" (no CRL). This test proves that end to end on a live
WireGuard interface: with a short `credential_ttl`, a node that stops renewing is
removed as a peer by another node's reconcile loop when its credential expires.

Needs its own hub because the shared `gw_hub` issues 24h credentials.
"""
import time

import pytest

from .conftest import bring_up_node, make_hub
from .helpers import podman, wg_peer_count, wait_for_peer_count

pytestmark = pytest.mark.integration


def _wait_peer_count_at_most(cid, at_most, iface="gw-mesh", timeout=150):
    """Block until the interface has at most `at_most` peers (i.e. one was torn
    down). Returns True if it dropped, False on timeout."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if wg_peer_count(cid, iface) <= at_most:
            return True
        time.sleep(3)
    return False


def test_expired_node_is_torn_down_by_peer(gw_image, gw_network):
    cids = []
    try:
        hub = make_hub(gw_image, gw_network, ttl="1m", hostname="ttlhub")
        cids.append(hub["cid"])

        alive = bring_up_node(gw_image, gw_network, hub, hostname="alive")
        cids.append(alive["cid"])
        doomed = bring_up_node(gw_image, gw_network, hub, hostname="doomed")
        cids.append(doomed["cid"])

        # `alive` forms a full mesh: peers with the hub AND with `doomed` = 2.
        assert wait_for_peer_count(alive["cid"], 2, timeout=60) >= 2, \
            "the surviving node never reached 2 peers (hub + doomed)"

        # `doomed` stops renewing (container stopped). Its 1-minute credential
        # now lapses with nothing to refresh it.
        podman("stop", "-t", "2", doomed["cid"])

        # The surviving node must drop `doomed` on expiry, leaving only the hub.
        # This is the reconcile-time expiry check removing a live WireGuard peer
        # — the "revocation = not renewing" guarantee, proven on the interface.
        assert _wait_peer_count_at_most(alive["cid"], 1, timeout=150), (
            "the surviving node did not tear down the expired peer "
            f"(still {wg_peer_count(alive['cid'])} peers after 150s)"
        )
    finally:
        for cid in cids:
            podman("rm", "-f", cid, check=False)
