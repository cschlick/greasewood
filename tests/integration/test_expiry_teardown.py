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

from .conftest import bring_up_node, overlay_addr_from_id_pub
from .helpers import (
    container_ipv6, pexec, podman, wait_for_control_plane,
    wg_peer_count, wait_for_peer_count,
)

pytestmark = pytest.mark.integration


def _short_ttl_hub(gw_image, gw_network, ttl="1m"):
    """A hub that issues short-lived credentials. Mirrors conftest.gw_hub but
    passes --credential-ttl. The renewal loop floors its interval at 30s, so a
    1-minute TTL keeps running nodes alive (they renew at ~30s) while a stopped
    node lapses within ~60s."""
    r = podman(
        "run", "-d", "--privileged", "--network", gw_network,
        "--sysctl", "net.ipv6.conf.all.disable_ipv6=0",
        gw_image, "sleep", "infinity",
    )
    cid = r.stdout.strip()
    time.sleep(1)
    ipv6 = container_ipv6(cid, gw_network)
    assert ipv6, "ttl-hub container got no IPv6 address"
    pexec(cid, "gw", "setup-hub", "--hostname", "ttlhub",
          "--endpoint", f"[{ipv6}]:51900", "--credential-ttl", ttl)
    id_pub = pexec(cid, "cat", "/var/lib/greasewood/id_pub.hex").stdout.strip()
    ca_pub = pexec(cid, "cat", "/var/lib/greasewood/ca.pub").stdout.strip()
    podman("exec", "-d", cid, "sh", "-c", "gw run >> /tmp/gw.log 2>&1")
    assert wait_for_control_plane(cid, timeout=20), "ttl-hub daemon did not start"
    return {
        "cid": cid, "ipv6": ipv6, "ca_pub": ca_pub,
        "overlay": overlay_addr_from_id_pub(id_pub),
    }


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
        hub = _short_ttl_hub(gw_image, gw_network, ttl="1m")
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
