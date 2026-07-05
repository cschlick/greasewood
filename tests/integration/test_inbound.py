"""
Integration test for outbound-only nodes (inbound=no).

A node enrolled with --inbound no should: still link to the anchor (it dials out,
the reachable anchor answers and roams to it), NOT advertise an endpoint in the
directory, and be refused promotion to anchor.
"""
import time

import pytest

from .conftest import bring_up_node
from .helpers import directory_records, ping_once, pexec, podman, wait_for_ping

pytestmark = pytest.mark.integration


def test_two_outbound_only_nodes_cannot_pair(gw_anchor, gw_image, gw_network):
    """direct-or-fail asymmetry: two inbound=no nodes each reach the (reachable)
    anchor by dialing out, but cannot link to EACH OTHER — neither advertises an
    endpoint, so neither can initiate. Proving a negative: confirm the mesh is
    otherwise healthy, then that the X<->Y link never forms."""
    cids = []
    try:
        x = bring_up_node(gw_image, gw_network, gw_anchor, hostname="obx", inbound="no")
        cids.append(x["cid"])
        y = bring_up_node(gw_image, gw_network, gw_anchor, hostname="oby", inbound="no")
        cids.append(y["cid"])

        # Each outbound-only node reaches the reachable anchor (it dials out).
        assert wait_for_ping(x["cid"], gw_anchor["overlay"], timeout=40), "obx can't reach anchor"
        assert wait_for_ping(y["cid"], gw_anchor["overlay"], timeout=40), "oby can't reach anchor"

        # Give any X<->Y handshake ample time, then confirm it NEVER forms
        # (both advertise no endpoint, so neither side can initiate).
        time.sleep(20)
        for _ in range(3):
            assert not ping_once(x["cid"], y["overlay"], timeout=2), \
                "two outbound-only nodes must not be able to link (direct-or-fail)"
            time.sleep(2)
    finally:
        for cid in cids:
            podman("rm", "-f", cid, check=False)


def test_outbound_only_node(gw_anchor, gw_image, gw_network):
    node = None
    try:
        node = bring_up_node(gw_image, gw_network, gw_anchor,
                             hostname="outbound1", inbound="no")

        # It dials the anchor (reachable), so the link still forms.
        assert wait_for_ping(node["cid"], gw_anchor["overlay"], timeout=30), \
            "outbound-only node could not reach the anchor it dials"

        # Its directory record advertises no endpoint (peers won't dial it).
        recs = directory_records(gw_anchor["cid"])
        rec = next((r for r in recs if r["cred"]["hostname"] == "outbound1"), None)
        assert rec is not None, "node not in directory"
        assert rec["endpoints"] == [], f"should advertise no endpoint: {rec['endpoints']}"
        assert rec["inbound"] == "no"

        # diagnose's reachability advisory: an outbound-only peer dialing in is
        # proof the anchor is inbound-reachable, so on the anchor it must confirm.
        d = pexec(gw_anchor["cid"], "gw", "diagnose")
        assert "inbound=yes CONFIRMED" in d.stdout, \
            f"diagnose should confirm anchor reachability:\n{d.stdout}"

        # It cannot be promoted to anchor.
        r = pexec(node["cid"], "gw", "anchor-promote", check=False)
        assert r.returncode != 0, "anchor-promote should refuse an outbound-only node"
        assert "outbound-only" in (r.stdout + r.stderr).lower(), \
            f"unexpected message:\n{r.stdout}\n{r.stderr}"

        # After switching it back to inbound, promotion is allowed (config check
        # only — we don't restart the daemon here).
        pexec(node["cid"], "gw", "set-inbound", "yes")
        r2 = pexec(node["cid"], "gw", "anchor-promote", check=False)
        assert r2.returncode == 0, \
            f"anchor-promote should work after set-inbound yes:\n{r2.stdout}\n{r2.stderr}"
    finally:
        if node:
            podman("rm", "-f", node["cid"], check=False)
