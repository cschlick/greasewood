"""
Integration test for `gw diagnose` — the connectivity debugging tool.

Brings up an anchor + node, lets the mesh form, then runs `gw diagnose` inside each
container and checks it correctly reports the link as LINKED (and that the anchor
sees the node and vice-versa). This exercises the real 7-step checks plus live
WireGuard handshake parsing.
"""
import pytest

from .conftest import bring_up_node
from .helpers import pexec, podman, wait_for_ping

pytestmark = pytest.mark.integration


def test_diagnose_reports_linked(gw_anchor, gw_image, gw_network):
    node = None
    try:
        node = bring_up_node(gw_image, gw_network, gw_anchor, hostname="diagnode")
        # Wait for the data plane to actually converge before diagnosing.
        assert wait_for_ping(node["cid"], gw_anchor["overlay"], timeout=40), \
            "node never reached the anchor overlay"

        # From the node's perspective: the anchor should show as LINKED.
        out = pexec(node["cid"], "gw", "diagnose").stdout
        assert "anchor" in out, out
        assert "LINKED" in out, f"expected a LINKED peer, got:\n{out}"
        assert "REJECTED" not in out, f"unexpected rejection:\n{out}"

        # From the anchor's perspective: no-arg diagnose is self ↔ anchor,
        # which on the anchor is just itself (the pairwise design) — so target
        # the node explicitly. It should show as LINKED there too.
        out_anchor = pexec(gw_anchor["cid"], "gw",
                           "diagnose", "diagnode").stdout
        assert "diagnode" in out_anchor, out_anchor
        assert "LINKED" in out_anchor, f"anchor should see node linked:\n{out_anchor}"
        assert out_anchor.count("●") == 1
    finally:
        if node:
            podman("rm", "-f", node["cid"], check=False)
