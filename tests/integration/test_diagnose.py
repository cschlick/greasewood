"""
Integration test for `gw diagnose` — the connectivity debugging tool.

Brings up a hub + node, lets the mesh form, then runs `gw diagnose` inside each
container and checks it correctly reports the link as LINKED (and that the hub
sees the node and vice-versa). This exercises the real 7-step checks plus live
WireGuard handshake parsing.
"""
import pytest

from .conftest import bring_up_node
from .helpers import pexec, podman, wait_for_ping

pytestmark = pytest.mark.integration


def test_diagnose_reports_linked(gw_root, gw_image, gw_network):
    node = None
    try:
        node = bring_up_node(gw_image, gw_network, gw_root, hostname="diagnode")
        # Wait for the data plane to actually converge before diagnosing.
        assert wait_for_ping(node["cid"], gw_root["overlay"], timeout=40), \
            "node never reached the hub overlay"

        # From the node's perspective: the hub should show as LINKED.
        out = pexec(node["cid"], "gw", "-c", "/etc/greasewood.toml", "diagnose").stdout
        assert "root" in out, out
        assert "LINKED" in out, f"expected a LINKED peer, got:\n{out}"
        assert "REJECTED" not in out, f"unexpected rejection:\n{out}"

        # From the hub's perspective: the node should show as LINKED too.
        out_hub = pexec(gw_root["cid"], "gw", "-c", "/etc/greasewood.toml", "diagnose").stdout
        assert "diagnode" in out_hub, out_hub
        assert "LINKED" in out_hub, f"hub should see node linked:\n{out_hub}"

        # Targeted form: `gw diagnose <hostname>` narrows to that one peer.
        one = pexec(gw_root["cid"], "gw", "-c", "/etc/greasewood.toml",
                    "diagnose", "diagnode").stdout
        assert one.count("●") == 1 and "diagnode" in one
    finally:
        if node:
            podman("rm", "-f", node["cid"], check=False)
