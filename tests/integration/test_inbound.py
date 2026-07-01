"""
Integration test for outbound-only nodes (inbound=no).

A node enrolled with --inbound no should: still link to the hub (it dials out,
the reachable hub answers and roams to it), NOT advertise an endpoint in the
directory, and be refused promotion to hub.
"""
import pytest

from .conftest import bring_up_node
from .helpers import directory_records, pexec, podman, wait_for_ping

pytestmark = pytest.mark.integration


def test_outbound_only_node(gw_hub, gw_image, gw_network):
    node = None
    try:
        node = bring_up_node(gw_image, gw_network, gw_hub,
                             hostname="outbound1", inbound="no")

        # It dials the hub (reachable), so the link still forms.
        assert wait_for_ping(node["cid"], gw_hub["overlay"], timeout=30), \
            "outbound-only node could not reach the hub it dials"

        # Its directory record advertises no endpoint (peers won't dial it).
        recs = directory_records(gw_hub["cid"])
        rec = next((r for r in recs if r["hostname"] == "outbound1"), None)
        assert rec is not None, "node not in directory"
        assert rec["endpoints"] == [], f"should advertise no endpoint: {rec['endpoints']}"
        assert rec["inbound"] == "no"

        # diagnose's reachability advisory: an outbound-only peer dialing in is
        # proof the hub is inbound-reachable, so on the hub it must confirm.
        d = pexec(gw_hub["cid"], "gw", "diagnose")
        assert "inbound=yes CONFIRMED" in d.stdout, \
            f"diagnose should confirm hub reachability:\n{d.stdout}"

        # It cannot be promoted to hub.
        r = pexec(node["cid"], "gw", "hub-promote", check=False)
        assert r.returncode != 0, "hub-promote should refuse an outbound-only node"
        assert "outbound-only" in (r.stdout + r.stderr).lower(), \
            f"unexpected message:\n{r.stdout}\n{r.stderr}"

        # After switching it back to inbound, promotion is allowed (config check
        # only — we don't restart the daemon here).
        pexec(node["cid"], "gw", "set-inbound", "yes")
        r2 = pexec(node["cid"], "gw", "hub-promote", check=False)
        assert r2.returncode == 0, \
            f"hub-promote should work after set-inbound yes:\n{r2.stdout}\n{r2.stderr}"
    finally:
        if node:
            podman("rm", "-f", node["cid"], check=False)
