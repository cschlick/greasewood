"""
Integration test: `gw revoke` takes effect on a RUNNING anchor with no restart.

End-to-end version of security-review finding #3 (the revoke list is re-read live
each reconcile). Revoking a node must evict it from the anchor's live WireGuard
interface within a reconcile cycle — without bouncing the daemon — even though
its record is still present in the directory (eviction is revoke-driven, not
record-deletion). Uses a dedicated anchor so the shared session anchor's revoke list
isn't polluted. (The renew-refusal half is covered by unit test_ca_guards.)
"""
import time

import pytest

from .conftest import bring_up_node, make_anchor
from .helpers import directory_records, pexec, podman, wg_peer_count, wait_for_peer_count

pytestmark = pytest.mark.integration


def _wait_peer_gone(cid, at_most, iface="gw-testmesh", timeout=60):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if wg_peer_count(cid, iface) <= at_most:
            return True
        time.sleep(2)
    return False


def test_revoke_evicts_live_without_restart(gw_image, gw_network):
    cids = []
    try:
        anchor = make_anchor(gw_image, gw_network, hostname="revanchor")
        cids.append(anchor["cid"])
        node = bring_up_node(gw_image, gw_network, anchor, hostname="doomed")
        cids.append(node["cid"])

        assert wait_for_peer_count(anchor["cid"], 1, timeout=60) >= 1, \
            "anchor never peered with the node"

        # Revoke ON THE RUNNING ANCHOR — no daemon restart.
        r = pexec(anchor["cid"], "gw", "revoke", node["id_pub"])
        assert r.returncode == 0, f"revoke failed:\n{r.stdout}\n{r.stderr}"

        # The anchor evicts it from the live interface within a reconcile cycle.
        assert _wait_peer_gone(anchor["cid"], 0, timeout=60), (
            "anchor did not evict the revoked peer live "
            f"(still {wg_peer_count(anchor['cid'])} peers)"
        )

        # The record is still in the directory — eviction is driven by the live
        # revoke check, not by deleting the record.
        names = {r["cred"]["hostname"] for r in directory_records(anchor["cid"])}
        assert "doomed" in names, f"record should remain in the directory: {names}"
    finally:
        for cid in cids:
            podman("rm", "-f", cid, check=False)
