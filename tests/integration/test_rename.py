"""
Integration test for `gw rename-node` — change a node's mesh hostname without
re-joining. Verifies the anchor adopts the new name over the live control plane,
the old name is freed for reuse, and the local config is updated.
"""
import pytest

from .conftest import bring_up_node
from .helpers import (
    directory_hostnames, pexec, podman, wait_for_hostname, wait_for_ping,
)

pytestmark = pytest.mark.integration


def test_rename_updates_anchor_and_frees_old_name(gw_anchor, gw_image, gw_network):
    node = other = None
    try:
        node = bring_up_node(gw_image, gw_network, gw_anchor, hostname="oldname")
        assert wait_for_hostname(gw_anchor["cid"], "oldname", timeout=20)
        # rename talks to the anchor control plane, so the mesh must be up.
        assert wait_for_ping(node["cid"], gw_anchor["overlay"], timeout=40), \
            "mesh never formed"

        r = pexec(node["cid"], "gw",
                  "rename-node", "newname", check=False)
        assert r.returncode == 0, r.stdout + r.stderr

        # Anchor adopts the new name; the old one disappears (same id, higher seq).
        assert wait_for_hostname(gw_anchor["cid"], "newname", timeout=20)
        assert "oldname" not in directory_hostnames(gw_anchor["cid"])

        # Local config was updated.
        cfg = pexec(node["cid"], "sh", "-c", "cat /etc/greasewood_*.toml").stdout
        assert 'hostname = "newname"' in cfg

        # The freed name can be claimed by a different node.
        other = bring_up_node(gw_image, gw_network, gw_anchor, hostname="oldname")
        assert wait_for_hostname(gw_anchor["cid"], "oldname", timeout=20)
    finally:
        for n in (node, other):
            if n:
                podman("rm", "-f", n["cid"], check=False)
