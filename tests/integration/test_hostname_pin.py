"""
Integration test: anchor-pinned hostnames (`gw invite --hostname`).

When the anchor pins a name at invite, the joiner's requested `--hostname` is
ignored (the credential carries the anchor's name), and the node cannot
`gw rename-node` itself afterward (the `hostname-pinned` marker). Dedicated anchor so the
shared session anchor isn't polluted.
"""
import pytest

from .conftest import bring_up_node, make_anchor
from .helpers import pexec, podman

pytestmark = pytest.mark.integration


def test_anchor_pinned_hostname_overrides_and_locks_rename(gw_image, gw_network):
    cids = []
    try:
        anchor = make_anchor(gw_image, gw_network, hostname="pinanchor")
        cids.append(anchor["cid"])

        # The node asks for "attacker-name" at join; the anchor pins "pinned-db".
        node = bring_up_node(gw_image, gw_network, anchor,
                             hostname="attacker-name", invite_hostname="pinned-db")
        cids.append(node["cid"])

        # 1. The anchor's pin wins — the issued name is "pinned-db", and the name
        #    the joiner requested never takes effect.
        status = pexec(node["cid"], "gw", "watch", "--snapshot").stdout
        assert "pinned-db" in status, f"pinned name not applied:\n{status}"
        assert "attacker-name" not in status, \
            f"joiner's requested name leaked through:\n{status}"

        # 2. A pinned node cannot rename itself.
        r = pexec(node["cid"], "gw", "rename-node", "somethingelse", check=False)
        assert r.returncode != 0, "rename should be refused for a pinned node"
        assert "pinned" in (r.stdout + r.stderr).lower(), \
            f"expected a 'pinned' refusal:\n{r.stdout}\n{r.stderr}"

        # 3. The anchor refuses to pin an already-taken name — checked at invite,
        #    before the token goes out (a pinned name can't collide at enroll).
        inv = pexec(anchor["cid"], "gw", "invite", "--endpoint", anchor["ipv6"],
                    "--hostname", "pinned-db", check=False)
        assert inv.returncode != 0, "invite should refuse an already-used pinned name"
        assert "already in use" in (inv.stdout + inv.stderr).lower(), \
            f"expected 'already in use':\n{inv.stdout}\n{inv.stderr}"
    finally:
        for cid in cids:
            podman("rm", "-f", cid, check=False)
