"""
Integration test: the grant table derives the tunnel topology (gw policy).

The full lifecycle on real kernel WireGuard: a fresh mesh with no policy is
flat (everyone peers); applying a grant table prunes every tunnel no grant
authorizes (web1↔web2 goes away) while granted flows (web↔api) and the
hardwired anchor links stay up; widening the policy restores the pruned
tunnel. Dedicated anchor so the shared session anchor isn't polluted.
"""
import time

import pytest

from .conftest import bring_up_node, make_anchor
from .helpers import ping_once, podman, wait_for_ping

pytestmark = pytest.mark.integration


def test_grant_table_derives_topology(gw_image, gw_network):
    cids = []
    try:
        anchor = make_anchor(gw_image, gw_network, hostname="polanchor")
        cids.append(anchor["cid"])
        web1 = bring_up_node(gw_image, gw_network, anchor,
                             hostname="web1", roles="web")
        cids.append(web1["cid"])
        web2 = bring_up_node(gw_image, gw_network, anchor,
                             hostname="web2", roles="web")
        cids.append(web2["cid"])
        api1 = bring_up_node(gw_image, gw_network, anchor,
                             hostname="api1", roles="api")
        cids.append(api1["cid"])

        # ---- open policy (* -> * : *) → flat mesh: everyone reaches everyone.
        # make_anchor applies the open baseline (a fresh anchor is default-CLOSED). ----
        assert wait_for_ping(web1["cid"], api1["overlay"], timeout=40), \
            "flat mesh: web1 should reach api1 under the open policy"
        assert wait_for_ping(web1["cid"], web2["overlay"], timeout=40), \
            "flat mesh: web1 should reach web2 under the open policy"

        # ---- apply web -> api : the table now derives the topology ----
        podman("exec", anchor["cid"], "sh", "-c",
               'printf \'[[grant]]\\nfrom = ["web"]\\nto = ["api"]\\n'
               'ports = ["tcp/8000"]\\n\' '
               '> "$(ls -d /var/lib/greasewood_*)"/grants.toml')
        out = podman("exec", anchor["cid"], "gw", "policy", "apply", "-y").stdout
        assert "web1 ↔ web2" in out          # the delta preview names the prune

        # granted flow survives; ungranted tunnel is torn down.
        assert wait_for_ping(web1["cid"], api1["overlay"], timeout=60), \
            "granted flow (web→api) must survive the policy"
        deadline = time.time() + 90
        while time.time() < deadline:
            if not ping_once(web1["cid"], web2["overlay"], timeout=2):
                break
            time.sleep(3)
        for _ in range(3):                   # confirm it STAYS down
            assert not ping_once(web1["cid"], web2["overlay"], timeout=2), \
                "web1↔web2 has no grant — the tunnel must be pruned"
            time.sleep(2)
        # the anchor is hardwired beneath the policy
        assert wait_for_ping(web1["cid"], anchor["overlay"], timeout=30), \
            "anchor links must survive any policy"

        # ---- widen the policy: the pruned tunnel comes back ----
        podman("exec", anchor["cid"], "sh", "-c",
               'printf \'\\n[[grant]]\\nfrom = ["web"]\\nto = ["web"]\\n'
               'ports = ["*"]\\n\' '
               '>> "$(ls -d /var/lib/greasewood_*)"/grants.toml')
        podman("exec", anchor["cid"], "gw", "policy", "apply", "-y")
        assert wait_for_ping(web1["cid"], web2["overlay"], timeout=90), \
            "widening the policy must restore web1↔web2"
    finally:
        for cid in cids:
            podman("rm", "-f", cid, check=False)


def test_fresh_anchor_ships_default_closed_star(gw_image, gw_network):
    """A fresh anchor ships DEFAULT-CLOSED: the shipped grant is
    `admin -> anchor,node : tcp/22`, so the anchor (role:admin) reaches nodes but
    two ordinary nodes CANNOT reach each other — the secure star. No open policy
    applied (open_policy=False)."""
    cids = []
    try:
        anchor = make_anchor(gw_image, gw_network, hostname="staranchor",
                             open_policy=False)
        cids.append(anchor["cid"])
        n1 = bring_up_node(gw_image, gw_network, anchor, hostname="star1")
        cids.append(n1["cid"])
        n2 = bring_up_node(gw_image, gw_network, anchor, hostname="star2")
        cids.append(n2["cid"])

        # anchor reaches every node (role:* peering + hardwired icmp/control)
        assert wait_for_ping(anchor["cid"], n1["overlay"], timeout=40), \
            "default-closed: the anchor must still reach every node"
        assert wait_for_ping(anchor["cid"], n2["overlay"], timeout=40), \
            "default-closed: the anchor must still reach every node"

        # ...but the two ordinary nodes have no grant connecting them → no tunnel.
        for _ in range(3):
            assert not ping_once(n1["cid"], n2["overlay"], timeout=2), \
                "default-closed star: node<->node must NOT be reachable"
            time.sleep(2)
    finally:
        for cid in cids:
            podman("rm", "-f", cid, check=False)
