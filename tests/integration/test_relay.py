"""
Integration test: anchor relay.

Two nodes that advertise NO endpoint (outbound-only) can't form a direct tunnel
— neither dials the other, so there's no handshake. This is the same "no
reachable endpoint" condition that an IPv4-only node hits facing an IPv6-only
one (no shared underlay family), just reproduced on a single network without
family tricks. Crucially the nodes are outbound-only from FIRST boot, so they
never establish a direct session that WireGuard roaming could keep alive.

With `sudo gw relay on` the anchor forwards between them and they reach each
other on the overlay; `gw relay off` drops the relayed path again.
"""
import time
import uuid

import pytest

from .conftest import door_enroll, make_anchor, overlay_addr_from_id_pub
from .helpers import container_addr, mesh_iface, pexec, podman, wait_for_ping

pytestmark = pytest.mark.integration


# Rewrite this node's config to advertise no endpoint (endpoint_auto off, no
# explicit endpoints), run as a config file edit before `gw run` so the node is
# outbound-only from its very first published record.
_OUTBOUND_ONLY = (
    "import glob\n"
    "p = glob.glob('/etc/greasewood_*.toml')[0]\n"
    "out = []\n"
    "for l in open(p).read().splitlines():\n"
    "    s = l.strip()\n"
    "    if s.startswith('endpoints'):\n"
    "        continue\n"
    "    if s.startswith('endpoint_auto'):\n"
    "        out.append('endpoint_auto = false')\n"
    "        continue\n"
    "    out.append(l)\n"
    "open(p, 'w').write(chr(10).join(out) + chr(10))\n"
)


def _bring_up_outbound_only(gw_image, net, anchor, hostname):
    """Like bring_up_node, but make the node outbound-only BEFORE `gw run`."""
    r = podman("run", "-d", "--privileged", "--network", net,
               "--sysctl", "net.ipv6.conf.all.disable_ipv6=0",
               gw_image, "sleep", "infinity")
    cid = r.stdout.strip()
    time.sleep(1)
    ipv6 = container_addr(cid, net)
    door_enroll(anchor, cid, ipv6, hostname=hostname)
    pexec(cid, "python3", "-c", _OUTBOUND_ONLY)          # advertise no endpoint
    id_pub = pexec(cid, "sh", "-c",
                   "cat /var/lib/greasewood_*/id_pub.hex").stdout.strip()
    podman("exec", "-d", cid, "sh", "-c", "gw -v run >> /tmp/gw.log 2>&1")
    return {"cid": cid, "hostname": hostname,
            "overlay": overlay_addr_from_id_pub(id_pub), "id_pub": id_pub}


def test_relay_connects_peers_that_cant_go_direct(gw_image):
    net = f"gw-relay-{uuid.uuid4().hex[:8]}"
    podman("network", "create", "--ipv6", "--subnet", "fd00:5e1a::/64", net)
    cids = []
    try:
        anchor = make_anchor(gw_image, net, hostname="relayanchor")
        cids.append(anchor["cid"])
        a = _bring_up_outbound_only(gw_image, net, anchor, "relay-a")
        cids.append(a["cid"])
        b = _bring_up_outbound_only(gw_image, net, anchor, "relay-b")
        cids.append(b["cid"])

        # Both dial the (endpoint-advertising) anchor fine…
        assert wait_for_ping(a["cid"], anchor["overlay"], timeout=60), \
            "A can't reach the anchor"
        assert wait_for_ping(b["cid"], anchor["overlay"], timeout=60), \
            "B can't reach the anchor"

        # Both A and B briefly advertised an endpoint at enrollment (join
        # --endpoint), so they may have formed a direct A<->B tunnel that
        # WireGuard roaming keeps alive even after they went endpoint-less.
        # Delete their mesh interface: the reconcile self-heal rebuilds peers
        # from the now endpoint-less records, so A and B end up reachable ONLY
        # via the anchor — the state a true v4-only/v6-only split starts in.
        for n in (a, b):
            pexec(n["cid"], "ip", "link", "del", mesh_iface(n["cid"]), check=False)
        time.sleep(20)  # interface self-heals + reconverges (no direct A<->B)
        assert wait_for_ping(a["cid"], anchor["overlay"], timeout=60), \
            "A didn't reconverge to the anchor after the interface flush"

        # …but with relay OFF, A and B can't reach each other: neither advertises
        # an endpoint, so neither can dial the other, and nothing relays.
        assert not wait_for_ping(a["cid"], b["overlay"], timeout=20), \
            "A reached B with relay off — expected no direct path (both outbound-only)"

        # Turn relay on at the anchor (opt-in, live — no restart).
        r = pexec(anchor["cid"], "gw", "relay", "on")
        assert r.returncode == 0, f"gw relay on failed:\n{r.stdout}\n{r.stderr}"

        # Relay ON: the anchor forwards → A and B reach each other on the overlay.
        assert wait_for_ping(a["cid"], b["overlay"], timeout=90), \
            "A can't reach B with relay on — anchor forwarding isn't working"
        assert wait_for_ping(b["cid"], a["overlay"], timeout=60), \
            "B can't reach A with relay on"

        # Turn it off → the relayed path drops. Give the fleet a few cycles to
        # pick up relay=False (else wait_for_ping catches the still-up tail).
        pexec(anchor["cid"], "gw", "relay", "off")
        time.sleep(20)
        assert not wait_for_ping(a["cid"], b["overlay"], timeout=40), \
            "A still reached B after relay off"
    finally:
        for cid in cids:
            podman("rm", "-f", cid, check=False)
        podman("network", "rm", "-f", net, check=False)
