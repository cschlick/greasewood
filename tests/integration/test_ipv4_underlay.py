"""
Integration test: IPv4 underlay.

greasewood's overlay is IPv6-only, but the *underlay* (the WireGuard endpoint
transport + the enrollment door) is address-family-agnostic. This runs a whole
mesh on an **IPv4-only** podman network — the case that matters for v4-by-default
clouds (EC2/Vultr) — and proves the IPv6 overlay converges over it:

  - the podman network has NO IPv6 (v4-only underlay),
  - containers keep IPv6 enabled *inside* (so gw-mesh can hold a v6 overlay addr),
  - enrollment (door over v4) + node<->node links all form,
  - nodes ping each other over their v6 overlay addresses, carried by v4 WG.
"""
import uuid

import pytest

from .conftest import bring_up_node, make_hub
from .helpers import container_ipv4, container_ipv6, podman, wait_for_ping

pytestmark = pytest.mark.integration


def test_ipv4_underlay_mesh_converges(gw_image):
    net = f"gw-v4-{uuid.uuid4().hex[:8]}"
    # v4-only network (no --ipv6): the underlay is IPv4.
    podman("network", "create", "--subnet", "10.89.199.0/24", net)
    cids = []
    try:
        hub = make_hub(gw_image, net, hostname="v4hub")
        cids.append(hub["cid"])

        # Sanity: the underlay really is IPv4-only.
        assert container_ipv4(hub["cid"], net), "hub got no v4 underlay address"
        assert not container_ipv6(hub["cid"], net), \
            "network unexpectedly has IPv6 — not a v4-only underlay test"

        a = bring_up_node(gw_image, net, hub, hostname="v4-a")
        cids.append(a["cid"])
        b = bring_up_node(gw_image, net, hub, hostname="v4-b")
        cids.append(b["cid"])

        # The overlay is IPv6, transported over the v4 underlay: every node
        # reaches the hub and each other on their v6 overlay addresses.
        for n in (a, b):
            assert wait_for_ping(n["cid"], hub["overlay"], timeout=60), \
                f"{n['hostname']} can't reach the hub overlay over the v4 underlay"
        assert wait_for_ping(a["cid"], b["overlay"], timeout=60), \
            "v4-underlay nodes can't reach each other on the overlay"
    finally:
        for cid in cids:
            podman("rm", "-f", cid, check=False)
        podman("network", "rm", "-f", net, check=False)
