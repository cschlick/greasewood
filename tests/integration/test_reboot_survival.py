"""
Reboot-survival integration tests.

A reboot, from greasewood's point of view, is: the daemon process is gone and
the WireGuard interfaces no longer exist, but /var/lib/greasewood (identity +
directory cache + CA/door keys) persists on disk. The systemd units make the
daemon start again at boot; what these tests lock down is the substantive
guarantee behind that — a cold `gw run` rehydrates entirely from persisted
state and the mesh re-forms with NO re-join and NO new token.

We simulate the reboot rather than rebooting the container (the test image runs
`sleep infinity` as PID 1, not systemd): kill the daemon, delete the gw-mesh /
gw-door interfaces, then start `gw run` again.
"""
import time

import pytest

from .conftest import bring_up_node, uniq_name
from .helpers import (
    pexec, podman, wait_for_control_plane, wait_for_hostname, wait_for_ping,
)

pytestmark = pytest.mark.integration


def _simulate_reboot(cid: str) -> None:
    """Return a container to a just-booted state: no daemon, no WG interfaces;
    only the persistent data dir survives (as on a real reboot)."""
    # Stop the daemon. The [g]w trick keeps pkill from matching its own cmdline.
    pexec(cid, "pkill", "-f", "[g]w.*run", check=False)
    time.sleep(2)
    for iface in ("gw-testmesh", "gw-door"):
        pexec(cid, "ip", "link", "del", iface, check=False)
    # Sanity: the interface is really gone.
    assert pexec(cid, "ip", "link", "show", "gw-testmesh", check=False).returncode != 0


def _start_daemon(cid: str) -> None:
    podman("exec", "-d", cid, "sh", "-c", "gw -v run >> /tmp/gw.log 2>&1")


def test_node_reconnects_after_reboot(gw_anchor, gw_image, gw_network):
    """A node reboots; it must rejoin the mesh from disk alone — no new token."""
    node = None
    try:
        node = bring_up_node(gw_image, gw_network, gw_anchor, hostname=uniq_name("rebooter"))
        assert wait_for_ping(node["cid"], gw_anchor["overlay"], timeout=40), \
            "mesh never formed before reboot"

        id_before = pexec(node["cid"], "sh", "-c",
                          "cat /var/lib/greasewood_*/id_pub.hex").stdout.strip()

        _simulate_reboot(node["cid"])
        # With the interface gone the overlay is unreachable (sanity check).
        assert not wait_for_ping(node["cid"], gw_anchor["overlay"], timeout=3)

        _start_daemon(node["cid"])  # cold start — no `gw join`, same data dir

        assert wait_for_ping(node["cid"], gw_anchor["overlay"], timeout=45), \
            "node did not reconnect after reboot"
        # Identity persisted (same id_pub → same overlay addr), proving it
        # rehydrated rather than re-enrolled.
        id_after = pexec(node["cid"], "sh", "-c",
                         "cat /var/lib/greasewood_*/id_pub.hex").stdout.strip()
        assert id_after == id_before
    finally:
        if node:
            podman("rm", "-f", node["cid"], check=False)


def test_anchor_reconnects_after_reboot(gw_anchor, gw_image, gw_network):
    """The anchor reboots; it must come back from disk (CA key, directory cache,
    door routing, control plane) and the node link must recover."""
    node = None
    try:
        name = uniq_name("anchorreb")
        node = bring_up_node(gw_image, gw_network, gw_anchor, hostname=name)
        assert wait_for_ping(node["cid"], gw_anchor["overlay"], timeout=40), \
            "mesh never formed before reboot"

        _simulate_reboot(gw_anchor["cid"])
        _start_daemon(gw_anchor["cid"])

        # Control plane comes back up on the overlay/loopback...
        assert wait_for_control_plane(gw_anchor["cid"], timeout=30), \
            "anchor control plane did not return after reboot"
        # ...the anchor still knows the node from its persisted directory cache...
        assert wait_for_hostname(gw_anchor["cid"], name, timeout=30)
        # ...and the data-plane link recovers without operator action.
        assert wait_for_ping(node["cid"], gw_anchor["overlay"], timeout=45), \
            "node link did not recover after anchor reboot"
    finally:
        if node:
            podman("rm", "-f", node["cid"], check=False)
