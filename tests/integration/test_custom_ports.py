"""
Integration test for configurable ports.

Stand up an anchor on non-default door + control ports and enroll a node. Proves
the door port travels in the token (the node reaches the door where the anchor put
it) and the control port travels in the enroll response (the node builds the
right anchor URL and publishes there).
"""
import time

import pytest

from .conftest import door_enroll_via, overlay_addr_from_id_pub
from .helpers import (
    container_ipv6, directory_records, pexec, podman, wait_for_control_plane,
    wait_for_ping,
)

pytestmark = pytest.mark.integration

CONTROL_PORT = 9100
DOOR_PORT = 52000


def _run_container(gw_image, gw_network):
    cid = podman(
        "run", "-d", "--privileged", "--network", gw_network,
        "--sysctl", "net.ipv6.conf.all.disable_ipv6=0",
        gw_image, "sleep", "infinity",
    ).stdout.strip()
    time.sleep(1)
    return cid


def test_custom_door_and_control_ports(gw_image, gw_network):
    anchor = node = None
    try:
        anchor = _run_container(gw_image, gw_network)
        anchor_ipv6 = container_ipv6(anchor, gw_network)
        pexec(anchor, "gw", "create", "customports", "--hostname", "customanchor",
              "--endpoint", f"[{anchor_ipv6}]:51900",
              "--control-port", str(CONTROL_PORT), "--door-port", str(DOOR_PORT))
        anchor_overlay = overlay_addr_from_id_pub(
            pexec(anchor, "sh", "-c", "cat /var/lib/greasewood_*/id_pub.hex").stdout.strip())
        podman("exec", "-d", anchor, "sh", "-c", "gw -v run >> /tmp/gw.log 2>&1")
        assert wait_for_control_plane(anchor, timeout=20, port=CONTROL_PORT), \
            "anchor control plane not up on the custom port"

        node = _run_container(gw_image, gw_network)
        node_ipv6 = container_ipv6(node, gw_network)
        # invite (embeds DOOR_PORT in the token) + join (reads it). The enroll
        # response carries CONTROL_PORT so the node builds the right anchor URL.
        door_enroll_via(anchor, anchor_ipv6, node, node_ipv6, hostname="cnode")

        # Node config points root_url at the custom control port.
        cfg = pexec(node, "sh", "-c", "cat /etc/greasewood_*.toml").stdout
        assert f":{CONTROL_PORT}" in cfg, f"root_url missing custom port:\n{cfg}"

        podman("exec", "-d", node, "sh", "-c", "gw -v run >> /tmp/gw.log 2>&1")

        # Mesh forms over the custom door port…
        assert wait_for_ping(node, anchor_overlay, timeout=30), \
            "node could not reach the anchor overlay"
        # …and the node published to the anchor on the custom control port.
        deadline = time.time() + 30
        names = set()
        while time.time() < deadline:
            names = {r["cred"]["hostname"] for r in directory_records(anchor, port=CONTROL_PORT)}
            if "cnode" in names:
                break
            time.sleep(2)
        assert "cnode" in names, f"node never published to the custom control port: {names}"
    finally:
        for cid in (anchor, node):
            if cid:
                podman("rm", "-f", cid, check=False)
