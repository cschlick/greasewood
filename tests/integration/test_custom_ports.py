"""
Integration test for configurable ports.

Stand up a hub on non-default door + control ports and enroll a node. Proves
the door port travels in the token (the node reaches the door where the hub put
it) and the control port travels in the enroll response (the node builds the
right hub URL and publishes there).
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
    hub = node = None
    try:
        hub = _run_container(gw_image, gw_network)
        hub_ipv6 = container_ipv6(hub, gw_network)
        pexec(hub, "gw", "create", "customports", "--hostname", "customhub",
              "--endpoint", f"[{hub_ipv6}]:51900",
              "--control-port", str(CONTROL_PORT), "--door-port", str(DOOR_PORT))
        hub_overlay = overlay_addr_from_id_pub(
            pexec(hub, "cat", "/var/lib/greasewood/id_pub.hex").stdout.strip())
        podman("exec", "-d", hub, "sh", "-c", "gw -v run >> /tmp/gw.log 2>&1")
        assert wait_for_control_plane(hub, timeout=20, port=CONTROL_PORT), \
            "hub control plane not up on the custom port"

        node = _run_container(gw_image, gw_network)
        node_ipv6 = container_ipv6(node, gw_network)
        # invite (embeds DOOR_PORT in the token) + join (reads it). The enroll
        # response carries CONTROL_PORT so the node builds the right hub URL.
        door_enroll_via(hub, hub_ipv6, node, node_ipv6, hostname="cnode")

        # Node config points root_url at the custom control port.
        cfg = pexec(node, "cat", "/etc/greasewood.toml").stdout
        assert f":{CONTROL_PORT}" in cfg, f"root_url missing custom port:\n{cfg}"

        podman("exec", "-d", node, "sh", "-c", "gw -v run >> /tmp/gw.log 2>&1")

        # Mesh forms over the custom door port…
        assert wait_for_ping(node, hub_overlay, timeout=30), \
            "node could not reach the hub overlay"
        # …and the node published to the hub on the custom control port.
        deadline = time.time() + 30
        names = set()
        while time.time() < deadline:
            names = {r["cred"]["hostname"] for r in directory_records(hub, port=CONTROL_PORT)}
            if "cnode" in names:
                break
            time.sleep(2)
        assert "cnode" in names, f"node never published to the custom control port: {names}"
    finally:
        for cid in (hub, node):
            if cid:
                podman("rm", "-f", cid, check=False)
