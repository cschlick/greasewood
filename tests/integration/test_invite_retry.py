"""
Integration test for the multi-attempt door window.

A rejected enrollment (e.g. a hostname collision) no longer burns the whole
invite: the hub keeps the door open for a few attempts and tells the joiner how
many remain. This verifies that a failed join followed by a corrected one — on
the SAME token — succeeds.
"""
import time
import uuid

import pytest

from .conftest import _ENROLL_LOCK, _extract_token
from .helpers import container_ipv6, pexec, podman, wait_for_hostname

pytestmark = pytest.mark.integration


def test_failed_join_keeps_window_open_for_retry(gw_hub, gw_image, gw_network):
    node = None
    try:
        node = podman(
            "run", "-d", "--privileged", "--network", gw_network,
            "--sysctl", "net.ipv6.conf.all.disable_ipv6=0",
            gw_image, "sleep", "infinity",
        ).stdout.strip()
        time.sleep(1)
        node_ipv6 = container_ipv6(node, gw_network)
        good = f"retry-{uuid.uuid4().hex[:6]}"

        # One token, two attempts. Serialize on the shared single-slot door.
        with _ENROLL_LOCK:
            res = pexec(gw_hub["cid"], "gw", "invite", "--endpoint", gw_hub["ipv6"])
            token = _extract_token(res.stdout + "\n" + res.stderr)

            # Attempt 1: collide with the hub's own hostname "hub" → refused,
            # but the window must stay open and report attempts remaining.
            r1 = pexec(node, "gw", "join", token, "--hostname", "hub",
                       "--endpoint", f"[{node_ipv6}]:51900", check=False)
            out1 = r1.stdout + r1.stderr
            assert r1.returncode != 0, out1
            assert "already in use" in out1, out1
            assert "attempt" in out1 and "left" in out1, out1

            # Attempt 2: SAME token, unique name → succeeds because the door
            # wasn't torn down by the failure.
            r2 = pexec(node, "gw", "join", token, "--hostname", good,
                       "--endpoint", f"[{node_ipv6}]:51900", check=False)
            assert r2.returncode == 0, out1 + "\n--- retry ---\n" + r2.stdout + r2.stderr

        # The successful enrollment's door publish put the node in the hub directory.
        assert wait_for_hostname(gw_hub["cid"], good, timeout=20), \
            "retried node never reached the hub directory"
    finally:
        if node:
            podman("rm", "-f", node, check=False)
