"""
Failover integration tests.

Exercises the anchor-failover flow:
  a) a mesh with multiple failover anchors,
  b) unexpected anchor death -> failover to a standby,
  c) a successor anchor re-invites an existing node to be a new failover.
"""
from __future__ import annotations

import time

import pytest

from .conftest import bring_up_node, make_anchor, uniq_name
from .helpers import (
    anchor_get, container_addr, container_ipv6, directory_records,
    pexec, podman, wait_for_control_plane, wait_for_peer_count, wait_for_ping,
)

pytestmark = [pytest.mark.integration]

FAILOVER_PW = "failover-test"


def _extract_token(text: str) -> str:
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("gw1."):
            return s
    raise AssertionError(f"no join token in output:\n{text}")


def _ep(addr: str, port: int = 51900) -> str:
    return f"[{addr}]:{port}" if ":" in addr else f"{addr}:{port}"


def _standby_url(overlay: str, port: int = 51902) -> str:
    return f"http://[{overlay}]:{port}"


def _set_root_and_seeds(cid: str, root_url: str, seeds: list[str]) -> None:
    seeds_toml = "[" + ",".join(f'"{s}"' for s in seeds) + "]"
    cmd = (
        f"sed -i 's|^root_url *=.*|root_url = \"{root_url}\"|' /etc/greasewood_*.toml && "
        f"sed -i 's|^seeds *=.*|seeds = {seeds_toml}|' /etc/greasewood_*.toml"
    )
    pexec(cid, "sh", "-c", cmd)


def _restart_daemon(cid: str) -> None:
    pexec(cid, "pkill", "-f", "[g]w.*run", check=False)
    time.sleep(1)
    podman("exec", "-d", cid, "sh", "-c", "gw -v run >> /tmp/gw.log 2>&1")


def _failover_blob_present(cid: str) -> bool:
    r = pexec(cid, "sh", "-c", "ls -l /var/lib/greasewood_*/failover_anchor.gwbk", check=False)
    return r.returncode == 0


def _directory_host_has_caps(cid: str, hostname: str, cap: str) -> bool:
    for rec in directory_records(cid):
        if rec["cred"]["hostname"] == hostname and cap in rec["cred"]["caps"]:
            return True
    return False


def test_mesh_with_failover_anchors(gw_image, gw_network):
    """Two nodes can be enrolled as failover standbys and peer with the anchor."""
    cids = []
    try:
        anchor = make_anchor(gw_image, gw_network, hostname="anchor")
        cids.append(anchor["cid"])

        s1 = bring_up_node(
            gw_image, gw_network, anchor,
            hostname="standby1", caps="failover",
            env={"GW_FAILOVER_PASSPHRASE": FAILOVER_PW},
        )
        cids.append(s1["cid"])
        s2 = bring_up_node(
            gw_image, gw_network, anchor,
            hostname="standby2", caps="failover",
            env={"GW_FAILOVER_PASSPHRASE": FAILOVER_PW},
        )
        cids.append(s2["cid"])

        assert _failover_blob_present(s1["cid"])
        assert _failover_blob_present(s2["cid"])

        for c in (anchor["cid"], s1["cid"], s2["cid"]):
            assert wait_for_peer_count(c, 2) == 2, "failover anchors did not peer"

        for a, b in ((anchor, s1), (anchor, s2), (s1, s2)):
            assert wait_for_ping(a["cid"], b["overlay"], timeout=40), \
                f"ping {a['hostname']} -> {b['hostname']} failed"
    finally:
        for c in cids:
            podman("rm", "-f", c, check=False)


def test_failover_to_standby_after_anchor_failure(gw_image, gw_network):
    """Kill the anchor; a failover standby activates and serves renewals."""
    cids = []
    try:
        anchor = make_anchor(gw_image, gw_network, hostname="anchor")
        cids.append(anchor["cid"])

        standby = bring_up_node(
            gw_image, gw_network, anchor,
            hostname="standby1", caps="failover",
            env={"GW_FAILOVER_PASSPHRASE": FAILOVER_PW},
        )
        cids.append(standby["cid"])

        node = bring_up_node(gw_image, gw_network, anchor, hostname="node1")
        cids.append(node["cid"])

        # Pre-seed the ordinary node with both anchors so it can find the
        # successor after the primary dies. Keep root_url pointing at A for now.
        anchor_url = _standby_url(anchor["overlay"])
        standby_url = _standby_url(standby["overlay"])
        _set_root_and_seeds(node["cid"], anchor_url, [anchor_url, standby_url])
        _restart_daemon(node["cid"])

        for c in (anchor["cid"], standby["cid"], node["cid"]):
            assert wait_for_peer_count(c, 2) == 2, "initial mesh did not form"

        # Simulate unexpected anchor death.
        podman("kill", anchor["cid"])
        time.sleep(2)

        # Activate the standby as the new anchor and start its daemon.
        act = pexec(standby["cid"], "gw", "anchor-activate",
                    env={"GW_FAILOVER_PASSPHRASE": FAILOVER_PW}, check=False)
        assert act.returncode == 0, (
            f"anchor-activate failed:\n{act.stdout}\n{act.stderr}")
        _restart_daemon(standby["cid"])
        assert wait_for_control_plane(standby["cid"], timeout=30), \
            "standby control plane did not start"

        # Repoint the node to the new anchor and force a renewal.
        _set_root_and_seeds(node["cid"], standby_url, [standby_url])
        _restart_daemon(node["cid"])
        pexec(node["cid"], "gw", "renew")
        assert wait_for_ping(node["cid"], standby["overlay"], timeout=45), \
            "node cannot ping the new anchor"
    finally:
        for c in cids:
            podman("rm", "-f", c, check=False)


def test_successor_anchor_reinvites_existing_node_as_failover(gw_image, gw_network):
    """anchor-standby re-opens the door for an existing node so it can become a failover."""
    cids = []
    try:
        anchor = make_anchor(gw_image, gw_network, hostname="anchor")
        cids.append(anchor["cid"])

        node = bring_up_node(gw_image, gw_network, anchor, hostname="node1")
        cids.append(node["cid"])

        # Anchor re-invites the live node as a failover standby.
        res = pexec(anchor["cid"], "gw", "anchor-standby", "node1",
                    "--endpoint", anchor["ipv6"],
                    env={"GW_FAILOVER_PASSPHRASE": FAILOVER_PW}, check=False)
        assert res.returncode == 0, (
            f"anchor-standby failed:\n{res.stdout}\n{res.stderr}")
        token = _extract_token(res.stdout + "\n" + res.stderr)

        ipv6 = container_ipv6(node["cid"], gw_network)
        j = pexec(node["cid"], "gw", "join", token,
                  "--endpoint", _ep(ipv6, 51900), check=False)
        assert j.returncode == 0, (
            f"re-join via anchor-standby failed (rc={j.returncode}):\n"
            f"stdout: {j.stdout}\nstderr: {j.stderr}"
        )

        assert _failover_blob_present(node["cid"])
        assert _directory_host_has_caps(anchor["cid"], "node1", "failover"), \
            "node1 did not gain failover cap in the anchor directory"
    finally:
        for c in cids:
            podman("rm", "-f", c, check=False)
