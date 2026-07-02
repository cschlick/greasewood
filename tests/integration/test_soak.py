"""
Soak test: a live mesh run across MANY renewal cycles, with continuous
monitoring — the regression net for time-dependent renewal/reconcile bugs.

Renewal bugs are invisible to fast tests and to a single end-of-run check: the
mesh can look healthy at minute 0 and minute 5 while silently dropping and
re-forming a tunnel at minute 2. Security-review finding #1 (renewed creds not
re-published → peers evict a healthy node one TTL after start) was exactly this
shape. So this holds a small mesh up with a SHORT credential TTL and samples it
every few seconds for several minutes, asserting at EVERY sample that:

  * no node has lost a peer (peer count stays at the full-mesh value),
  * every overlay tunnel still carries traffic (all-pairs ping from the hub),
  * the hub's directory still holds every node, and
  * credentials are actually being renewed (max exp advances over the run).

A single dropped peer or a single failed ping at any sample fails the test with
the full timeline, so an intermittent teardown can't hide.

Gated behind GW_SOAK=1 (long-running). Tunables:
  GW_SOAK_SECS    total run time in seconds        (default 300)
  GW_SOAK_TTL     credential TTL                    (default 1m — the shortest
                  duration the config parser accepts, and the proven floor given
                  the 30s renewal floor + ~20s sync propagation)
  GW_SOAK_N       number of non-hub nodes           (default 3)
  GW_SOAK_SAMPLE  seconds between samples            (default 10)

  GW_SOAK=1 pytest tests/integration/test_soak.py -v -s
"""
import os
import time

import pytest

from .conftest import bring_up_node, make_hub
from .helpers import (
    directory_records,
    ping_once,
    podman,
    wait_for_peer_count,
    wg_handshake_ages,
    wg_peer_count,
)

pytestmark = [pytest.mark.integration, pytest.mark.soak]

if not os.environ.get("GW_SOAK"):
    pytest.skip("soak test is gated — set GW_SOAK=1 to run",
                allow_module_level=True)

DURATION = int(os.environ.get("GW_SOAK_SECS", "300"))
TTL = os.environ.get("GW_SOAK_TTL", "1m")
N = int(os.environ.get("GW_SOAK_N", "3"))
SAMPLE = int(os.environ.get("GW_SOAK_SAMPLE", "10"))


def _max_exp(hub_cid: str) -> str:
    """The latest credential expiry the hub is currently serving — rises each
    time any node renews and republishes."""
    return max((r["cred"]["exp"] for r in directory_records(hub_cid)), default="")


def test_mesh_soak(gw_image, gw_network):
    cids = []
    try:
        hub = make_hub(gw_image, gw_network, ttl=TTL, hostname="soakhub")
        cids.append(hub["cid"])
        nodes = []
        for i in range(N):
            node = bring_up_node(gw_image, gw_network, hub, hostname=f"soak{i}")
            cids.append(node["cid"])
            nodes.append(node)

        members = [hub] + nodes            # everyone, full mesh
        expected_peers = len(members) - 1  # each member peers with all others

        # Converge: every member must reach the full peer count before we start
        # timing. Generous timeout — bring-up + first publish + sync + reconcile.
        for m in members:
            got = wait_for_peer_count(m["cid"], expected_peers, timeout=120)
            assert got >= expected_peers, (
                f"{m.get('hostname', 'hub')} only reached {got}/{expected_peers} "
                f"peers before the soak started")

        overlays = [m["overlay"] for m in nodes]  # ping targets (hub → each node)
        start = time.time()
        first_exp = _max_exp(hub["cid"])
        samples = 0
        timeline = []

        while time.time() - start < DURATION:
            elapsed = int(time.time() - start)
            # 1. Peer counts: no member may drop below the full mesh.
            for m in members:
                pc = wg_peer_count(m["cid"])
                assert pc >= expected_peers, (
                    f"[t={elapsed}s] {m.get('hostname', 'hub')} dropped to "
                    f"{pc}/{expected_peers} peers — a renewal cycle evicted a "
                    f"healthy peer.\nTimeline:\n" + "\n".join(timeline))

            # 2. Liveness: every overlay tunnel still carries traffic. Pinging
            #    also keeps tunnels warm so handshake ages stay meaningful.
            for node in nodes:
                assert ping_once(hub["cid"], node["overlay"], timeout=3), (
                    f"[t={elapsed}s] hub → {node['hostname']} "
                    f"({node['overlay']}) ping failed mid-soak.\nTimeline:\n"
                    + "\n".join(timeline))

            # 3. Directory still complete (hub + N nodes).
            dir_n = len(directory_records(hub["cid"]))
            assert dir_n >= len(members), (
                f"[t={elapsed}s] hub directory shrank to {dir_n}/{len(members)} "
                f"records.\nTimeline:\n" + "\n".join(timeline))

            worst_hs = max((max(wg_handshake_ages(m["cid"]), default=0)
                            for m in members), default=0)
            line = (f"t={elapsed:>4}s  peers=ok  ping=ok  dir={dir_n}  "
                    f"worst_handshake={worst_hs}s  max_exp={_max_exp(hub['cid'])[-9:]}")
            timeline.append(line)
            print(line, flush=True)
            samples += 1
            time.sleep(SAMPLE)

        # Renewals actually happened: the newest expiry the hub serves must have
        # advanced past where we started (otherwise nothing renewed and we merely
        # ran shorter than one TTL).
        last_exp = _max_exp(hub["cid"])
        assert last_exp > first_exp, (
            f"no renewal observed over {DURATION}s: max credential expiry stayed "
            f"at {first_exp} — renewals aren't propagating to the hub.\n"
            + "\n".join(timeline))

        print(f"\nsoak OK: {samples} samples over {DURATION}s, "
              f"{len(members)} members, TTL={TTL}, zero teardowns; "
              f"max_exp advanced {first_exp} → {last_exp}")
    finally:
        for cid in cids:
            podman("rm", "-f", cid, check=False)
