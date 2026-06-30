"""
Stress / scale integration tests — grow the greasewood mesh to many nodes
and verify it converges to a fully-connected overlay.

Each node is a privileged Podman container running a real WireGuard interface
plus the gw daemon, so these are SLOW and resource-heavy (budget ~50-100 MB
and one veth + wg device per node). They are gated behind an env var so a
normal `pytest tests/integration/` run stays lean:

    GW_STRESS=1 pytest tests/integration/test_stress.py -v -s

Scale knobs (env):
    GW_STRESS_N        number of nodes to grow to          (default 8)
    GW_STRESS_WAVES    comma-separated growth waves         (default "3,8")
    GW_STRESS_WORKERS  max concurrent container bring-ups   (default 6)

`-s` is recommended: each test prints convergence timing to stdout.
"""
from __future__ import annotations

import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import pytest

from .conftest import bring_up_node
from .helpers import (
    podman,
    wait_for_directory_size,
    wait_for_ping,
    wg_peer_count,
)

pytestmark = [pytest.mark.integration, pytest.mark.stress]

if not os.environ.get("GW_STRESS"):
    pytest.skip(
        "stress tests are gated — set GW_STRESS=1 to run",
        allow_module_level=True,
    )


# ---------------------------------------------------------------------------
# Tunables
# ---------------------------------------------------------------------------

N_NODES = int(os.environ.get("GW_STRESS_N", "8"))
WAVES = [int(x) for x in os.environ.get("GW_STRESS_WAVES", "3,8").split(",")]
MAX_WORKERS = int(os.environ.get("GW_STRESS_WORKERS", "6"))

# Full mesh: every member knows every other. Convergence is bounded by the
# slowest node's publish + one sync cycle (~20 s) + one reconcile cycle (~5 s).
CONVERGE_TIMEOUT = int(os.environ.get("GW_STRESS_CONVERGE_TIMEOUT", "120"))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _grow(gw_image, gw_network, gw_root, count, workers=MAX_WORKERS):
    """Bring up `count` nodes concurrently. Returns the list of node dicts."""
    nodes = []
    errors = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [
            pool.submit(bring_up_node, gw_image, gw_network, gw_root)
            for _ in range(count)
        ]
        for fut in as_completed(futures):
            try:
                nodes.append(fut.result())
            except Exception as e:  # noqa: BLE001 — collect, surface after cleanup
                errors.append(e)
    if errors:
        # Tear down whatever did come up before failing.
        for n in nodes:
            podman("rm", "-f", n["cid"], check=False)
        raise AssertionError(f"{len(errors)}/{count} node bring-ups failed: {errors[0]}")
    return nodes


def _wait_full_mesh(members, timeout=CONVERGE_TIMEOUT):
    """
    Block until every member has (len(members) - 1) WireGuard peers.

    `members` is the full membership list including the root; in a full mesh
    each member peers with all the others. Returns (converged: bool, elapsed).
    """
    expected = len(members) - 1
    start = time.time()
    deadline = start + timeout
    while time.time() < deadline:
        counts = [wg_peer_count(m["cid"]) for m in members]
        if all(c >= expected for c in counts):
            return True, time.time() - start
        time.sleep(2)
    return False, time.time() - start


def _all_pairs_ping(members, workers=MAX_WORKERS, per_pair_timeout=20):
    """
    Ping every ordered (src, dst) overlay pair. Returns a list of failures as
    (src_host, dst_host, dst_overlay). Parallelized across `workers`.

    Each pair is retried for up to `per_pair_timeout`s: a freshly-installed
    WireGuard peer handshakes lazily on the first packet, so a single-shot
    ping can race the handshake. Already-warm pairs return in milliseconds;
    only a genuinely unreachable pair pays the full timeout.
    """
    pairs = [
        (src, dst)
        for src in members
        for dst in members
        if src["cid"] != dst["cid"]
    ]

    def _check(pair):
        src, dst = pair
        ok = wait_for_ping(src["cid"], dst["overlay"], timeout=per_pair_timeout)
        return None if ok else (src["hostname"], dst["hostname"], dst["overlay"])

    failures = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for result in pool.map(_check, pairs):
            if result is not None:
                failures.append(result)
    return failures


def _hostname(member):
    return member.get("hostname", "root")


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_grow_mesh_to_n_nodes(gw_root, gw_image, gw_network):
    """
    Grow the mesh to N nodes in one shot, then assert:
      1. all N records (+ root) land in the root directory,
      2. every member converges to a full set of WireGuard peers,
      3. all-pairs overlay ping succeeds (true full mesh, not just star).
    """
    nodes = []
    try:
        t0 = time.time()
        nodes = _grow(gw_image, gw_network, gw_root, N_NODES)
        bring_up_elapsed = time.time() - t0
        print(f"\n[stress] brought up {N_NODES} nodes in {bring_up_elapsed:.1f}s")

        # 1. Directory: root + N nodes
        expected_records = N_NODES + 1
        got = wait_for_directory_size(gw_root["url"], expected_records, timeout=60)
        assert got >= expected_records, (
            f"root directory has {got}/{expected_records} records"
        )
        print(f"[stress] root directory holds {got} records")

        # 2. Full-mesh WireGuard peer convergence
        members = [gw_root] + nodes
        converged, elapsed = _wait_full_mesh(members)
        counts = {_hostname(m): wg_peer_count(m["cid"]) for m in members}
        assert converged, (
            f"mesh did not fully converge in {CONVERGE_TIMEOUT}s "
            f"(expected {len(members) - 1} peers each); got {counts}"
        )
        print(f"[stress] full WG mesh converged in {elapsed:.1f}s "
              f"({len(members) - 1} peers/node)")

        # 3. All-pairs overlay reachability
        failures = _all_pairs_ping(members)
        total_pairs = len(members) * (len(members) - 1)
        assert not failures, (
            f"{len(failures)}/{total_pairs} overlay pings failed; "
            f"first few: {failures[:5]}"
        )
        print(f"[stress] all {total_pairs} ordered overlay pings succeeded")
    finally:
        for n in nodes:
            podman("rm", "-f", n["cid"], check=False)


def test_mesh_growth_in_waves(gw_root, gw_image, gw_network):
    """
    Grow the mesh incrementally and re-verify full connectivity after each
    wave. Catches propagation bugs that only bite when peers are *added* to an
    already-running mesh (stale directory caches, reconcile drift, etc.).
    """
    nodes = []
    try:
        for target in WAVES:
            assert target >= len(nodes), "GW_STRESS_WAVES must be non-decreasing"
            add = target - len(nodes)
            if add:
                t0 = time.time()
                nodes += _grow(gw_image, gw_network, gw_root, add)
                print(f"\n[stress] wave → {target} nodes "
                      f"(+{add} in {time.time() - t0:.1f}s)")

            members = [gw_root] + nodes
            converged, elapsed = _wait_full_mesh(members)
            counts = {_hostname(m): wg_peer_count(m["cid"]) for m in members}
            assert converged, (
                f"wave {target}: mesh did not converge in {CONVERGE_TIMEOUT}s; "
                f"peer counts {counts}"
            )

            failures = _all_pairs_ping(members)
            assert not failures, (
                f"wave {target}: {len(failures)} overlay pings failed; "
                f"first few: {failures[:5]}"
            )
            print(f"[stress] wave {target}: converged in {elapsed:.1f}s, "
                  f"all-pairs reachable")
    finally:
        for n in nodes:
            podman("rm", "-f", n["cid"], check=False)
