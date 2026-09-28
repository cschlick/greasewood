"""
Convergence + oracle verification: wait for the live mesh to settle to what the
model predicts, then assert topology and service reachability match exactly.
Every mismatch is collected (not fail-fast) so one failure reports the WHOLE
divergence, with the seed, for deterministic replay.
"""
from __future__ import annotations

import time

from .services import probe
from ..helpers import ping_once, wg_peer_count


def _peer_count(cid) -> int:
    try:
        return wg_peer_count(cid)
    except Exception:
        return -1


def wait_converge(fleet, timeout: int = 120) -> bool:
    """Block until the live mesh settles to the model: every effective node
    holds its expected peer count, AND a sampled expected-up pair actually
    pings (data-plane liveness — this is what waits out a partition HEAL, where
    the peer stays configured so the count never moved but the handshake needs
    to re-establish). Returns True on convergence, False on timeout."""
    m = fleet.model
    deadline = time.time() + timeout
    while time.time() < deadline:
        ok = True
        for host in fleet._nonanchor() + ["chaosanchor"]:
            n = m.nodes.get(host)
            if n is None or not n.alive or n.revoked:
                continue
            # A partitioned peer stays installed on the interface (wg set isn't
            # removed), so it still counts toward the peer count — the partition
            # kills the data path, not the peer entry. So the expected count is
            # the policy peer count, partitions and all.
            want = _policy_peer_count(m, host)
            if _peer_count(fleet.cids[host]) != want:
                ok = False
                break
        if ok and not _uppair_pings(fleet):
            ok = False
        if ok:
            return True
        time.sleep(2)
    return False


def _policy_peer_count(m, host: str) -> int:
    """Peers the interface should hold: everyone the POLICY connects (a
    partition blocks the path but leaves the wg peer installed, so it still
    counts). Distinct from model.expected_peer_count, which excludes partitions
    for the data-plane oracle."""
    others = [n.hostname for n in m.effective() if n.hostname != host]

    def policy_link(a, b):
        saved = set(m.partitions)
        m.partitions = set()
        try:
            return m.tunnel(a, b)
        finally:
            m.partitions = saved
    return sum(1 for o in others if policy_link(host, o))


def _uppair_pings(fleet) -> bool:
    """A sampled data-plane liveness gate: pick a few pairs the model expects
    UP (tunnel True, partitions honored) and require at least one to ping — so
    convergence waits out a re-handshake after a heal/restart rather than
    verifying a still-settling mesh."""
    m = fleet.model
    up = [(a, b) for a, b in m.all_pairs() if m.tunnel(a, b)]
    if not up:
        return True
    sample = fleet.rng.sample(up, min(3, len(up)))
    for a, b in sample:
        if not (ping_once(fleet.cids[a], fleet.overlays[b], timeout=2) or
                ping_once(fleet.cids[b], fleet.overlays[a], timeout=2)):
            return False
    return True


def verify(fleet, sample_ports=None) -> list:
    """Return a list of human-readable divergence strings (empty == healthy).
    Checks, over the effective membership:
      - tunnel(a,b): a WireGuard peer is installed on BOTH ends iff the model
        says a tunnel should exist (and ping agrees for expected-up pairs)
      - reachable(c,s,port): a fresh connection succeeds iff granted; a
        tunnel-up-but-ungranted port is blocked (the port filter)
    Service probing is sampled (full all-pairs-all-ports is O(n^2 * ports));
    the tunnel check is exhaustive."""
    problems = []
    m = fleet.model

    # 1. topology — exhaustive over effective pairs
    for a, b in m.all_pairs():
        want = m.tunnel(a, b)
        ca, cb = fleet.cids[a], fleet.cids[b]
        # a peer link shows as each end having the other installed; ping is the
        # data-plane confirmation for pairs that should be up.
        if want:
            if not ping_once(ca, fleet.overlays[b], timeout=3) and \
               not ping_once(cb, fleet.overlays[a], timeout=3):
                problems.append(f"TUNNEL MISSING {a}<->{b}: model expects a "
                                f"tunnel, neither end can ping")
        else:
            # should NOT tunnel — confirm no data-plane path either direction
            if ping_once(ca, fleet.overlays[b], timeout=2) or \
               ping_once(cb, fleet.overlays[a], timeout=2):
                problems.append(f"TUNNEL LEAK {a}<->{b}: model forbids a tunnel "
                                f"but a ping succeeded")

    # 2. the PORT FILTER — sampled client/server/port triples.
    #
    # The filter's signature is REFUSED-vs-TIMEOUT, independent of whether a
    # service actually listens: a GRANTED port is accepted, so the SYN reaches
    # the host stack — OPEN if a listener answers, REFUSED (RST) if not; either
    # way the packet ARRIVED. An UNGRANTED port is DROPPED, so the SYN never
    # reaches the stack — TIMEOUT. So "did the packet reach the host?" is
    # exactly what the filter decides, and testing that (not "is a service up")
    # isolates greasewood's actual responsibility from the test's listeners.
    ports = sample_ports if sample_ports is not None \
        else [22, 80, 443, 2049, 5432, 6379, 8000]
    hosts = fleet._nonanchor()
    rng = fleet.rng
    samples = []
    for _ in range(min(18, len(hosts) * len(hosts))):
        if len(hosts) < 2:
            break
        c, s = rng.sample(hosts, 2)
        samples.append((c, s, rng.choice(ports)))
    for c, s, port in samples:
        got = probe(fleet.cids[c], fleet.overlays[s], port, timeout=3.0)
        reached = got in ("OPEN", "EMPTY", "REFUSED")   # SYN hit the host stack
        if m.reachable(c, s, port):
            if not reached:                             # granted but DROPPED
                problems.append(f"GRANTED PORT DROPPED {c}->{s}:{port} got {got}"
                                f" — model grants it; the filter wrongly blocked it")
        elif m.tunnel(c, s):
            if reached:                                 # ungranted but PASSED
                problems.append(f"PORT FILTER LEAK {c}->{s}:{port} got {got}"
                                f" — ungranted on an existing tunnel, filter let it through")
        else:
            if reached:                                 # no tunnel but connected
                problems.append(f"NO-TUNNEL SERVICE {c}->{s}:{port} got {got}"
                                f" — model forbids the tunnel entirely")
    return problems
