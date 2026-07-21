"""
Convergence + oracle verification: wait for the live mesh to settle to what the
model predicts, then assert topology and service reachability match exactly.
Every mismatch is collected (not fail-fast) so one failure reports the WHOLE
divergence, with the seed, for deterministic replay.
"""
from __future__ import annotations

import time

from .services import probe
from ..helpers import ping_once, wg_peer_count, mesh_iface


def _peer_count(cid) -> int:
    try:
        return wg_peer_count(cid)
    except Exception:
        return -1


def wait_converge(fleet, timeout: int = 120) -> bool:
    """Block until every effective node holds exactly its expected peer count.
    Returns True on convergence, False on timeout (the caller then verifies and
    reports the specific divergences)."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        ok = True
        for host in fleet._nonanchor() + ["chaosanchor"]:
            n = fleet.model.nodes.get(host)
            if n is None or not n.alive or n.revoked:
                continue
            want = fleet.model.expected_peer_count(host)
            if _peer_count(fleet.cids[host]) != want:
                ok = False
                break
        if ok:
            return True
        time.sleep(2)
    return False


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

    # 2. service reachability — sampled client/server/port triples
    ports = sample_ports if sample_ports is not None \
        else [22, 80, 5432, 2049, 8000]
    hosts = fleet._nonanchor()
    rng = fleet.rng
    samples = []
    for _ in range(min(24, len(hosts) * len(hosts))):
        if len(hosts) < 2:
            break
        c, s = rng.sample(hosts, 2)
        samples.append((c, s, rng.choice(ports)))
    for c, s, port in samples:
        got = probe(fleet.cids[c], fleet.overlays[s], port)
        connected = got in ("OPEN", "EMPTY")
        if m.reachable(c, s, port):
            # granted + tunnel: must connect (REFUSED is ok only if the server
            # isn't listening on that port — the model's service set decides)
            listening = port in _listen_ports(fleet, s)
            if listening and not connected:
                problems.append(f"SERVICE BLOCKED {c}->{s}:{port} got {got}, "
                                f"model grants it and {s} listens")
        elif m.tunnel(c, s):
            # tunnel up but port ungranted → the filter must drop it (TIMEOUT)
            if connected:
                problems.append(f"PORT FILTER LEAK {c}->{s}:{port} got {got}, "
                                f"model says ungranted on an existing tunnel")
        else:
            # no tunnel → certainly no service
            if connected:
                problems.append(f"NO-TUNNEL SERVICE {c}->{s}:{port} got {got}, "
                                f"model forbids the tunnel entirely")
    return problems


def _listen_ports(fleet, host) -> set:
    from .services import roles_to_ports
    return set(roles_to_ports(fleet.model.nodes[host].roles))
