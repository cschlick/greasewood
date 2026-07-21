"""
The chaos oracle must be correct before it can judge greasewood. These pin its
topology + port derivation against hand-worked cases, AND cross-check it against
greasewood's OWN policy engine on random inputs — the two are written
independently, so agreement on a fuzzed corpus is strong evidence both are right
(a shared bug would have to be identical in two separate implementations).
"""
import random

from tests.integration.chaos.model import Grant, MeshModel, Node


def _mesh(*nodes, grants=None):
    m = MeshModel(grants=grants)
    for n in nodes:
        m.add(n)
    return m


def test_anchor_peers_with_everyone_regardless_of_policy():
    m = _mesh(Node("anchor", is_anchor=True), Node("a", ("web",)),
              Node("b", ("db",)), grants=[])              # empty table = closed
    assert m.tunnel("anchor", "a") and m.tunnel("anchor", "b")
    assert not m.tunnel("a", "b")                         # no grant connects them


def test_flat_mesh_when_no_table():
    m = _mesh(Node("anchor", is_anchor=True), Node("a", ("web",)),
              Node("b", ("db",)), grants=None)
    assert m.tunnel("a", "b")                             # None => everyone peers


def test_role_grant_either_direction():
    g = [Grant(("web",), ("api",), ("tcp/8000",))]
    m = _mesh(Node("anchor", is_anchor=True), Node("w", ("web",)),
              Node("p", ("api",)), Node("d", ("db",)), grants=g)
    assert m.tunnel("w", "p") and m.tunnel("p", "w")      # symmetric
    assert not m.tunnel("w", "d")                         # db unconnected


def test_host_grant_targets_one_machine():
    g = [Grant(("host:bb",), ("host:nas",), ("tcp/2049",))]
    m = _mesh(Node("bb"), Node("nas"), Node("other"), grants=g)
    assert m.tunnel("bb", "nas")
    assert not m.tunnel("bb", "other") and not m.tunnel("nas", "other")


def test_port_filter_same_tunnel_open_and_closed():
    g = [Grant(("web",), ("srv",), ("tcp/80",))]
    m = _mesh(Node("w", ("web",)), Node("s", ("srv",)), grants=g)
    assert m.tunnel("w", "s")
    assert m.reachable("w", "s", 80)                      # granted port
    assert not m.reachable("w", "s", 5432)               # ungranted port
    assert m.port_blocked("w", "s", 5432)                # tunnel up, port closed


def test_wildcard_port_opens_all():
    g = [Grant(("m",), ("*",), ("*",))]
    m = _mesh(Node("mon", ("m",)), Node("x", ("web",)), grants=g)
    assert m.reachable("mon", "x", 22) and m.reachable("mon", "x", 9999)


def test_revoked_and_dead_form_no_tunnels():
    g = None
    m = _mesh(Node("anchor", is_anchor=True), Node("a"), Node("b"), grants=g)
    m.revoke("b")
    assert not m.tunnel("a", "b") and not m.tunnel("anchor", "b")
    m.set_alive("a", False)
    assert not m.tunnel("anchor", "a")
    assert m.expected_peer_count("anchor") == 0          # both gone


# --- cross-check against greasewood's OWN engine (independent agreement) -----

def _to_gw_grant(g):
    return {"from": sorted(g.src), "to": sorted(g.dst), "ports": sorted(g.ports)}


def test_oracle_agrees_with_policy_engine_on_fuzzed_meshes():
    from greasewood.policy import peers_allowed
    rng = random.Random(1234)
    roles = ["web", "api", "db", "worker", "cache"]
    for _ in range(300):
        names = [f"n{i}" for i in range(rng.randint(2, 6))]
        nodes = [Node(nm, tuple(rng.sample(roles, rng.randint(0, 3))))
                 for nm in names]
        # random grants over roles + a few host: entries
        grants = []
        for _ in range(rng.randint(0, 4)):
            pool = roles + [f"host:{nm}" for nm in names] + ["*"]
            src = tuple(rng.sample(pool, rng.randint(1, 2)))
            dst = tuple(rng.sample(pool, rng.randint(1, 2)))
            grants.append(Grant(src, dst, ("*",)))
        table = grants or ([] if rng.random() < 0.5 else None)
        m = MeshModel(grants=list(table) if table is not None else None)
        for n in nodes:
            m.add(n)
        gw_grants = ([_to_gw_grant(g) for g in table]
                     if table is not None else None)
        for i in range(len(nodes)):
            for j in range(i + 1, len(nodes)):
                a, b = nodes[i], nodes[j]
                mine = m.tunnel(a.hostname, b.hostname)
                theirs = peers_allowed(
                    [f"role:{r}" for r in a.roles],
                    [f"role:{r}" for r in b.roles],
                    gw_grants, a.hostname, b.hostname)
                assert mine == theirs, (a, b, table)


def test_partition_blocks_a_policy_allowed_tunnel():
    m = _mesh(Node("anchor", is_anchor=True), Node("a"), Node("b"), grants=None)
    assert m.tunnel("a", "b")                            # flat mesh: allowed
    m.partition("a", "b")
    assert not m.tunnel("a", "b")                        # underlay cut: down
    assert m.tunnel("anchor", "a")                       # others unaffected
    assert m.expected_peer_count("a") == 1               # only the anchor now
    m.heal("a", "b")
    assert m.tunnel("a", "b")                            # restored


def test_partition_forgotten_on_revoke_and_drop():
    m = _mesh(Node("anchor", is_anchor=True), Node("a"), Node("b"), grants=None)
    m.partition("a", "b")
    m.revoke("a")
    assert m.partitions == set()                         # no orphan partition
    m2 = _mesh(Node("a"), Node("b"), grants=None)
    m2.partition("a", "b")
    m2.drop("b")
    assert m2.partitions == set()


def test_partition_and_policy_both_required():
    g = [Grant(("web",), ("api",), ("*",))]
    m = _mesh(Node("w", ("web",)), Node("p", ("api",)), grants=g)
    m.partition("w", "p")
    assert not m.tunnel("w", "p")                        # policy allows, path cut
    assert not m.reachable("w", "p", 80)                 # no tunnel => no service
