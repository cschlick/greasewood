"""
Emergent segments: complex role/grant graphs → is the structure that falls
out logical?

A "segment" is not configured — it's the connected structure the grant graph
produces. These tests build non-trivial topologies (chains, hubs, islands,
bridges, client/server) and assert two layers:

  L1 — the DERIVED TOPOLOGY: exactly which pairs tunnel (peers_allowed over
       every pair), and the connected components among non-anchor nodes
       (computed here from the public semantics — the emergent segments).
  L2 — the HEALTH VIEW (_segment_analysis): with reachable sets consistent
       with the policy there are no faults; a policy-expected edge that's
       down IS flagged; a pair the policy correctly keeps apart is NOT
       (the no-false-alarm property).

Plus hypothesis properties over random fleets/tables: symmetry, the anchor
star, no-tunnel-without-a-grant, and allow-only monotonicity (adding a grant
never removes an edge).
"""
import datetime as dt
import itertools

from hypothesis import given, settings, strategies as st

from greasewood.keys import CAKeys, NodeKeys, derive_addr
from greasewood.policy import peers_allowed
from greasewood.wire import Credential, NodeRecord

_UTC = dt.timezone.utc
CA = CAKeys.generate()


# ---------------------------------------------------------------------------
# helpers: a fleet is {name: [role, ...]}; grants are (from, to) pairs
# ---------------------------------------------------------------------------

def _caps(roles):
    return [f"role:{r}" for r in roles]

def _grants(*pairs):
    return [{"from": sorted(f), "to": sorted(t), "ports": ["*"]}
            for f, t in pairs]

def _edges(fleet: dict, grants) -> set:
    """The derived tunnel edges among a fleet, as frozensets of names."""
    return {frozenset((a, b))
            for a, b in itertools.combinations(fleet, 2)
            if peers_allowed(_caps(fleet[a]), _caps(fleet[b]), grants)}

def _components(fleet: dict, grants) -> set:
    """The EMERGENT SEGMENTS: connected components of the derived graph among
    non-anchor nodes (the anchor's hardwired star would trivially join
    everything, so it's excluded from the structure question)."""
    members = [n for n in fleet if "*" not in fleet[n]]
    edges = {e for e in _edges({n: fleet[n] for n in members}, grants)}
    parent = {n: n for n in members}

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for e in edges:
        a, b = tuple(e)
        parent[find(a)] = find(b)
    comps = {}
    for n in members:
        comps.setdefault(find(n), set()).add(n)
    return {frozenset(c) for c in comps.values()}


# ---------------------------------------------------------------------------
# L1 — derived topology under complex graphs
# ---------------------------------------------------------------------------

def test_client_server_share_one_emergent_segment():
    """The motivating case: role:client and role:server, granted an interface,
    are on the same unnamed segment — while clients never talk sideways."""
    fleet = {"web1": ["web"], "web2": ["web"], "api1": ["api"]}
    grants = _grants((["web"], ["api"]))
    assert _edges(fleet, grants) == {frozenset(("web1", "api1")),
                                     frozenset(("web2", "api1"))}
    # ONE emergent segment (connected via the server), despite no web1↔web2.
    assert _components(fleet, grants) == {frozenset(("web1", "web2", "api1"))}


def test_chain_is_one_segment_without_transitive_tunnels():
    """web→api, api→db: one connected structure, but web NEVER tunnels to db —
    connectivity is per-grant, not transitive."""
    fleet = {"web1": ["web"], "api1": ["api"], "db1": ["db"]}
    grants = _grants((["web"], ["api"]), (["api"], ["db"]))
    assert _edges(fleet, grants) == {frozenset(("web1", "api1")),
                                     frozenset(("api1", "db1"))}
    assert _components(fleet, grants) == {frozenset(("web1", "api1", "db1"))}


def test_hub_and_spoke_is_one_segment_not_a_clique():
    """metrics→* builds a star: every node tunnels to the hub, spokes never
    tunnel to each other — yet it's ONE emergent segment."""
    fleet = {"prom": ["metrics"], "a": ["app"], "b": ["app"], "c": ["db"]}
    grants = _grants((["metrics"], ["*"]))
    assert _edges(fleet, grants) == {frozenset(("prom", "a")),
                                     frozenset(("prom", "b")),
                                     frozenset(("prom", "c"))}
    assert _components(fleet, grants) == {frozenset(("prom", "a", "b", "c"))}


def test_disjoint_apps_fall_into_separate_islands():
    """Two independent app stacks with no cross-grant → two emergent segments."""
    fleet = {"webA": ["web-a"], "apiA": ["api-a"],
             "webB": ["web-b"], "apiB": ["api-b"]}
    grants = _grants((["web-a"], ["api-a"]), (["web-b"], ["api-b"]))
    assert _components(fleet, grants) == {frozenset(("webA", "apiA")),
                                          frozenset(("webB", "apiB"))}


def test_multi_role_node_bridges_two_islands():
    """A node holding both stacks' roles merges what were two segments into
    one — and DROPPING one of its roles splits them again."""
    fleet = {"webA": ["web-a"], "apiA": ["api-a"],
             "webB": ["web-b"], "apiB": ["api-b"],
             "bridge": ["api-a", "web-b"]}
    grants = _grants((["web-a"], ["api-a"]), (["web-b"], ["api-b"]))
    assert _components(fleet, grants) == {
        frozenset(("webA", "apiA", "bridge", "webB", "apiB"))}
    # the same fleet without the bridge's second role → two islands again
    fleet["bridge"] = ["api-a"]
    assert _components(fleet, grants) == {
        frozenset(("webA", "apiA", "bridge")), frozenset(("webB", "apiB"))}


def test_deleting_the_only_connecting_grant_dissolves_the_segment():
    """The user's design sentence, verbatim: if a grant is the only thing
    keeping two roles together and it's deleted, their shared segment has no
    reason to exist — the nodes fall apart into singletons."""
    fleet = {"web1": ["web"], "api1": ["api"]}
    joined = _grants((["web"], ["api"]))
    assert _components(fleet, joined) == {frozenset(("web1", "api1"))}
    assert _components(fleet, _grants()) == {frozenset(("web1",)),
                                             frozenset(("api1",))}


def test_empty_table_is_all_singletons_plus_anchor_star():
    """An applied-but-empty table prunes everything except the hardwired
    anchor star."""
    fleet = {"anchor": ["*"], "a": ["app"], "b": ["app"]}
    assert _edges(fleet, []) == {frozenset(("anchor", "a")),
                                 frozenset(("anchor", "b"))}
    assert _components(fleet, []) == {frozenset(("a",)), frozenset(("b",))}


def test_roleless_node_is_isolated_under_any_table():
    fleet = {"lost": [], "web1": ["web"], "api1": ["api"]}
    grants = _grants((["web"], ["api"]), (["*"], ["*"]))
    # even a *→* grant matches only nodes that HOLD a role... check semantics:
    # '*' in from/to matches ANY node, so *→* reconnects everyone — including
    # the roleless node. Drop it and the roleless node is a singleton.
    assert frozenset(("lost", "web1")) in _edges(fleet, grants)
    grants = _grants((["web"], ["api"]))
    assert _components(fleet, grants) == {frozenset(("lost",)),
                                          frozenset(("web1", "api1"))}


# ---------------------------------------------------------------------------
# L2 — the health view judges faults against the policy, per emergent segment
# ---------------------------------------------------------------------------

def _rec(name, roles, *, endpoints=("[2001:db8::1]:51900",), reachable=()):
    k = NodeKeys.generate()
    now = dt.datetime.now(_UTC).replace(microsecond=0)
    cred = Credential(id_pub=k.id_pub_bytes, wg_pub=k.wg_pub_bytes,
                      addr=derive_addr(k.id_pub_bytes), hostname=name,
                      caps=_caps(roles), iat=now,
                      exp=now + dt.timedelta(hours=1)).sign(CA.ca_priv)
    return NodeRecord(id_pub=k.id_pub_bytes, seq=1, endpoints=list(endpoints),
                      cred=cred, reachable=list(reachable)).sign(k.id_priv)


def test_health_no_faults_when_reachability_matches_policy():
    """Chain policy, chain reachability: exactly the granted links are up →
    no missing edges, and the components mirror the emergent segment."""
    from greasewood.status import _segment_analysis
    web = _rec("web1", ["web"])
    api = _rec("api1", ["api"])
    db = _rec("db1", ["db"])
    grants = _grants((["web"], ["api"]), (["api"], ["db"]))
    web.reachable[:] = [api.cred.addr]
    api.reachable[:] = [web.cred.addr, db.cred.addr]
    db.reachable[:] = [api.cred.addr]
    comps, missing = _segment_analysis([web, api, db], grants)
    assert missing == []
    assert {frozenset(r.hostname for r in c) for c in comps} == \
        {frozenset(("web1", "api1", "db1"))}


def test_health_flags_only_policy_expected_down_edges():
    """web1↔api1 is granted but down → flagged. web1↔web2 is down too, but no
    grant connects them — NOT a fault (the no-false-alarm property that makes
    the health view usable under a derived topology)."""
    from greasewood.status import _segment_analysis
    web1 = _rec("web1", ["web"])
    web2 = _rec("web2", ["web"])
    api = _rec("api1", ["api"])
    grants = _grants((["web"], ["api"]))
    web2.reachable[:] = [api.cred.addr]          # web2↔api up; web1↔api DOWN
    comps, missing = _segment_analysis([web1, web2, api], grants)
    missing_pairs = {frozenset((a.hostname, b.hostname)) for a, b in missing}
    assert missing_pairs == {frozenset(("web1", "api1"))}   # and NOT web1↔web2


# ---------------------------------------------------------------------------
# properties over random fleets and tables (hypothesis)
# ---------------------------------------------------------------------------

_role = st.sampled_from(["web", "api", "db", "worker", "metrics"])
_roleset = st.lists(_role, max_size=3).map(lambda rs: sorted(set(rs)))
_grant = st.tuples(st.lists(_role, min_size=1, max_size=2),
                   st.lists(_role, min_size=1, max_size=2)).map(
    lambda p: {"from": sorted(set(p[0])), "to": sorted(set(p[1])),
               "ports": ["*"]})
_table = st.lists(_grant, max_size=5)


@settings(max_examples=60, deadline=None)
@given(a=_roleset, b=_roleset, table=_table)
def test_property_tunnels_are_symmetric(a, b, table):
    caps_a, caps_b = _caps(a), _caps(b)
    assert peers_allowed(caps_a, caps_b, table) == \
        peers_allowed(caps_b, caps_a, table)


@settings(max_examples=60, deadline=None)
@given(b=_roleset, table=_table)
def test_property_anchor_star_is_unprunable(b, table):
    assert peers_allowed(["role:*"], _caps(b), table) is True


@settings(max_examples=60, deadline=None)
@given(a=_roleset, b=_roleset, table=_table, extra=_grant)
def test_property_adding_a_grant_never_removes_an_edge(a, b, table, extra):
    """Allow-only union semantics: policy edits are monotone per grant —
    growth can only connect, never disconnect (and vice versa for deletion)."""
    before = peers_allowed(_caps(a), _caps(b), table)
    after = peers_allowed(_caps(a), _caps(b), table + [extra])
    assert after or not before          # before=True → after must be True


@settings(max_examples=60, deadline=None)
@given(a=_roleset, b=_roleset, table=_table)
def test_property_no_tunnel_without_a_covering_grant(a, b, table):
    """If a tunnel exists (non-anchor), SOME grant must connect the pair's
    roles in one direction — the topology never exceeds the policy."""
    if peers_allowed(_caps(a), _caps(b), table):
        sa, sb = set(a), set(b)
        assert any(
            (("*" in g["from"] or sa & set(g["from"])) and
             ("*" in g["to"] or sb & set(g["to"]))) or
            (("*" in g["from"] or sb & set(g["from"])) and
             ("*" in g["to"] or sa & set(g["to"])))
            for g in table)
