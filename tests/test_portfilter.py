"""
Port enforcement: the grant table → greasewood's own nftables ruleset
(greasewood.portfilter). Unit-level: the rendered ruleset is correct, scoped,
and only-tightens. The kernel behavior (a granted port passes, an ungranted
port on the same tunnel is dropped) is proven in the integration suite.
"""
import types

import pytest

from greasewood import portfilter as pf


def _rec(addr, roles):
    return types.SimpleNamespace(
        cred=types.SimpleNamespace(addr=addr, caps=[f"role:{r}" for r in roles]))


WEB1, WEB2, API1, DB1 = "fd8d::1", "fd8d::2", "fd8d::3", "fd8d::4"
FLEET = [_rec(WEB1, ["web"]), _rec(WEB2, ["web"]),
         _rec(API1, ["api"]), _rec(DB1, ["db"])]


def _render(local_roles, grants):
    return pf.render_ruleset("greasewood_test", "gw-mesh", 51902, FLEET,
                             [f"role:{r}" for r in local_roles], grants)


# ---------------------------------------------------------------------------
# structural invariants
# ---------------------------------------------------------------------------

def test_only_greasewoods_own_table():
    out = _render(["api"], [{"from": ["web"], "to": ["api"], "ports": ["tcp/8000"]}])
    assert "table inet greasewood_test {" in out
    # never names the operator's tables/chains, never a physical iface
    assert "eth0" not in out


def test_every_rule_scoped_to_the_mesh_interface():
    out = _render(["api"], [{"from": ["web"], "to": ["api"], "ports": ["tcp/8000"]}])
    # the guard + the accepts/drop that touch mesh traffic all name gw-mesh
    assert 'iifname != "gw-mesh" accept' in out
    assert 'iifname "gw-mesh" drop' in out
    # the granted accept is mesh-scoped too
    assert 'iifname "gw-mesh" tcp dport 8000 ip6 saddr @p_tcp_8000 accept' in out


def test_control_and_diagnostics_are_hardwired():
    # the control port + ct-established + icmpv6 are always allowed, so
    # enforcement never cuts the channel that carries the policy, nor replies.
    out = _render(["web"], [{"from": ["web"], "to": ["api"], "ports": ["*"]}])
    assert "tcp dport 51902 accept" in out
    assert "ct state established,related accept" in out
    assert "meta l4proto ipv6-icmp accept" in out


# ---------------------------------------------------------------------------
# server-side allow derivation
# ---------------------------------------------------------------------------

def test_server_accepts_granted_port_from_client_addresses():
    out = _render(["api"], [{"from": ["web"], "to": ["api"], "ports": ["tcp/8000"]}])
    assert "set p_tcp_8000" in out
    # exactly the two web addresses, and not the db node
    assert WEB1 in out and WEB2 in out
    line = next(l for l in out.splitlines() if "p_tcp_8000 {" in l)
    assert DB1 not in line and API1 not in line


def test_client_has_no_inbound_grant_relies_on_established():
    # web is a CLIENT of api — no grant names web in `to`, so no inbound accept
    # for it; its replies ride ct established (asymmetry falls out of stateful).
    out = _render(["web"], [{"from": ["web"], "to": ["api"], "ports": ["tcp/8000"]}])
    assert "dport 8000" not in out            # no server rule on the client
    assert 'iifname "gw-mesh" drop' in out


def test_wildcard_to_matches_every_node_as_destination():
    out = _render(["db"], [{"from": ["metrics"], "to": ["*"], "ports": ["tcp/9100"]}])
    # a db node is a destination for metrics→* ; sources = metrics holders (none
    # in FLEET) → the grant contributes nothing, so no p_tcp_9100 set
    assert "p_tcp_9100" not in out
    # but with a metrics node present, it appears
    fleet = FLEET + [_rec("fd8d::9", ["metrics"])]
    out2 = pf.render_ruleset("greasewood_test", "gw-mesh", 51902, fleet, ["role:db"],
                             [{"from": ["metrics"], "to": ["*"], "ports": ["tcp/9100"]}])
    assert "set p_tcp_9100" in out2 and "fd8d::9" in out2


def test_all_ports_grant_uses_the_saddr_set():
    out = _render(["api"], [{"from": ["web"], "to": ["api"], "ports": ["*"]}])
    assert "set p_all" in out
    assert 'iifname "gw-mesh" ip6 saddr @p_all accept' in out


# ---------------------------------------------------------------------------
# the two default postures
# ---------------------------------------------------------------------------

def test_no_policy_admits_the_whole_overlay():
    # flat mesh (grants=None) → enforcement is a no-op: mesh default is accept.
    out = _render(["api"], None)
    assert 'iifname "gw-mesh" accept' in out
    assert 'iifname "gw-mesh" drop' not in out


def test_explicit_wildcard_grant_renders_as_clean_open():
    # `* -> * : *` written in grants.toml means the same as no policy — open —
    # and renders as a single accept, NOT an all-addresses set (cheap at scale).
    out = _render(["api"], [{"from": ["*"], "to": ["*"], "ports": ["*"]}])
    assert 'iifname "gw-mesh" accept' in out
    assert "p_all" not in out and "p_tcp" not in out   # no grant-derived sets
    assert 'iifname "gw-mesh" drop' not in out


def test_policy_with_no_rule_for_this_node_default_denies_mesh():
    # a table exists but grants nothing TO this node → default-deny within mesh
    # (established/icmp/control still allowed, so it's reachable + replies work).
    out = _render(["db"], [{"from": ["web"], "to": ["api"], "ports": ["*"]}])
    assert 'iifname "gw-mesh" drop' in out
    assert "tcp dport 51902 accept" in out


# ---------------------------------------------------------------------------
# change detection (regenerate-on-change)
# ---------------------------------------------------------------------------

def test_ruleset_is_deterministic():
    grants = [{"from": ["web"], "to": ["api"], "ports": ["tcp/8000"]}]
    assert _render(["api"], grants) == _render(["api"], grants)


def test_apply_skips_reload_when_unchanged(monkeypatch):
    loads = []
    monkeypatch.setattr("greasewood.wg.nft_load", lambda script: loads.append(script))
    monkeypatch.setattr("greasewood.wg.nft_table_exists", lambda t: True)  # table stays present
    gp = types.SimpleNamespace(
        table=types.SimpleNamespace(
            grants=[{"from": ["web"], "to": ["api"], "ports": ["tcp/8000"]}]))
    enforcer = pf.PortFilter("greasewood_test", "gw-mesh", 51902, ["role:api"], gp)
    enforcer.apply(FLEET)
    enforcer.apply(FLEET)                      # identical + present → no second reload
    assert len(loads) == 1
    # a membership change (new web node) triggers exactly one more reload
    enforcer.apply(FLEET + [_rec("fd8d::5", ["web"])])
    assert len(loads) == 2
    assert "fd8d::5" in loads[1]


# ---------------------------------------------------------------------------
# availability gate
# ---------------------------------------------------------------------------

def test_ensure_available_raises_without_nft(monkeypatch):
    monkeypatch.setattr("greasewood.portfilter.shutil.which", lambda n: None)
    with pytest.raises(pf.NftUnavailable, match="not installed"):
        pf.ensure_available()


def test_ensure_available_raises_when_ruleset_fails(monkeypatch):
    import subprocess
    monkeypatch.setattr("greasewood.portfilter.shutil.which", lambda n: "/usr/sbin/nft")
    monkeypatch.setattr("greasewood.portfilter.subprocess.run",
                        lambda *a, **k: subprocess.CompletedProcess(
                            a, 1, "", "Operation not permitted"))
    with pytest.raises(pf.NftUnavailable, match="failed"):
        pf.ensure_available()


def test_table_name_is_per_mesh_and_nft_safe():
    # per-membership so multi-mesh hosts don't clobber one shared table; and
    # hyphens/dots in the key become underscores (nft identifier rules).
    assert pf.table_name("prod") == "greasewood_prod"
    assert pf.table_name("gw-a.b") == "greasewood_gw_a_b"
    assert pf.table_name("prod") != pf.table_name("dev")


def test_reasserts_table_when_externally_removed(monkeypatch):
    """An `nft flush ruleset` (operator's nft -f) wipes our table; the enforcer
    must notice via a kernel presence check and reinstall, not trust its cache
    and leave the mesh unenforced."""
    loads = []
    monkeypatch.setattr("greasewood.wg.nft_load", lambda script: loads.append(script))
    present = {"v": True}
    monkeypatch.setattr("greasewood.wg.nft_table_exists", lambda t: present["v"])
    gp = types.SimpleNamespace(
        table=types.SimpleNamespace(
            grants=[{"from": ["web"], "to": ["api"], "ports": ["tcp/8000"]}]))
    enforcer = pf.PortFilter("greasewood_test", "gw-mesh", 51902, ["role:api"], gp)

    enforcer.apply(FLEET)
    assert len(loads) == 1                       # initial install
    enforcer.apply(FLEET)                         # unchanged + present → skip
    assert len(loads) == 1
    present["v"] = False                          # simulate `flush ruleset`
    enforcer.apply(FLEET)                         # unchanged but GONE → reinstall
    assert len(loads) == 2
    present["v"] = True
    enforcer.apply(FLEET)                         # back + present → skip again
    assert len(loads) == 2
