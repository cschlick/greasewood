"""
Roles + grants + derived topology (greasewood.policy / wire.GrantTable).

The invariants under test:
  - tunnel existence derives from the grant table (either-direction match);
    with a table, even same-role nodes DON'T peer without a grant
  - no table → the flat trusted mesh (implicit * -> * : *); roles inert
  - the anchor (role:*) peers with everyone REGARDLESS of the table — the
    control plane is hardwired beneath policy, never prunable by it
  - adoption is CA-verified and seq-monotonic (no replay of an old table)
  - grants.toml is allow-only by schema: a deny rule is not expressible
"""
import json

import pytest

from greasewood import policy
from greasewood.keys import CAKeys, NodeKeys, derive_addr
from greasewood.wire import Credential, GrantTable, NodeRecord

import datetime as dt

_UTC = dt.timezone.utc
CA = CAKeys.generate()


def _rec(name, caps):
    k = NodeKeys.generate()
    now = dt.datetime.now(_UTC).replace(microsecond=0)
    cred = Credential(id_pub=k.id_pub_bytes, wg_pub=k.wg_pub_bytes,
                      addr=derive_addr(k.id_pub_bytes), hostname=name,
                      caps=list(caps), iat=now,
                      exp=now + dt.timedelta(hours=1)).sign(CA.ca_priv)
    return NodeRecord(id_pub=k.id_pub_bytes, seq=1, endpoints=[],
                      cred=cred).sign(k.id_priv)


def _grants(*triples):
    """[(from, to, ports), ...] → normalized grant list."""
    return [{"from": sorted(f), "to": sorted(t), "ports": sorted(p)}
            for f, t, p in triples]


# ---------------------------------------------------------------------------
# tag vocabulary
# ---------------------------------------------------------------------------

def test_node_tags_reads_role_caps_only():
    # Roles are the ONLY configured vocabulary. segment: caps are not a thing —
    # segments are emergent (the structure the grant graph produces).
    caps = ["role:web", "role:*", "tls", "segment:legacy"]
    assert policy.node_tags(caps) == {"web", "*"}


# ---------------------------------------------------------------------------
# peers_allowed — the tunnel-existence decision
# ---------------------------------------------------------------------------

class TestNoPolicyFlatMesh:
    def test_no_table_everyone_peers(self):
        # No policy → the flat trusted mesh (implicit * -> * : *). A fresh mesh
        # needs no file, and roles are inert until a table exists.
        assert policy.peers_allowed(["role:db"], ["role:db"], None)
        assert policy.peers_allowed(["role:db"], ["role:web"], None)
        assert policy.peers_allowed([], [], None)


class TestDerivedTopology:
    def test_grant_creates_the_tunnel_either_direction(self):
        grants = _grants((["web"], ["api"], ["tcp/8000"]))
        # directed grant → symmetric tunnel (a WG session is bidirectional)
        assert policy.peers_allowed(["role:web"], ["role:api"], grants)
        assert policy.peers_allowed(["role:api"], ["role:web"], grants)

    def test_with_a_table_same_role_does_not_peer_without_a_grant(self):
        # THE derived-topology property: only grants create tunnels. Two web
        # nodes share no tunnel until someone writes web -> web.
        grants = _grants((["web"], ["api"], ["tcp/8000"]))
        assert not policy.peers_allowed(["role:web"], ["role:web"], grants)

    def test_segment_caps_are_not_grant_vocabulary(self):
        # Segments are emergent, not caps: a segment: tag matches nothing.
        grants = _grants((["db"], ["db"], ["tcp/5432"]))
        assert not policy.peers_allowed(["segment:db"], ["segment:db"], grants)
        assert policy.peers_allowed(["role:db"], ["role:db"], grants)

    def test_wildcard_tag_in_grant_matches_any_node(self):
        grants = _grants((["metrics"], ["*"], ["tcp/9100"]))
        assert policy.peers_allowed(["role:metrics"], ["role:whatever"], grants)
        assert not policy.peers_allowed(["role:other"], ["role:whatever"], grants)

    def test_anchor_hardwired_beneath_the_table(self):
        # An empty table prunes everything EXCEPT the anchor — the channel that
        # carries the policy is not prunable by the policy.
        assert policy.peers_allowed(["role:*"], ["role:web"], [])
        assert policy.peers_allowed(["role:web"], ["role:*"], [])
        assert not policy.peers_allowed(["role:web"], ["role:web"], [])


# ---------------------------------------------------------------------------
# grants.toml parsing — allow-only by schema
# ---------------------------------------------------------------------------

class TestGrantsToml:
    def test_parse_good(self):
        grants = policy.parse_grants_toml('''
[[grant]]
from  = ["web", "worker"]
to    = ["api"]
ports = ["tcp/8000"]

[[grant]]
from  = ["metrics"]
to    = ["*"]
# ports omitted → all ports
''')
        assert grants[0] == {"from": ["web", "worker"], "to": ["api"],
                             "ports": ["tcp/8000"]}
        assert grants[1]["ports"] == ["*"]

    def test_deny_is_not_expressible(self):
        with pytest.raises(ValueError, match="unknown key"):
            policy.parse_grants_toml(
                '[[grant]]\nfrom=["a"]\nto=["b"]\naction="deny"\n')

    def test_typoed_key_rejected(self):
        with pytest.raises(ValueError, match="unknown key"):
            policy.parse_grants_toml('[[grant]]\nform=["a"]\nto=["b"]\n')

    def test_bad_port_rejected(self):
        for bad in ("8000", "tcp/0", "tcp/70000", "icmp/1", "tcp/abc"):
            with pytest.raises(ValueError, match="bad port"):
                policy.parse_grants_toml(
                    f'[[grant]]\nfrom=["a"]\nto=["b"]\nports=["{bad}"]\n')

    def test_non_string_role_rejected(self):
        with pytest.raises(ValueError, match="list of strings"):
            policy.parse_grants_toml('[[grant]]\nfrom=[1]\nto=["b"]\n')

    def test_unknown_top_level_key_rejected(self):
        with pytest.raises(ValueError, match="top-level"):
            policy.parse_grants_toml('deny = true\n[[grant]]\nfrom=["a"]\nto=["b"]\n')


# ---------------------------------------------------------------------------
# GrantTable — signing / verification / hostile input
# ---------------------------------------------------------------------------

class TestGrantTableWire:
    def test_sign_verify_roundtrip(self):
        table = GrantTable(seq=3, grants=_grants((["web"], ["api"], ["tcp/8000"])))
        signed = table.sign(CA.ca_priv)
        again = GrantTable.from_dict(signed.to_dict())
        again.verify([CA.ca_pub_bytes])            # must not raise
        assert again.seq == 3 and again.grants == signed.grants

    def test_tampered_table_rejected(self):
        signed = GrantTable(seq=1, grants=_grants((["web"], ["api"], ["*"]))
                            ).sign(CA.ca_priv)
        d = signed.to_dict()
        d["grants"][0]["to"] = ["*"]               # widen the grant post-signature
        with pytest.raises(ValueError, match="no trusted CA signature"):
            GrantTable.from_dict(d).verify([CA.ca_pub_bytes])

    def test_untrusted_ca_rejected(self):
        other = CAKeys.generate()
        signed = GrantTable(seq=1, grants=[]).sign(other.ca_priv)
        with pytest.raises(ValueError):
            GrantTable.from_dict(signed.to_dict()).verify([CA.ca_pub_bytes])

    def test_hostile_types_rejected_cleanly(self):
        base = GrantTable(seq=1, grants=[]).sign(CA.ca_priv).to_dict()
        for mutate in (
            lambda d: d.__setitem__("seq", "1"),
            lambda d: d.__setitem__("seq", -2),
            lambda d: d.__setitem__("grants", "not-a-list"),
            lambda d: d.__setitem__("grants", [{"from": "web", "to": ["b"]}]),
        ):
            d = json.loads(json.dumps(base))
            mutate(d)
            with pytest.raises(ValueError):
                GrantTable.from_dict(d)


# ---------------------------------------------------------------------------
# GrantPolicy — adoption (verify + monotonic seq) and persistence
# ---------------------------------------------------------------------------

class TestGrantPolicyAdoption:
    def _signed(self, seq, grants):
        return GrantTable(seq=seq, grants=grants).sign(CA.ca_priv).to_dict()

    def test_offer_adopts_valid_and_persists(self, tmp_path):
        gp = policy.GrantPolicy(cache_path=tmp_path / "policy.json",
                                get_ca_pubs=lambda: [CA.ca_pub_bytes])
        assert gp(["role:db"], ["role:db"])                # flat mesh before adoption
        assert gp.offer(self._signed(1, _grants((["web"], ["api"], ["*"]))))
        assert not gp(["role:db"], ["role:db"])            # table now governs
        assert gp(["role:web"], ["role:api"])
        # persisted → a fresh holder loads last-known-good
        gp2 = policy.GrantPolicy(cache_path=tmp_path / "policy.json",
                                 get_ca_pubs=lambda: [CA.ca_pub_bytes])
        gp2.load_cache()
        assert gp2.table.seq == 1

    def test_offer_rejects_bad_signature(self, tmp_path):
        gp = policy.GrantPolicy(cache_path=tmp_path / "policy.json",
                                get_ca_pubs=lambda: [CA.ca_pub_bytes])
        d = self._signed(1, [])
        d["seq"] = 2                                       # break the signature
        assert not gp.offer(d)
        assert gp.table is None

    def test_offer_rejects_stale_seq(self, tmp_path):
        # Monotonic: an old table can't be replayed to reopen a deleted grant.
        gp = policy.GrantPolicy(get_ca_pubs=lambda: [CA.ca_pub_bytes])
        assert gp.offer(self._signed(5, []))
        assert not gp.offer(self._signed(4, _grants((["a"], ["b"], ["*"]))))
        assert gp.table.seq == 5

    def test_corrupt_cache_ignored(self, tmp_path):
        (tmp_path / "policy.json").write_text("{corrupt")
        gp = policy.GrantPolicy(cache_path=tmp_path / "policy.json",
                                get_ca_pubs=lambda: [CA.ca_pub_bytes])
        gp.load_cache()                                    # must not raise
        assert gp.table is None


# ---------------------------------------------------------------------------
# tunnel_delta + unmatched_tags — what `gw policy apply` previews
# ---------------------------------------------------------------------------

def test_tunnel_delta_reports_created_and_removed():
    web = _rec("web1", ["role:web"])
    api = _rec("api1", ["role:api"])
    db = _rec("db1", ["role:db"])
    anchor = _rec("anchor", ["role:*"])
    records = [web, api, db, anchor]

    created, removed = policy.tunnel_delta(
        records, None, _grants((["web"], ["api"], ["tcp/8000"])))
    # flat mesh had web↔api, web↔db, api↔db; the table keeps only web↔api
    assert created == []
    assert sorted(removed) == [("api1", "db1"), ("web1", "db1")]
    # anchor pairs never appear in a delta — hardwired beneath policy
    assert not any("anchor" in pair for pair in removed)


def test_unmatched_tags_flags_typos():
    records = [_rec("web1", ["role:web"])]
    tags = policy.unmatched_tags(_grants((["wbe"], ["web"], ["*"])), records)
    assert tags == {"wbe"}


# ---------------------------------------------------------------------------
# the default grant table `gw create` materializes
# ---------------------------------------------------------------------------

def test_default_grants_toml_is_default_closed_admin_ssh():
    """The starting grants.toml is DEFAULT-CLOSED: a single active grant,
    `admin -> [anchor, node] : tcp/22`. Not fully open — enforcement realizes a
    secure star. The commented alternatives are just comments, so exactly one
    grant parses."""
    from greasewood.portfilter import _fully_open
    grants = policy.parse_grants_toml(policy.DEFAULT_GRANTS_TOML)
    assert grants == [{"from": ["admin"], "to": ["anchor", "node"],
                       "ports": ["tcp/22"]}]
    assert not _fully_open(grants)
    # admin (the anchor) reaches every node; two ordinary nodes do NOT peer.
    assert policy.peers_allowed(["role:admin"], ["role:node"], grants)
    assert not policy.peers_allowed(["role:node"], ["role:node"], grants)
    # the anchor's reach-all still peers with everyone, beneath the table.
    assert policy.peers_allowed(["role:*"], ["role:node"], grants)


def test_example_grants_toml_parses_to_default_closed():
    """The shipped grants.toml.example leads with the default-closed baseline
    (`admin -> anchor,node : tcp/22`); the looser/tighter baselines and service
    samples are commented, so copying it yields the same secure star as create."""
    import pathlib
    example = pathlib.Path(__file__).resolve().parent.parent / "grants.toml.example"
    grants = policy.parse_grants_toml(example.read_text())
    assert grants == [{"from": ["admin"], "to": ["anchor", "node"],
                       "ports": ["tcp/22"]}]


# ---------------------------------------------------------------------------
# AnchorPolicySigner — grants.toml is the source of truth, auto-signed
# ---------------------------------------------------------------------------

class TestAnchorPolicySigner:
    def _ca(self):
        return CA   # module-level CAKeys

    def test_signs_grants_toml_into_policy_json(self, tmp_path):
        (tmp_path / "grants.toml").write_text(
            '[[grant]]\nfrom=["web"]\nto=["api"]\nports=["tcp/8000"]\n')
        s = policy.AnchorPolicySigner(tmp_path, CA)
        d = s.refresh()
        assert d["seq"] == 1
        assert d["grants"] == [{"from": ["web"], "to": ["api"], "ports": ["tcp/8000"]}]
        # it wrote policy.json, and it verifies under the CA
        from greasewood.wire import GrantTable
        on_disk = GrantTable.from_dict(json.loads((tmp_path / "policy.json").read_text()))
        on_disk.verify([CA.ca_pub_bytes])
        assert on_disk.seq == 1

    def test_resigns_only_on_content_change_bumping_seq(self, tmp_path):
        gp = tmp_path / "grants.toml"
        gp.write_text('[[grant]]\nfrom=["web"]\nto=["api"]\nports=["*"]\n')
        s = policy.AnchorPolicySigner(tmp_path, CA)
        assert s.refresh()["seq"] == 1
        # unchanged file → no bump (same seq), even across a new signer instance
        assert s.refresh()["seq"] == 1
        assert policy.AnchorPolicySigner(tmp_path, CA).refresh()["seq"] == 1
        # edit → bump to 2
        import os, time
        gp.write_text('[[grant]]\nfrom=["web"]\nto=["db"]\nports=["*"]\n')
        os.utime(gp, (time.time() + 1, time.time() + 1))   # ensure mtime moves
        d = s.refresh()
        assert d["seq"] == 2 and d["grants"][0]["to"] == ["db"]

    def test_invalid_grants_toml_keeps_last_good(self, tmp_path):
        gp = tmp_path / "grants.toml"
        gp.write_text('[[grant]]\nfrom=["web"]\nto=["api"]\nports=["*"]\n')
        s = policy.AnchorPolicySigner(tmp_path, CA)
        assert s.refresh()["seq"] == 1
        import os, time
        gp.write_text('this is not valid toml [[[')
        os.utime(gp, (time.time() + 1, time.time() + 1))
        d = s.refresh()                            # must NOT crash or revert to open
        assert d["seq"] == 1                        # last good still served
        assert d["grants"] == [{"from": ["web"], "to": ["api"], "ports": ["*"]}]

    def test_feeds_grant_policy_live(self, tmp_path):
        (tmp_path / "grants.toml").write_text(
            '[[grant]]\nfrom=["web"]\nto=["api"]\nports=["*"]\n')
        gp = policy.GrantPolicy(get_ca_pubs=lambda: [CA.ca_pub_bytes])
        s = policy.AnchorPolicySigner(tmp_path, CA)
        s.refresh(offer_to=gp)
        # the anchor's own data plane now sees the signed table
        assert gp.table is not None and gp.table.seq == 1
        assert gp(["role:web"], ["role:api"]) is True
        assert gp(["role:web"], ["role:web"]) is False   # not granted → no tunnel

    def test_disk_authoritative_seq_survives_external_apply(self, tmp_path):
        # If `gw policy apply` writes a higher seq, the signer baselines off it
        # (reads policy.json) rather than an in-memory counter — no drift.
        (tmp_path / "grants.toml").write_text(
            '[[grant]]\nfrom=["web"]\nto=["api"]\nports=["*"]\n')
        s = policy.AnchorPolicySigner(tmp_path, CA)
        s.refresh()                                # v1
        # simulate an external apply bumping to v5 with the SAME grants
        from greasewood.wire import GrantTable
        ext = GrantTable(seq=5, grants=[{"from": ["web"], "to": ["api"],
                                         "ports": ["*"]}]).sign(CA.ca_priv)
        (tmp_path / "policy.json").write_text(json.dumps(ext.to_dict()))
        d = s.refresh()                            # grants.toml unchanged content
        assert d["seq"] == 5                        # serves the external truth, no bump


# ---------------------------------------------------------------------------
# confirmed-apply model: the anchor reloads applied policy; edits are surfaced
# ---------------------------------------------------------------------------

def test_grant_policy_refresh_from_cache_picks_up_apply(tmp_path):
    """The anchor has no seeds to sync from, so its data plane picks up a
    `gw policy apply` by reloading policy.json (mtime-guarded, seq-monotonic)."""
    from greasewood.wire import GrantTable
    cache = tmp_path / "policy.json"
    gp = policy.GrantPolicy(cache_path=cache, get_ca_pubs=lambda: [CA.ca_pub_bytes])
    # v1: web -> api
    cache.write_text(json.dumps(GrantTable(
        seq=1, grants=[{"from": ["web"], "to": ["api"], "ports": ["*"]}]
    ).sign(CA.ca_priv).to_dict()))
    assert gp.refresh_from_cache() is True
    assert gp(["role:web"], ["role:api"]) and not gp(["role:web"], ["role:db"])
    assert gp.refresh_from_cache() is False        # unchanged → no reload
    # an apply writes v2 tightening to web -> db
    import os, time
    cache.write_text(json.dumps(GrantTable(
        seq=2, grants=[{"from": ["web"], "to": ["db"], "ports": ["*"]}]
    ).sign(CA.ca_priv).to_dict()))
    os.utime(cache, (time.time() + 1, time.time() + 1))
    assert gp.refresh_from_cache() is True
    assert gp(["role:web"], ["role:db"]) and not gp(["role:web"], ["role:api"])


def test_unapplied_edits_flags_pending_changes(tmp_path):
    from greasewood.wire import GrantTable
    (tmp_path / "grants.toml").write_text(
        '[[grant]]\nfrom=["web"]\nto=["api"]\nports=["*"]\n')
    # no policy.json yet → the edit is pending
    assert policy.unapplied_edits(tmp_path)
    # apply it (matching signed policy) → nothing pending
    (tmp_path / "policy.json").write_text(json.dumps(GrantTable(
        seq=1, grants=[{"from": ["web"], "to": ["api"], "ports": ["*"]}]
    ).sign(CA.ca_priv).to_dict()))
    assert policy.unapplied_edits(tmp_path) == ""
    # edit grants.toml again → pending until re-applied
    (tmp_path / "grants.toml").write_text(
        '[[grant]]\nfrom=["web"]\nto=["db"]\nports=["*"]\n')
    assert "grant(s)" in policy.unapplied_edits(tmp_path)
