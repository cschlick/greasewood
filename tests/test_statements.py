"""
AnchorStatement (wire) + StatementLog (statements) — the replicated,
CA-signed membership decisions of the anchor-file model. Signing/verification
discipline mirrors Credential; merge is order-free latest-ts-per-(kind,id);
tombstones kill only credentials issued at or before them, so departed ids
can re-enroll.
"""
import datetime as dt

import pytest

from greasewood.directory import Directory, DROP_GRACE
from greasewood.keys import CAKeys, NodeKeys, derive_addr
from greasewood.statements import StatementLog, statements_path
from greasewood.wire import AnchorStatement, Credential, NodeRecord

_UTC = dt.timezone.utc


def _now():
    return dt.datetime.now(_UTC).replace(microsecond=0)


def _stmt(ca, kind, node, ts=None, caps=(), hostname=""):
    return AnchorStatement(kind=kind, id_pub=node.id_pub_bytes,
                           ts=ts or _now(), caps=list(caps),
                           hostname=hostname).sign(ca.ca_priv)


def _rec(ca, node, hostname, iat=None, ttl_h=24):
    iat = iat or _now()
    cred = Credential(id_pub=node.id_pub_bytes, wg_pub=node.wg_pub_bytes,
                      addr=derive_addr(node.id_pub_bytes), hostname=hostname,
                      caps=["role:node"], iat=iat,
                      exp=iat + dt.timedelta(hours=ttl_h)).sign(ca.ca_priv)
    return NodeRecord(id_pub=node.id_pub_bytes, seq=1, endpoints=[],
                      cred=cred).sign(node.id_priv)


# ---------------------------------------------------------------------------
# wire-level: sign / verify / round-trip
# ---------------------------------------------------------------------------

def test_statement_roundtrip_and_verify():
    ca, node = CAKeys.generate(), NodeKeys.generate()
    s = _stmt(ca, "setcaps", node, caps=["role:node", "tls"], hostname="db01")
    s2 = AnchorStatement.from_dict(s.to_dict())
    s2.verify([ca.ca_pub_bytes])                      # trusted → passes
    assert s2.kind == "setcaps" and s2.caps == ["role:node", "tls"]
    assert s2.ts == s.ts


def test_statement_untrusted_ca_refused():
    ca, other, node = CAKeys.generate(), CAKeys.generate(), NodeKeys.generate()
    s = _stmt(ca, "revoke", node)
    with pytest.raises(ValueError, match="no trusted CA"):
        s.verify([other.ca_pub_bytes])


def test_statement_tamper_refused():
    ca, node = CAKeys.generate(), NodeKeys.generate()
    s = _stmt(ca, "tombstone", node)
    d = s.to_dict()
    d["kind"] = "revoke"                              # promote a leave to a kill
    with pytest.raises(ValueError, match="no trusted CA"):
        AnchorStatement.from_dict(d).verify([ca.ca_pub_bytes])


def test_unknown_kind_rejected_at_parse():
    ca, node = CAKeys.generate(), NodeKeys.generate()
    d = _stmt(ca, "revoke", node).to_dict()
    d["kind"] = "obliterate"
    with pytest.raises(ValueError, match="unknown statement kind"):
        AnchorStatement.from_dict(d)


# ---------------------------------------------------------------------------
# StatementLog: merge, queries, effects
# ---------------------------------------------------------------------------

def test_merge_verifies_and_keeps_latest_per_kind_and_id():
    ca, evil, node = CAKeys.generate(), CAKeys.generate(), NodeKeys.generate()
    logf = StatementLog()
    older = _stmt(ca, "setcaps", node, ts=_now() - dt.timedelta(hours=2),
                  caps=["role:node"])
    newer = _stmt(ca, "setcaps", node, caps=["role:node", "cockpit"])
    forged = _stmt(evil, "revoke", node)              # untrusted signer
    assert logf.merge([older, forged], [ca.ca_pub_bytes]) == 1
    assert logf.merge([newer, older], [ca.ca_pub_bytes]) == 1   # older ignored
    caps, _ts = logf.caps_override(node.id_pub_hex)
    assert set(caps) == {"cockpit", "role:node"}
    assert logf.revoked_ids() == set()                # the forgery never landed


def test_revoke_is_monotone():
    ca, node = CAKeys.generate(), NodeKeys.generate()
    logf = StatementLog()
    logf.merge([_stmt(ca, "revoke", node)], [ca.ca_pub_bytes])
    assert node.id_pub_hex in logf.revoked_ids()
    assert logf.prune() == 0                          # revokes never pruned
    assert node.id_pub_hex in logf.revoked_ids()


def test_tombstone_kills_old_record_but_not_reenrollment():
    """The heart of leave/sweep in the multi-holder world: a tombstone ends
    the membership whose credentials predate it — and ONLY that membership.
    A fresh enrollment (iat after the tombstone) sails through, so 'the name
    can be reused and the id can return' survives the redesign."""
    ca, node = CAKeys.generate(), NodeKeys.generate()
    d = Directory()
    d.put(_rec(ca, node, "bb", iat=_now() - dt.timedelta(hours=1)))
    logf = StatementLog()
    logf.merge([_stmt(ca, "tombstone", node, hostname="bb")], [ca.ca_pub_bytes])

    assert logf.drop_dead_records(d) == 1
    assert d.get(node.id_pub_hex) is None

    # bb re-enrolls: fresh credential, iat after the tombstone
    d.put(_rec(ca, node, "bb", iat=_now() + dt.timedelta(seconds=1)))
    assert logf.drop_dead_records(d) == 0
    assert d.get(node.id_pub_hex) is not None


def test_drop_dead_records_protect():
    ca, node = CAKeys.generate(), NodeKeys.generate()
    d = Directory()
    d.put(_rec(ca, node, "self", iat=_now() - dt.timedelta(hours=1)))
    logf = StatementLog()
    logf.merge([_stmt(ca, "tombstone", node)], [ca.ca_pub_bytes])
    assert logf.drop_dead_records(d, protect=node.id_pub_hex) == 0
    assert d.get(node.id_pub_hex) is not None


def test_prune_rules():
    ca = CAKeys.generate()
    gone, living = NodeKeys.generate(), NodeKeys.generate()
    logf = StatementLog()
    old = _now() - DROP_GRACE - dt.timedelta(days=1)
    logf.merge([
        _stmt(ca, "tombstone", gone, ts=old),                 # ancient → pruned
        _stmt(ca, "setcaps", gone, ts=old - dt.timedelta(days=1),
              caps=["role:node"]),                            # membership ended → pruned
        _stmt(ca, "tombstone", living, ts=_now()),            # recent → kept
        _stmt(ca, "setcaps", living, ts=_now() + dt.timedelta(seconds=1),
              caps=["role:node"]),  # newer than the tombstone → survives (re-enroll era)
    ], [ca.ca_pub_bytes])
    assert logf.prune() == 2
    assert logf.tombstone_ts(gone.id_pub_hex) is None
    assert logf.caps_override(gone.id_pub_hex) is None
    assert logf.tombstone_ts(living.id_pub_hex) is not None
    assert logf.caps_override(living.id_pub_hex) is not None


def test_persistence_reverifies_against_current_trust(tmp_path):
    """A completed re-root drops the old CA from trusted_pubs; its cached
    statements must die at load, not survive as zombie authority."""
    old_ca, new_ca, node = CAKeys.generate(), CAKeys.generate(), NodeKeys.generate()
    logf = StatementLog()
    logf.merge([_stmt(old_ca, "revoke", node)], [old_ca.ca_pub_bytes])
    p = statements_path(tmp_path)
    logf.save(p)

    both = StatementLog.load(p, [old_ca.ca_pub_bytes, new_ca.ca_pub_bytes])
    assert node.id_pub_hex in both.revoked_ids()      # overlap window: kept

    rerooted = StatementLog.load(p, [new_ca.ca_pub_bytes])
    assert rerooted.revoked_ids() == set()            # old CA dropped: gone
