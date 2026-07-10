"""
CA.drop_stale — the AUTHORIZATION drop that bounds the indefinite recert of
expired-but-not-revoked nodes. After a node has been expired longer than
drop_grace, the CA forgets it (nodes/<id>.json removed), so renew() can no
longer re-issue from the registry and a return requires a full re-enrollment.
This is the automatic GC that replaces manual `gw revoke` for an abandoned
(destroyed cloud) fleet.
"""
import datetime as dt
import json

from greasewood.ca import CA
from greasewood.keys import CAKeys, NodeKeys
from greasewood.wire import RenewRequest

_UTC = dt.timezone.utc


def _ca(tmp_path, ttl=dt.timedelta(hours=24)):
    return CA(CAKeys.generate(), tmp_path, credential_ttl=ttl)


def _node_file(tmp_path, id_pub):
    return tmp_path / "nodes" / f"{id_pub.hex()}.json"


def test_issue_stamps_exp_and_iat(tmp_path):
    ca = _ca(tmp_path)
    k = NodeKeys.generate()
    cred = ca.issue(k.id_pub_bytes, k.wg_pub_bytes, "n1", ["mesh"])
    rec = json.loads(_node_file(tmp_path, k.id_pub_bytes).read_text())
    assert rec["exp"] == cred.exp.replace(microsecond=0).isoformat()
    assert "iat" in rec


def test_drop_stale_forgets_only_long_expired(tmp_path):
    grace = dt.timedelta(days=7)
    # A short TTL so the issued creds are already close to expiry; we drive the
    # decision with an explicit `now` rather than sleeping.
    ca = _ca(tmp_path, ttl=dt.timedelta(hours=1))
    fresh = NodeKeys.generate()
    stale = NodeKeys.generate()
    ca.issue(fresh.id_pub_bytes, fresh.wg_pub_bytes, "fresh", ["mesh"])
    stale_cred = ca.issue(stale.id_pub_bytes, stale.wg_pub_bytes, "stale", ["mesh"])

    # 'now' is well past stale's exp+grace but the fresh node just renewed at
    # `later` (so its registry exp is later); to test selectivity, evaluate at a
    # time past stale's grace but before fresh would be (they share exp, so
    # re-issue fresh to push its exp forward).
    later = stale_cred.exp + grace + dt.timedelta(days=1)
    # Model a live node that kept renewing: rewrite 'fresh's stored exp to
    # `later`, so its exp+grace is well in the future and it's spared.
    p = _node_file(tmp_path, fresh.id_pub_bytes)
    rec = json.loads(p.read_text())
    rec["exp"] = later.replace(microsecond=0).isoformat()
    p.write_text(json.dumps(rec))

    dropped = ca.drop_stale(grace, now=later)
    names = {h for _, h in dropped}
    assert names == {"stale"}                                   # only the abandoned one
    assert not _node_file(tmp_path, stale.id_pub_bytes).exists()  # forgotten
    assert _node_file(tmp_path, fresh.id_pub_bytes).exists()      # kept


def test_dropped_node_cannot_renew(tmp_path):
    """The whole point: once dropped, renew() refuses (unknown node) so the node
    must re-enroll, not merely reconnect."""
    import pytest
    from greasewood.ca import UnknownNodeError
    ca = _ca(tmp_path, ttl=dt.timedelta(hours=1))
    k = NodeKeys.generate()
    cred = ca.issue(k.id_pub_bytes, k.wg_pub_bytes, "gone", ["mesh"])
    later = cred.exp + dt.timedelta(days=8)
    assert ca.drop_stale(dt.timedelta(days=7), now=later)        # dropped
    req = RenewRequest(id_pub=k.id_pub_bytes, wg_pub=k.wg_pub_bytes, nonce="n",
                       ts=dt.datetime.now(_UTC).replace(microsecond=0)).sign(k.id_priv)
    with pytest.raises(UnknownNodeError):
        ca.renew(req)


def test_drop_stale_grandfathers_legacy_records(tmp_path):
    """A pre-drop registry record has no exp field — it must NOT be dropped
    (renewal will stamp one); silently reaping every legacy node would be a
    fleet-wide eviction on upgrade."""
    ca = _ca(tmp_path)
    k = NodeKeys.generate()
    p = _node_file(tmp_path, k.id_pub_bytes)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps({"hostname": "legacy", "caps": ["role:mesh"]}))  # no exp
    dropped = ca.drop_stale(dt.timedelta(days=7),
                            now=dt.datetime.now(_UTC) + dt.timedelta(days=999))
    assert dropped == [] and p.exists()


def test_set_caps_preserves_the_drop_clock(tmp_path):
    """Editing caps is not a renewal — it must not reset exp/iat, or a `gw
    set-caps` on an abandoned node would postpone its drop indefinitely."""
    ca = _ca(tmp_path, ttl=dt.timedelta(hours=1))
    k = NodeKeys.generate()
    cred = ca.issue(k.id_pub_bytes, k.wg_pub_bytes, "n", ["mesh"])
    before = json.loads(_node_file(tmp_path, k.id_pub_bytes).read_text())["exp"]
    ca.set_caps(k.id_pub_bytes, ["mesh", "role:db"])
    after = json.loads(_node_file(tmp_path, k.id_pub_bytes).read_text())
    assert after["exp"] == before                                # exp unchanged
    assert "role:db" in after["caps"]                            # caps updated
