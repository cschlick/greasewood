"""
Unit tests for CA.issue / CA.renew rejection guards.

These are the security-critical refusals — a revoked identity must not get a
fresh credential, a stale request must be rejected, and an unknown node can't
renew. The happy paths are covered elsewhere (test_ca_hostnames, integration);
this locks down the deny branches.
"""
import datetime as dt

import pytest

from greasewood.ca import CA
from greasewood.keys import CAKeys, NodeKeys
from greasewood.wire import RenewRequest

_UTC = dt.timezone.utc


def _ca(tmp_path):
    return CA(CAKeys.generate(), tmp_path)


def _req(k, ts=None, hostname=""):
    return RenewRequest(
        id_pub=k.id_pub_bytes,
        wg_pub=k.wg_pub_bytes,
        nonce="n",
        ts=ts or dt.datetime.now(_UTC).replace(microsecond=0),
        hostname=hostname,
    ).sign(k.id_priv)


def test_issue_to_revoked_id_rejected(tmp_path):
    ca = _ca(tmp_path)
    k = NodeKeys.generate()
    ca.issue(k.id_pub_bytes, k.wg_pub_bytes, "n1", ["mesh"])
    ca.add_revoke(k.id_pub_bytes)
    with pytest.raises(ValueError, match="revoke list"):
        ca.issue(k.id_pub_bytes, k.wg_pub_bytes, "n1", ["mesh"])


def test_renew_rejects_large_skew(tmp_path):
    ca = _ca(tmp_path)
    k = NodeKeys.generate()
    ca.issue(k.id_pub_bytes, k.wg_pub_bytes, "n1", ["mesh"])
    old = dt.datetime.now(_UTC).replace(microsecond=0) - dt.timedelta(seconds=600)
    with pytest.raises(ValueError, match="skew"):
        ca.renew(_req(k, ts=old))


def test_renew_rejects_revoked(tmp_path):
    ca = _ca(tmp_path)
    k = NodeKeys.generate()
    ca.issue(k.id_pub_bytes, k.wg_pub_bytes, "n1", ["mesh"])
    ca.add_revoke(k.id_pub_bytes)
    with pytest.raises(ValueError, match="revoke list"):
        ca.renew(_req(k))


def test_renew_unknown_node_rejected(tmp_path):
    ca = _ca(tmp_path)
    k = NodeKeys.generate()  # never issued a credential
    with pytest.raises(ValueError, match="unknown node"):
        ca.renew(_req(k))


def test_rename_refused_when_hostname_pinned(tmp_path):
    # A node enrolled with `gw invite --hostname` carries `hostname-pinned`; it may
    # renew, but a rename (renew with a changed hostname) must be refused.
    ca = _ca(tmp_path)
    k = NodeKeys.generate()
    ca.issue(k.id_pub_bytes, k.wg_pub_bytes, "pinned1", ["segment:mesh", "hostname-pinned"])
    # Plain renewal (no hostname change) still works.
    ca.renew(_req(k))
    # Rename attempt is rejected.
    with pytest.raises(ValueError, match="anchor-pinned"):
        ca.renew(_req(k, hostname="newname"))


def test_rename_allowed_when_not_pinned(tmp_path):
    # Without the marker, rename (renew with a new hostname) succeeds.
    ca = _ca(tmp_path)
    k = NodeKeys.generate()
    ca.issue(k.id_pub_bytes, k.wg_pub_bytes, "free1", ["mesh"])
    cred = ca.renew(_req(k, hostname="renamed"))
    assert cred.hostname == "renamed"


def test_set_caps_takes_effect_at_renewal(tmp_path):
    # `gw set-caps`/`set-segments` rewrite the registry; the change lands at the
    # node's next renewal (renew re-issues from the registry), no re-join.
    ca = _ca(tmp_path)
    k = NodeKeys.generate()
    ca.issue(k.id_pub_bytes, k.wg_pub_bytes, "n1", ["segment:mesh"])
    ca.set_caps(k.id_pub_bytes, ["segment:prod", "tls"])
    cred = ca.renew(_req(k))          # no hostname change → plain renewal
    assert set(cred.caps) == {"segment:prod", "tls"}
    assert cred.hostname == "n1"      # name preserved
    # Unknown node → error.
    other = NodeKeys.generate()
    with pytest.raises(ValueError, match="unknown node"):
        ca.set_caps(other.id_pub_bytes, ["segment:mesh"])


def test_hostname_owner_and_collision(tmp_path):
    # hostname_owner backs `gw invite --hostname`'s pre-check; issue() enforces
    # the same uniqueness at enrollment.
    ca = _ca(tmp_path)
    a = NodeKeys.generate()
    b = NodeKeys.generate()
    ca.issue(a.id_pub_bytes, a.wg_pub_bytes, "web1", ["mesh"])
    assert ca.hostname_owner("web1") == a.id_pub_bytes.hex()
    assert ca.hostname_owner("WEB1") == a.id_pub_bytes.hex()  # sanitized match
    assert ca.hostname_owner("free") is None
    # A different node can't take the name; the same node re-issuing it is fine.
    with pytest.raises(ValueError, match="already in use"):
        ca.issue(b.id_pub_bytes, b.wg_pub_bytes, "web1", ["mesh"])
    ca.issue(a.id_pub_bytes, a.wg_pub_bytes, "web1", ["mesh"])


def test_unknown_node_is_typed_not_prose():
    """Regression: the control plane's re-root fallback fired on the exception
    MESSAGE text ('unknown node' in str(e)); it now keys on UnknownNodeError,
    so rewording a message can't silently disable a security-relevant path."""
    from greasewood.ca import CA, UnknownNodeError
    import inspect
    from greasewood import server
    assert issubclass(UnknownNodeError, ValueError)   # old catches still work
    src = inspect.getsource(server._Handler._reroot_reissue)
    assert "isinstance(orig_err, UnknownNodeError)" in src
    assert '"unknown node" not in' not in src         # the prose gate is gone


# --- stale-key guard (key_file) -------------------------------------------
# A long-running daemon arms the guard by passing key_file; if ca.key changes
# on disk underneath it (gw create --force while the daemon is up), issue()
# must refuse with an actionable error instead of signing with the stale
# in-memory key — the failure otherwise surfaces on the JOINING machine as an
# unexplained "no trusted CA signature found".

def test_issue_refused_when_key_file_changes(tmp_path):
    keys = CAKeys.generate()
    kf = tmp_path / "ca.key"
    keys.save(kf)
    ca = CA(keys, tmp_path, key_file=kf)
    k = NodeKeys.generate()
    ca.issue(k.id_pub_bytes, k.wg_pub_bytes, "n1", ["mesh"])   # snapshot matches
    CAKeys.generate().save(kf)                                 # re-create underneath
    k2 = NodeKeys.generate()
    with pytest.raises(ValueError, match="changed on disk"):
        ca.issue(k2.id_pub_bytes, k2.wg_pub_bytes, "n2", ["mesh"])


def test_renew_refused_when_key_file_changes(tmp_path):
    keys = CAKeys.generate()
    kf = tmp_path / "ca.key"
    keys.save(kf)
    ca = CA(keys, tmp_path, key_file=kf)
    k = NodeKeys.generate()
    ca.issue(k.id_pub_bytes, k.wg_pub_bytes, "n1", ["mesh"])
    CAKeys.generate().save(kf)
    with pytest.raises(ValueError, match="changed on disk"):
        ca.renew(_req(k))


def test_issue_refused_when_key_file_unreadable(tmp_path):
    keys = CAKeys.generate()
    kf = tmp_path / "ca.key"
    keys.save(kf)
    ca = CA(keys, tmp_path, key_file=kf)
    kf.unlink()
    k = NodeKeys.generate()
    with pytest.raises(ValueError, match="unreadable"):
        ca.issue(k.id_pub_bytes, k.wg_pub_bytes, "n1", ["mesh"])


def test_guard_dormant_without_key_file(tmp_path):
    # One-shot CLI constructions pass no key_file — no guard, no disk reads.
    ca = _ca(tmp_path)
    k = NodeKeys.generate()
    ca.issue(k.id_pub_bytes, k.wg_pub_bytes, "n1", ["mesh"])   # must not raise
