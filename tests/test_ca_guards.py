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
    # A node enrolled with `gw invite --hostname` carries `host:pinned`; it may
    # renew, but a rename (renew with a changed hostname) must be refused.
    ca = _ca(tmp_path)
    k = NodeKeys.generate()
    ca.issue(k.id_pub_bytes, k.wg_pub_bytes, "pinned1", ["mesh", "host:pinned"])
    # Plain renewal (no hostname change) still works.
    ca.renew(_req(k))
    # Rename attempt is rejected.
    with pytest.raises(ValueError, match="hub-pinned"):
        ca.renew(_req(k, hostname="newname"))


def test_rename_allowed_when_not_pinned(tmp_path):
    # Without the marker, rename (renew with a new hostname) succeeds.
    ca = _ca(tmp_path)
    k = NodeKeys.generate()
    ca.issue(k.id_pub_bytes, k.wg_pub_bytes, "free1", ["mesh"])
    cred = ca.renew(_req(k, hostname="renamed"))
    assert cred.hostname == "renamed"


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
