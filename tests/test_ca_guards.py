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
