"""
Unit tests for hub-side hostname uniqueness (CA.issue).

The hub refuses to enroll a node whose (sanitized) hostname is already used by
a different node, while letting a node re-issue/renew/rename itself.
"""
import datetime as dt

import pytest

from greasewood.keys import CAKeys, NodeKeys
from greasewood.ca import CA
from greasewood.wire import RenewRequest

_UTC = dt.timezone.utc


def _ca(tmp_path):
    return CA(CAKeys.generate(), tmp_path)


def _node():
    k = NodeKeys.generate()
    return k.id_pub_bytes, k.wg_pub_bytes


def test_duplicate_hostname_rejected(tmp_path):
    ca = _ca(tmp_path)
    id1, wg1 = _node()
    id2, wg2 = _node()
    ca.issue(id1, wg1, "db", ["mesh"])
    with pytest.raises(ValueError, match="already in use"):
        ca.issue(id2, wg2, "db", ["mesh"])


def test_sanitized_collision_rejected(tmp_path):
    ca = _ca(tmp_path)
    id1, wg1 = _node()
    id2, wg2 = _node()
    ca.issue(id1, wg1, "db", ["mesh"])
    with pytest.raises(ValueError):
        ca.issue(id2, wg2, "DB", ["mesh"])  # sanitizes to the same name


def test_distinct_names_ok(tmp_path):
    ca = _ca(tmp_path)
    id1, wg1 = _node()
    id2, wg2 = _node()
    ca.issue(id1, wg1, "db", ["mesh"])
    ca.issue(id2, wg2, "api", ["mesh"])  # no raise


def test_same_node_reissue_ok(tmp_path):
    """Re-enrollment / renewal of the same identity keeps its name."""
    ca = _ca(tmp_path)
    id1, wg1 = _node()
    ca.issue(id1, wg1, "db", ["mesh"])
    ca.issue(id1, wg1, "db", ["mesh"])  # no raise (owner == self)


def test_same_node_can_rename_to_free_name(tmp_path):
    ca = _ca(tmp_path)
    id1, wg1 = _node()
    ca.issue(id1, wg1, "db", ["mesh"])
    ca.issue(id1, wg1, "db2", ["mesh"])  # no raise


def test_revoke_frees_hostname_for_reuse(tmp_path):
    """Revoking a node releases its hostname so a different identity can take it."""
    ca = _ca(tmp_path)
    id1, wg1 = _node()
    id2, wg2 = _node()
    ca.issue(id1, wg1, "db", ["mesh"])
    with pytest.raises(ValueError, match="already in use"):
        ca.issue(id2, wg2, "db", ["mesh"])

    freed = ca.add_revoke(id1)
    assert freed is True  # the name was held and is now released

    ca.issue(id2, wg2, "db", ["mesh"])  # no raise — name is free now


def test_forget_node_missing_is_noop(tmp_path):
    ca = _ca(tmp_path)
    idx, _ = _node()
    assert ca.forget_node(idx) is False  # nothing to remove


def test_renew_does_not_self_conflict(tmp_path):
    ca = _ca(tmp_path)
    k = NodeKeys.generate()
    ca.issue(k.id_pub_bytes, k.wg_pub_bytes, "db", ["mesh"])
    req = RenewRequest(
        id_pub=k.id_pub_bytes, wg_pub=k.wg_pub_bytes, nonce="n",
        ts=dt.datetime.now(_UTC).replace(microsecond=0),
    ).sign(k.id_priv)
    ca.renew(req)  # no raise — renewal re-issues for the same id
