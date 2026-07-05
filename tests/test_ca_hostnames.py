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


def _renew_req(k, hostname=""):
    return RenewRequest(
        id_pub=k.id_pub_bytes, wg_pub=k.wg_pub_bytes, nonce="n",
        ts=dt.datetime.now(_UTC).replace(microsecond=0), hostname=hostname,
    ).sign(k.id_priv)


def test_renew_with_hostname_renames_and_frees_old(tmp_path):
    """`gw rename-node` path: renew carrying a new hostname re-issues under it and
    releases the old name for another node."""
    ca = _ca(tmp_path)
    k = NodeKeys.generate()
    ca.issue(k.id_pub_bytes, k.wg_pub_bytes, "old", ["mesh"])

    ca.renew(_renew_req(k, hostname="new"))  # rename old -> new
    assert ca.node_info(k.id_pub_bytes)[0] == "new"

    # The old name is now free for a different node.
    id2, wg2 = _node()
    ca.issue(id2, wg2, "old", ["mesh"])  # no raise


def test_renew_rename_to_taken_name_refused(tmp_path):
    ca = _ca(tmp_path)
    k1 = NodeKeys.generate()
    id2, wg2 = _node()
    ca.issue(k1.id_pub_bytes, k1.wg_pub_bytes, "alpha", ["mesh"])
    ca.issue(id2, wg2, "beta", ["mesh"])
    with pytest.raises(ValueError, match="already in use"):
        ca.renew(_renew_req(k1, hostname="beta"))  # collides with node 2


def test_plain_renew_wire_form_unchanged(tmp_path):
    """A hostname-less renewal must serialize exactly as before (no 'hostname'
    key), so it stays wire-compatible."""
    k = NodeKeys.generate()
    req = _renew_req(k)  # no hostname
    assert "hostname" not in req.to_dict()
    req.verify_self_sig()  # round-trips + verifies


def test_renew_does_not_self_conflict(tmp_path):
    ca = _ca(tmp_path)
    k = NodeKeys.generate()
    ca.issue(k.id_pub_bytes, k.wg_pub_bytes, "db", ["mesh"])
    req = RenewRequest(
        id_pub=k.id_pub_bytes, wg_pub=k.wg_pub_bytes, nonce="n",
        ts=dt.datetime.now(_UTC).replace(microsecond=0),
    ).sign(k.id_priv)
    ca.renew(req)  # no raise — renewal re-issues for the same id

@pytest.mark.skipif(__import__("os").geteuid() == 0, reason="root ignores file perms")
def test_hostname_owner_unreadable_registry_raises_not_lies(tmp_path):
    """An unreadable registry must surface PermissionError (the CLI turns it
    into 'try sudo'), NOT read as 'no node named X' — swallowing it made a
    non-root `gw set-segments <name>` deny an existing node's existence."""
    import os
    ca = _ca(tmp_path)
    id1, wg1 = _node()
    ca.issue(id1, wg1, "chat01", ["mesh"])
    assert ca.hostname_owner("chat01") == id1.hex()

    node_file = next((tmp_path / "nodes").glob("*.json"))
    os.chmod(node_file, 0o000)                 # registry entry unreadable
    try:
        with pytest.raises(PermissionError):
            ca.hostname_owner("chat01")
    finally:
        os.chmod(node_file, 0o600)

    os.chmod(tmp_path / "nodes", 0o000)        # whole registry dir unreadable
    try:
        with pytest.raises(PermissionError):
            ca.hostname_owner("chat01")
    finally:
        os.chmod(tmp_path / "nodes", 0o700)


def test_hostname_owner_missing_dir_is_empty_not_error(tmp_path):
    """No nodes/ dir at all = genuinely empty registry → None, no error."""
    ca = _ca(tmp_path)                          # nothing issued, no nodes/
    assert ca.hostname_owner("anything") is None
