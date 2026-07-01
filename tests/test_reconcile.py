"""
Unit tests for reconcile.default_policy — the authorization gate. The deny
branch (a peer lacking the `mesh` cap) is never hit in integration because every
test node carries `mesh`, so it's covered here.
"""
from greasewood.reconcile import default_policy


def test_mesh_to_mesh_allowed():
    assert default_policy(["mesh"], ["mesh"]) is True


def test_extra_caps_still_allowed_if_both_have_mesh():
    assert default_policy(["mesh", "tls"], ["mesh"]) is True


def test_peer_without_mesh_denied():
    assert default_policy(["mesh"], ["tls"]) is False


def test_local_without_mesh_denied():
    assert default_policy(["tls"], ["mesh"]) is False


def test_empty_caps_denied():
    assert default_policy([], []) is False
