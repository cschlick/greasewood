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


# --- segmentation groups (group:<name> cap tags) ---

def test_same_group_allowed():
    assert default_policy(["mesh", "group:prod"], ["mesh", "group:prod"]) is True


def test_different_groups_denied():
    assert default_policy(["mesh", "group:prod"], ["mesh", "group:dev"]) is False


def test_grouped_and_ungrouped_denied():
    # Assigning a group isolates a node from the ungrouped default pool.
    assert default_policy(["mesh", "group:prod"], ["mesh"]) is False


def test_both_ungrouped_allowed():
    # The default pool (and the backward-compatible no-groups fleet).
    assert default_policy(["mesh"], ["mesh"]) is True


def test_wildcard_reaches_grouped():
    # The hub (group:*) must reach every segment.
    assert default_policy(["mesh", "group:*"], ["mesh", "group:prod"]) is True


def test_wildcard_reaches_ungrouped():
    assert default_policy(["mesh", "group:*"], ["mesh"]) is True


def test_overlapping_membership_allowed():
    # A node in multiple groups peers with any node sharing one of them.
    assert default_policy(["mesh", "group:prod", "group:web"],
                          ["mesh", "group:web"]) is True


def test_group_without_mesh_still_denied():
    # The mesh cap is the baseline; groups don't bypass it.
    assert default_policy(["group:prod"], ["mesh", "group:prod"]) is False
