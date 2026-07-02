"""
Unit tests for reconcile.default_policy — the authorization gate. Peering is
decided purely by **shared segments** (`segment:<name>` tags); every node is in
`segment:mesh` by default, and `segment:*` is the reach-all wildcard (the hub).
These branches aren't all reachable in integration (every node is in a segment),
so they're covered here.
"""
from greasewood.reconcile import default_policy


def test_same_default_segment_allowed():
    # Two default nodes both carry segment:mesh → they peer (the flat default).
    assert default_policy(["segment:mesh"], ["segment:mesh"]) is True


def test_shared_segment_allowed():
    assert default_policy(["segment:prod"], ["segment:prod"]) is True


def test_different_segments_denied():
    assert default_policy(["segment:prod"], ["segment:dev"]) is False


def test_default_and_segmented_denied():
    # Putting a node in segment:prod drops it from mesh, so it's isolated from
    # the default pool.
    assert default_policy(["segment:mesh"], ["segment:prod"]) is False


def test_no_segment_denied():
    # A node in no segment peers with no one.
    assert default_policy([], []) is False
    assert default_policy([], ["segment:mesh"]) is False


def test_wildcard_reaches_every_segment():
    # The hub carries segment:* and must reach every node, in any segment.
    assert default_policy(["segment:*"], ["segment:prod"]) is True
    assert default_policy(["segment:prod"], ["segment:*"]) is True
    assert default_policy(["segment:*"], ["segment:mesh"]) is True


def test_bridge_node_reaches_multiple_segments():
    # A node in several segments peers with anyone sharing one (the bridge case:
    # A=mesh, B=mesh+dev, C=dev → A-B and B-C peer, A-C don't).
    a, b, c = ["segment:mesh"], ["segment:mesh", "segment:dev"], ["segment:dev"]
    assert default_policy(a, b) is True   # share mesh
    assert default_policy(b, c) is True   # share dev
    assert default_policy(a, c) is False  # share nothing


def test_capabilities_do_not_affect_peering():
    # Ability/marker tags (tls, hostname-pinned) are not segments: they neither
    # create nor block a link.
    assert default_policy(["tls"], ["tls"]) is False               # no segment → no link
    assert default_policy(["segment:mesh", "tls", "hostname-pinned"],
                          ["segment:mesh"]) is True                 # shared segment wins
