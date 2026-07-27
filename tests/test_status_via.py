"""
The `via` column: how a peer's traffic actually travels.

`ip6`/`ip4` for a live direct tunnel, `ip6R`/`ip4R` when it rides the anchor.
Relay is decrypt-and-forward, so "the anchor can read this link" is a fact the
operator should see in the roster rather than having to reconstruct from
`wg show` — which is exactly the archaeology this column exists to end.
"""
from types import SimpleNamespace

from greasewood.status import _via


def _peer(endpoint="", allowed=(), hs=1_000_000):
    return SimpleNamespace(endpoint=endpoint, allowed_addrs=frozenset(allowed),
                           latest_handshake=hs, rx_bytes=0, tx_bytes=0,
                           keepalive=25)


NOW = 1_000_050          # 50s after the handshakes above → fresh


def test_direct_v6_link():
    peers = {"P": _peer("[2001:db8::9]:51900", {"fd8d::2"})}
    assert _via("fd8d::2", "P", peers, NOW) == ("ip6", None)


def test_direct_v4_link():
    peers = {"P": _peer("5.6.7.8:51900", {"fd8d::2"})}
    assert _via("fd8d::2", "P", peers, NOW) == ("ip4", None)


def test_a_dead_link_names_no_family():
    # A configured-but-never-handshaked endpoint is not a path. Naming its
    # family would imply traffic flows where none does.
    peers = {"P": _peer("[2001:db8::9]:51900", {"fd8d::2"}, hs=0)}
    assert _via("fd8d::2", "P", peers, NOW) == ("", None)


def test_a_stale_link_names_no_family():
    peers = {"P": _peer("[2001:db8::9]:51900", {"fd8d::2"}, hs=1)}
    assert _via("fd8d::2", "P", peers, NOW) == ("", None)


def test_relayed_peer_is_marked_R_with_the_carrier_family():
    # The fold: the peer has no entry of its own; its /128 rides the anchor's
    # AllowedIPs. The family shown is the leg WE actually use — to the anchor.
    anchor = _peer("[2001:db8::1]:51900", {"fd8d::a", "fd8d::2"})
    peers = {"ANCHOR": anchor}
    via, carrier = _via("fd8d::2", "P", peers, NOW)
    assert via == "ip6R"
    assert carrier is anchor          # its liveness IS this link's liveness


def test_relay_over_v4_carrier():
    peers = {"ANCHOR": _peer("1.2.3.4:51900", {"fd8d::a", "fd8d::2"})}
    assert _via("fd8d::2", "P", peers, NOW)[0] == "ip4R"


def test_a_peers_own_entry_is_not_a_relay_carrier():
    # Its own AllowedIPs obviously contain its own addr — that must not be
    # mistaken for someone else relaying it.
    peers = {"P": _peer("", {"fd8d::2"}, hs=0)}
    assert _via("fd8d::2", "P", peers, NOW) == ("", None)


def test_no_path_at_all():
    assert _via("fd8d::2", "P", {}, NOW) == ("", None)


def test_a_partial_peer_object_degrades_to_blank():
    # A display field must never take the roster down (an older wg parse, a stub).
    peers = {"P": SimpleNamespace()}
    assert _via("fd8d::2", "P", peers, NOW) == ("", None)
