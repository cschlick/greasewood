"""
Unit tests for the address-family-agnostic underlay: endpoint formatting,
family detection, per-peer endpoint selection, --endpoint normalization, and the
multi-host (v4+v6) token round-trip. The OVERLAY stays IPv6; these cover only the
underlay transport.
"""
from greasewood.wg import format_endpoint, endpoint_family
from greasewood.reconcile import _select_endpoint
from greasewood.cli import _endpoint_with_port
from greasewood.door import encode_token, decode_token, generate_seed


def test_format_endpoint_brackets_v6_not_v4():
    assert format_endpoint("1.2.3.4", 51900) == "1.2.3.4:51900"
    assert format_endpoint("fd8d:e5c1:db1a:7::1", 51900) == "[fd8d:e5c1:db1a:7::1]:51900"


def test_endpoint_family():
    assert endpoint_family("1.2.3.4:51900") == 4
    assert endpoint_family("[fd8d::1]:51900") == 6


def test_select_endpoint_prefers_v6_when_available():
    eps = ["[fd8d::1]:51900", "1.2.3.4:51900"]   # advertised v6-first
    assert _select_endpoint(eps, {4, 6}) == "[fd8d::1]:51900"


def test_select_endpoint_v4_only_node_picks_v4():
    eps = ["[fd8d::1]:51900", "1.2.3.4:51900"]
    assert _select_endpoint(eps, {4}) == "1.2.3.4:51900"


def test_select_endpoint_family_mismatch_is_none():
    # v4-only node, peer only reachable on v6 → no reachable endpoint (the link
    # won't form; direct-or-fail across families).
    assert _select_endpoint(["[fd8d::1]:51900"], {4}) is None


def test_select_endpoint_no_families_falls_back_to_first():
    assert _select_endpoint(["1.2.3.4:51900", "[fd8d::1]:51900"], None) == "1.2.3.4:51900"


def test_select_endpoint_empty():
    assert _select_endpoint([], {4, 6}) is None


def test_endpoint_with_port_normalization():
    assert _endpoint_with_port("1.2.3.4", 51900) == "1.2.3.4:51900"       # bare v4
    assert _endpoint_with_port("fd8d::1", 51900) == "[fd8d::1]:51900"     # bare v6
    assert _endpoint_with_port("[fd8d::1]", 51900) == "[fd8d::1]:51900"   # bracketed v6
    assert _endpoint_with_port("1.2.3.4:51900", 51900) == "1.2.3.4:51900"  # full v4
    assert _endpoint_with_port("[fd8d::1]:51900", 51900) == "[fd8d::1]:51900"  # full v6


def test_token_carries_multiple_anchor_hosts():
    # The token's single host field carries comma-separated anchor underlay hosts
    # (v6 + v4); a v6 literal has colons but never commas, so it round-trips.
    seed = generate_seed()
    anchor_door_pub = b"\x01" * 32
    ca_pub = b"\x02" * 32
    hosts = "fd8d:e5c1:db1a:7::1,203.0.113.5"
    tok = encode_token(anchor_door_pub, ca_pub, hosts, seed, 51901)
    dpub, cpub, host, dseed, dport, _dom = decode_token(tok)
    assert host.split(",") == ["fd8d:e5c1:db1a:7::1", "203.0.113.5"]
    assert dport == 51901 and dseed == seed and dpub == anchor_door_pub
