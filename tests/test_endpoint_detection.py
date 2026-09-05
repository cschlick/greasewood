"""
Endpoint auto-detection and door dialing versus VPN tunnel addresses.

Field incident: the anchor ran a commercial WireGuard VPN, whose client
address is a "global" /128 (every client of the VPN gets the SAME one). The
detector elected it as the anchor's public IPv6 — it passes the 2000::/3 GUA
test — and every record and invite token then advertised an address that is
(a) NATed from the internet and (b) LOCAL on any other machine running the
same VPN. A returning node on that VPN dialed the door at its own address and
hung forever.

Three defenses, each tested here:
  * detection demotes /128s (across stability classes) and prefers the
    default-route interface, so a real /64 always beats the VPN mirage;
  * the joiner refuses to dial a token host it itself owns;
  * the door dance tries every remaining host gated on the actual WireGuard
    handshake, and a total failure reports each host instead of hanging.
"""
import ipaddress
import subprocess as sp

import pytest

from greasewood import cli


def _fake_run(monkeypatch, table):
    """Route cli's subprocess.run through `table` keyed by argv prefix."""
    def fake(argv, **kw):
        for prefix, (rc, out) in table.items():
            if tuple(argv[:len(prefix)]) == prefix:
                return sp.CompletedProcess(argv, rc, out, "")
        return sp.CompletedProcess(argv, 1, "", "not scripted")
    monkeypatch.setattr(cli.subprocess, "run", fake)


# ---------------------------------------------------------------------------
# _detect_public_ipv6 — the election
# ---------------------------------------------------------------------------

_IP6_VPN_AND_LAN = """\
2: enp1s0    inet6 2601:643:8800:36f0:aaaa::7a/64 scope global dynamic mngtmpaddr noprefixroute
3: proton    inet6 2a07:b944::2:2/128 scope global
"""

_IP6_VPN_AND_TEMPORARY = """\
2: enp1s0    inet6 2601:643:8800:36f0:bbbb::99/64 scope global temporary dynamic
3: proton    inet6 2a07:b944::2:2/128 scope global
"""

_IP6_VPN_ONLY = """\
3: proton    inet6 2a07:b944::2:2/128 scope global
"""


def test_lan_slash64_beats_vpn_slash128(monkeypatch):
    """The bb/router incident: a stable VPN /128 must lose to a real /64 —
    even when the VPN interface carries the default route (full tunnel)."""
    _fake_run(monkeypatch, {
        ("ip", "-6", "-o", "addr"): (0, _IP6_VPN_AND_LAN),
        ("ip", "-6", "route"): (0, "default via fe80::1 dev proton metric 1024\n"),
    })
    assert cli._detect_public_ipv6() == "2601:643:8800:36f0:aaaa::7a"


def test_temporary_slash64_beats_stable_vpn_slash128(monkeypatch):
    """Prefix realness outranks the stability class: a rotating privacy /64
    is reachable while it lives; the VPN /128 never is."""
    _fake_run(monkeypatch, {
        ("ip", "-6", "-o", "addr"): (0, _IP6_VPN_AND_TEMPORARY),
        ("ip", "-6", "route"): (0, "default via fe80::1 dev enp1s0 metric 1024\n"),
    })
    assert cli._detect_public_ipv6() == "2601:643:8800:36f0:bbbb::99"


def test_slash128_is_last_resort_not_excluded(monkeypatch):
    """DHCPv6 IA_NA legitimately assigns /128s — with nothing better, the
    /128 is still advertised (demoted, never dropped)."""
    _fake_run(monkeypatch, {
        ("ip", "-6", "-o", "addr"): (0, _IP6_VPN_ONLY),
        ("ip", "-6", "route"): (1, ""),
    })
    assert cli._detect_public_ipv6() == "2a07:b944::2:2"


def test_default_route_iface_breaks_ties(monkeypatch):
    two_lans = (
        "2: eth0    inet6 2001:db8:1::1/64 scope global\n"
        "3: eth1    inet6 2001:db8:2::1/64 scope global\n"
    )
    _fake_run(monkeypatch, {
        ("ip", "-6", "-o", "addr"): (0, two_lans),
        ("ip", "-6", "route"): (0, "default via fe80::1 dev eth1 metric 1024\n"),
    })
    assert cli._detect_public_ipv6() == "2001:db8:2::1"


# ---------------------------------------------------------------------------
# _order_door_hosts — never dial yourself; family-order, don't drop
# ---------------------------------------------------------------------------

def test_own_address_is_skipped_with_reason(monkeypatch):
    """bb's exact failure: the token carried the anchor's VPN v6, which bb
    ALSO owned — dialing it loops back to bb. It must be skipped, loudly."""
    monkeypatch.setattr(cli, "_local_global_addrs",
                        lambda: {ipaddress.ip_address("2a07:b944::2:2")})
    monkeypatch.setattr(cli, "_local_families", lambda: {4, 6})
    ordered, skipped = cli._order_door_hosts(["2a07:b944::2:2", "76.103.154.103"])
    assert ordered == ["76.103.154.103"]
    assert len(skipped) == 1 and skipped[0][0] == "2a07:b944::2:2"
    assert "own addresses" in skipped[0][1]


def test_missing_family_demotes_but_keeps_host(monkeypatch):
    """Family detection is a heuristic; the handshake is the proof — a host
    from a family we seem to lack is dialed LAST, never dropped."""
    monkeypatch.setattr(cli, "_local_global_addrs", lambda: set())
    monkeypatch.setattr(cli, "_local_families", lambda: {4})
    ordered, skipped = cli._order_door_hosts(["2001:db8::1", "203.0.113.5"])
    assert ordered == ["203.0.113.5", "2001:db8::1"]
    assert skipped == []


def test_dns_names_always_dialable(monkeypatch):
    monkeypatch.setattr(cli, "_local_global_addrs", lambda: set())
    monkeypatch.setattr(cli, "_local_families", lambda: {4, 6})
    ordered, skipped = cli._order_door_hosts(["anchor.example.com"])
    assert ordered == ["anchor.example.com"] and skipped == []


# ---------------------------------------------------------------------------
# _dial_door — handshake-gated fallback, loud total failure
# ---------------------------------------------------------------------------

class _FakeDoorWg:
    """Records door bring-ups; `answering` hosts produce a handshake."""
    def __init__(self, answering=()):
        self.answering = set(answering)
        self.dialed = []
        self.destroyed = []
        self._current = None

    def ensure_node_door_interface(self, priv, pub, psk, host, port):
        self.dialed.append(host)
        self._current = host

    def get_peers(self, iface):
        import types
        if self._current in self.answering:
            return {"pk": types.SimpleNamespace(latest_handshake=1)}
        return {"pk": types.SimpleNamespace(latest_handshake=0)}

    def destroy_interface(self, iface):
        self.destroyed.append(iface)


def test_dial_door_falls_back_to_the_host_that_handshakes(monkeypatch):
    monkeypatch.setattr(cli, "_DOOR_HANDSHAKE_TIMEOUT", 0.05)
    fake = _FakeDoorWg(answering={"192.0.2.9"})
    host = cli._dial_door(fake, ["2001:db8::dead", "192.0.2.9"],
                          b"k" * 32, "PUB=", "PSK=", 51820)
    assert host == "192.0.2.9"
    assert fake.dialed == ["2001:db8::dead", "192.0.2.9"]   # tried in order
    assert fake.destroyed == []                             # door left up


def test_dial_door_total_failure_reports_every_host(monkeypatch):
    monkeypatch.setattr(cli, "_DOOR_HANDSHAKE_TIMEOUT", 0.05)
    fake = _FakeDoorWg(answering=set())
    with pytest.raises(SystemExit) as e:
        cli._dial_door(fake, ["2001:db8::dead", "192.0.2.9"],
                       b"k" * 32, "PUB=", "PSK=", 51820)
    msg = str(e.value)
    assert "2001:db8::dead" in msg and "192.0.2.9" in msg
    assert "no WireGuard handshake" in msg
    assert "hairpin" in msg                    # the v4-from-inside hint fired
    assert fake.destroyed == ["gw-door"]       # torn down on failure
