"""
Endpoint attestations: reachability as verified fact. Nodes testify about the
endpoints their live tunnels actually ride; holders aggregate (signed,
membership-gated, freshness-bounded); watch compares testimony with the
advertisement and shouts on the mirage signature that produced two field
incidents (the VM ULA, the VPN /128).
"""
import datetime as dt
import json
import types
import urllib.request

import pytest

from greasewood import attest, status
from greasewood.attest import (AttestLog, AttestLoop, attest_path,
                               build_attestations, MAX_AGE)
from greasewood.directory import Directory
from greasewood.keys import CAKeys, NodeKeys, derive_addr
from greasewood.server import ControlServer
from greasewood.wire import Credential, EndpointAttestation, NodeRecord

_UTC = dt.timezone.utc


def _now():
    return dt.datetime.now(_UTC).replace(microsecond=0)


def _rec(ca, k, name, endpoints=()):
    cred = Credential(id_pub=k.id_pub_bytes, wg_pub=k.wg_pub_bytes,
                      addr=derive_addr(k.id_pub_bytes), hostname=name,
                      caps=["role:node"], iat=_now(),
                      exp=_now() + dt.timedelta(hours=24)).sign(ca.ca_priv)
    return NodeRecord(id_pub=k.id_pub_bytes, seq=1, endpoints=list(endpoints),
                      cred=cred).sign(k.id_priv)


def _att(attester, subject, endpoint, ts=None):
    return EndpointAttestation(
        attester=attester.id_pub_bytes, subject=subject.id_pub_bytes,
        endpoint=endpoint, ts=ts or _now()).sign(attester.id_priv)


# ---------------------------------------------------------------------------
# wire + log
# ---------------------------------------------------------------------------

def test_roundtrip_verify_and_tamper():
    a, s = NodeKeys.generate(), NodeKeys.generate()
    att = _att(a, s, "[2001:db8::1]:51900")
    att2 = EndpointAttestation.from_dict(att.to_dict())
    att2.verify_self_sig()
    d = att.to_dict()
    d["endpoint"] = "[2001:db8::bad]:51900"
    with pytest.raises(ValueError, match="invalid endpoint-attestation"):
        EndpointAttestation.from_dict(d).verify_self_sig()


def test_merge_gates_signature_membership_and_freshness():
    a, s, stranger = NodeKeys.generate(), NodeKeys.generate(), NodeKeys.generate()
    log = AttestLog()
    known = {a.id_pub_hex}
    good = _att(a, s, "1.2.3.4:51900")
    outsider = _att(stranger, s, "6.6.6.6:51900")          # never enrolled
    stale = _att(a, s, "1.2.3.4:51900", ts=_now() - MAX_AGE - dt.timedelta(minutes=1))
    forged = EndpointAttestation(attester=a.id_pub_bytes, subject=s.id_pub_bytes,
                                 endpoint="6.6.6.6:1", ts=_now(),
                                 sig=good.sig)             # wrong body for sig
    assert log.merge([good, outsider, stale, forged],
                     lambda h: h in known) == 1
    assert log.confirmations_for(s.id_pub_hex) == {"1.2.3.4:51900": [a.id_pub_hex]}


def test_latest_wins_and_prune():
    a, s = NodeKeys.generate(), NodeKeys.generate()
    log = AttestLog()
    older = _att(a, s, "old:1", ts=_now() - dt.timedelta(minutes=10))
    newer = _att(a, s, "[fd00::1]:51900")
    assert log.merge([older], lambda h: True) == 1
    assert log.merge([newer, older], lambda h: True) == 1   # older ignored
    assert list(log.confirmations_for(s.id_pub_hex)) == ["[fd00::1]:51900"]
    # age everything out
    ancient = _att(a, s, "x:1", ts=_now() - MAX_AGE - dt.timedelta(seconds=61))
    log2 = AttestLog()
    log2._by_pair[(a.id_pub_hex, s.id_pub_hex)] = ancient   # bypass merge gate
    assert log2.prune() == 1
    assert log2.size() == 0


def test_persistence_roundtrip(tmp_path):
    a, s = NodeKeys.generate(), NodeKeys.generate()
    log = AttestLog()
    log.merge([_att(a, s, "1.2.3.4:51900")], lambda h: True)
    log.save(attest_path(tmp_path))
    back = AttestLog.load(attest_path(tmp_path), lambda h: True)
    assert back.confirmations_for(s.id_pub_hex) == {"1.2.3.4:51900": [a.id_pub_hex]}


# ---------------------------------------------------------------------------
# emission: kernel truth only
# ---------------------------------------------------------------------------

def test_build_attestations_from_live_handshakes(monkeypatch):
    ca = CAKeys.generate()
    me, fresh_peer, stale_peer = (NodeKeys.generate(), NodeKeys.generate(),
                                  NodeKeys.generate())
    d = Directory()
    d.put(_rec(ca, me, "me"))
    d.put(_rec(ca, fresh_peer, "fresh"))
    d.put(_rec(ca, stale_peer, "stale"))
    import base64
    now = _now()

    def peers(iface):
        assert iface == "gw-test"
        return {
            base64.b64encode(fresh_peer.wg_pub_bytes).decode():
                types.SimpleNamespace(endpoint="[2001:db8::7]:51900",
                                      latest_handshake=int(now.timestamp()) - 30),
            base64.b64encode(stale_peer.wg_pub_bytes).decode():
                types.SimpleNamespace(endpoint="9.9.9.9:51900",
                                      latest_handshake=int(now.timestamp()) - 900),
            "unknownpub=": types.SimpleNamespace(endpoint="8.8.8.8:1",
                                                 latest_handshake=int(now.timestamp())),
        }
    monkeypatch.setattr("greasewood.wg.get_peers", peers)
    out = build_attestations(me, d, "gw-test", now=now)
    assert len(out) == 1                              # fresh + known only
    a = out[0]
    assert a.subject == fresh_peer.id_pub_bytes
    assert a.endpoint == "[2001:db8::7]:51900"
    a.verify_self_sig()                               # properly signed by me


# ---------------------------------------------------------------------------
# transport: POST /attest → served in /directory → synced
# ---------------------------------------------------------------------------

def test_attest_endpoint_accepts_and_serves(tmp_path):
    from greasewood.ca import CA
    from greasewood.sync import SyncLoop, pull_directory
    ca_keys = CAKeys.generate()
    attester, subject = NodeKeys.generate(), NodeKeys.generate()
    d = Directory()
    d.put(_rec(ca_keys, attester, "a"))
    d.put(_rec(ca_keys, subject, "s"))
    holder_log = AttestLog()
    srv = ControlServer(
        listen="[::1]:0", directory=d,
        get_ca_pubs=lambda: [ca_keys.ca_pub_bytes], get_revoked=set,
        ca=CA(ca_keys, tmp_path, directory=d), data_dir=tmp_path,
        attestations=holder_log,
    )
    srv.start()
    port = srv._server.server_address[1]
    try:
        attest.push_attestations(f"http://[::1]:{port}",
                                 [_att(attester, subject, "1.2.3.4:51900")])
        assert holder_log.size() == 1

        # …and a node's sync picks the testimony up and persists it.
        node_log = AttestLog()
        loop = SyncLoop(Directory.load(tmp_path / "nope.json"),
                        lambda: [f"http://[::1]:{port}"],
                        tmp_path / "directory.json",
                        get_ca_pubs=lambda: [ca_keys.ca_pub_bytes],
                        attestations=node_log)
        # the node needs the attester's record to accept its testimony;
        # the same pull delivers it, merge order records-then-attestations.
        loop._pull_once()
        assert node_log.confirmations_for(subject.id_pub_hex) \
            == {"1.2.3.4:51900": [attester.id_pub_hex]}
        assert attest_path(tmp_path).exists()
    finally:
        srv.stop()


def test_attest_endpoint_refuses_unknown_attester(tmp_path):
    from greasewood.ca import CA
    ca_keys = CAKeys.generate()
    stranger, subject = NodeKeys.generate(), NodeKeys.generate()
    d = Directory()
    d.put(_rec(ca_keys, subject, "s"))                 # attester NOT enrolled
    holder_log = AttestLog()
    srv = ControlServer(
        listen="[::1]:0", directory=d,
        get_ca_pubs=lambda: [ca_keys.ca_pub_bytes], get_revoked=set,
        ca=CA(ca_keys, tmp_path, directory=d), data_dir=tmp_path,
        attestations=holder_log,
    )
    srv.start()
    port = srv._server.server_address[1]
    try:
        attest.push_attestations(f"http://[::1]:{port}",
                                 [_att(stranger, subject, "6.6.6.6:1")])
        assert holder_log.size() == 0
    finally:
        srv.stop()


# ---------------------------------------------------------------------------
# the display: confirmed vs mirage
# ---------------------------------------------------------------------------

def _cfg(tmp_path):
    return types.SimpleNamespace(data_dir=tmp_path)


def test_reach_confirmed_line(tmp_path):
    a, me = NodeKeys.generate(), NodeKeys.generate()
    log = AttestLog()
    log.merge([_att(a, me, "[2001:db8::5]:51900")], lambda h: True)
    log.save(attest_path(tmp_path))
    lines = status._reach_confirmation_lines(_cfg(tmp_path), me.id_pub_hex,
                                             ["[2001:db8::5]:51900"])
    assert len(lines) == 1
    assert "✓" in lines[0] and "1 peer" in lines[0]


def test_reach_mirage_warning(tmp_path):
    """The VPN-/128 signature: peers DO reach this node — just never at the
    address it advertises. That must shout, not sit as silent green."""
    a, b, me = NodeKeys.generate(), NodeKeys.generate(), NodeKeys.generate()
    log = AttestLog()
    log.merge([_att(a, me, "[fe80-real::1]:51900"),
               _att(b, me, "[fe80-real::1]:51900")], lambda h: True)
    log.save(attest_path(tmp_path))
    lines = status._reach_confirmation_lines(_cfg(tmp_path), me.id_pub_hex,
                                             ["[2a07:b944::2:2]:51900"])
    assert len(lines) == 1
    assert "⚠" in lines[0] and "mirage" in lines[0]
    assert "[fe80-real::1]:51900" in lines[0]          # where they DO reach it


def test_reach_silent_without_testimony(tmp_path):
    me = NodeKeys.generate()
    assert status._reach_confirmation_lines(_cfg(tmp_path), me.id_pub_hex,
                                            ["1.2.3.4:51900"]) == []
