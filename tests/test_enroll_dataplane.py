"""
EnrollServer._handle when the anchor's data plane is broken (mesh interface
missing): the joiner must get an actionable reason — the self-heal/retry/restart
story — not a raw CalledProcessError command dump ("internal — Command
'['wg', 'set', ...]' returned non-zero exit status 1").
"""
import base64
import json
import socket
import struct
import subprocess
import types

from greasewood.enroll import EnrollServer, EnrollContext, _send_msg, _recv_msg
from greasewood.keys import NodeKeys


def _framed(data: dict) -> bytes:
    body = json.dumps(data).encode()
    return struct.pack(">I", len(body)) + body


class _FakeCA:
    """Records issue/forget calls; `registered` seeds node_info for ids that
    were already enrolled before the attempt."""

    def __init__(self, registered=()):
        self.registered = set(registered)
        self.forgotten = []

    def node_info(self, id_pub):
        return ("known", ["segment:mesh"]) if id_pub in self.registered else None

    def issue(self, id_pub, wg_pub, hostname, caps):
        self.registered.add(id_pub)          # issue() writes the registry entry
        return object()

    def forget_node(self, id_pub):
        self.registered.discard(id_pub)
        self.forgotten.append(id_pub)
        return True


def _attempt(monkeypatch, ca, joiner):
    """One enrollment attempt against a broken data plane; returns the reply."""
    def broken_set_peer(iface, pub, addr, endpoint=None, keepalive=25):
        raise subprocess.CalledProcessError(
            1, ["wg", "set", iface, "peer", pub, "allowed-ips", f"{addr}/128"])
    monkeypatch.setattr("greasewood.wg.set_peer", broken_set_peer)

    ctx = EnrollContext(
        ca=ca, directory=types.SimpleNamespace(get=lambda *a: None),
        node_keys=NodeKeys.generate(), wg_iface="gw-mesh")
    srv = EnrollServer(ctx, lambda: None)
    ours, theirs = socket.socketpair()
    try:
        ours.sendall(_framed({
            "v": 1,
            "id_pub": joiner.id_pub_hex,
            "wg_pub": base64.b64encode(joiner.wg_pub_bytes).decode(),
            "hostname": "nats01",
        }))
        ok = srv._handle(theirs, "fd8d::2", attempts_left=3)
        return ok, _recv_msg(ours)
    finally:
        ours.close()
        theirs.close()


def test_peer_install_failure_reports_actionable_reason(monkeypatch):
    joiner = NodeKeys.generate()
    ok, resp = _attempt(monkeypatch, _FakeCA(), joiner)
    assert ok is False                       # attempt failed, window stays open
    assert resp["ok"] is False
    assert resp["error"] == "anchor data-plane failure"
    assert "mesh interface 'gw-mesh' is missing or broken" in resp["reason"]
    assert "retry this token" in resp["reason"]           # self-heal story
    assert "restart the anchor daemon" in resp["reason"]
    assert "CalledProcessError" not in resp["reason"]     # no traceback leak
    assert resp["attempts_remaining"] == 2


def test_failed_install_rolls_back_fresh_registration(monkeypatch):
    """Field bug: issue() claimed the hostname, then the peer install failed —
    the ghost entry made every retry from a fresh identity fail with
    "hostname 'nats01' is already in use". A registration created BY the failed
    attempt must be rolled back so the name is free again."""
    joiner = NodeKeys.generate()
    ca = _FakeCA()                                       # nats01 not yet enrolled
    _attempt(monkeypatch, ca, joiner)
    assert ca.forgotten == [joiner.id_pub_bytes]         # rolled back
    assert joiner.id_pub_bytes not in ca.registered      # name free for retry


def test_failed_install_keeps_preexisting_registration(monkeypatch):
    """A RE-enroll of an already-known id that fails must NOT delete the live
    node's registration — rollback only covers what this attempt created."""
    joiner = NodeKeys.generate()
    ca = _FakeCA(registered={joiner.id_pub_bytes})       # enrolled before
    _attempt(monkeypatch, ca, joiner)
    assert ca.forgotten == []                            # untouched
    assert joiner.id_pub_bytes in ca.registered


def test_second_leg_bug_is_loud_but_never_fails_enrollment(monkeypatch, caplog):
    """The second leg runs AFTER enrollment succeeded, so a bug in it must not
    propagate (the accept loop would mis-count a completed enrollment as a
    failed attempt). It's swallowed — but LOUDLY (ERROR + traceback), not as a
    soft warning that reads like a peer hiccup. This is the class of bug that a
    broad `except Exception` once hid as 'older node / laggy recv'."""
    import logging
    from greasewood import enroll
    from greasewood.directory import Directory
    ctx = EnrollContext(ca=None, directory=Directory(),
                        node_keys=NodeKeys.generate(), wg_iface="gw-mesh")
    srv = EnrollServer(ctx, lambda: None)
    monkeypatch.setattr(enroll, "_recv_msg", lambda conn: {"record": {}})

    def boom(_d):
        raise NameError("simulated bug in record handling")
    monkeypatch.setattr("greasewood.wire.NodeRecord.from_dict", boom)

    with caplog.at_level(logging.WARNING, logger="greasewood.enroll"):
        srv._receive_first_record(object())          # must NOT raise
    errors = [r for r in caplog.records if r.levelname == "ERROR"]
    assert any("bug" in r.getMessage() for r in errors)      # loud, not a warning
    assert not any(r.levelname == "WARNING" for r in caplog.records)


def test_second_leg_bad_record_is_quiet(monkeypatch, caplog):
    """A malformed/unverifiable record (ValueError/KeyError) is the EXPECTED
    peer-side failure — a quiet warning, not the loud bug path."""
    import logging
    from greasewood import enroll
    from greasewood.directory import Directory
    ctx = EnrollContext(ca=None, directory=Directory(),
                        node_keys=NodeKeys.generate(), wg_iface="gw-mesh")
    srv = EnrollServer(ctx, lambda: None)
    # missing "record" key → KeyError, the expected reject path
    monkeypatch.setattr(enroll, "_recv_msg", lambda conn: {})
    monkeypatch.setattr(enroll, "_send_msg", lambda conn, msg: None)

    with caplog.at_level(logging.WARNING, logger="greasewood.enroll"):
        srv._receive_first_record(object())          # must NOT raise
    assert any(r.levelname == "WARNING" and "rejected" in r.getMessage()
               for r in caplog.records)
    assert not any(r.levelname == "ERROR" for r in caplog.records)
