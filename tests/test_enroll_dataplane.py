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
