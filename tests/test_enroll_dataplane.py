"""
EnrollServer._handle when the hub's data plane is broken (mesh interface
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

from greasewood.enroll import EnrollServer, _send_msg, _recv_msg
from greasewood.keys import NodeKeys


def _framed(data: dict) -> bytes:
    body = json.dumps(data).encode()
    return struct.pack(">I", len(body)) + body


def test_peer_install_failure_reports_actionable_reason(monkeypatch):
    joiner = NodeKeys.generate()
    hub = NodeKeys.generate()

    def broken_set_peer(iface, pub, addr, endpoint=None, keepalive=25):
        raise subprocess.CalledProcessError(
            1, ["wg", "set", iface, "peer", pub, "allowed-ips", f"{addr}/128"])
    monkeypatch.setattr("greasewood.wg.set_peer", broken_set_peer)

    srv = EnrollServer(
        ca=types.SimpleNamespace(issue=lambda *a, **k: object()),
        directory=types.SimpleNamespace(get=lambda *a: None),
        node_keys=hub, wg_iface="gw-mesh", on_done=lambda: None)

    ours, theirs = socket.socketpair()
    try:
        ours.sendall(_framed({
            "v": 1,
            "id_pub": joiner.id_pub_hex,
            "wg_pub": base64.b64encode(joiner.wg_pub_bytes).decode(),
            "hostname": "nats01",
        }))
        ok = srv._handle(theirs, "fd8d::2", attempts_left=3)
        assert ok is False                       # attempt failed, window stays open
        resp = _recv_msg(ours)
        assert resp["ok"] is False
        assert resp["error"] == "hub data-plane failure"
        assert "mesh interface 'gw-mesh' is missing or broken" in resp["reason"]
        assert "retry this token" in resp["reason"]           # self-heal story
        assert "systemctl restart greasewood" in resp["reason"]
        assert "CalledProcessError" not in resp["reason"]     # no traceback leak
        assert resp["attempts_remaining"] == 2
    finally:
        ours.close()
        theirs.close()
