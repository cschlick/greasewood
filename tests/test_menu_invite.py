"""
Menu invites (`gw invite --self-roles`): the joiner self-SELECTS a role, but only
from the anchor's menu, and the anchor still CA-signs. The enroll server
intersects the joiner's request with the window's menu — bounded self-selection,
never self-assertion. These pin the security boundary at the enroll layer.
"""
import base64
import json
import socket
import struct
import subprocess
import types

from greasewood.enroll import EnrollServer, EnrollContext, _recv_msg
from greasewood.keys import NodeKeys
from greasewood import door


class _CapturingCA:
    """Records the caps issue() was asked to sign, so we can assert what the menu
    logic decided. node_info→None (never pre-registered)."""

    def __init__(self):
        self.issued_caps = None
        self.registered = set()
        self.forgotten = []

    def node_info(self, id_pub):
        return None

    def issue(self, id_pub, wg_pub, hostname, caps):
        self.issued_caps = list(caps)
        self.registered.add(id_pub)
        return object()

    def forget_node(self, id_pub):
        self.forgotten.append(id_pub)
        return True


def _enroll(monkeypatch, *, base_caps, menu, requested):
    """One enroll attempt. The peer install fails right AFTER issue() (broken
    set_peer) — so we capture the caps issue() saw without needing a live data
    plane. The out-of-menu REFUSAL returns before issue(), so issued_caps stays
    None there. Returns (ca, reply)."""
    monkeypatch.setattr(
        "greasewood.wg.set_peer",
        lambda *a, **k: (_ for _ in ()).throw(subprocess.CalledProcessError(1, ["wg"])))
    ca = _CapturingCA()
    ctx = EnrollContext(ca=ca, directory=types.SimpleNamespace(get=lambda *a: None),
                        node_keys=NodeKeys.generate(), wg_iface="gw-mesh")
    srv = EnrollServer(ctx, lambda: None, caps=base_caps, allowed_roles=menu)
    joiner = NodeKeys.generate()
    ours, theirs = socket.socketpair()
    try:
        body = json.dumps({"v": 1, "id_pub": joiner.id_pub_hex,
                           "wg_pub": base64.b64encode(joiner.wg_pub_bytes).decode(),
                           "hostname": "n1", "roles": requested}).encode()
        ours.sendall(struct.pack(">I", len(body)) + body)
        srv._handle(theirs, "fd8d::2", attempts_left=3)
        return ca, _recv_msg(ours)
    finally:
        ours.close()
        theirs.close()


def test_selected_role_within_menu_is_granted(monkeypatch):
    ca, _ = _enroll(monkeypatch, base_caps=["tls"], menu=["web", "db", "cache"],
                    requested=["db"])
    assert ca.issued_caps == ["tls", "role:db"]          # base + self-selected


def test_multiple_selected_roles_within_menu(monkeypatch):
    ca, _ = _enroll(monkeypatch, base_caps=["tls"], menu=["web", "db", "cache"],
                    requested=["web", "cache"])
    assert ca.issued_caps == ["tls", "role:web", "role:cache"]


def test_role_outside_menu_is_refused_and_never_issued(monkeypatch):
    ca, resp = _enroll(monkeypatch, base_caps=["tls"], menu=["web", "db"],
                       requested=["admin"])
    assert ca.issued_caps is None                        # the crux: never signed
    assert resp["ok"] is False and resp["error"] == "role not offered"
    assert "admin" in resp["reason"] and "web, db" in resp["reason"]   # names the menu


def test_partial_out_of_menu_refuses_the_whole_request(monkeypatch):
    # one good, one bad → refuse (no cherry-picking that silently drops the bad one)
    ca, resp = _enroll(monkeypatch, base_caps=["tls"], menu=["web", "db"],
                       requested=["web", "admin"])
    assert ca.issued_caps is None and resp["error"] == "role not offered"


def test_classic_invite_ignores_requested_roles(monkeypatch):
    # No menu → the request's roles are ignored entirely; the window is authoritative.
    ca, _ = _enroll(monkeypatch, base_caps=["role:mesh", "tls"], menu=[],
                    requested=["admin", "db"])
    assert ca.issued_caps == ["role:mesh", "tls"]        # request ignored


def test_no_selection_on_menu_invite_gets_base_only(monkeypatch):
    ca, _ = _enroll(monkeypatch, base_caps=["tls"], menu=["web", "db"], requested=[])
    assert ca.issued_caps == ["tls"]                     # opt-in: no role unless asked


def test_token_carries_and_roundtrips_the_menu():
    tok = door.encode_token(b"\x01" * 32, b"\x02" * 32, "fd::1", b"\x03" * 32,
                            mesh_domain="pm.internal", self_roles=["web", "db", "cache"])
    assert door.decode_token(tok).self_roles == ["web", "db", "cache"]
    # a classic token (no menu) decodes to []
    plain = door.encode_token(b"\x01" * 32, b"\x02" * 32, "fd::1", b"\x03" * 32,
                              mesh_domain="pm.internal")
    assert door.decode_token(plain).self_roles == []
