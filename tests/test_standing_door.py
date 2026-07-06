"""
The STANDING door: a persistent enrollment window for baked images/autoscaling.
One token, any number of one-at-a-time enrollments, closed only deliberately.

Covers: window read semantics, the DoorWatcher's standing branch (no expiry,
reboot re-erection from persisted keys, on_done keeps the window), the
EnrollServer's stay-open loop, `gw close-door` revocation, and the invite
guard that refuses to silently supersede a standing door.
"""
import json
import types

import pytest

from greasewood import cli, door, enroll, status
from greasewood.directory import Directory
from greasewood.keys import CAKeys, NodeKeys

pytestmark = []


def _standing_window(data_dir, caps=None):
    door.window_path(data_dir).write_text(json.dumps({
        "v": 1, "standing": True, "caps": caps or ["segment:autoscale"],
        "hostname": None, "guest_pub": "R3Vlc3RQdWJHdWVzdFB1Ykd1ZXN0UHViR3U=",
        "psk": "UHNrUHNrUHNrUHNrUHNrUHNrUHNrUHNrUHM=",
    }))


def test_read_window_standing_never_expires(tmp_path):
    _standing_window(tmp_path)
    w = door.read_window(tmp_path)
    assert w is not None and w["standing"] is True
    # A normal expired window reads as None.
    door.window_path(tmp_path).write_text(json.dumps(
        {"v": 1, "expires": "2020-01-01T00:00:00Z", "caps": []}))
    assert door.read_window(tmp_path) is None


def test_mark_opened_standing_and_enroll_count(tmp_path):
    door.mark_door_opened(tmp_path, None, caps=["segment:autoscale"], standing=True)
    door.mark_door_enrolled(tmp_path, "fd8d::2", "node-a")
    door.mark_door_enrolled(tmp_path, "fd8d::2", "node-b")
    st = door.read_door_status(tmp_path)
    assert st["standing"] is True and st["expires"] is None
    assert st["enroll_count"] == 2
    assert st["enrolled"]["hostname"] == "node-b"


def _watcher(tmp_path, **kw):
    return enroll.DoorWatcher(
        data_dir=tmp_path, ca=None, directory=Directory(),
        node_keys=NodeKeys.generate(), wg_iface="gw-mesh",
        door_port=51901, **kw)


def test_watcher_standing_starts_server_and_reerects_door(tmp_path, monkeypatch):
    """A standing window with the door interface missing (anchor rebooted) must
    re-erect gw-door from the persisted guest key + PSK, then serve."""
    _standing_window(tmp_path)
    calls = {}
    monkeypatch.setattr("greasewood.wg.interface_exists", lambda i: False)
    monkeypatch.setattr("greasewood.wg.ensure_anchor_door_interface",
                        lambda key, pub, psk, port: calls.update(
                            {"pub": pub, "port": port}))

    started = {}

    class FakeSrv:
        def __init__(self, **kwargs):
            started.update(kwargs)
        def start(self):
            started["started"] = True
    monkeypatch.setattr(enroll, "EnrollServer", FakeSrv)

    w = _watcher(tmp_path)
    w._tick()
    assert calls["pub"] == "R3Vlc3RQdWJHdWVzdFB1Ykd1ZXN0UHViR3U="
    assert calls["port"] == 51901
    assert started["started"] and started["standing"] is True
    assert started["timeout_secs"] is None            # no deadline
    st = door.read_door_status(tmp_path)
    assert st["standing"] is True and st["state"] == "open"


def test_watcher_standing_on_done_keeps_window(tmp_path, monkeypatch):
    """The standing window survives its enroll server exiting (daemon shutdown)
    — it's what re-opens the door on the next boot."""
    _standing_window(tmp_path)
    monkeypatch.setattr("greasewood.wg.interface_exists", lambda i: True)
    captured = {}

    class FakeSrv:
        def __init__(self, **kwargs):
            captured.update(kwargs)
        def start(self):
            pass
    monkeypatch.setattr(enroll, "EnrollServer", FakeSrv)
    w = _watcher(tmp_path)
    w._tick()
    captured["on_done"]()                              # server exits
    assert door.window_path(tmp_path).exists()         # window intact
    assert w._enroll is None                           # slot free for next tick


def test_enroll_server_standing_stays_open_after_success(tmp_path, monkeypatch):
    """_serve with standing=True loops after a successful enrollment instead of
    closing the window."""
    import socket
    import threading
    import time

    handled = []

    srv = enroll.EnrollServer(
        ca=None, directory=Directory(), node_keys=NodeKeys.generate(),
        wg_iface="gw-mesh", on_done=lambda: handled.append("done"),
        standing=True, data_dir=tmp_path)

    # Bind on loopback instead of ANCHOR_DOOR_IP so the test needs no interface.
    real_socket = socket.socket

    def fake_handle(conn, peer_ip, attempts_left):
        handled.append(peer_ip)
        return True                                    # a SUCCESS
    srv._handle = fake_handle
    monkeypatch.setattr(enroll, "ANCHOR_DOOR_IP", "::1")

    t = threading.Thread(target=srv._serve, daemon=True)
    t.start()
    time.sleep(0.3)
    for _ in range(2):                                 # two successive joins
        c = real_socket(socket.AF_INET6, socket.SOCK_STREAM)
        c.connect(("::1", enroll.ENROLL_PORT))
        time.sleep(0.3)
        c.close()
    assert handled.count("::1") == 2                   # served BOTH successes
    assert "done" not in handled                       # ...without closing
    srv.stop()
    t.join(timeout=3)
    assert handled[-1] == "done"                       # closes only on stop()


def test_close_door_invalidates_and_reports(tmp_path, monkeypatch, capsys):
    _standing_window(tmp_path)
    (tmp_path / "gw.toml").write_text(f"""[node]
hostname = "anchor"
data_dir = "{tmp_path}"
role = "anchor"
[network]
seeds = []
[ca]
trusted_pubs = []
""")
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)
    monkeypatch.setattr("greasewood.wg.destroy_interface", lambda i: None)
    rc = cli.cmd_close_door(types.SimpleNamespace(config=str(tmp_path / "gw.toml")))
    assert rc == 0
    out = capsys.readouterr().out
    assert "standing door closed" in out and "permanently invalid" in out
    assert "Enrolled nodes are unaffected" in out
    assert not door.window_path(tmp_path).exists()
    assert door.read_door_status(tmp_path)["close_reason"] == \
        "closed by operator (close-door)"


def test_invite_refuses_to_silently_supersede_standing(tmp_path, monkeypatch):
    """A plain invite over an open standing door must hard-fail: it would
    invalidate the token baked into a whole image pipeline as a side effect."""
    _standing_window(tmp_path)
    (tmp_path / "ca.key").write_text("placeholder")
    (tmp_path / "gw.toml").write_text(f"""[node]
hostname = "anchor"
data_dir = "{tmp_path}"
role = "anchor"
[network]
interface = "gw-mesh"
seeds = []
[anchor]
ca_key_file = "{tmp_path}/ca.key"
[ca]
trusted_pubs = []
""")
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)
    monkeypatch.setattr("greasewood.wg.interface_exists", lambda i: True)
    import urllib.request
    monkeypatch.setattr(urllib.request, "urlopen", lambda *a, **k: None)

    ns = types.SimpleNamespace(config=str(tmp_path / "gw.toml"), quiet=True,
                               endpoint="fd00::1", segments=None, caps=None,
                               hostname=None, standing=False, supersede=False)
    with pytest.raises(SystemExit) as e:
        cli.cmd_invite(ns)
    assert "STANDING door is open" in str(e.value)
    assert "gw close-door" in str(e.value)
    assert door.window_path(tmp_path).exists()         # untouched


def test_invite_standing_rejects_pinned_hostname(tmp_path, monkeypatch):
    (tmp_path / "ca.key").write_text("placeholder")
    (tmp_path / "gw.toml").write_text(f"""[node]
hostname = "anchor"
data_dir = "{tmp_path}"
role = "anchor"
[network]
interface = "gw-mesh"
seeds = []
[anchor]
ca_key_file = "{tmp_path}/ca.key"
[ca]
trusted_pubs = []
""")
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)
    monkeypatch.setattr("greasewood.wg.interface_exists", lambda i: True)
    import urllib.request
    monkeypatch.setattr(urllib.request, "urlopen", lambda *a, **k: None)
    ns = types.SimpleNamespace(config=str(tmp_path / "gw.toml"), quiet=True,
                               endpoint="fd00::1", segments=None, caps=None,
                               hostname="pinned", standing=True, supersede=False)
    with pytest.raises(SystemExit) as e:
        cli.cmd_invite(ns)
    assert "--hostname cannot be combined with --standing" in str(e.value)


def test_standing_window_stores_and_status_shows_token(tmp_path):
    """A standing invite stores its token (0600 root) so it can be re-retrieved
    for baking without re-issuing; the anchor door block surfaces it."""
    import types
    from greasewood import cli, door

    door.window_path(tmp_path).write_text(json.dumps({
        "v": 1, "standing": True, "caps": ["segment:autoscale"], "hostname": None,
        "guest_pub": "x", "psk": "y", "token": "gw1.THE-STANDING-TOKEN",
    }))
    door.mark_door_opened(tmp_path, None, caps=["segment:autoscale"], standing=True)
    cfg = types.SimpleNamespace(data_dir=tmp_path, role="anchor")
    lines = status._door_status_lines(cfg)
    joined = "\n".join(lines)
    assert "OPEN (standing)" in joined
    assert "token: gw1.THE-STANDING-TOKEN" in joined


def test_single_use_window_has_no_stored_token(tmp_path):
    """Only standing tokens are stored (they're long-lived/bakeable); a
    single-use window carries no token to leak."""
    import types
    from greasewood import cli, door
    door.window_path(tmp_path).write_text(json.dumps({
        "v": 1, "expires": "2099-01-01T00:00:00Z", "caps": [], "hostname": None,
    }))
    door.mark_door_opened(tmp_path, "2099-01-01T00:00:00Z")
    lines = status._door_status_lines(types.SimpleNamespace(data_dir=tmp_path, role="anchor"))
    assert not any("token:" in ln for ln in lines)
