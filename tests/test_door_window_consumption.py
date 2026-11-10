"""
A completed single-use enrollment CONSUMES the door window on disk — whatever
it holds by then. The door interface always carries the LATEST invite's keys,
so a join can only have ridden the current window's token; deleting only a
byte-identical window wedged the door OPEN (CI's "anchor did not tear down
gw-door"): a window rewritten between the server's start and the join was left
live, the next tick started a server on it, and every later enrollment was
served one window behind, mismatching forever. Non-enrolled closes keep the
conservative only-my-own-window rule, standing windows are never consumed,
and a superseded server's late callback must not clobber its successor.
"""
import datetime as dt
import json

from greasewood import door, enroll
from greasewood.directory import Directory
from greasewood.keys import NodeKeys

_UTC = dt.timezone.utc


def _timed_window(data_dir, *, offset_secs=900):
    expires = (dt.datetime.now(_UTC) + dt.timedelta(seconds=offset_secs))
    door.window_path(data_dir).write_text(json.dumps({
        "v": 1, "expires": expires.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "caps": ["role:node"], "allowed_roles": [], "hostname": None,
        "failover_blob": None,
    }))
    return expires.strftime("%Y-%m-%dT%H:%M:%SZ")


def _watcher(tmp_path):
    ctx = enroll.EnrollContext(
        ca=None, directory=Directory(), node_keys=NodeKeys.generate(),
        wg_iface="gw-mesh", data_dir=tmp_path)
    return enroll.DoorWatcher(ctx, door_port=51901)


def _fake_server(monkeypatch):
    """Capture each started server's on_done; servers are inert."""
    started = []

    class FakeSrv:
        def __init__(self, ctx, on_done, **kwargs):
            self.on_done = on_done
            started.append(self)

        def start(self):
            pass

        def stop(self):
            pass
    monkeypatch.setattr(enroll, "EnrollServer", FakeSrv)
    return started


def test_enrolled_consumes_a_rewritten_window(tmp_path, monkeypatch):
    """THE wedge: window rewritten (fresh invite) between server start and the
    join completing. 'enrolled' must delete the CURRENT file anyway, so the
    watcher's next tick tears the door down instead of re-serving a stale
    window forever."""
    started = _fake_server(monkeypatch)
    _timed_window(tmp_path)
    w = _watcher(tmp_path)
    w._tick()                                   # server S1 for window W1
    assert len(started) == 1
    _timed_window(tmp_path, offset_secs=920)    # W2 lands mid-enrollment
    started[0].on_done("enrolled")
    assert not door.window_path(tmp_path).exists()   # consumed, not leaked
    assert w._enroll is None


def test_non_enrolled_close_leaves_a_newer_window(tmp_path, monkeypatch):
    """A server that closed WITHOUT enrolling (expired/superseded) must not
    eat a fresh invite's window — only its own."""
    started = _fake_server(monkeypatch)
    _timed_window(tmp_path)
    w = _watcher(tmp_path)
    w._tick()
    _timed_window(tmp_path, offset_secs=920)    # a fresh invite's window
    started[0].on_done("superseded")
    assert door.window_path(tmp_path).exists()  # successor's token survives


def test_own_window_still_deleted_on_any_close(tmp_path, monkeypatch):
    """The pre-existing contract: an unchanged window is deleted whatever the
    close reason (attempts exhausted closes the door)."""
    started = _fake_server(monkeypatch)
    _timed_window(tmp_path)
    w = _watcher(tmp_path)
    w._tick()
    started[0].on_done("attempts_exhausted")
    assert not door.window_path(tmp_path).exists()


def test_enrolled_never_consumes_a_standing_window(tmp_path, monkeypatch):
    """A standing window that replaced the timed one mid-enrollment survives:
    it is what re-opens the door on the next boot."""
    started = _fake_server(monkeypatch)
    _timed_window(tmp_path)
    w = _watcher(tmp_path)
    w._tick()
    door.window_path(tmp_path).write_text(json.dumps({
        "v": 1, "standing": True, "caps": ["role:node"],
        "guest_pub": "R3Vlc3RQdWJHdWVzdFB1Ykd1ZXN0UHViR3U=",
        "psk": "UHNrUHNrUHNrUHNrUHNrUHNrUHNrUHNrUHM=",
    }))
    started[0].on_done("enrolled")
    assert door.window_path(tmp_path).exists()


def test_late_on_done_does_not_clobber_successor(tmp_path, monkeypatch):
    """A superseded server's callback can fire AFTER the watcher registered
    its successor; the successor's registration must survive, or the next
    tick would stack a third server on the same port."""
    started = _fake_server(monkeypatch)
    _timed_window(tmp_path)
    w = _watcher(tmp_path)
    w._tick()                                   # S1 for W1
    _timed_window(tmp_path, offset_secs=920)    # supersede → S2 next tick
    w._tick()
    assert len(started) == 2
    assert w._enroll is started[1]
    started[0].on_done("superseded")            # S1's late exit
    assert w._enroll is started[1]              # S2 still registered
    started[1].on_done("enrolled")
    assert w._enroll is None
