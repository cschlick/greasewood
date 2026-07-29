"""
Clock-skew sentinel (sync side). An expiry-based trust system fails weirdly
under clock drift — valid creds look expired, renewals bounce off the ±300s
skew guard — and the symptom (peers vanishing) doesn't point at the cause.
The anchor stamps its time into /directory; the sync loop compares each pull and
warns loudly (rate-limited) past 60s, naming NTP instead of leaving the
operator to reverse-engineer it from credential errors.
"""
import datetime as dt
import json
import logging

from greasewood.directory import Directory
from greasewood.keys import NodeKeys
from greasewood.server import ControlServer
from greasewood.sync import SyncLoop, pull_directory, pull_revoked

_UTC = dt.timezone.utc


def _make_loop(tmp_path) -> SyncLoop:
    return SyncLoop(
        directory=Directory(),
        get_seeds=lambda: [],
        cache_path=tmp_path / "dir.json",
    )


def test_pull_directory_returns_anchor_time(tmp_path):
    srv = ControlServer(
        listen="[::1]:0", directory=Directory(),
        get_ca_pubs=lambda: [], get_revoked=set,
    )
    port = srv._server.server_address[1]
    srv.start()
    try:
        records, renew_after, anchor_now, _dom, _policy = pull_directory(f"http://[::1]:{port}")
        assert records == [] and renew_after is None
        assert anchor_now is not None and anchor_now.tzinfo is not None
        assert abs((dt.datetime.now(_UTC) - anchor_now).total_seconds()) < 30
    finally:
        srv.stop()


def test_skew_past_threshold_warns(tmp_path, caplog):
    loop = _make_loop(tmp_path)
    behind = dt.datetime.now(_UTC) - dt.timedelta(seconds=120)
    with caplog.at_level(logging.WARNING, logger="greasewood.sync"):
        loop._note_anchor_clock(behind)
    assert any("clock" in r.message and "NTP" in r.message
               for r in caplog.records), caplog.text


def test_small_skew_is_silent(tmp_path, caplog):
    loop = _make_loop(tmp_path)
    close = dt.datetime.now(_UTC) - dt.timedelta(seconds=5)
    with caplog.at_level(logging.WARNING, logger="greasewood.sync"):
        loop._note_anchor_clock(close)
        loop._note_anchor_clock(None)          # anchor didn't send a time (old anchor)
    assert not caplog.records


def test_skew_warning_is_rate_limited(tmp_path, caplog):
    loop = _make_loop(tmp_path)
    behind = dt.datetime.now(_UTC) - dt.timedelta(seconds=300)
    with caplog.at_level(logging.WARNING, logger="greasewood.sync"):
        loop._note_anchor_clock(behind)
        loop._note_anchor_clock(behind)        # 20s later in real life; same warn window
        loop._note_anchor_clock(behind)
    assert len(caplog.records) == 1         # once per window, not once per pull


def test_revoked_endpoint_serves_revoke_list():
    a, b = NodeKeys.generate(), NodeKeys.generate()
    srv = ControlServer(
        listen="[::1]:0", directory=Directory(),
        get_ca_pubs=lambda: [],
        get_revoked=lambda: {a.id_pub_hex, b.id_pub_hex},
    )
    port = srv._server.server_address[1]
    srv.start()
    try:
        rev = pull_revoked(f"http://[::1]:{port}")
        assert rev == {a.id_pub_hex, b.id_pub_hex}
    finally:
        srv.stop()


def test_sync_loop_caches_revoked_list(tmp_path, monkeypatch):
    from greasewood import sync as syncmod
    a = NodeKeys.generate()
    monkeypatch.setattr(syncmod, "pull_directory",
                        lambda url, timeout=10.0: ([], None, None, None, None))
    monkeypatch.setattr(syncmod, "pull_revoked",
                        lambda url, timeout=5.0: {a.id_pub_hex})

    loop = SyncLoop(
        directory=Directory(),
        get_seeds=lambda: ["http://seed"],
        cache_path=tmp_path / "dir.json",
    )
    loop._pull_once()

    revoked_path = tmp_path / "revoked.json"
    assert revoked_path.exists()
    data = json.loads(revoked_path.read_text())
    assert data["revoked"] == [a.id_pub_hex]
