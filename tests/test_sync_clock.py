"""
Clock-skew sentinel (sync side). An expiry-based trust system fails weirdly
under clock drift — valid creds look expired, renewals bounce off the ±300s
skew guard — and the symptom (peers vanishing) doesn't point at the cause.
The hub stamps its time into /directory; the sync loop compares each pull and
warns loudly (rate-limited) past 60s, naming NTP instead of leaving the
operator to reverse-engineer it from credential errors.
"""
import datetime as dt
import logging

from greasewood.directory import Directory
from greasewood.server import ControlServer
from greasewood.sync import SyncLoop, pull_directory

_UTC = dt.timezone.utc


def _make_loop(tmp_path) -> SyncLoop:
    return SyncLoop(
        directory=Directory(),
        get_seeds=lambda: [],
        cache_path=tmp_path / "dir.json",
    )


def test_pull_directory_returns_hub_time(tmp_path):
    srv = ControlServer(
        listen="[::1]:0", directory=Directory(),
        get_ca_pubs=lambda: [], get_revoked=set,
    )
    port = srv._server.server_address[1]
    srv.start()
    try:
        records, renew_after, hub_now = pull_directory(f"http://[::1]:{port}")
        assert records == [] and renew_after is None
        assert hub_now is not None and hub_now.tzinfo is not None
        assert abs((dt.datetime.now(_UTC) - hub_now).total_seconds()) < 30
    finally:
        srv.stop()


def test_skew_past_threshold_warns(tmp_path, caplog):
    loop = _make_loop(tmp_path)
    behind = dt.datetime.now(_UTC) - dt.timedelta(seconds=120)
    with caplog.at_level(logging.WARNING, logger="greasewood.sync"):
        loop._note_hub_clock(behind)
    assert any("clock" in r.message and "NTP" in r.message
               for r in caplog.records), caplog.text


def test_small_skew_is_silent(tmp_path, caplog):
    loop = _make_loop(tmp_path)
    close = dt.datetime.now(_UTC) - dt.timedelta(seconds=5)
    with caplog.at_level(logging.WARNING, logger="greasewood.sync"):
        loop._note_hub_clock(close)
        loop._note_hub_clock(None)          # hub didn't send a time (old hub)
    assert not caplog.records


def test_skew_warning_is_rate_limited(tmp_path, caplog):
    loop = _make_loop(tmp_path)
    behind = dt.datetime.now(_UTC) - dt.timedelta(seconds=300)
    with caplog.at_level(logging.WARNING, logger="greasewood.sync"):
        loop._note_hub_clock(behind)
        loop._note_hub_clock(behind)        # 20s later in real life; same warn window
        loop._note_hub_clock(behind)
    assert len(caplog.records) == 1         # once per window, not once per pull
