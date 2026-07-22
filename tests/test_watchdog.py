"""
Backend-neutral liveness: the reconcile heartbeat + the WedgeWatchdog self-exit.

systemd catches a wedged-but-alive daemon via sd_notify/WatchdogSec; off systemd
there's no notify socket, so WedgeWatchdog watches the same reconcile stamp and
exits the process for a death-restart supervisor. These lock down the age
computation and the fire/don't-fire decision — no init system, no real exit.
"""
import datetime as dt

from greasewood import reconcile as R
from greasewood.loop import WedgeWatchdog

_UTC = dt.timezone.utc


def _stamp(data_dir, when: dt.datetime) -> None:
    R.stamp_reconcile_path(data_dir).write_text(when.replace(microsecond=0).isoformat())


def test_seconds_since_reconcile_none_until_stamped(tmp_path):
    assert R.seconds_since_reconcile(tmp_path) is None       # never reconciled
    _stamp(tmp_path, dt.datetime.now(_UTC))
    age = R.seconds_since_reconcile(tmp_path)
    assert age is not None and age < 5


def test_seconds_since_reconcile_grows_with_staleness(tmp_path):
    _stamp(tmp_path, dt.datetime.now(_UTC) - dt.timedelta(seconds=300))
    age = R.seconds_since_reconcile(tmp_path)
    assert 295 <= age <= 360


def test_seconds_since_reconcile_none_on_garbled_stamp(tmp_path):
    R.stamp_reconcile_path(tmp_path).write_text("not-a-timestamp")
    assert R.seconds_since_reconcile(tmp_path) is None


def test_watchdog_stays_quiet_while_fresh():
    exits = []
    wd = WedgeWatchdog(age_fn=lambda: 3.0, threshold=120, exit=exits.append)
    wd._tick()
    assert exits == []                                       # 3s < 120s → no exit


def test_watchdog_exits_when_reconcile_is_stale():
    exits = []
    wd = WedgeWatchdog(age_fn=lambda: 300.0, threshold=120, exit=exits.append)
    wd._tick()
    assert exits == [70]                                     # stale → EX_SOFTWARE exit


def test_watchdog_measures_uptime_before_first_reconcile(monkeypatch):
    # age_fn returns None (never stamped) → judged against process start, so a
    # daemon that comes up but never reconciles is still caught.
    exits = []
    wd = WedgeWatchdog(age_fn=lambda: None, threshold=120, exit=exits.append)
    wd._started -= 300                                       # pretend 300s of uptime
    wd._tick()
    assert exits == [70]


def test_watchdog_uptime_grace_before_threshold():
    exits = []
    wd = WedgeWatchdog(age_fn=lambda: None, threshold=120, exit=exits.append)
    wd._tick()                                               # just started → within grace
    assert exits == []
