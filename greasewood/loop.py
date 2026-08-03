"""
greasewood.loop — the ONE shape for the daemon's background loops.

The daemon runs several: reconcile, directory sync, credential renewal, TLS-cert
renewal, endpoint auto-refresh, and the door watcher. Loop owns the lifecycle
they all share — a
stop event, start() returning the thread, and a run() that ticks on an
interval with a catch-all — so "how do background loops behave" is a one-file
answer, and no loop can silently die on an exception escaping its tick (a
dead reconcile loop is a frozen data plane under a healthy-looking daemon).

Subclasses implement _tick(). RenewalLoop overrides run() entirely — it is
honestly different (event-driven wait with its own retry ladder) — but keeps
the base's start()/stop() so its lifecycle still matches.
"""
from __future__ import annotations

import logging
import os
import socket
import threading
import time

log = logging.getLogger(__name__)


def sd_watchdog_ping() -> None:
    """Tell systemd this daemon is genuinely alive (WATCHDOG=1) — called after
    each SUCCESSFUL reconcile pass, so 'alive' means 'reconciling', not just
    'process exists'. Pairs with WatchdogSec= in the unit: a daemon that keeps
    running but stops reconciling misses its pings and is killed + restarted
    by systemd — the failure mode a plain process supervisor can't see.
    A no-op outside systemd (no NOTIFY_SOCKET) and on any socket error: the
    watchdog is a supervisor contract, never a reason to fail a working
    daemon. Pure stdlib — one datagram on the notify socket."""
    addr = os.environ.get("NOTIFY_SOCKET")
    if not addr:
        return
    try:
        if addr.startswith("@"):                  # abstract-namespace socket
            addr = "\0" + addr[1:]
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as s:
            s.connect(addr)
            s.send(b"WATCHDOG=1")
    except OSError:
        pass


class Loop:
    def __init__(self, interval: float, name: str) -> None:
        self._interval = interval
        self._name = name
        self._stop = threading.Event()

    def _tick(self) -> None:
        raise NotImplementedError

    def run(self) -> None:
        while not self._stop.wait(self._interval):
            try:
                self._tick()
            except Exception as e:
                log.error("%s loop error: %s", self._name, e)

    def start(self) -> threading.Thread:
        t = threading.Thread(target=self.run, name=self._name, daemon=True)
        t.start()
        return t

    def stop(self) -> None:
        self._stop.set()


# --- wedge watchdog (the non-systemd half of the liveness contract) --------

class WedgeWatchdog(Loop):
    """Self-exit when the daemon stops making liveness progress — the portable
    equivalent of the systemd unit's WatchdogSec=.

    A daemon that is alive but no longer reconciling, syncing, or renewing
    (wedged in a blocking call, a deadlocked thread, or a RenewalLoop that has
    silently stopped) is invisible to a plain process supervisor: the process
    exists, so nothing restarts it, and the data plane silently freezes. systemd
    catches this via sd_notify (the daemon stops pinging → killed after
    WatchdogSec). Off systemd there is no notify socket, so THIS loop is the
    consumer: it watches whichever heartbeat the caller supplies and, once it
    goes stale past `threshold`, exits the process so a death-restart supervisor
    (OpenRC's supervise-daemon, runit, a bare respawn) brings it back.

    It runs in its own thread, so it still fires when the monitored thread is
    the one wedged. `age_fn` may return a float/None (legacy: seconds since the
    last reconcile, None = none yet) or a tuple `(age, reason)`. Until the first
    tick lands we measure against process start, so a daemon that comes up but
    never makes progress is caught too. `exit` is injectable for tests (default
    os._exit — a clean sys.exit would leave the other daemon threads running)."""

    def __init__(self, age_fn, *, threshold: float = 120.0,
                 interval: float = 15.0, exit=None) -> None:
        super().__init__(interval, "watchdog")
        self._age_fn = age_fn
        self._threshold = threshold
        self._exit = exit if exit is not None else (lambda code: os._exit(code))
        self._started = time.monotonic()

    def _tick(self) -> None:
        result = self._age_fn()
        if isinstance(result, tuple):
            age, reason = result
        else:
            age, reason = result, "reconcile"
        uptime = time.monotonic() - self._started
        if age is None:                      # no progress yet → measure uptime
            age = uptime
        else:
            # The age_fn uses wall-clock stamps. A machine that slept (or had
            # its clock stepped) can report a huge age even though the daemon is
            # healthy; it just hasn't had a chance to run. Cap the age at the
            # process's active uptime so we don't exit before the loops recover.
            age = min(age, uptime)
        if age <= self._threshold:
            return
        log.critical(
            "daemon %s stale for %ds (threshold %ds) — looks wedged; exiting "
            "so the supervisor restarts it",
            reason, int(age), int(self._threshold))
        self._exit(70)                       # EX_SOFTWARE
