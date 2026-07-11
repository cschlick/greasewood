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
import threading

log = logging.getLogger(__name__)


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
