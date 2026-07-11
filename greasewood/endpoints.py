"""
greasewood.endpoints — periodic advertised-endpoint re-detection.

The daemon detects its public underlay endpoint(s) once, at join. On any host
whose address can change under a running daemon — an IPv6 prefix renumbering
swaps the stable GUA, a laptop moves to a v4-only network — the advertised
endpoint then goes stale, and peers can no longer cold-dial it (established
sessions survive via WireGuard roaming, but a fresh inbound dial hits the dead
address). This loop re-detects periodically and re-advertises ONLY when the set
actually changes.

It keys off detection that already prefers the STABLE address (temporary
privacy-extension addresses, which rotate constantly, are never selected), so on
a stable network it fires nothing — it re-advertises exactly once, when the real
address changes. Opt-in per node via [node] endpoint_auto (false when the
operator pinned an explicit --endpoint, which must never be auto-overridden).

Wired by dependency injection (detect/current/republish callables) so it carries
no cli/config import of its own.
"""
from __future__ import annotations

import logging

from .loop import Loop

log = logging.getLogger(__name__)


class EndpointLoop(Loop):
    """Re-detect advertised endpoints each interval; re-advertise on change.

    detect()    -> list[str]: freshly detected endpoint(s), [] if none/transient
    current()   -> list[str]: what the node currently advertises
    republish() takes the new list and re-signs + pushes the record.
    """

    def __init__(self, *, detect, current, republish, interval: float = 60.0) -> None:
        super().__init__(interval, "endpoints")
        self._detect = detect
        self._current = current
        self._republish = republish

    def _tick(self) -> None:
        detected = self._detect()
        # [] = detection found nothing OR a transient `ip` failure. Do NOT wipe a
        # working advertisement on that — keep what we have (roaming covers live
        # sessions); we only ever act on a POSITIVE detection that differs.
        if not detected:
            return
        current = self._current()
        if sorted(detected) == sorted(current):
            return                                  # the steady-state no-op
        log.info("advertised endpoint(s) changed: %s → %s — re-advertising",
                 current or "(none)", detected)
        self._republish(detected)
