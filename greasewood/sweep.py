"""
greasewood.sweep — the anchor's abandoned-node garbage collector.

Expiry is liveness, not death: an expired-but-not-revoked node is admitted by
the anchor to recertify itself (see reconcile / renewal). That recert is
deliberately unbounded in the short term so a node asleep past its TTL heals
automatically — but left unbounded forever it means the anchor keeps a
permanent, ever-growing registry of nodes that will never return (destroyed
cloud instances left to expire). This loop puts a ceiling on it:

  * CA registry (authorization): forget any node whose last-issued credential
    expired more than `drop_grace` ago — renew() re-issues from the registry, so
    a forgotten node can no longer renew and must re-enroll through the door.
  * Directory (visibility): prune the same long-expired records from the served
    directory so they age out of the fleet's caches (DROP_GRACE, the fleet
    constant — the anchor is the sync source, so its prune is what lets peers
    converge).

Revocation is untouched — that's the instant, authoritative kill for a
compromised key. This is the lazy sweep for abandonment: no `gw revoke` needed.
"""
from __future__ import annotations

import logging

from .directory import Directory, DROP_GRACE
from .loop import Loop

log = logging.getLogger(__name__)

# Hourly is plenty: the deadline is measured in days, so an hour of slack on
# when a week-dead node is reaped is irrelevant, and it keeps the sweep off the
# critical path of anything the daemon does per-second.
_SWEEP_INTERVAL = 3600.0


class StaleSweep(Loop):
    def __init__(self, ca, directory: Directory, drop_grace,
                 cache_path, interval: float = _SWEEP_INTERVAL) -> None:
        super().__init__(interval, "sweep")
        self._ca = ca
        self._directory = directory
        self._drop_grace = drop_grace      # anchor config → authorization drop
        self._cache_path = cache_path

    def _tick(self) -> None:
        dropped = self._ca.drop_stale(self._drop_grace)
        # Prune the served directory on the fleet-wide constant (DROP_GRACE), so
        # visibility converges the same way on every node regardless of the
        # anchor's authorization grace.
        pruned = self._directory.prune_stale()
        if dropped or pruned:
            log.info("stale sweep: dropped %d abandoned node(s) from the CA, "
                     "pruned %d record(s) from the directory", len(dropped), pruned)
            if self._cache_path is not None:
                self._directory.save(self._cache_path)
