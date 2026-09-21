"""
greasewood.sweep — the holder's abandoned-node garbage collector.

Expiry is liveness, not death: an expired-but-not-revoked node is admitted by
holders to recertify itself (see reconcile / renewal). That recert is
deliberately unbounded in the short term so a node asleep past its TTL heals
automatically — but left unbounded forever the fleet would carry records for
nodes that will never return (destroyed cloud instances left to expire).

With the registry gone, one prune does the whole job: dropping the aged-out
record ends BOTH the node's visibility and its ability to renew — renewal
re-issues from the record, so no record means re-enrollment through the door
(a true re-join, not a reconnect). Every node prunes on the same pure
function of the record's own exp (directory.DROP_GRACE), so the fleet
converges with no delete-propagation; the holder's sweep also tidies the
statement log's own bounded lifetime rules.

Revocation is untouched — that's the instant, authoritative kill for a
compromised key. This is the lazy sweep for abandonment: no `gw revoke` needed.
"""
from __future__ import annotations

import logging

from .directory import Directory
from .loop import Loop

log = logging.getLogger(__name__)

# Hourly is plenty: the deadline is measured in days, so an hour of slack on
# when a week-dead node is reaped is irrelevant, and it keeps the sweep off the
# critical path of anything the daemon does per-second.
_SWEEP_INTERVAL = 3600.0


class StaleSweep(Loop):
    def __init__(self, directory: Directory, cache_path,
                 statements=None, interval: float = _SWEEP_INTERVAL,
                 protect: "str | None" = None) -> None:
        super().__init__(interval, "sweep")
        self._directory = directory
        self._cache_path = cache_path
        self._statements = statements
        # This holder's own id_pub hex: the sweep must never reap the holder
        # itself. If its own renewal stalls (clock skew, a wedged loop) its
        # credential goes stale like anyone's — but sweeping its record ends
        # the fleet's path to the control plane, turning a recoverable stall
        # into a partition.
        self._protect = protect

    def _tick(self) -> None:
        pruned = self._directory.prune_stale(protect=self._protect)
        if self._statements is not None:
            self._statements.prune()
        if pruned:
            log.info("stale sweep: pruned %d abandoned record(s) — a return "
                     "requires re-enrollment (renewal re-issues from the "
                     "record, and it is gone)", pruned)
            if self._cache_path is not None:
                self._directory.save(self._cache_path)
