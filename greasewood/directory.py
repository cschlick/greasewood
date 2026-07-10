"""
greasewood.directory — in-memory directory with file-backed persistence.

Merge rule: highest seq wins per id_pub (§10.2).
Self-signed records make merges conflict-free — a compromised seed can withhold
or reorder records but cannot forge one (no id_priv) and cannot MITM (the WG
handshake authenticates wg_pub, bound to id_pub by a ca_sig the seed can't fake).
Worst a bad seed can do is cause a failed connection, never an intercepted one.

The local cache means nodes keep running from last-known-good state while the
anchor is offline, for up to one credential TTL.
"""
from __future__ import annotations

import datetime as dt
import json
import logging
import threading
from pathlib import Path

from .keys import atomic_write
from .wire import NodeRecord

log = logging.getLogger(__name__)

_UTC = dt.timezone.utc

# How long past a credential's expiry a record is kept before it's dropped
# entirely — the fleet-wide "true drop" deadline for the DIRECTORY (the cache
# every node holds). Expiry alone just makes reconcile reject a record (peers
# evict it, `gw watch` hides it) and leaves the anchor willing to recertify it;
# past exp + DROP_GRACE the node is presumed gone for good and its record ages
# out of every cache. Because the deadline is a pure function of the record's
# own cred.exp, this needs no tombstone or delete-propagation protocol: a dead
# node never re-publishes a higher seq, so each node drops it independently and
# they converge. A live node re-publishes (fresh exp, bumped seq) long before
# the deadline, so it's never touched. The anchor's `drop_grace` config governs
# the SEPARATE authorization drop (when the CA stops recertifying); this fleet
# constant governs directory visibility and defaults to the same 7d.
DROP_GRACE = dt.timedelta(days=7)


def _past_drop(record: NodeRecord, grace: dt.timedelta, now: dt.datetime) -> bool:
    return now >= record.cred.exp + grace


class Directory:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._records: dict[str, NodeRecord] = {}  # id_pub_hex → NodeRecord

    def merge(self, records: list[NodeRecord]) -> int:
        """
        Merge incoming records; return count of accepted (higher-seq) entries.

        Each record is structurally verified (self-signature + addr derivation +
        id_pub/cred consistency) before it can enter the directory. This is
        CA-independent, so it never drops a genuine record during a CA re-root,
        and it stops a malicious or compromised directory response from
        shadowing a real record with a high-seq forgery (which, once cached,
        would otherwise stick forever). Full trust/expiry/revocation checks
        still run at reconcile time.

        The ONE clock-dependent drop is the fleet deadline (past exp +
        DROP_GRACE): a record that stale can't be a live node's (a live node
        re-publishes a fresh exp), and the 7-day margin dwarfs any plausible
        skew, so no genuine record is ever caught by it.
        """
        accepted = 0
        now = dt.datetime.now(_UTC)
        with self._lock:
            for r in records:
                try:
                    r.verify_structural()
                except ValueError as e:
                    log.debug("merge: dropping unverifiable record for %s: %s",
                              r.id_pub.hex()[:16], e)
                    continue
                # Never re-admit a record already past the fleet drop deadline:
                # otherwise a peer that hasn't pruned yet could re-inject a dead
                # node we just dropped, and the fleet would never converge.
                if _past_drop(r, DROP_GRACE, now):
                    log.debug("merge: dropping long-expired record for %s (past drop grace)",
                              r.id_pub.hex()[:16])
                    continue
                key = r.id_pub.hex()
                existing = self._records.get(key)
                if existing is None or r.seq > existing.seq:
                    self._records[key] = r
                    accepted += 1
        return accepted

    def prune_stale(self, grace: dt.timedelta = DROP_GRACE,
                    now: "dt.datetime | None" = None,
                    protect: "str | None" = None) -> int:
        """Evict records whose credential expired more than `grace` ago — the
        resident-set counterpart to merge()'s incoming filter. `protect` (an
        id_pub hex) is never dropped, so a node can't erase its own record from
        its own view. Returns the number removed."""
        now = now or dt.datetime.now(_UTC)
        with self._lock:
            stale = [k for k, r in self._records.items()
                     if k != protect and _past_drop(r, grace, now)]
            for k in stale:
                del self._records[k]
        return len(stale)

    def all(self) -> list[NodeRecord]:
        with self._lock:
            return list(self._records.values())

    def get(self, id_pub_hex: str) -> NodeRecord | None:
        with self._lock:
            return self._records.get(id_pub_hex)

    def put(self, record: NodeRecord) -> None:
        """Insert/replace a record unconditionally (used for local node's own record)."""
        with self._lock:
            self._records[record.id_pub.hex()] = record

    def size(self) -> int:
        with self._lock:
            return len(self._records)

    def save(self, path: Path) -> None:
        # The lock covers the file write too: concurrent saves (publish handler
        # threads, the sync loop) share one .tmp path, and interleaved writes to
        # it would corrupt the cache that replaces directory.json.
        with self._lock:
            data = [r.to_dict() for r in self._records.values()]
            # 0644: the cache is public state — no-root `gw watch --snapshot`
            # reads it. atomic_write's unique temp also covers the OTHER race
            # the lock can't: a CLI process writing while the daemon syncs.
            atomic_write(path, json.dumps(data, indent=2), mode=0o644)

    @classmethod
    def load(cls, path: Path) -> "Directory":
        d = cls()
        if not path.exists():
            return d
        try:
            raw = json.loads(path.read_text())
        except Exception as e:
            log.warning("directory cache unreadable, starting empty: %s", e)
            return d
        # Per-record: a single corrupt/truncated entry costs one peer, not the
        # whole cache — the point of the cache is to keep running from
        # last-known-good while the anchor is offline.
        records = []
        for raw_record in raw if isinstance(raw, list) else []:
            try:
                records.append(NodeRecord.from_dict(raw_record))
            except Exception as e:
                log.warning("skipping one corrupt directory-cache record: %s", e)
        d.merge(records)
        return d
