"""
greasewood.directory — in-memory directory with file-backed persistence.

Merge rule: highest seq wins per id_pub (§10.2).
Self-signed records make merges conflict-free — a compromised seed can withhold
or reorder records but cannot forge one (no id_priv) and cannot MITM (the WG
handshake authenticates wg_pub, bound to id_pub by a ca_sig the seed can't fake).
Worst a bad seed can do is cause a failed connection, never an intercepted one.

The local cache means nodes keep running from last-known-good state while the
hub is offline, for up to one credential TTL.
"""
from __future__ import annotations

import json
import logging
import threading
from pathlib import Path

from .wire import NodeRecord

log = logging.getLogger(__name__)


class Directory:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._records: dict[str, NodeRecord] = {}  # id_pub_hex → NodeRecord

    def merge(self, records: list[NodeRecord]) -> int:
        """
        Merge incoming records; return count of accepted (higher-seq) entries.

        Each record is structurally verified (self-signature + addr derivation +
        id_pub/cred consistency) before it can enter the directory. This is
        CA- and clock-independent, so it never drops a genuine record during a
        CA re-root or under clock skew, but it does stop a malicious or
        compromised directory response from shadowing a real record with a
        high-seq forgery (which, once cached, would otherwise stick forever).
        Full trust/expiry/revocation checks still run at reconcile time.
        """
        accepted = 0
        with self._lock:
            for r in records:
                try:
                    r.verify_structural()
                except ValueError as e:
                    log.debug("merge: dropping unverifiable record for %s: %s",
                              r.id_pub.hex()[:16], e)
                    continue
                key = r.id_pub.hex()
                existing = self._records.get(key)
                if existing is None or r.seq > existing.seq:
                    self._records[key] = r
                    accepted += 1
        return accepted

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
            tmp = path.with_suffix(".tmp")
            tmp.write_text(json.dumps(data, indent=2))
            tmp.replace(path)

    @classmethod
    def load(cls, path: Path) -> "Directory":
        d = cls()
        if not path.exists():
            return d
        try:
            raw = json.loads(path.read_text())
            records = [NodeRecord.from_dict(r) for r in raw]
            d.merge(records)
        except Exception as e:
            log.warning("directory cache load failed, starting empty: %s", e)
        return d
