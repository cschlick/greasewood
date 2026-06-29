"""
greasewood.sync — directory pull loop.

Every node pulls the full record-set from one or more seeds every ~20s
and merges by highest seq per id_pub. The root can be offline for up to
one credential TTL with no impact on live links — nodes keep running from
their local cache (§10.2). Without local caching, the root would silently
be a hard availability dependency; the cache is what makes "root not in
the data path" true in practice.
"""
from __future__ import annotations

import json
import logging
import threading
import urllib.error
import urllib.request
from pathlib import Path

from .directory import Directory
from .wire import NodeRecord

log = logging.getLogger(__name__)


def pull_directory(seed_url: str, timeout: float = 10.0) -> list[NodeRecord]:
    """Fetch the record list from a seed's /directory endpoint."""
    url = f"{seed_url.rstrip('/')}/directory"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            raw = json.loads(resp.read())
            return [NodeRecord.from_dict(r) for r in raw]
    except (urllib.error.URLError, json.JSONDecodeError, KeyError) as e:
        raise RuntimeError(f"pull from {url} failed: {e}") from e


class SyncLoop:
    def __init__(
        self,
        directory: Directory,
        seeds: list[str],
        cache_path: Path,
        interval: float = 20.0,
    ) -> None:
        self._directory = directory
        self._seeds = seeds
        self._cache_path = cache_path
        self._interval = interval
        self._stop = threading.Event()

    def _pull_once(self) -> None:
        for seed in self._seeds:
            try:
                records = pull_directory(seed)
                n = self._directory.merge(records)
                if n:
                    self._directory.save(self._cache_path)
                log.debug("synced %d records from %s (%d new/updated)", len(records), seed, n)
                return
            except RuntimeError as e:
                log.warning("sync from %s failed: %s", seed, e)

    def run(self) -> None:
        while not self._stop.wait(self._interval):
            try:
                self._pull_once()
            except Exception as e:
                log.error("sync loop error: %s", e)

    def start(self) -> threading.Thread:
        t = threading.Thread(target=self.run, name="sync", daemon=True)
        t.start()
        return t

    def stop(self) -> None:
        self._stop.set()
