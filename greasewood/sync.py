"""
greasewood.sync — directory pull loop.

Every node pulls the full record-set from one or more seeds every ~20s
and merges by highest seq per id_pub. The hub can be offline for up to
one credential TTL with no impact on live links — nodes keep running from
their local cache (§10.2). Without local caching, the hub would silently
be a hard availability dependency; the cache is what makes "hub not in
the data path" true in practice.
"""
from __future__ import annotations

import json
import logging
import threading
import urllib.error
import urllib.request
from pathlib import Path
from typing import Callable

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


def push_record(seed_url: str, record: NodeRecord, timeout: float = 10.0) -> None:
    """POST a self-signed NodeRecord to a seed's /publish endpoint."""
    url = f"{seed_url.rstrip('/')}/publish"
    body = json.dumps(record.to_dict()).encode()
    req = urllib.request.Request(
        url, data=body, headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read())
    except urllib.error.URLError as e:
        raise RuntimeError(f"publish to {url} failed: {e}") from e
    if "error" in data:
        raise RuntimeError(data["error"])


class SyncLoop:
    def __init__(
        self,
        directory: Directory,
        get_seeds: "Callable[[], list[str]]",
        cache_path: Path,
        interval: float = 20.0,
    ) -> None:
        self._directory = directory
        # Resolved each cycle — seeds follow the active hub during CA
        # succession (§11), so they cannot be captured once.
        self._get_seeds = get_seeds
        self._cache_path = cache_path
        self._interval = interval
        self._stop = threading.Event()

    def _pull_once(self) -> None:
        # Re-merge the cache file first so records written directly to disk
        # are picked up without a daemon restart.
        from .directory import Directory as _Dir
        on_disk = _Dir.load(self._cache_path)
        self._directory.merge(on_disk.all())

        for seed in self._get_seeds():
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
