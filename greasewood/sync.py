"""
greasewood.sync — directory pull loop.

Every node pulls the full record-set from one or more seeds every ~20s
and merges by highest seq per id_pub. The anchor can be offline for up to
one credential TTL with no impact on live links — nodes keep running from
their local cache (§10.2). Without local caching, the anchor would silently
be a hard availability dependency; the cache is what makes "anchor not in
the data path" true in practice.
"""
from __future__ import annotations

import datetime as dt
import json
import logging
import threading
import urllib.error
import urllib.request
from pathlib import Path
from typing import Callable

from .directory import Directory
from .loop import Loop
from .wire import NodeRecord

log = logging.getLogger(__name__)
_UTC = dt.timezone.utc


def _parse_renew_after(raw) -> "dt.datetime | None":
    if not raw:
        return None
    try:
        ts = dt.datetime.fromisoformat(raw)
        return ts if ts.tzinfo else ts.replace(tzinfo=_UTC)
    except (ValueError, TypeError):
        return None


def pull_directory(seed_url: str, timeout: float = 10.0):
    """Fetch (records, renew_after, anchor_now) from a seed's /directory endpoint.

    Accepts both the current object shape {"records": [...], "renew_after": ...}
    and a bare list (older anchors), so a mixed-version mesh still syncs. renew_after
    is the fleet-wide renew hint (see gw renew-all); anchor_now is the anchor's own
    clock (for skew detection) — either parsed to a UTC datetime or None."""
    url = f"{seed_url.rstrip('/')}/directory"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            raw = json.loads(resp.read())
        if isinstance(raw, dict):
            records = [NodeRecord.from_dict(r) for r in raw.get("records", [])]
            return (records, _parse_renew_after(raw.get("renew_after")),
                    _parse_renew_after(raw.get("now")),
                    raw.get("mesh_domain") or None)
        return [NodeRecord.from_dict(r) for r in raw], None, None, None
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


class SyncLoop(Loop):
    def __init__(
        self,
        directory: Directory,
        get_seeds: "Callable[[], list[str]]",
        cache_path: Path,
        interval: float = 20.0,
        on_renew_after: "Callable[[dt.datetime], None] | None" = None,
        expected_domain: "str | None" = None,
    ) -> None:
        super().__init__(interval, "sync")
        # This member's mesh domain, compared against the anchor's advertisement
        # each pull to detect a fleet rename (None disables the check).
        self._expected_domain = expected_domain
        self._directory = directory
        # A callable so the caller decides where seeds come from; in practice
        # the configured seeds (the anchor).
        self._get_seeds = get_seeds
        self._cache_path = cache_path
        # Called with the anchor's fleet-wide renew hint (renew_after) after each
        # successful pull; the renewal loop decides whether/when to act on it.
        self._on_renew_after = on_renew_after
        self._last_skew_warn: float | None = None
        self._warned_domain: str | None = None

    # Clock-skew sentinel: past ±300s the anchor refuses renewals, and well before
    # that expiry checks start lying — but the symptom (peers vanishing, renew
    # 400s) doesn't say "your clock is wrong". Warn at 60s, before it bites.
    _SKEW_WARN_SECS = 60.0
    _SKEW_WARN_INTERVAL = 600.0  # at most one warning per 10 min, not per pull

    def _note_anchor_clock(self, anchor_now: "dt.datetime | None") -> None:
        if anchor_now is None:
            return  # older anchor that doesn't stamp its time
        skew = (dt.datetime.now(_UTC) - anchor_now).total_seconds()
        if abs(skew) < self._SKEW_WARN_SECS:
            self._last_skew_warn = None
            return
        import time
        now = time.monotonic()
        if self._last_skew_warn is not None \
                and now - self._last_skew_warn < self._SKEW_WARN_INTERVAL:
            return
        self._last_skew_warn = now
        log.warning("local clock is %+.0fs off the anchor — check NTP. Past ±300s "
                    "the anchor refuses renewals, and credential expiry checks "
                    "misfire well before that.", skew)

    def _note_mesh_domain(self, anchor_domain: "str | None") -> None:
        """The anchor advertises the mesh's ONE name domain. If it no longer
        matches this member's config, the mesh was RENAMED (gw rename-mesh on
        the anchor) — every artifact here (config/data-dir/interface/unit/domain)
        is keyed to the old name, so tell the operator the exact migration
        command. Warned once per observed domain."""
        if (not anchor_domain or self._expected_domain is None
                or anchor_domain == self._expected_domain):
            # In sync (or no expectation) — clear any stale pending marker.
            if anchor_domain and anchor_domain == self._expected_domain:
                self._clear_pending_rename()
            return
        from .config import membership_key
        # Persist the pending rename so it survives daemon restarts and surfaces
        # in `gw watch` — a scrolled-past log line is easy to miss for a change
        # that needs an operator action.
        self._write_pending_rename(anchor_domain)
        if anchor_domain != self._warned_domain:
            self._warned_domain = anchor_domain
            log.warning(
                "the anchor renamed this mesh: %s → %s. This member still uses its "
                "old-name artifacts; migrate them (config, data dir, interface, "
                "service) with:  sudo gw rename-mesh %s   (brief tunnel blip "
                "while the interface renames)",
                self._expected_domain, anchor_domain, membership_key(anchor_domain))

    def _pending_rename_path(self):
        return self._cache_path.parent / "pending_rename.json"

    def _write_pending_rename(self, new_domain: str) -> None:
        import json
        try:
            self._pending_rename_path().write_text(json.dumps(
                {"new_domain": new_domain, "old_domain": self._expected_domain}))
        except OSError:
            pass

    def _clear_pending_rename(self) -> None:
        try:
            self._pending_rename_path().unlink(missing_ok=True)
        except OSError:
            pass

    def _pull_once(self) -> None:
        # Re-merge the cache file first so records written directly to disk
        # are picked up without a daemon restart.
        from .directory import Directory as _Dir
        on_disk = _Dir.load(self._cache_path)
        self._directory.merge(on_disk.all())

        for seed in self._get_seeds():
            try:
                records, renew_after, anchor_now, anchor_domain = pull_directory(seed)
                n = self._directory.merge(records)
                if n:
                    self._directory.save(self._cache_path)
                log.debug("synced %d records from %s (%d new/updated)", len(records), seed, n)
                self._stamp_sync()   # record a successful pull for `gw watch`
                self._note_anchor_clock(anchor_now)
                self._note_mesh_domain(anchor_domain)
                if self._on_renew_after and renew_after is not None:
                    self._on_renew_after(renew_after)
                return
            except RuntimeError as e:
                log.warning("sync from %s failed: %s", seed, e)

    def _stamp_sync(self) -> None:
        """Record the time of a successful directory pull, so `gw watch` can
        show sync freshness (it reads a *cache*; a stale roster is worth
        flagging). Stamped on every successful pull, even a no-op one."""
        try:
            stamp_sync_path(self._cache_path.parent).write_text(
                dt.datetime.now(_UTC).replace(microsecond=0).isoformat())
        except OSError:
            pass

    # Loop plumbing (run/start/stop) comes from Loop.
    _tick = _pull_once


def stamp_sync_path(data_dir) -> "Path":
    """Where the last-successful-sync timestamp lives."""
    return Path(data_dir) / "last_sync"


def read_last_sync(data_dir) -> "str | None":
    """The ISO time of the last successful directory sync, or None."""
    try:
        return stamp_sync_path(data_dir).read_text().strip()
    except (FileNotFoundError, OSError):
        return None
