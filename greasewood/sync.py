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
from .keys import atomic_write
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


def _parse_statements(raw_list) -> list:
    """Parse the /directory response's statement list, per-entry tolerant (a
    single malformed statement — or a kind from a newer version — costs that
    entry, not the pull). Verification happens at merge, not here."""
    from .wire import AnchorStatement
    out = []
    for d in raw_list if isinstance(raw_list, list) else []:
        try:
            out.append(AnchorStatement.from_dict(d))
        except Exception as e:
            log.debug("skipping one unparseable statement: %s", e)
    return out


def _parse_attestations_field(raw_list) -> list:
    from .attest import parse_attestations
    return parse_attestations(raw_list)


def pull_directory(seed_url: str, timeout: float = 10.0):
    """Fetch (records, renew_after, anchor_now, mesh_domain, policy,
    statements, attestations) from a seed's /directory endpoint.

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
                    raw.get("mesh_domain") or None,
                    raw.get("policy") or None,
                    _parse_statements(raw.get("statements")),
                    _parse_attestations_field(raw.get("attestations")))
        return ([NodeRecord.from_dict(r) for r in raw],
                None, None, None, None, [], [])
    except (urllib.error.URLError, json.JSONDecodeError, KeyError) as e:
        raise RuntimeError(f"pull from {url} failed: {e}") from e


def pull_revoked(seed_url: str, timeout: float = 5.0) -> "set[str] | None":
    """Fetch the seed's current revoke list from its /revoked endpoint.

    Returns None on a missing endpoint (older anchors) or any pull error, so
    sync doesn't fail just because the seed doesn't expose this yet. The caller
    decides whether to persist an empty list (a 404 means "no info", not
    "nothing revoked")."""
    url = f"{seed_url.rstrip('/')}/revoked"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            raw = json.loads(resp.read())
        if isinstance(raw, dict) and "revoked" in raw:
            return set(raw["revoked"])
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        log.debug("pull_revoked from %s failed: %s", url, e)
    except Exception as e:
        log.debug("pull_revoked from %s failed: %s", url, e)
    return None


def _revoke_path(data_dir: Path) -> Path:
    return data_dir / "revoked.json"


def _save_revoked(data_dir: Path, revoked: set[str]) -> None:
    """Persist a fetched revoke list to the node's data dir."""
    atomic_write(_revoke_path(data_dir),
                 json.dumps({"revoked": sorted(revoked)}, indent=2))


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
        on_policy: "Callable[[dict], bool] | None" = None,
        statements=None,
        get_ca_pubs: "Callable[[], list[bytes]] | None" = None,
        own_id_hex: "str | None" = None,
        attestations=None,
        on_upgrade_hint=None,
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
        # The replicated membership-decision log (StatementLog) plus what its
        # merge gate needs: the trusted-CA set to verify incoming statements
        # against, and this node's own id so a tombstone can never make a node
        # erase ITS OWN record from its own view (which would reset its record
        # seq and wedge renewal republishing — the same self-protection
        # prune_stale grew). None disables statement handling entirely.
        self._statements = statements
        self._get_ca_pubs = get_ca_pubs or list
        self._own_id_hex = own_id_hex
        # Peers' endpoint testimony (attest.AttestLog), merged from pulls so
        # every node's watch can show confirmed-vs-advertised. None disables.
        self._attestations = attestations
        # Called with the anchor's fleet-wide renew hint (renew_after) after each
        # successful pull; the renewal loop decides whether/when to act on it.
        self._on_renew_after = on_renew_after
        # Called with the newest fleet upgrade announcement after each
        # successful pull — a level, like renew_after. The receiver
        # (upgrade.UpgradeManager) owns all policy: opt-in, jitter, backoff.
        self._on_upgrade_hint = on_upgrade_hint
        # Offered the raw signed-policy dict from each pull; the receiver
        # (policy.GrantPolicy.offer) verifies + adopts. Sync stays dumb.
        self._on_policy = on_policy
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
        # Re-merge the cache files first so records — and statements minted by
        # a one-shot CLI (`gw revoke`, `gw set-roles`) into statements.json —
        # are picked up without a daemon restart.
        from .directory import Directory as _Dir
        on_disk = _Dir.load(self._cache_path)
        self._directory.merge(on_disk.all())
        if self._statements is not None:
            from .statements import StatementLog as _SL, statements_path
            disk_stmts = _SL.load(statements_path(self._cache_path.parent),
                                  self._get_ca_pubs())
            self._statements.merge(disk_stmts.all(), self._get_ca_pubs())

        # Shed records that have been expired past the fleet drop deadline —
        # merge() already refuses stale INCOMING records; this drops resident
        # ones that aged out while cached, so a churned fleet's dead nodes leave
        # every node's view without any delete-propagation protocol. Persist it
        # even when the anchor is unreachable (nothing new merges, but the local
        # roster still converges), so this runs before the seed loop's return.
        pruned = self._directory.prune_stale()
        if pruned:
            self._directory.save(self._cache_path)

        for seed in self._get_seeds():
            try:
                (records, renew_after, anchor_now, anchor_domain,
                 policy_dict, stmts, attns) = pull_directory(seed)
                n = self._directory.merge(records)
                dead = self._apply_statements(stmts)
                self._offer_upgrade_hint()
                self._apply_attestations(attns)
                if n or dead:
                    self._directory.save(self._cache_path)
                # Also pull the anchor's revoke list and cache it locally, so
                # regular nodes can mark and evict revoked peers immediately.
                revoked = pull_revoked(seed)
                if revoked is not None:
                    _save_revoked(self._cache_path.parent, revoked)
                log.debug("synced %d records from %s (%d new/updated)", len(records), seed, n)
                self._stamp_sync()   # record a successful pull for `gw watch`
                self._note_anchor_clock(anchor_now)
                self._note_mesh_domain(anchor_domain)
                if self._on_renew_after and renew_after is not None:
                    self._on_renew_after(renew_after)
                if self._on_policy and policy_dict is not None:
                    self._on_policy(policy_dict)
                return
            except RuntimeError as e:
                log.warning("sync from %s failed: %s", seed, e)

    def _offer_upgrade_hint(self) -> None:
        if self._on_upgrade_hint is None or self._statements is None:
            return
        hint = self._statements.upgrade_hint()
        if hint is None:
            return
        try:
            self._on_upgrade_hint(hint)
        except Exception:
            log.exception("upgrade-hint handler failed (sync unaffected)")

    def _apply_attestations(self, attns) -> None:
        if self._attestations is None:
            return
        from .attest import attest_path

        def _known(hex_id: str) -> bool:
            rec = self._directory.get(hex_id)
            if rec is None:
                return False
            try:
                rec.cred.verify(self._get_ca_pubs(), allow_expired=True)
            except ValueError:
                return False
            return True

        changed = self._attestations.merge(attns, _known) if attns else 0
        self._attestations.prune()
        if changed:
            try:
                self._attestations.save(attest_path(self._cache_path.parent))
            except OSError as e:
                log.warning("could not persist attestations: %s", e)

    def _apply_statements(self, stmts) -> int:
        """Merge pulled statements (CA-verified inside the log), persist on
        change, and apply their one node-side effect: dropping records a
        tombstone killed — this is how a `gw leave` or sweep decided at ONE
        holder reaches every view immediately instead of waiting out the
        credential TTL. Returns the number of records dropped."""
        if self._statements is None:
            return 0
        from .statements import statements_path
        changed = 0
        if stmts:
            changed = self._statements.merge(stmts, self._get_ca_pubs())
        self._statements.prune()
        dead = self._statements.drop_dead_records(
            self._directory, protect=self._own_id_hex)
        if changed:
            try:
                self._statements.save(statements_path(self._cache_path.parent))
            except OSError as e:
                log.warning("could not persist statements: %s", e)
        return dead

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


def seconds_since_sync(data_dir) -> "float | None":
    """Age in seconds of the last successful directory sync, or None if the
    daemon has never stamped one. Anchor nodes do not stamp last_sync."""
    last = read_last_sync(data_dir)
    if last is None:
        return None
    try:
        ts = dt.datetime.fromisoformat(last)
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=_UTC)
        return (dt.datetime.now(_UTC) - ts).total_seconds()
    except ValueError:
        return None
