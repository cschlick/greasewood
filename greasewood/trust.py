"""
greasewood.trust — the trusted-CA set and how it migrates (§11).

A node bootstraps trust from a static set of root CA public keys (config
[ca] trusted_pubs). From there the set grows and shrinks at runtime through
signed CAStatements distributed in a CABundle, so hub/CA status can move from
node to node — indefinitely, all N nodes taking a turn — with zero config edits
and no private key ever moving.

Resolution (resolve_trust):

  1. Transitive closure of endorsements. Starting from the roots, a CA Y is
     "ever-trusted" if some ever-trusted CA X endorsed it. This is what lets a
     node rooted at A trust the whole chain A -> B -> C -> ... down to the
     current hub, long after A stopped serving.

  2. A retired CA's past statements remain valid, but it cannot make new ones
     of EITHER kind. A statement by X only counts if it was issued before X was
     retired: an endorsement (endorse.iat < X's retirement) or a retirement
     (retire.iat <= X's own retirement). So a successor survives its
     predecessor's retirement, but a decommissioned hub's leaked key can
     neither inject a fresh rogue CA nor retire the live hub to DoS the fleet.
     (The retirement guard is the symmetric twin of the endorsement guard —
     without it a leaked retired key could un-trust the current hub everywhere.)

  3. Active set = ever-trusted minus retired. Only active CAs may sign
     credentials a node will accept.

Durability: endorsements are meant to be long-lived (the chain must stay
intact for old nodes); retirements likewise persist. `now`-based expiry is a
safety bound, not the migration mechanism — the overlap window is controlled
operationally by when the operator runs endorse vs. retire.
"""
from __future__ import annotations

import datetime as dt
import json
import logging
import threading
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

from .wire import CAStatement

log = logging.getLogger(__name__)
_UTC = dt.timezone.utc


@dataclass
class CABundle:
    """A de-duplicated collection of signed CAStatements, served by the hub
    and cached by every node alongside the directory."""
    statements: list[CAStatement] = field(default_factory=list)

    def merge(self, incoming: list[CAStatement]) -> int:
        """Add statements not already present (identity = signature). Returns
        the count actually added. Invalidly-signed statements are dropped."""
        have = {s.ident() for s in self.statements}
        added = 0
        for s in incoming:
            try:
                s.verify_sig()
            except ValueError:
                continue
            if s.ident() not in have:
                self.statements.append(s)
                have.add(s.ident())
                added += 1
        return added

    def to_dict(self) -> dict:
        return {"v": 1, "statements": [s.to_dict() for s in self.statements]}

    @classmethod
    def from_dict(cls, d: dict) -> "CABundle":
        out = cls()
        for sd in d.get("statements", []):
            try:
                out.statements.append(CAStatement.from_dict(sd))
            except Exception:
                continue
        return out

    @classmethod
    def load(cls, path: Path) -> "CABundle":
        if not path.exists():
            return cls()
        try:
            return cls.from_dict(json.loads(path.read_text()))
        except Exception:
            return cls()

    def save(self, path: Path) -> None:
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(json.dumps(self.to_dict(), indent=2))
        tmp.replace(path)


def _now() -> dt.datetime:
    return dt.datetime.now(_UTC)


def resolve_trust(
    roots: set[bytes],
    bundle: CABundle,
    now: dt.datetime | None = None,
) -> set[bytes]:
    """
    Return the set of CA public keys (raw bytes) a node should currently
    accept credential signatures from, given its static roots and the bundle.

    See module docstring for the model: transitive endorsement closure, then
    subtract retirements, honoring the rule that a CA cannot endorse after it
    was retired.
    """
    now = now or _now()
    valid = [s for s in bundle.statements if s.is_valid_at(now)]
    endorsements = [s for s in valid if s.kind == "endorse"]
    retirements = [s for s in valid if s.kind == "retire"]

    roots = set(roots)
    ever = set(roots)
    retired_at: dict[bytes, dt.datetime] = {}

    # Fixpoint: `ever` (who has ever been legitimately trusted) and the
    # effective retirement times are mutually dependent, so iterate until
    # stable. Each outer pass recomputes effective retirements from the current
    # `ever`, then rebuilds the endorsement closure honoring those times.
    while True:
        # Effective retirements: a retirement counts only if its issuer is
        # ever-trusted AND was not itself retired before it signed. This is the
        # symmetric guard to the endorsement rule below — it stops a leaked,
        # already-retired key from retiring (un-trusting) the live hub. Compute
        # by shrinking the candidate set until stable (monotonic → terminates).
        eff = [s for s in retirements if s.by_pub in ever]
        while True:
            retired_at = {}
            for s in eff:
                cur = retired_at.get(s.subject_pub)
                if cur is None or s.iat < cur:
                    retired_at[s.subject_pub] = s.iat
            # Drop a retirement whose issuer was retired strictly before it was
            # issued (<=, so a CA may always retire itself: rt == s.iat keeps it).
            new_eff = [
                s for s in eff
                if retired_at.get(s.by_pub) is None or s.iat <= retired_at[s.by_pub]
            ]
            if len(new_eff) == len(eff):
                break
            eff = new_eff

        new_ever = set(roots)
        changed = True
        while changed:
            changed = False
            for s in endorsements:
                if s.by_pub in new_ever and s.subject_pub not in new_ever:
                    rt = retired_at.get(s.by_pub)
                    # endorsement only counts if made before the endorser's
                    # retirement (roots, never retired, always count)
                    if rt is None or s.iat < rt:
                        new_ever.add(s.subject_pub)
                        changed = True

        if new_ever == ever:
            break
        ever = new_ever

    # Subjects with an effective retirement are out of the active set.
    return ever - set(retired_at)


def active_hub_endpoint(
    roots: set[bytes],
    bundle: CABundle,
    now: dt.datetime | None = None,
) -> str | None:
    """
    The control-plane URL a node should currently treat as "the hub": the most
    recently endorsed, still-active CA that advertised an endpoint. Returns None
    if no endorsement carries an endpoint (caller falls back to configured
    root_url — i.e. the original hub).
    """
    now = now or _now()
    active = resolve_trust(roots, bundle, now)
    best: CAStatement | None = None
    for s in bundle.statements:
        if (s.kind == "endorse" and s.hub_endpoint and s.is_valid_at(now)
                and s.subject_pub in active):
            if best is None or s.iat > best.iat:
                best = s
    return best.hub_endpoint if best else None


# ---------------------------------------------------------------------------
# Runtime: live trust state + distribution
# ---------------------------------------------------------------------------

def fetch_ca_bundle(hub_url: str, timeout: float = 10.0) -> list[CAStatement]:
    """GET {hub_url}/ca-bundle and parse it into statements."""
    url = f"{hub_url.rstrip('/')}/ca-bundle"
    with urllib.request.urlopen(url, timeout=timeout) as resp:
        raw = json.loads(resp.read())
    out: list[CAStatement] = []
    for sd in raw.get("statements", []):
        try:
            out.append(CAStatement.from_dict(sd))
        except Exception:
            continue
    return out


class TrustStore:
    """
    Thread-safe holder of a node's live trust state: static roots + the CA
    bundle. Everything that needs "who do I currently trust?" / "where is the
    hub?" reads from here, so trust can change at runtime as the bundle syncs.
    """

    def __init__(
        self,
        roots: list[bytes],
        bundle: "CABundle",
        bundle_path: Path,
        static_seeds: list[str] | None = None,
        fallback_hub_url: str = "",
    ) -> None:
        self._roots = set(roots)
        self._bundle = bundle
        self._path = bundle_path
        self._static_seeds = list(static_seeds or [])
        self._fallback = fallback_hub_url
        self._lock = threading.Lock()

    def trusted_pubs(self) -> list[bytes]:
        with self._lock:
            return list(resolve_trust(self._roots, self._bundle))

    def hub_url(self) -> str:
        with self._lock:
            ep = active_hub_endpoint(self._roots, self._bundle)
        return ep or self._fallback

    def seeds(self) -> list[str]:
        """Directory seeds = static seeds plus the current hub, de-duplicated.

        INVARIANT: seeds are hubs only — the configured hub URL(s) plus the
        active hub advertised via SIGNED CA endorsements (a successor hub). The
        directory (peer NodeRecords) is NEVER scraped into this list: the hub is
        the single source of truth for the directory, and an ordinary node can
        never become a seed. Do not add directory-derived / auto-discovered
        endpoints here.
        """
        hub = self.hub_url()
        out = list(self._static_seeds)
        if hub and hub not in out:
            out.append(hub)
        return out

    def bundle_dict(self) -> dict:
        with self._lock:
            return self._bundle.to_dict()

    def merge(self, statements: list[CAStatement]) -> int:
        with self._lock:
            n = self._bundle.merge(statements)
            if n:
                self._bundle.save(self._path)
            return n

    def refresh_from_disk(self) -> int:
        """Re-read the on-disk bundle and merge it — picks up local
        hub-endorse / hub-retire writes without a daemon restart."""
        return self.merge(CABundle.load(self._path).statements)


class TrustSyncLoop:
    """Pulls the CA bundle from the current hub and re-reads local writes,
    keeping the TrustStore current. Mirror of SyncLoop for the trust set."""

    def __init__(self, store: TrustStore, interval: float = 20.0) -> None:
        self._store = store
        self._interval = interval
        self._stop = threading.Event()

    def _tick(self) -> None:
        self._store.refresh_from_disk()
        url = self._store.hub_url()
        if not url:
            return
        try:
            stmts = fetch_ca_bundle(url)
        except (urllib.error.URLError, json.JSONDecodeError, OSError) as e:
            log.debug("trust sync from %s failed: %s", url, e)
            return
        n = self._store.merge(stmts)
        if n:
            log.info("trust: merged %d new CA statement(s) from %s", n, url)

    def run(self) -> None:
        while not self._stop.wait(self._interval):
            try:
                self._tick()
            except Exception as e:  # noqa: BLE001
                log.error("trust sync loop error: %s", e)

    def start(self) -> threading.Thread:
        t = threading.Thread(target=self.run, name="trust-sync", daemon=True)
        t.start()
        return t

    def stop(self) -> None:
        self._stop.set()
