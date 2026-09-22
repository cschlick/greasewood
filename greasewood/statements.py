"""
greasewood.statements — the replicated log of CA-signed membership decisions.

With the anchor-FILE model, anchor duties can run on several holders at once,
so the decisions that used to be one machine's private file edits — revoke a
node, forget a departed node, change a node's caps — become AnchorStatements
(wire.py): CA-signed, carried in /directory next to NodeRecords, merged by
every node, and applied identically everywhere. The credential already IS the
registry entry (hostname, caps, exp all ride in it, replicated in records);
statements cover the three mutations a credential can't express.

Merge model, per (kind, subject id):
  revoke    — monotone: once seen, kept forever (no unrevoke; key rotation is
              the recovery from a wrong revoke, exactly as before).
  tombstone — latest ts wins. Kills records whose credential was issued at or
              before ts; a re-enrollment's fresh credential (iat > ts) is
              untouched, so departed ids can return through the door.
  setcaps   — latest ts wins. Consulted by whichever holder serves the
              subject's next renewal.
  upgrade   — latest ts wins. A fleet release announcement (gw upgrade-all);
              the subject id is the announcing CA's own pub, and nodes act on
              it only when opted in (auto_upgrade). A level, not an edge: an
              offline node sees it when it returns, like the renew hint.

Convergence needs no consensus: statements are individually authentic
(CA-signed), the merge is order-free (set-union + latest-ts), and every party
— holder or plain node — runs the same rules. Two holders deciding about one
id concurrently is the active/active design's accepted race: the later ts
prevails everywhere, and both decisions stay in the audit trail.

Bounding the log: revokes are kept forever (tiny, and the one kind that must
never lapse). A tombstone older than the fleet drop grace is pruned — any
record it could still kill expired long past the grace and was dropped by the
directory's own deadline. A setcaps is pruned once a tombstone or revoke at
or after its ts ends the membership it applied to (a re-enrolled node's caps
come from its new enrollment). An upgrade hint is one slot per CA — tiny,
kept until a newer announcement replaces it (a node at or past the version
simply no-ops on it).
"""
from __future__ import annotations

import datetime as dt
import json
import logging
import threading
from pathlib import Path

from .directory import DROP_GRACE
from .keys import atomic_write
from .wire import AnchorStatement

log = logging.getLogger(__name__)

_UTC = dt.timezone.utc

STATEMENTS_BASENAME = "statements.json"


class StatementLog:
    """Thread-safe, file-backed store of the newest statement per (kind, id)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        # (kind, id_pub_hex) → AnchorStatement (the newest-ts one seen)
        self._stmts: dict[tuple[str, str], AnchorStatement] = {}

    # --- merge / mutate ---

    def merge(self, stmts: "list[AnchorStatement]", ca_pubs: "list[bytes]") -> int:
        """Merge incoming statements, keeping the newest per (kind, id).
        Each must carry a signature from a currently-trusted CA — verified
        HERE, before it can enter the log, so an untrusted statement can never
        be persisted or re-served (mirrors Directory.merge's structural gate).
        Returns the number accepted (new or newer)."""
        accepted = 0
        with self._lock:
            for s in stmts:
                try:
                    s.verify(ca_pubs)
                except ValueError as e:
                    log.debug("statement merge: dropping %s for %s: %s",
                              getattr(s, "kind", "?"), s.id_pub.hex()[:16], e)
                    continue
                key = (s.kind, s.id_pub.hex())
                existing = self._stmts.get(key)
                if existing is None or s.ts > existing.ts:
                    self._stmts[key] = s
                    accepted += 1
        return accepted

    def add(self, stmt: AnchorStatement) -> None:
        """Insert a statement this holder just minted (already signed by the
        local CA key — no verification round-trip needed)."""
        with self._lock:
            key = (stmt.kind, stmt.id_pub.hex())
            existing = self._stmts.get(key)
            if existing is None or stmt.ts >= existing.ts:
                self._stmts[key] = stmt

    # --- queries ---

    def all(self) -> "list[AnchorStatement]":
        with self._lock:
            return list(self._stmts.values())

    def revoked_ids(self) -> "set[str]":
        with self._lock:
            return {i for (k, i) in self._stmts if k == "revoke"}

    def tombstone_ts(self, id_pub_hex: str) -> "dt.datetime | None":
        with self._lock:
            s = self._stmts.get(("tombstone", id_pub_hex))
            return s.ts if s else None

    def caps_override(self, id_pub_hex: str) -> "tuple[list[str], dt.datetime] | None":
        """The operator's latest caps decision for this id, or None."""
        with self._lock:
            s = self._stmts.get(("setcaps", id_pub_hex))
            return (list(s.caps), s.ts) if s else None

    def upgrade_hint(self) -> "AnchorStatement | None":
        """The newest fleet upgrade announcement (gw upgrade-all), or None.
        Keyed per announcing CA like every statement; across CAs (a re-root's
        overlap window) the latest ts wins, same as concurrent holders."""
        with self._lock:
            hints = [s for (k, _), s in self._stmts.items() if k == "upgrade"]
        return max(hints, key=lambda s: s.ts) if hints else None

    def is_dead(self, id_pub_hex: str, cred_iat: dt.datetime) -> bool:
        """Does a tombstone end the membership a credential with this iat
        belongs to? (iat AFTER the tombstone = a re-enrollment; alive.)"""
        ts = self.tombstone_ts(id_pub_hex)
        return ts is not None and cred_iat <= ts

    def size(self) -> int:
        with self._lock:
            return len(self._stmts)

    # --- effects ---

    def drop_dead_records(self, directory, protect: "str | None" = None) -> int:
        """Evict directory records killed by a tombstone (cred issued at or
        before it). Run after every merge, on holders and plain nodes alike —
        this is how a leave/sweep decided at ONE holder reaches every view.
        `protect` mirrors Directory.prune_stale's self-protection."""
        dropped = 0
        for r in directory.all():
            hex_id = r.id_pub.hex()
            if hex_id == protect:
                continue
            if self.is_dead(hex_id, r.cred.iat):
                if directory.remove(hex_id):
                    dropped += 1
        return dropped

    # --- lifetime ---

    def prune(self, now: "dt.datetime | None" = None) -> int:
        """Apply the bounding rules from the module docstring. Returns the
        number pruned. Revokes are never pruned."""
        now = now or dt.datetime.now(_UTC)
        with self._lock:
            doomed = []
            for (kind, hex_id), s in self._stmts.items():
                if kind == "tombstone" and now >= s.ts + DROP_GRACE:
                    doomed.append((kind, hex_id))
                elif kind == "setcaps":
                    tomb = self._stmts.get(("tombstone", hex_id))
                    ended = (tomb is not None and tomb.ts >= s.ts) \
                        or ("revoke", hex_id) in self._stmts
                    if ended:
                        doomed.append((kind, hex_id))
            for key in doomed:
                del self._stmts[key]
        return len(doomed)

    # --- persistence (same discipline as Directory) ---

    def save(self, path: Path) -> None:
        with self._lock:
            data = [s.to_dict() for s in self._stmts.values()]
            # 0644: statements are public, CA-signed facts — the same trust
            # class as the directory cache, and no-root status readers want them.
            atomic_write(path, json.dumps(data, indent=2), mode=0o644)

    @classmethod
    def load(cls, path: Path, ca_pubs: "list[bytes]") -> "StatementLog":
        """Load from disk, re-verifying every entry against the CURRENT trusted
        set — a statement whose CA was dropped from trusted_pubs (a completed
        re-root) dies here rather than living on from the cache."""
        logf = cls()
        if not path.exists():
            return logf
        try:
            raw = json.loads(path.read_text())
        except Exception as e:
            log.warning("statement cache unreadable, starting empty: %s", e)
            return logf
        stmts = []
        for d in raw if isinstance(raw, list) else []:
            try:
                stmts.append(AnchorStatement.from_dict(d))
            except Exception as e:
                log.warning("skipping one corrupt cached statement: %s", e)
        logf.merge(stmts, ca_pubs)
        return logf


def statements_path(data_dir) -> Path:
    return Path(data_dir) / STATEMENTS_BASENAME
