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

  2. A retired CA's past endorsements remain valid, but it cannot make new
     ones. An endorsement by X only counts if it was issued before X was
     retired (endorse.iat < X's retirement). So a successor survives its
     predecessor's retirement, but a decommissioned hub's leaked key cannot
     inject a fresh rogue CA.

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
from dataclasses import dataclass, field
from pathlib import Path

from .wire import CAStatement

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

    # Fixpoint: `ever` (who has ever been legitimately trusted) and the
    # retirement times of endorsers are mutually dependent, so iterate until
    # stable. Each outer pass recomputes retirement times from the current
    # `ever`, then rebuilds the endorsement closure honoring those times.
    while True:
        retired_at: dict[bytes, dt.datetime] = {}
        for s in retirements:
            if s.by_pub in ever:
                cur = retired_at.get(s.subject_pub)
                if cur is None or s.iat < cur:
                    retired_at[s.subject_pub] = s.iat

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

    retired = {s.subject_pub for s in retirements if s.by_pub in ever}
    return ever - retired


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
