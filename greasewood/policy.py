"""
greasewood.policy — roles, grants, and the derived tunnel topology.

The mesh's access policy is a single allow-only grant table (grants.toml on
the anchor → CA-signed GrantTable → distributed via directory sync). Grants
are sentences about ROLES — `from = ["web"], to = ["api"], ports = ["tcp/8000"]`
— where a role is just a CA-signed cap (`role:web`), the same mechanism as
segments. `segment:X` and `role:X` are one vocabulary here: both contribute
the tag `X`, so existing fleets' segment caps work in grants unchanged.

The table DERIVES the tunnel topology: a WireGuard peer link exists between
two nodes iff some grant connects their tags, in either direction (tunnels
are symmetric; the grant's direction matters to the port filter, not to link
existence). Tunnels are therefore minimal by construction — the peer graph is
the projection of the policy, never a link wider.

Two rules live BENEATH the table, in code, deliberately not expressible or
deletable in grants.toml:

  1. Every node always peers with the anchor (a node holding the `*` tag).
     The policy rides the directory sync, which rides the anchor tunnel — the
     channel that carries the policy must never be prunable BY the policy,
     or one bad edit bricks the fleet (nodes could never receive the fix).

  2. With NO table at all, peering falls back to legacy segment intersection
     (today's flat-mesh behavior, byte-for-byte). A fresh mesh needs no
     policy file; `role:` tags are inert until a table exists.

Adoption is monotonic: nodes accept a table only with a higher seq than the
one they hold (and a valid CA signature), and keep last-known-good on disk —
same posture as the directory cache.
"""
from __future__ import annotations

import json
import logging
import threading
from pathlib import Path

from .keys import atomic_write
from .wire import GrantTable, _validate_grant

log = logging.getLogger(__name__)

# Both cap prefixes contribute to one tag vocabulary (segment:db ≡ role:db for
# policy purposes). Segments keep their legacy no-table meaning; roles are the
# go-forward name for grant vocabulary.
_TAG_PREFIXES = ("segment:", "role:")

POLICY_BASENAME = "policy.json"      # the signed table (anchor: source; node: cache)
GRANTS_BASENAME = "grants.toml"      # the human-authored file (anchor only)


def node_tags(caps: list) -> set:
    """The policy tags a node holds — its segment: and role: caps, prefix
    stripped, one namespace. Includes '*' if the node holds a wildcard cap
    (the anchor)."""
    return {c.split(":", 1)[1] for c in caps if c.startswith(_TAG_PREFIXES)}


def parse_grants_toml(text: str) -> list:
    """grants.toml text → normalized grant list. Raises ValueError with a
    line-addressable message on anything malformed. Allow-only by schema:
    there is no action/deny key to parse."""
    import tomllib
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as e:
        raise ValueError(f"grants.toml: invalid TOML — {e}") from None
    unknown = set(data) - {"grant"}
    if unknown:
        raise ValueError(f"grants.toml: unknown top-level key(s) {sorted(unknown)} "
                         f"(only [[grant]] tables are allowed)")
    raw = data.get("grant", [])
    if not isinstance(raw, list):
        raise ValueError("grants.toml: [[grant]] must be an array of tables")
    return [_validate_grant(g, i) for i, g in enumerate(raw)]


def _grant_connects(grant: dict, a_tags: set, b_tags: set) -> bool:
    """Does this grant authorize a flow from a → b? '*' in from/to matches
    any node."""
    src_match = "*" in grant["from"] or a_tags & set(grant["from"])
    dst_match = "*" in grant["to"] or b_tags & set(grant["to"])
    return bool(src_match and dst_match)


def peers_allowed(local_caps: list, peer_caps: list,
                  grants: "list | None") -> bool:
    """THE tunnel-existence decision (used as reconcile's step-6 policy).

    Hardwired first, beneath any table: the anchor ('*' tag on either side)
    peers with everyone — the control plane is never prunable by policy.
    Then: no table → legacy segment intersection; with a table → a link exists
    iff some grant connects the two nodes' tags in either direction.
    """
    local, peer = node_tags(local_caps), node_tags(peer_caps)
    if "*" in local or "*" in peer:
        return True
    if grants is None:
        # Legacy flat mesh: shared segment = tunnel, all ports. Note roles are
        # deliberately NOT rooms — only segment: caps peer in this mode.
        from .reconcile import default_policy
        return default_policy(local_caps, peer_caps)
    return any(_grant_connects(g, local, peer) or _grant_connects(g, peer, local)
               for g in grants)


class GrantPolicy:
    """The daemon's live view of the grant table: a thread-safe holder that is
    ALSO reconcile's policy callable. The sync loop offers newly-pulled tables
    (verified + seq-monotonic before adoption); reconcile calls it per peer
    pair each cycle. Keeps last-known-good on disk so a reboot doesn't regress
    to the flat mesh while the anchor is unreachable."""

    def __init__(self, cache_path: "Path | None" = None,
                 get_ca_pubs=None) -> None:
        self._cache_path = Path(cache_path) if cache_path else None
        self._get_ca_pubs = get_ca_pubs or (lambda: [])
        self._table: "GrantTable | None" = None
        self._lock = threading.Lock()

    @property
    def table(self) -> "GrantTable | None":
        with self._lock:
            return self._table

    def __call__(self, local_caps: list, peer_caps: list) -> bool:
        table = self.table
        return peers_allowed(local_caps, peer_caps,
                             table.grants if table else None)

    def load_cache(self) -> None:
        """Adopt the on-disk last-known-good table, if any (verified — the
        cache is only as trustworthy as its signature, same as records)."""
        if self._cache_path is None or not self._cache_path.exists():
            return
        try:
            table = GrantTable.from_dict(json.loads(self._cache_path.read_text()))
            table.verify(self._get_ca_pubs())
        except Exception as e:
            log.warning("policy cache unusable, ignoring: %s", e)
            return
        with self._lock:
            self._table = table
        log.info("policy v%d loaded (%d grants)", table.seq, len(table.grants))

    def offer(self, policy_dict: "dict | None") -> bool:
        """A freshly-synced policy dict from the anchor. Adopt iff it parses,
        carries a trusted CA signature, and its seq EXCEEDS what we hold
        (monotonic — an old table can't be replayed to reopen a deleted
        grant). Returns True if adopted."""
        if not policy_dict:
            return False
        try:
            table = GrantTable.from_dict(policy_dict)
            table.verify(self._get_ca_pubs())
        except (ValueError, KeyError, TypeError) as e:
            log.warning("rejected synced policy: %s", e)
            return False
        with self._lock:
            if self._table is not None and table.seq <= self._table.seq:
                return False
            self._table = table
        if self._cache_path is not None:
            try:
                atomic_write(self._cache_path,
                             json.dumps(table.to_dict(), indent=2), mode=0o644)
            except OSError as e:
                log.warning("could not persist policy cache: %s", e)
        log.info("policy v%d adopted (%d grants) — topology follows on this "
                 "reconcile cycle", table.seq, len(table.grants))
        return True


def tunnel_delta(records, old_grants: "list | None",
                 new_grants: "list | None"):
    """(created, removed) tunnel pairs a policy change would cause, as
    (hostname_a, hostname_b) tuples — what `gw policy apply` shows before
    asking. Compares peers_allowed over every record pair under both tables."""
    created, removed = [], []
    recs = list(records)
    for i, a in enumerate(recs):
        for b in recs[i + 1:]:
            before = peers_allowed(a.cred.caps, b.cred.caps, old_grants)
            after = peers_allowed(a.cred.caps, b.cred.caps, new_grants)
            if after and not before:
                created.append((a.hostname, b.hostname))
            elif before and not after:
                removed.append((a.hostname, b.hostname))
    return created, removed


def unmatched_tags(grants: list, records) -> set:
    """Grant tags that NO current node holds — usually a typo'd role. A grant
    naming one fails closed and silently, so `gw policy apply` warns."""
    held = set()
    for r in records:
        held |= node_tags(r.cred.caps)
    named = set()
    for g in grants:
        named |= set(g["from"]) | set(g["to"])
    return {t for t in named - held if t != "*"}


def render_grants(table: "GrantTable | None") -> str:
    """The compact arrow form for `gw policy show` (display-only — nothing
    parses this back)."""
    if table is None:
        return ("no policy — legacy peering: nodes tunnel iff they share a "
                "segment (all ports)")
    if not table.grants:
        return (f"policy v{table.seq}: EMPTY — no grants; only anchor tunnels "
                f"exist")
    src_w = max(len(", ".join(g["from"])) for g in table.grants)
    dst_w = max(len(", ".join(g["to"])) for g in table.grants)
    lines = [f"policy v{table.seq} · {len(table.grants)} grant(s) · "
             f"allow-only (a flow passes iff some grant covers it)"]
    for g in table.grants:
        lines.append(f"  {', '.join(g['from']):<{src_w}} -> "
                     f"{', '.join(g['to']):<{dst_w}} : {', '.join(g['ports'])}")
    lines.append("  (hardwired, not editable: every node <-> anchor)")
    return "\n".join(lines)
