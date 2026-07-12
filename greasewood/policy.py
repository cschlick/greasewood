"""
greasewood.policy — roles, grants, and the derived tunnel topology.

The mesh's access policy is a single allow-only grant table (grants.toml on
the anchor → CA-signed GrantTable → distributed via directory sync). Grants
are sentences about ROLES — `from = ["web"], to = ["api"], ports = ["tcp/8000"]`
— where a role is a CA-signed cap (`role:web`), anchor-assigned, never
self-asserted. Roles are the ONLY configured vocabulary; "segments" are the
emergent, unnamed structure the grant graph produces (nodes a grant connects
share one), reported by `gw watch`, configured by nothing.

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

  2. With NO table at all, every verified member peers — the flat trusted
     mesh (implicitly `* -> * : *`). A fresh mesh needs no policy file;
     roles are inert until a table exists.

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

# Roles are THE configured vocabulary. "Segments" are not caps at all — they
# are the emergent, unnamed connectivity structure the grant graph produces
# (role:client and role:server nodes granted an interface share an unnamed
# segment; delete the grant and it dissolves). `gw watch` reports them;
# nothing configures them.
_TAG_PREFIXES = ("role:",)

POLICY_BASENAME = "policy.json"      # the signed table (anchor: source; node: cache)
GRANTS_BASENAME = "grants.toml"      # the human-authored file (anchor only)

# Roles the anchor self-assigns at `gw create` and NEVER hands to anyone else.
# Enforced on every assignment path (invite --roles/--self-roles, set-roles,
# set-caps) so they can't be acquired by a joiner or node:
#   '*'      — reach-all; the anchor peers with everyone.
#   'anchor' — the single-member role that names the anchor in grants (e.g.
#              `to = ["anchor"]`). Reserving assignment is what keeps it to ONE
#              member: only the create-time anchor ever holds it.
RESERVED_ROLES = ("*", "anchor")


# The starting grants.toml `gw create` drops on a new anchor. DEFAULT-CLOSED:
# the shipped policy is a secure star — only `role:admin` (the anchor, by
# default) can SSH nodes; nodes reach only the anchor's control plane and can't
# reach each other. Alternatives (fully open, lateral SSH, ...) ship commented,
# so the operator sees the whole menu and picks rather than starting blind.
DEFAULT_GRANTS_TOML = """\
# greasewood grant table — the mesh's access policy.
#
# A grant is a sentence about ROLES:  from = [...] -> to = [...] : ports = [...]
# A flow is allowed iff some grant covers it; there is NO deny rule — you omit
# the grant instead. Grants govern BOTH which tunnels exist and which ports are
# open. A node with no inbound grant is reachable by no one, yet is NOT isolated:
# it can still DIAL OUT to anything it has a `from <me> -> to <them>` grant for
# (replies ride the established tunnel).
#
# Roles (assigned by the anchor at `gw invite`):
#   node    — every ordinary member (the default role for new nodes)
#   anchor  — the single anchor host; reserved, never assignable to a joiner
#             (the anchor is its sole member), addressable here as `to=["anchor"]`
#   admin   — terminal-access: hold it to SSH every node. The anchor holds it by
#             default; tag any box `role:admin` to add an operator workstation.
#
# ALWAYS ON, hardwired, NOT editable here (policy must never be able to sever
# the channel that distributes policy):
#   * every node <-> anchor, tcp/51902   — the control plane (carries THIS file)
#   * the enrollment door,   tcp/51903   — join-time only
#   * established/related replies, and ICMPv6
#
# Edit below, then:  sudo gw policy apply  (previews tunnel changes, signs with
# the CA key, publishes). Changes take effect ONLY after apply.

# --- Active policy | DEFAULT-CLOSED: only admin gets a terminal --------------
# A fresh mesh is a secure star: the anchor (role:admin) can SSH every node,
# nodes reach only the anchor's control plane, and nodes cannot reach EACH OTHER
# at all. Open real services by adding role-to-role grants (see the example).
[[grant]]
from  = ["admin"]
to    = ["anchor", "node"]
ports = ["tcp/22"]

# --- Other baselines | uncomment one to REPLACE the grant above -------------
#
# ALLOW EVERYTHING (flat mesh — every node reaches every node on every port;
# identical to running with no policy at all, just written out):
#   [[grant]]
#   from  = ["*"]
#   to    = ["*"]
#   ports = ["*"]
#
# SSH BETWEEN ALL NODES (lateral SSH — any node may SSH any other; looser than
# admin-only, it permits node-to-node movement):
#   [[grant]]
#   from  = ["node"]
#   to    = ["node", "anchor"]
#   ports = ["tcp/22"]
#
# ALLOW NOTHING is not a grant you write — it's the ABSENCE of grants. Delete
# every [[grant]] and nodes reach ONLY the anchor (the hardwired control plane):
# no admin terminal, no services. Rarely what you want.

# --- Example service grant (add alongside the active one) -------------------
# web + worker nodes may reach an api node on 8000:
#   [[grant]]
#   from  = ["web", "worker"]
#   to    = ["api"]
#   ports = ["tcp/8000"]
"""


def node_tags(caps: list) -> set:
    """The roles a node holds — its role: caps, prefix stripped. Includes '*'
    if the node holds the wildcard role (the anchor)."""
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

    Hardwired first, beneath any table: the anchor ('*' role on either side)
    peers with everyone — the control plane is never prunable by policy.
    Then: NO table → the flat trusted mesh (every verified member peers; the
    implicit policy is `* -> * : *`, so a fresh mesh needs no file). With a
    table → a link exists iff some grant connects the two nodes' roles in
    either direction. Roles never create connectivity by themselves; only
    grants (or the absence of any policy) do.
    """
    local, peer = node_tags(local_caps), node_tags(peer_caps)
    if "*" in local or "*" in peer:
        return True
    if grants is None:
        return True          # no policy → flat mesh among verified members
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
        self._cache_mtime = None
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

    def refresh_from_cache(self) -> bool:
        """Reload policy.json if it changed on disk (mtime-guarded) — how the
        ANCHOR's own data plane picks up a `gw policy apply` (the anchor has no
        seeds to sync from, so the sync path doesn't feed it). Seq-monotonic via
        offer(). Returns True if a newer table was adopted. Cheap: a stat + a
        read only when the file actually changed."""
        if self._cache_path is None:
            return False
        try:
            mtime = self._cache_path.stat().st_mtime
        except FileNotFoundError:
            return False
        if mtime == self._cache_mtime:
            return False
        self._cache_mtime = mtime
        try:
            return self.offer(json.loads(self._cache_path.read_text()))
        except (OSError, ValueError) as e:
            log.warning("policy cache reload failed: %s", e)
            return False

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


class AnchorPolicySigner:
    """Anchor-only: keeps the signed, distributed policy.json in step with the
    human-edited grants.toml. grants.toml is the SOURCE OF TRUTH; this signs it
    (with the CA key) into policy.json — the CA-signed form nodes actually
    receive and trust (a node can't trust raw grants.toml from another host).

    refresh() is cheap and idempotent: it re-signs only when grants.toml's
    CONTENT changed (mtime-guarded to skip re-parsing), bumping the seq. A
    malformed grants.toml is logged and IGNORED — the last good signed policy
    keeps serving; the daemon never reverts to open or crashes on a bad edit.
    This is what makes 'edit grants.toml' take effect with no manual step; the
    trade vs `gw policy apply` is that there's no pre-change preview, so the
    applied delta is logged instead."""

    def __init__(self, data_dir: "Path", ca_keys, get_records=None) -> None:
        self._grants_path = Path(data_dir) / GRANTS_BASENAME
        self._policy_path = Path(data_dir) / POLICY_BASENAME
        self._ca_priv = ca_keys.ca_priv
        self._get_records = get_records or (lambda: [])
        self._mtime = None                        # grants.toml mtime last parsed

    def _current(self) -> "GrantTable | None":
        """The signed policy currently on disk (policy.json) — the authority for
        both seq and grants. Reading it every refresh (rather than caching in
        memory) means a manual `gw policy apply` and this signer can never
        disagree about the sequence number: whoever wrote policy.json last set
        it, and the signer only bumps when grants.toml's CONTENT differs."""
        try:
            return GrantTable.from_dict(json.loads(self._policy_path.read_text()))
        except (FileNotFoundError, ValueError, KeyError, OSError):
            return None

    def refresh(self, offer_to=None) -> "dict | None":
        """Return the current signed policy dict (for /directory), re-signing
        from grants.toml first if the file changed. offer_to (a GrantPolicy) is
        updated in place so the anchor's OWN data plane tracks grants.toml live."""
        current = self._current()
        try:
            mtime = self._grants_path.stat().st_mtime
        except FileNotFoundError:
            # No grants.toml → no source to sign; serve whatever policy.json holds
            # (create writes the default, so a live anchor rarely lacks it).
            return current.to_dict() if current else None
        if mtime == self._mtime and current is not None:
            return current.to_dict()              # grants.toml unchanged → serve on-disk

        try:
            grants = parse_grants_toml(self._grants_path.read_text())
        except (ValueError, OSError) as e:
            log.warning("grants.toml invalid — keeping the last signed policy "
                        "(v%s); fix it and it auto-applies: %s",
                        current.seq if current else "none", e)
            self._mtime = mtime                    # don't re-warn until next edit
            return current.to_dict() if current else None

        self._mtime = mtime
        if current is not None and grants == current.grants:
            return current.to_dict()              # no real change

        seq = (current.seq + 1) if current else 1
        table = GrantTable(seq=seq, grants=grants).sign(self._ca_priv)
        atomic_write(self._policy_path, json.dumps(table.to_dict(), indent=2),
                     mode=0o644)
        created, removed = tunnel_delta(
            self._get_records(), current.grants if current else None, grants)
        log.info("auto-applied grants.toml → policy v%d (%d grant(s); "
                 "+%d/-%d tunnels)", seq, len(grants), len(created), len(removed))
        if offer_to is not None:
            offer_to.offer(table.to_dict())
        return table.to_dict()


def sign_default_policy(data_dir: "Path", ca_keys) -> None:
    """`gw create`: sign the freshly-written default grants.toml into policy.json
    v1, so a new anchor has a real, signed, explicit policy from birth (not an
    implicit fallback). No-op if grants.toml is absent."""
    signer = AnchorPolicySigner(data_dir, ca_keys)
    signer.refresh()


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


def unapplied_edits(data_dir) -> str:
    """A short summary if the anchor's grants.toml differs from the applied,
    signed policy.json — i.e. edits made but not yet `gw policy apply`d — else
    "". Surfaced at daemon startup and in `gw policy show` so a forgotten apply
    is visible rather than a silently-ineffective edit."""
    from pathlib import Path as _P
    gp, pp = _P(data_dir) / GRANTS_BASENAME, _P(data_dir) / POLICY_BASENAME
    if not gp.exists():
        return ""
    try:
        pending = parse_grants_toml(gp.read_text())
    except (ValueError, OSError):
        return "grants.toml is currently invalid"
    applied = None
    if pp.exists():
        try:
            applied = GrantTable.from_dict(json.loads(pp.read_text())).grants
        except (ValueError, KeyError, OSError):
            applied = None
    if pending == applied:
        return ""
    added = [g for g in pending if g not in (applied or [])]
    removed = [g for g in (applied or []) if g not in pending]
    return f"+{len(added)}/-{len(removed)} grant(s) vs the applied policy"


def render_grants(table: "GrantTable | None") -> str:
    """The compact arrow form for `gw policy show` (display-only — nothing
    parses this back)."""
    if table is None:
        return ("policy: default — everything open (implicitly `* -> * : *`); "
                "every verified member tunnels with every other. Write "
                "grants.toml + `gw policy apply` to tighten (the topology then "
                "derives from roles).")
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
