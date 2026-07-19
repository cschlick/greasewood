"""
greasewood.policy — roles, grants, and the derived tunnel topology.

The mesh's access policy is a single allow-only grant table (grants.toml on
the anchor → CA-signed GrantTable → distributed via directory sync). Grants
are sentences about TAGS — `from = ["web"], to = ["api"], ports = ["tcp/8000"]`
— where a tag is a role (a CA-signed cap `role:web`, anchor-assigned, never
self-asserted) or a specific machine by its CA-attested hostname
(`host:nas` — derived at match time from the credential's hostname field,
never stored or assignable as a cap; see node_tags). Roles and host names are
the ONLY configured vocabulary; "segments" are the emergent, unnamed
structure the grant graph produces (nodes a grant connects share one),
reported by `gw watch`, configured by nothing.

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
# A grant is a sentence about TAGS:  from = [...] -> to = [...] : ports = [...]
# A flow is allowed iff some grant covers it; there is NO deny rule — you omit
# the grant instead. Grants govern BOTH which tunnels exist and which ports are
# open. A node with no inbound grant is reachable by no one, yet is NOT isolated:
# it can still DIAL OUT to anything it has a `from <me> -> to <them>` grant for
# (replies ride the established tunnel).
#
# An entry in from/to is a ROLE name, `host:<name>` (ONE machine, by its
# CA-attested hostname — e.g. from = ["host:bb"], to = ["host:nas"]; pin any
# name you grant by: `gw invite --hostname <name>`), or '*' (every node).
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

# --- Declarative role assignments (optional) --------------------------------
# Add an [assign] table and this file also declares who HOLDS which roles —
# `gw policy apply` reconciles listed hosts to it (with a preview), listed
# hosts refuse imperative `gw set-roles`, and the `gw watch` role editor
# writes this table. Unlisted hosts (and meshes without the section) keep
# today's imperative flow. Full reference: grants.toml.example.
#   [assign]
#   nas = ["nfs_srv"]
#   bb  = ["nfs_usr"]
"""


def node_tags(caps: list, hostname: "str | None" = None) -> set:
    """The grant-matchable tags a node holds: its role: caps (prefix stripped —
    includes '*' for the anchor), PLUS the derived `host:<hostname>` tag when a
    hostname is given. The host tag is never stored anywhere — it is derived
    at match time from the CA-signed credential's hostname field, so it rides
    the same trust chain as a role without being assignable, revocable, or
    forgeable as a cap. A role-derived tag containing ':' is DROPPED: a role
    cap must never be able to smuggle a `host:`-namespaced tag (a role named
    'host:nas' would otherwise impersonate a host grant target)."""
    tags = set()
    for c in caps:
        if c.startswith(_TAG_PREFIXES):
            t = c.split(":", 1)[1]
            if ":" not in t:
                tags.add(t)
    if hostname:
        tags.add(f"host:{hostname}")
    return tags


def parse_grants_toml(text: str) -> list:
    """grants.toml text → normalized grant list. Raises ValueError with a
    line-addressable message on anything malformed. Allow-only by schema:
    there is no action/deny key to parse."""
    import tomllib
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as e:
        raise ValueError(f"grants.toml: invalid TOML — {e}") from None
    unknown = set(data) - {"grant", "assign"}
    if unknown:
        raise ValueError(f"grants.toml: unknown top-level key(s) {sorted(unknown)} "
                         f"(only [[grant]] tables and an [assign] table are allowed)")
    raw = data.get("grant", [])
    if not isinstance(raw, list):
        raise ValueError("grants.toml: [[grant]] must be an array of tables")
    return [_validate_grant(g, i) for i, g in enumerate(raw)]


def parse_assignments(text: str) -> "dict | None":
    """The OPTIONAL [assign] table in grants.toml — declarative role
    assignments, hostname → role list:

        [assign]
        nas = ["nfs_srv"]
        bb  = ["nfs_usr", "web"]

    Returns {hostname: [roles]}, or None when no [assign] section exists (its
    absence is a mode: roles stay imperative, `gw set-roles`-style). Listed
    hosts' roles are reconciled into the anchor registry at `gw policy apply`
    (see apply_assignments); unlisted hosts are untouched. Raises ValueError,
    line-addressable, on anything malformed — the same posture as grants."""
    import tomllib
    from .hosts import valid_label
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as e:
        raise ValueError(f"grants.toml: invalid TOML — {e}") from None
    if "assign" not in data:
        return None
    raw = data["assign"]
    if not isinstance(raw, dict):
        raise ValueError("grants.toml: [assign] must be a table of "
                         "hostname = [roles]")
    out = {}
    for host, roles in raw.items():
        if not valid_label(host):
            raise ValueError(f"[assign]: {host!r} is not a DNS-safe hostname "
                             f"label (use the name as `gw watch` shows it)")
        if not isinstance(roles, list) or not all(
                isinstance(r, str) and r for r in roles):
            raise ValueError(f"[assign] {host}: roles must be a list of "
                             f"role-name strings")
        for r in roles:
            if r in RESERVED_ROLES:
                raise ValueError(f"[assign] {host}: {r!r} is reserved for the "
                                 f"anchor and can never be assigned")
            if ":" in r:
                raise ValueError(f"[assign] {host}: {r!r} — a role name can't "
                                 f"contain ':' (host: entries belong in grants, "
                                 f"not assignments)")
        out[host] = sorted(set(roles))
    return out


def rewrite_assignment(text: str, host: str, roles: list) -> str:
    """Surgically set one host's line in grants.toml's [assign] table,
    preserving everything else byte-for-byte (comments included): replace the
    host's line if present, else append it to the section, else append a new
    [assign] section. This is how the watch role editor writes — the FILE
    stays the source of truth; the TUI is a hand on the same file."""
    import json as _json
    import re as _re
    line = f"{host} = {_json.dumps(sorted(roles))}"   # a JSON str list is valid TOML
    m = _re.search(r"(?m)^\[assign\]\s*$", text)
    if m is None:
        return text.rstrip("\n") + f"\n\n[assign]\n{line}\n"
    nxt = _re.search(r"(?m)^\s*\[", text[m.end():])
    end = m.end() + (nxt.start() if nxt else len(text) - m.end())
    section = text[m.end():end]
    hm = _re.search(rf"(?m)^\s*{_re.escape(host)}\s*=.*$", section)
    if hm:
        section = section[:hm.start()] + line + section[hm.end():]
    else:
        section = section.rstrip("\n") + f"\n{line}\n"
        if nxt:
            section += "\n"
    return text[:m.end()] + section + text[end:]


def apply_assignments(assignments: dict, ca) -> tuple:
    """Reconcile the anchor registry to the [assign] table: for each listed
    host with a current member, swap its role: caps to the declared set
    (keeping tls/hostname-pinned/anything else). Idempotent. Returns
    (changes, missing): changes as (host, old_roles, new_roles) for what
    actually changed, missing as hostnames no member currently holds (they
    reconcile on a later apply, once the machine joins)."""
    changes, missing = [], []
    for host, roles in sorted((assignments or {}).items()):
        owner = ca.hostname_owner(host)
        if owner is None:
            missing.append(host)
            continue
        id_pub = bytes.fromhex(owner)
        _, current = ca.node_info(id_pub)
        old = sorted(c[len("role:"):] for c in current if c.startswith("role:"))
        if old == list(roles):
            continue
        kept = [c for c in current if not c.startswith("role:")]
        ca.set_caps(id_pub, kept + [f"role:{r}" for r in roles])
        changes.append((host, old, list(roles)))
    return changes, missing


def _grant_connects(grant: dict, a_tags: set, b_tags: set) -> bool:
    """Does this grant authorize a flow from a → b? '*' in from/to matches
    any node."""
    src_match = "*" in grant["from"] or a_tags & set(grant["from"])
    dst_match = "*" in grant["to"] or b_tags & set(grant["to"])
    return bool(src_match and dst_match)


def peers_allowed(local_caps: list, peer_caps: list,
                  grants: "list | None",
                  local_hostname: "str | None" = None,
                  peer_hostname: "str | None" = None) -> bool:
    """THE tunnel-existence decision (used as reconcile's step-6 policy).

    Hardwired first, beneath any table: the anchor ('*' role on either side)
    peers with everyone — the control plane is never prunable by policy.
    Then: NO table → the flat trusted mesh (every verified member peers; the
    implicit policy is `* -> * : *`, so a fresh mesh needs no file). With a
    table → a link exists iff some grant connects the two nodes' tags in
    either direction. Tags are roles plus the derived `host:<name>` (see
    node_tags) — pass the credential hostnames to enable host grants; omitted,
    only role grants match (back-compatible). Roles never create connectivity
    by themselves; only grants (or the absence of any policy) do.
    """
    local = node_tags(local_caps, local_hostname)
    peer = node_tags(peer_caps, peer_hostname)
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

    def __call__(self, local_caps: list, peer_caps: list,
                 local_hostname: "str | None" = None,
                 peer_hostname: "str | None" = None) -> bool:
        table = self.table
        return peers_allowed(local_caps, peer_caps,
                             table.grants if table else None,
                             local_hostname, peer_hostname)

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
            prev = self._table.seq if self._table is not None else None
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
        # Durable domain-event: the policy VERSION changed (the cause; the
        # topology event on the next reconcile is the effect).
        from . import audit
        audit.event("policy", prev=(prev if prev is not None else "none"),
                    seq=table.seq, grants=len(table.grants))
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
                 new_grants: "list | None", caps_override: "dict | None" = None):
    """(created, removed) tunnel pairs a policy change would cause, as
    (hostname_a, hostname_b) tuples — what `gw policy apply` shows before
    asking. Compares peers_allowed over every record pair under both tables.
    caps_override ({id_pub_hex: caps}) applies on the AFTER side only — how an
    [assign] role change enters the same preview as a grant change."""
    created, removed = [], []
    recs = list(records)
    over = caps_override or {}

    def _after_caps(r):
        return over.get(r.id_pub.hex(), r.cred.caps)

    for i, a in enumerate(recs):
        for b in recs[i + 1:]:
            before = peers_allowed(a.cred.caps, b.cred.caps, old_grants,
                                   a.cred.hostname, b.cred.hostname)
            after = peers_allowed(_after_caps(a), _after_caps(b), new_grants,
                                  a.cred.hostname, b.cred.hostname)
            if after and not before:
                created.append((a.hostname, b.hostname))
            elif before and not after:
                removed.append((a.hostname, b.hostname))
    return created, removed


def unmatched_tags(grants: list, records,
                   caps_override: "dict | None" = None) -> set:
    """Grant tags that NO current node holds — usually a typo'd role or a
    `host:` name no member has. A grant naming one fails closed and silently,
    so `gw policy apply` warns. caps_override ({id_pub_hex: caps}) counts an
    [assign] re-role applied in the SAME apply as held — a role granted and
    assigned together must not warn as a typo."""
    over = caps_override or {}
    held = set()
    for r in records:
        held |= node_tags(over.get(r.id_pub.hex(), r.cred.caps),
                          r.cred.hostname)
    named = set()
    for g in grants:
        named |= set(g["from"]) | set(g["to"])
    return {t for t in named - held if t != "*"}


def unpinned_host_grants(grants: list, records) -> list:
    """`host:` grant targets whose current holder chose its own name (no
    `hostname-pinned` cap). A host grant is only as strong as name assignment:
    a self-named node controls what it is called (within uniqueness), so `gw
    policy apply` warns and suggests pinning. Returns sorted hostnames."""
    named = set()
    for g in grants:
        for entry in list(g["from"]) + list(g["to"]):
            if entry.startswith("host:"):
                named.add(entry[len("host:"):])
    unpinned = []
    for r in records:
        if r.cred.hostname in named and "hostname-pinned" not in r.cred.caps:
            unpinned.append(r.cred.hostname)
    return sorted(unpinned)


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
