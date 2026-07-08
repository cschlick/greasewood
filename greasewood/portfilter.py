"""
greasewood.portfilter — per-port enforcement of the grant table (on by default).

Grants already enforce tunnel EXISTENCE (no grant → no WireGuard peer → nothing
to filter). This adds the finer layer: within the tunnels that exist, allow only
the ports the grants name. It is ON by default (the default policy is fully open,
so a fresh mesh is flat until grants tighten it); `enforce_ports = false` opts a
host out. It writes ONLY greasewood's own nftables table, scoped to the mesh
interface — never the operator's rules, never a physical NIC.

Design (the model settled in the roles/grants discussion):
  - greasewood owns `table inet greasewood_<mesh>` (per-membership,
    so multi-mesh hosts don't collide); every rule matches
    `iifname "<mesh-iface>"`, so it is structurally incapable of touching
    eth0 / the underlay. The underlay firewall stays advisory forever.
  - Default-deny WITHIN the mesh: accept established/related (client replies),
    ICMPv6 (diagnostics), the control port (the channel that carries policy —
    hardwired, like the anchor star in peering), and the granted flows; drop
    the rest of mesh traffic. It can only ever TIGHTEN — it presupposes the
    operator has admitted the overlay (`iifname "<mesh>" accept` in their own
    policy, or no host firewall at all; `gw firewall` advises this).
  - Enforcement is inbound on the SERVER side: a grant `web -> api : tcp/8000`
    becomes, on an api node, "accept tcp/8000 from web-member addresses". The
    client needs no inbound rule — its replies ride ct established. So the
    client/server asymmetry falls out of stateful filtering, for free.
  - The addresses are trustworthy because WireGuard's cryptokey routing pins
    address ↔ key: a packet from an overlay /128 can only be its owner.
  - Fail CLOSED: the table PERSISTS across daemon stop/crash (ungranted ports
    stay blocked with no daemon running). `gw purge` is the explicit teardown.
  - Regenerate-on-change: the full ruleset is rendered and `nft -f`'d
    atomically only when it differs from what's installed. At greasewood's
    scale (hundreds of nodes; the mesh's N² peering caps first) a full atomic
    reload beats element-diffing, and it's trivially auditable.
"""
from __future__ import annotations

import logging
import shutil
import subprocess

from .policy import node_tags

log = logging.getLogger(__name__)

_CHAIN = "meshfilter"


def table_name(key: str) -> str:
    """greasewood's own nftables table for ONE membership. Per-mesh, so two
    meshes on one host (multi-mesh) don't clobber each other's rules. nft
    identifiers allow only [A-Za-z0-9_], so the key's hyphens/dots become
    underscores: e.g. mesh key 'prod' → table inet greasewood_prod."""
    safe = "".join(c if c.isalnum() else "_" for c in key)
    return f"greasewood_{safe}"


class NftUnavailable(RuntimeError):
    """nftables isn't usable here — `nft` missing, or the kernel/permissions
    reject `nft list ruleset`. Enforcement can't proceed; the caller refuses
    loudly (never silently fail open when enforcement was requested)."""


def ensure_available() -> None:
    """Raise NftUnavailable unless nftables is usable. Called ONCE at daemon
    start when enforcement is on (the default), before anything is touched — so
    the daemon refuses loudly rather than running with silently-absent
    enforcement (fail closed)."""
    if shutil.which("nft") is None:
        raise NftUnavailable(
            "nftables (nft) is not installed. Port enforcement (on by default) "
            "needs it — install nftables, or set enforce_ports = false to run "
            "without it (grants still control which tunnels exist).")
    r = subprocess.run(["nft", "list", "ruleset"], capture_output=True, text=True)
    if r.returncode != 0:
        raise NftUnavailable(
            "`nft list ruleset` failed (kernel nf_tables support or "
            f"permissions?): {r.stderr.strip() or r.returncode}. Port "
            "enforcement needs a working nftables; set enforce_ports = false "
            "to run without it.")


def _port_allowances(records, local_caps: list, grants: "list | None") -> dict:
    """For THIS node (server side), map each allowed inbound flow to the set of
    source overlay addresses permitted to use it:

        {"*": {addr, ...},                 # all ports, from these sources
         ("tcp", 5432): {addr, ...}, ...}  # this proto/port, from these sources

    A grant applies to this node when this node holds a role in the grant's
    `to` (or `to` names `*`); its sources are the addresses of every node
    holding a role in the grant's `from` (or every node, for `from = ["*"]`).
    """
    my_tags = node_tags(local_caps)
    allow: dict = {}

    def _sources(from_roles: list) -> set:
        wild = "*" in from_roles
        want = set(from_roles)
        return {r.cred.addr for r in records
                if wild or (node_tags(r.cred.caps) & want)}

    for grant in (grants or []):
        to = grant["to"]
        if "*" not in to and not (my_tags & set(to)):
            continue                       # this node is not a destination
        srcs = _sources(grant["from"])
        if not srcs:
            continue
        for spec in grant["ports"]:
            if spec == "*":
                key = "*"
            else:
                proto, _, num = spec.partition("/")
                key = (proto, int(num))
            allow.setdefault(key, set()).update(srcs)
    return allow


def _fully_open(grants: "list | None") -> bool:
    """True when the policy opens the whole mesh: either no table (the default
    policy is `* -> * : *`), or a table that contains an explicit `* -> * : *`
    grant (which, under allow-only union, subsumes everything). Rendered as a
    single `accept` — no per-port sets — so 'open' stays cheap regardless of
    fleet size or how it's written."""
    if grants is None:
        return True
    return any("*" in g["from"] and "*" in g["to"] and "*" in g["ports"]
               for g in grants)


def render_ruleset(table: str, iface: str, control_port: int, records,
                   local_caps: list, grants: "list | None") -> str:
    """The full desired `table inet greasewood_<mesh>` as an `nft -f` document. A fully
    open policy (no table, or an explicit * -> * : *) admits all mesh traffic
    with one accept; otherwise default-deny within the mesh + the granted flows.
    Enforcement is always installed — 'open' is a policy state, not its absence."""
    allow = {} if _fully_open(grants) else _port_allowances(records, local_caps, grants)

    sets, rules = [], []
    # Set + rule per port bucket. Deterministic ordering → stable text → the
    # change-detector doesn't reload on set reordering.
    all_sources = sorted(allow.get("*", set()))
    if all_sources:
        sets.append(f'    set p_all {{ type ipv6_addr; elements = {{ '
                    f'{", ".join(all_sources)} }} }}')
        rules.append(f'        iifname "{iface}" ip6 saddr @p_all accept')
    for key in sorted(k for k in allow if k != "*"):
        proto, port = key
        srcs = sorted(allow[key])
        name = f"p_{proto}_{port}"
        sets.append(f'    set {name} {{ type ipv6_addr; elements = {{ '
                    f'{", ".join(srcs)} }} }}')
        rules.append(f'        iifname "{iface}" {proto} dport {port} '
                     f'ip6 saddr @{name} accept')

    # Fully open → admit the whole overlay (one accept). Otherwise default-deny
    # mesh traffic (a policy exists but grants nothing to this node ⇒ only the
    # hardwired control/established/icmp allows apply).
    mesh_default = 'accept' if _fully_open(grants) else 'drop'

    body = [f"table inet {table} {{"]
    body += sets
    body += [
        f"    chain {_CHAIN} {{",
        "        type filter hook input priority filter; policy accept;",
        # Only mesh traffic is ours; everything else leaves this chain (accept
        # is non-terminal across tables, so the operator's rules still decide).
        f'        iifname != "{iface}" accept',
        "        ct state established,related accept",   # replies to our outbound
        "        meta l4proto ipv6-icmp accept",         # ping / diagnostics
        f"        tcp dport {control_port} accept",       # control plane — hardwired
    ]
    body += rules
    body += [
        f'        iifname "{iface}" {mesh_default}',      # everything else on the mesh
        "    }",
        "}",
    ]
    return "\n".join(body) + "\n"


class PortFilter:
    """Reconcile-driven port enforcer. Given the trusted records each cycle,
    (re)installs greasewood's own nftables table iff the desired ruleset
    changed. Holds no lock — reconcile calls it single-threaded."""

    def __init__(self, table: str, iface: str, control_port: int,
                 local_caps: list, grant_policy) -> None:
        self._table = table
        self._iface = iface
        self._control_port = control_port
        self._local_caps = local_caps
        self._grant_policy = grant_policy      # .table → GrantTable | None
        self._applied: "str | None" = None

    def _grants(self):
        table = self._grant_policy.table if self._grant_policy else None
        return table.grants if table else None

    def _installed(self) -> bool:
        """Is our table actually present in the kernel? If we can't tell, assume
        yes (don't thrash reinstalls on a transient nft hiccup)."""
        from . import wg as wgmod
        try:
            return wgmod.nft_table_exists(self._table)
        except Exception:
            return True

    def apply(self, records) -> None:
        desired = render_ruleset(self._table, self._iface, self._control_port,
                                 records, self._local_caps, self._grants())
        # Skip only when the ruleset is unchanged AND our table is still in the
        # kernel. The in-memory cache alone isn't enough: an operator's
        # `nft -f` that starts with `flush ruleset` wipes every table including
        # ours, and the cache would wrongly think it's still installed — leaving
        # the mesh coarsely admitted but no longer tightened (fail OPEN). The
        # presence check re-asserts our table within one reconcile cycle.
        if desired == self._applied and self._installed():
            return
        # Replace our table atomically: `delete table` (ignored if absent) +
        # the fresh definition in one `nft -f` transaction, so a peer never
        # sees a half-built ruleset.
        script = (f"table inet {self._table}\n"
                  f"delete table inet {self._table}\n{desired}")
        from . import wg as wgmod
        from . import audit
        try:
            with audit.context("portfilter: apply grant-derived mesh rules"):
                wgmod.nft_load(script)
            self._applied = desired
            log.info("port enforcement applied (%d bytes of rules)", len(desired))
        except Exception as e:
            log.error("could not apply port enforcement: %s — mesh traffic "
                      "unchanged this cycle, retry next", e)

    def teardown(self) -> None:
        """Remove greasewood's table. NOT called on daemon stop (fail closed —
        rules persist without us); only `gw purge` calls this."""
        from . import wg as wgmod
        try:
            wgmod.nft_delete_table(self._table)
            log.info("removed the greasewood nftables table")
        except Exception as e:
            log.warning("could not remove nftables table: %s", e)
