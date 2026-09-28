"""
greasewood.reconcile — the heart of the agent (§7).

For each record in the directory, run the 7-step verification and compute
whether a WireGuard peer should be installed or removed. Apply the diff to
the live kernel state using granular wg-set operations.

This is the only code that touches the data plane. Membership, liveness,
revocation, key rotation, and ACL enforcement all express themselves as
the single question "does this WG peer get installed or removed," computed
locally with no agreement or coordination required.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
import datetime as dt
import json
import logging
import threading
from pathlib import Path
import time
from typing import Callable, NamedTuple

from .directory import Directory
from .loop import Loop
from . import hosts
from . import audit
from . import wg as wgmod

log = logging.getLogger(__name__)

# Expired-but-admitted peers already announced in the log, id_pub → the exp we
# announced for. Keeps the admission line to one per expiry instead of one per
# reconcile cycle (see the transition logging below). Bounded by mesh size.
_ADMITTED_EXPIRED: "dict[bytes, dt.datetime]" = {}

# persistent-keepalive (secs) for a healthy or still-probing peer. A peer whose
# endpoint has gone dead past a full probe cycle drops to 0 — see _EndpointTracker.
_KEEPALIVE = 25

# A peer counts as a live link (for the published `reachable` set) if it
# handshaked within this window. ~180s covers WireGuard's ~2-min refresh on an
# idle-but-live tunnel (keepalive=25 keeps it well inside).
_LIVE_LINK_SECS = 180



# Step 6 authorization policy:
#   (local_caps, peer_caps, local_hostname=None, peer_hostname=None) → bool
# Hostnames enable derived host: tags (see policy.node_tags); a policy that
# ignores them (role grants only) is fine — they default to None.
Policy = Callable[..., bool]


class _Desired(NamedTuple):
    """What one WireGuard peer should look like after this cycle."""
    addr: str                   # the peer's overlay /128
    endpoint: "str | None"      # underlay endpoint to pin (None: peer initiates)
    keepalive: int              # 25, or 0 when backed off (dead endpoint)

    @property
    def allowed(self) -> tuple:
        """The AllowedIPs set for this peer: just its own /128."""
        return (self.addr,)


class ReconcileResult(NamedTuple):
    trusted: list               # fully-verified records — the ONLY derivable set
    reachable: list             # overlay addrs with a live handshake (published)


def _roles(caps: list[str]) -> set[str]:
    """A node's roles, carried as `role:<name>` tags in its CA-signed caps
    (attested, anchor-assigned, renewed) — no separate wire field. `role:*` is
    the reach-all wildcard (the anchor carries it)."""
    return {c[len("role:"):] for c in caps if c.startswith("role:")}


def default_policy(local_caps: list[str], peer_caps: list[str],
                   local_hostname: "str | None" = None,
                   peer_hostname: "str | None" = None) -> bool:
    """The peering decision when the daemon is wired without a GrantPolicy
    (tests, embedding): defer to policy.peers_allowed with no table — the flat
    trusted mesh. The real decision lives in greasewood.policy; enforcement is
    mutual either way (a link needs BOTH ends to install each other, each
    reading the other's roles from its CA-signed credential — a node can't
    talk its way into a role it wasn't issued)."""
    from .policy import peers_allowed
    return peers_allowed(local_caps, peer_caps, None,
                         local_hostname, peer_hostname)


def _endpoint_candidates(endpoints: list[str],
                         local_families: "set[int] | None") -> list[str]:
    """The peer endpoints this node could actually originate on, in advertised
    order (which is v6-first, so a dual-stack node prefers v6). Empty if the peer
    advertises none, or only a family we can't reach (→ no endpoint installed, so
    the link won't form — direct-or-fail across families, no special case)."""
    if not endpoints:
        return []
    if not local_families:            # unknown families → keep them all, in order
        return list(endpoints)
    return [ep for ep in endpoints
            if (6 if ep.startswith("[") else 4) in local_families]


def _select_endpoint(endpoints: list[str],
                     local_families: "set[int] | None") -> "str | None":
    """The single preferred endpoint (first reachable candidate), or None. The
    stateless choice used when no fallback tracker is supplied."""
    candidates = _endpoint_candidates(endpoints, local_families)
    return candidates[0] if candidates else None


@dataclass
class _PeerEndpoint:
    """One peer's endpoint-fallback state, carried across reconcile cycles."""
    current: str                            # the endpoint currently pinned
    since: float                            # when we pinned/rotated to it
    unhealthy_since: "float | None" = None  # first cycle with no live handshake
    dead: bool = False                      # past a full probe cycle → backoff


# How long after the last witness handshake we consider this node "dark"
# (just woke from sleep, or all connectivity was lost). During that dark window
# we keep poking all peers rather than letting the EndpointTracker back off.
_WAKE_REARM = _LIVE_LINK_SECS
# Extra settle time after we first recover a witness handshake, so other peers
# have a chance to re-establish before backoff is allowed to suppress keepalive.
_WAKE_SETTLE = _LIVE_LINK_SECS


class _EndpointTracker:
    """Per-peer endpoint fallback state, carried across reconcile cycles.

    WireGuard pins one endpoint per peer and keeps retrying it forever, so a
    peer that advertises a working v4 AND a broken v6 (the common dual-stack
    case) never connects if v6 was chosen. This advances to the peer's NEXT
    advertised endpoint once the current one has gone `dwell` seconds with no
    handshake, round-robining until one sticks. It only ever tries endpoints the
    PEER advertised — still direct-or-fail, no relay. A fresh handshake resets
    the dwell clock, so a healthy link is never disturbed.

    It also tracks a "wake window" keyed to a witness peer (usually the
    anchor). If the witness hasn't handshaked recently, this node was likely
    asleep or roaming; we keep sending keepalives even if individual peer
    endpoints look dead, and we extend that window after a witness handshake
    recovers so the rest of the fleet has time to settle.
    """

    def __init__(self, dwell: float = 20.0, healthy: float = _LIVE_LINK_SECS,
                 wake_rearm: float = _WAKE_REARM,
                 wake_settle: float = _WAKE_SETTLE) -> None:
        self._dwell = dwell
        # A handshake within `healthy` seconds means the current endpoint works
        # (defaults to the shared _LIVE_LINK_SECS window).
        self._healthy = healthy
        self._wake_rearm = wake_rearm
        self._wake_settle = wake_settle
        self._state: dict[str, _PeerEndpoint] = {}  # keyed by wg_pub_b64
        # Time of the most recent handshake from the witness peer (anchor, or
        # any peer if this node is the anchor). 0 means we have never seen one.
        self._last_witness = 0.0
        # While now < _wake_until, is_backoff() stays false for every peer.
        self._wake_until = 0.0

    def _is_healthy(self, hs: int, now: float) -> bool:
        return bool(hs) and (now - hs) <= self._healthy

    def witness(self, now: float, peer_latest_handshake: float) -> None:
        """Call once per cycle with the latest handshake of the witness peer.

        A long gap with no witness means this node was probably asleep; keep the
        wake window open so we keep poking. When a witness finally handshakes,
        extend the window further so other peers get a fair settle window.
        """
        if peer_latest_handshake > 0:
            if (self._last_witness > 0
                    and peer_latest_handshake > self._last_witness + 0.5
                    and now - self._last_witness > self._wake_rearm):
                # Recovered from a dark gap — let the whole peer set settle.
                self._wake_until = now + self._wake_settle
            self._last_witness = peer_latest_handshake

        dark = (self._last_witness > 0
                and now - self._last_witness > self._wake_rearm)
        if dark:
            # Still no recent word from the witness; stay in wake mode.
            self._wake_until = now + self._wake_settle

    def in_wake(self, now: float) -> bool:
        return now < self._wake_until

    def choose(self, wg_pub_b64: str, candidates: list[str],
               hs: int, now: float) -> "str | None":
        if not candidates:
            self._state.pop(wg_pub_b64, None)
            return None
        st = self._state.get(wg_pub_b64)
        if st is None or st.current not in candidates:
            # New peer, or it re-advertised a set without our current endpoint.
            # Start the unhealthy clock now if it isn't already handshaking, so
            # the backoff countdown runs from when we first pinned the endpoint.
            healthy = self._is_healthy(hs, now)
            st = _PeerEndpoint(current=candidates[0], since=now,
                               unhealthy_since=None if healthy else now)
            self._state[wg_pub_b64] = st
            return st.current
        if self._is_healthy(hs, now):
            # Working link → reset the dwell clock, clear any backoff.
            st.since, st.unhealthy_since, st.dead = now, None, False
            return st.current
        if st.unhealthy_since is None:
            st.unhealthy_since = now
        if len(candidates) > 1 and (now - st.since) >= self._dwell:
            i = candidates.index(st.current)
            st.current = candidates[(i + 1) % len(candidates)]
            st.since = now
        # Backoff: once we've been unhealthy for a full probe cycle (dwell per
        # advertised endpoint) with no handshake, the endpoint(s) are dead. We
        # keep it pinned for automatic recovery, but the caller drops keepalive
        # to 0 so we stop firing a futile packet every 25s into the void.
        st.dead = (now - st.unhealthy_since) >= self._dwell * len(candidates)
        if self.in_wake(now):
            # Post-sleep / roaming window: do not let this peer settle into
            # keepalive=0 while we are still trying to re-establish the first
            # live link. Reset its backoff clock each cycle during the window.
            st.dead = False
            if st.unhealthy_since is not None:
                st.unhealthy_since = now
        return st.current

    def is_backoff(self, wg_pub_b64: str) -> bool:
        """True if this peer's endpoint has been dead past a full probe cycle —
        pinned but not worth keepalive traffic (see choose())."""
        st = self._state.get(wg_pub_b64)
        return bool(st and st.dead)


def _witness_handshake(live_peers: dict, directory: Directory,
                       local_id_pub: bytes, is_anchor: bool) -> int:
    """The latest handshake of a witness peer: the anchor if this node is not
    the anchor, otherwise any live peer. Used to detect a post-sleep or roaming
    dark window. Returns 0 if no suitable peer has handshaked."""
    if not is_anchor:
        anchor_wg_pubs = {
            base64.b64encode(r.cred.wg_pub).decode()
            for r in directory.all()
            if "*" in _roles(r.cred.caps) and r.id_pub != local_id_pub
        }
        if anchor_wg_pubs:
            hs = [live_peers[p].latest_handshake
                  for p in anchor_wg_pubs if p in live_peers]
            if hs:
                return max(hs)
    hs = [p.latest_handshake for p in live_peers.values() if p.latest_handshake]
    return max(hs) if hs else 0


def reconcile_once(
    iface: str,
    directory: Directory,
    local_id_pub: bytes,
    local_caps: list[str],
    ca_pubs: list[bytes],
    revoked: set[str],
    policy: Policy = default_policy,
    local_families: "set[int] | None" = None,
    endpoint_tracker: "_EndpointTracker | None" = None,
    local_hostname: "str | None" = None,
) -> ReconcileResult:
    """
    Single reconcile pass against the full directory.

    Per-record steps (§7):
      1+2  record.verify() → CA sig + expiry
      3    record.verify() → self-sig
      4    record.verify() → addr derives from id_pub
      5    record.verify() → revoke list
      6    policy(local_caps, peer_caps)
      7    install or remove WireGuard peer

    Result: kernel WireGuard peer set matches exactly the authorized directory.

    Returns (trusted, reachable). `trusted` is the records that passed full
    verification (steps 1–5, including the local node's own record) — the ONLY
    set other outputs may be derived from; the /etc/hosts block is built from
    it, so a revoked or expired node stops resolving on the same cycle its
    tunnel comes down. `reachable` is the overlay addrs of peers with a live
    handshake — what this node publishes for the fleet's segment-health view. The directory cache
    itself is deliberately looser (structural checks only) so it survives
    re-roots and clock skew; anything user-visible must go through this gate.
    """
    # Live kernel state up front: the endpoint tracker needs each peer's last
    # handshake time to decide whether its current endpoint is working.
    live_peers = wgmod.get_peers(iface)
    if live_peers is None:
        # Couldn't read live WireGuard state (a transient `wg show` failure).
        # Acting on this as "no peers" would skip every removal and re-add
        # everything — so skip the diff this cycle and retry next tick.
        log.warning("could not read live peers on %s; skipping reconcile this cycle", iface)
        return ReconcileResult([], [])
    now = time.time()

    # The peers that SHOULD exist after this cycle: wg_pub_b64 → _Desired
    # (addr, endpoint, keepalive). Built from the verified+authorized records.
    desired: dict[str, _Desired] = {}
    context: dict[str, str] = {}   # wg_pub_b64 → human context for the audit trail
    trusted: list = []

    # If we advertise no underlay endpoints, no peer can initiate to us; we are
    # strictly outbound-only and MUST keep sending keepalives even when the
    # currently-pinned endpoint looks dead.  Otherwise a laptop that slept or
    # roamed never recovers: it drops keepalive to 0 and just waits for the
    # remote to call, which it cannot do because we have no endpoint.
    own_record = directory.get(local_id_pub.hex()) if local_id_pub is not None else None
    local_is_outbound_only = own_record is None or not own_record.endpoints

    # Expiry is a liveness signal, not a trust kill.  Two parties must keep
    # talking to an expired-but-not-revoked record within drop_grace:
    #   - the ANCHOR, so stale nodes can renew/recertify themselves; and
    #   - any MEMBER talking to the ANCHOR, so a member whose local cache has an
    #     stale anchor record can still install the anchor peer, sync, and renew.
    # Everybody else (a normal peer that has gone expired) is ignored by
    # non-anchor members until it recertifies.
    is_anchor = "*" in _roles(local_caps)

    # Tell the endpoint tracker when this node last heard from a witness peer.
    # A long gap with the anchor (or any peer, if this is the anchor) means we
    # may just have woken from sleep and should keep poking every peer for a
    # settle window rather than trusting old backoff state.
    if endpoint_tracker is not None:
        endpoint_tracker.witness(
            now,
            _witness_handshake(live_peers, directory, local_id_pub, is_anchor)
        )

    for record in directory.all():
        record_is_anchor = "*" in _roles(record.cred.caps)
        try:
            record.verify(ca_pubs, revoked,
                          allow_expired=(is_anchor or record_is_anchor))
        except ValueError as e:
            log.debug("skip %s: %s", record.hostname, e)
            continue
        if (is_anchor or record_is_anchor) and record.id_pub != local_id_pub \
                and dt.datetime.now(dt.timezone.utc) >= record.cred.exp:
            # Log the ADMISSION TRANSITION, not the steady state: this branch
            # runs every reconcile cycle (seconds), and a peer that stays
            # expired for days floods the journal with an identical line every
            # cycle — burying the renewal/CA lines an operator greps for.
            # Remembered per id against the credential's exp: a recert issues
            # a new exp, so the NEXT expiry of the same peer logs again.
            if _ADMITTED_EXPIRED.get(record.id_pub) != record.cred.exp:
                _ADMITTED_EXPIRED[record.id_pub] = record.cred.exp
                who = "anchor" if is_anchor else "member"
                log.info("%s admitting expired %s %s [%s] for recertification "
                         "(not revoked) — it can renew over this tunnel; "
                         "logged once, admission continues every cycle",
                         who, "peer" if is_anchor else "anchor",
                         record.hostname, record.cred.addr)
        else:
            _ADMITTED_EXPIRED.pop(record.id_pub, None)
        trusted.append(record)

        if record.id_pub == local_id_pub:
            continue  # never install self as peer

        # Step 6: authorization policy. Hostnames ride along so derived
        # host: tags match — both come from CA-signed credentials.
        if not policy(local_caps, record.cred.caps,
                      local_hostname, record.cred.hostname):
            log.debug("skip %s: policy denied", record.hostname)
            continue

        wg_pub_b64 = base64.b64encode(record.cred.wg_pub).decode()
        candidates = _endpoint_candidates(record.endpoints, local_families)

        live_peer = live_peers.get(wg_pub_b64)
        last_handshake = live_peer.latest_handshake if live_peer else 0

        keepalive = _KEEPALIVE
        if endpoint_tracker is not None:
            endpoint = endpoint_tracker.choose(wg_pub_b64, candidates,
                                               last_handshake, now)
            if endpoint_tracker.is_backoff(wg_pub_b64) and not local_is_outbound_only:
                keepalive = 0          # dead endpoint: stop the futile 25s poke
        else:
            endpoint = candidates[0] if candidates else None
        # Context for the audit trail: name + segments, so every peer command
        # says WHO and WHY, not just a bare pubkey.
        roles = ",".join(sorted(_roles(record.cred.caps))) or "-"
        context[wg_pub_b64] = f"{record.hostname} [{record.cred.addr}] roles={roles}"

        desired[wg_pub_b64] = _Desired(record.cred.addr, endpoint, keepalive)

    # The three-way diff, named by intent: authorized-but-absent get installed,
    # present get their endpoint/route/keepalive re-checked, no-longer-authorized
    # get removed. This is the whole membership decision, per peer, no coordination.
    live_pubs, desired_pubs = set(live_peers), set(desired)
    to_install = desired_pubs - live_pubs
    to_verify = desired_pubs & live_pubs
    to_remove = live_pubs - desired_pubs

    def _who(wg_pub: str) -> str:
        return context.get(wg_pub, f"...{wg_pub[-8:]}")

    for wg_pub in to_install:
        want = desired[wg_pub]
        try:
            with audit.context(f"reconcile: +peer {_who(wg_pub)}"):
                wgmod.set_peer(iface, wg_pub, list(want.allowed), want.endpoint,
                               keepalive=want.keepalive)
        except Exception as e:
            log.warning("add peer ...%s failed: %s", wg_pub[-8:], e)

    for wg_pub in to_verify:
        want, have = desired[wg_pub], live_peers[wg_pub]
        # endpoint=None (the peer stopped advertising, e.g. went outbound-only)
        # deliberately does NOT clear a live endpoint: WireGuard roams the
        # endpoint on any authenticated packet anyway, and clearing one would
        # require remove+re-add — tearing down a working session for no gain.
        endpoint_changed = want.endpoint and have.endpoint != want.endpoint
        # AllowedIPs set differs → re-set (a plain missing /128).
        allowed_changed = have.allowed_addrs != frozenset(want.allowed)
        keepalive_changed = have.keepalive != want.keepalive  # dead↔alive flips 25↔0
        if endpoint_changed or allowed_changed or keepalive_changed:
            try:
                why = ("endpoint" if endpoint_changed else
                       "keepalive" if keepalive_changed else "route")
                with audit.context(f"reconcile: ~peer {_who(wg_pub)} ({why})"):
                    wgmod.set_peer(iface, wg_pub, list(want.allowed), want.endpoint,
                                   keepalive=want.keepalive)
            except Exception as e:
                log.warning("update peer ...%s failed: %s", wg_pub[-8:], e)

    # Addresses any DESIRED peer still routes — never delete a route that is
    # still wanted by a remaining peer.
    desired_addrs = {a for want in desired.values() for a in want.allowed}
    for wg_pub in to_remove:
        try:
            have = live_peers[wg_pub]
            stale_routes = [a for a in sorted(have.allowed_addrs)
                            if a not in desired_addrs]
            with audit.context(f"reconcile: -peer {_who(wg_pub)}"):
                wgmod.remove_peer(iface, wg_pub, stale_routes)
        except Exception as e:
            log.warning("remove peer ...%s failed: %s", wg_pub[-8:], e)

    # A MEMBERSHIP change this cycle → one durable domain-event line summarizing
    # the transition (the per-peer +/-peer commands above carry the detail). Only
    # emitted when the peer set actually changed — a re-verify (~peer: endpoint/
    # keepalive) is not a membership event, so steady state stays silent.
    if to_install or to_remove:
        audit.event("topology", added=len(to_install), removed=len(to_remove),
                    peers=len(desired_pubs))

    # The overlay addrs we currently have a LIVE link to (recent handshake). This
    # is what a node publishes as its `reachable` set so the fleet can see which
    # edges are up — an unreachable segment-mate (firewalled) shows as a missing
    # edge from both ends. Session-existence, not direction (a working tunnel is
    # bidirectional regardless of who dialed).
    reachable_set = {
        want.addr for wg_pub, want in desired.items()
        if (live_peer := live_peers.get(wg_pub)) and live_peer.latest_handshake
        and (now - live_peer.latest_handshake) <= _LIVE_LINK_SECS
    }
    return ReconcileResult(trusted, sorted(reachable_set))


class ReconcileLoop(Loop):
    def __init__(
        self,
        iface: str,
        directory: Directory,
        local_id_pub: bytes,
        local_caps: list[str],
        get_ca_pubs: "Callable[[], list[bytes]]",
        get_revoked: "Callable[[], set[str]]",
        interval: float = 5.0,
        policy: Policy = default_policy,
        hosts_domain: str | None = None,
        get_local_families: "Callable[[], set[int] | None] | None" = None,
        ensure_iface: "Callable[[], None] | None" = None,
        data_dir: "Path | None" = None,
        on_reachable: "Callable[[list[str]], None] | None" = None,
        port_enforcer=None,   # portfilter.PortFilter | None (opt-in --enforce-ports)
        policy_refresh=None,  # callable: reload the grant table from disk each cycle
        reachable_min_interval: float = 30.0,
        local_hostname: "str | None" = None,   # enables derived host: tags
        republish_version=None,
    ) -> None:
        super().__init__(interval, "reconcile")
        # For the rename-mesh grace marker (rename_grace.json): while it's
        # live, the OLD domain's names keep resolving alongside the new; at
        # the deadline the old block + marker retire.
        self._data_dir = data_dir
        self._iface = iface
        # Recreates the mesh interface (a closure over the daemon's config +
        # keys). The daemon creates the interface once at startup, but it can
        # vanish underneath a running daemon — a purge/re-create on the same
        # host, or a manual `ip link del` — after which every peer install
        # fails (door enrollments included) until a restart. With this hook the
        # loop self-heals: each cycle re-checks and recreates if it's gone.
        self._ensure_iface = ensure_iface
        self._port_enforcer = port_enforcer
        self._policy_refresh = policy_refresh
        self._directory = directory
        self._local_id_pub = local_id_pub
        self._local_caps = local_caps
        self._local_hostname = local_hostname
        # Which underlay families this node can originate on (v4/v6), for
        # peer-endpoint selection. Resolved EACH CYCLE (like the CA/revoke
        # callables below), NOT captured once: a laptop that loses IPv6 mid-run
        # (moved to a v4-only network) must re-detect and fall back to a peer's
        # v4 endpoint without a restart — otherwise it keeps dialing the now-dead
        # v6 and is stranded. None callable / None result → keep all endpoints.
        self._get_local_families = get_local_families
        # Both callables, resolved each cycle. The trusted-CA set is static in
        # practice (from config), but the revoke list changes at runtime when
        # the operator runs `gw revoke` — capturing it once would mean an anchor
        # restart to pick up a revocation.
        self._get_ca_pubs = get_ca_pubs
        self._get_revoked = get_revoked
        self._policy = policy
        # If set, maintain the /etc/hosts mesh block each cycle (opt-in).
        self._hosts_domain = hosts_domain
        # Per-peer endpoint fallback state, persisted across cycles (a no-op for
        # single-endpoint peers). Dwell scales with the reconcile interval so a
        # dead endpoint gets a few handshake attempts before we rotate.
        self._endpoint_tracker = _EndpointTracker(dwell=max(15.0, interval * 3))
        # Called when this node's live-link set (reachable) changes — the daemon
        # re-signs + republishes its record so the fleet sees the edge change.
        # Rate-limited so a flapping link can't spam the directory.
        self._on_reachable = on_reachable
        self._reachable_min_interval = reachable_min_interval
        self._last_reachable: "list[str] | None" = None
        self._last_reachable_pub = 0.0
        self._republish_version = republish_version

    def set_local_caps(self, caps: list) -> None:
        """Adopt a new local role set live — used when the anchor changed our
        roles and we renewed our credential mid-run. The next reconcile tick
        makes peering decisions with the new roles; no restart needed. (A bare
        reference swap: reconcile reads it once per tick.)"""
        self._local_caps = list(caps)

    def _maybe_publish_reachable(self, reachable: "list[str]") -> None:
        """Fire on_reachable when the live-link set changes AND at least
        reachable_min_interval has passed since the last publish — so a flapping
        edge can't spam the directory (the change is caught on the next cycle
        past the window)."""
        if self._on_reachable is None or reachable == self._last_reachable:
            return
        now = time.monotonic()
        if self._last_reachable is not None \
                and now - self._last_reachable_pub < self._reachable_min_interval:
            return  # changed, but too soon — re-detected and sent next cycle
        try:
            self._on_reachable(reachable)
            self._last_reachable = reachable
            self._last_reachable_pub = now
        except Exception as e:
            log.warning("publishing reachable set failed: %s", e)


    def _tick(self) -> None:
        if self._policy_refresh is not None:
            try:
                self._policy_refresh()   # pick up an applied policy change from disk
            except Exception as e:
                log.warning("policy reload failed: %s", e)
        if self._ensure_iface is not None and not wgmod.interface_exists(self._iface):
            log.warning("mesh interface %s is MISSING — recreating it. Something "
                        "deleted it while the daemon was running (a purge or "
                        "re-create on this host, or a manual 'ip link del').",
                        self._iface)
            try:
                self._ensure_iface()
            except Exception as e:
                log.error("could not recreate %s: %s — will retry next cycle",
                          self._iface, e)
                return
        try:
            trusted, reachable = reconcile_once(
                self._iface,
                self._directory,
                self._local_id_pub,
                self._local_caps,
                self._get_ca_pubs(),
                self._get_revoked(),
                self._policy,
                self._get_local_families() if self._get_local_families else None,
                endpoint_tracker=self._endpoint_tracker,
                local_hostname=self._local_hostname,
            )
        except Exception as e:
            log.error("reconcile error: %s", e)
            return  # no verified set this cycle; hosts stays as-is, heals next pass
        self._stamp_reconcile()   # heartbeat: a pass completed (freshness in gw watch)
        from .loop import sd_watchdog_ping
        sd_watchdog_ping()        # …and the same heartbeat to systemd's watchdog
        self._reconcile_version()
        self._maybe_publish_reachable(reachable)
        if self._port_enforcer is not None:
            # trusted = the fully-verified records; the enforcer maps their
            # roles → source addresses under the active grant table. Same set
            # the hosts block is built from, so filter and names never disagree.
            self._port_enforcer.apply(trusted)
        if self._hosts_domain:
            try:
                # Only fully-verified records (never directory.all()): a revoked
                # or expired node must drop out of name resolution on the same
                # cycle its WireGuard peer is removed.
                hosts.sync(trusted, self._hosts_domain)
                self._rename_grace(trusted, hosts)
            except Exception as e:
                log.error("hosts sync error: %s", e)

    def _reconcile_version(self) -> None:
        """Re-publish the running daemon's version in our own record so the
        fleet can see it in `gw watch`. The version is an unsigned display field
        (omitted from _body_dict), so older peers that don't parse it still
        verify the self-signature. A no-op once the record matches."""
        if self._data_dir is None or self._republish_version is None:
            return
        desired = read_daemon_version(self._data_dir)
        if not desired:
            return
        own = self._directory.get(self._local_id_pub.hex())
        if own is not None and own.version != desired:
            log.info("version: record=%s but daemon=%s — republishing",
                     own.version or "(none)", desired)
            try:
                self._republish_version(desired)
            except Exception as e:
                log.warning("could not republish version: %s", e)

    def _stamp_reconcile(self) -> None:
        """Record the time of a completed reconcile pass, so `gw watch` can show
        reconcile freshness — the 'is the daemon alive and working' signal, and
        the only freshness the anchor has (it's the sync source, so it never
        stamps last_sync). Written every pass, even a no-op one."""
        if self._data_dir is None:
            return
        try:
            stamp_reconcile_path(self._data_dir).write_text(
                dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat())
        except OSError:
            pass

    def _rename_grace(self, trusted, hosts) -> None:
        """During a rename-mesh grace window, keep the OLD domain's names
        resolving too (dual names, so nothing dials into a void mid-rename);
        at the deadline, retire the old block and the marker."""
        if self._data_dir is None:
            return
        marker = Path(self._data_dir) / "rename_grace.json"
        if not marker.exists():
            return
        try:
            data = json.loads(marker.read_text())
            old_domain = data["old_domain"]
            until = dt.datetime.fromisoformat(data["until"])
        except Exception:
            marker.unlink(missing_ok=True)
            return
        if dt.datetime.now(dt.timezone.utc) < until:
            hosts.sync(trusted, old_domain)
        else:
            hosts.remove_block(old_domain)
            marker.unlink(missing_ok=True)
            log.info("rename grace over — retired the old *.%s names", old_domain)

    # run/start/stop come from Loop.


def stamp_reconcile_path(data_dir) -> "Path":
    """Where the last-completed-reconcile timestamp lives (the daemon-liveness
    heartbeat, parallel to sync's last_sync)."""
    return Path(data_dir) / "last_reconcile"


def daemon_version_path(data_dir) -> "Path":
    """Where the running daemon stamps its greasewood version at startup. `gw
    watch` compares it to the installed version to catch an upgrade that hasn't
    been followed by a restart (the daemon keeps the OLD code in memory)."""
    return Path(data_dir) / "daemon_version"


def write_daemon_version(data_dir, version: str) -> None:
    """Record the version the daemon is actually running (called once at start).
    Best-effort — a stamp we can't write just means no drift warning."""
    try:
        daemon_version_path(data_dir).write_text(version.strip() + "\n")
    except OSError:
        pass


def read_daemon_version(data_dir) -> "str | None":
    """The version the running daemon stamped, or None if it never did."""
    try:
        return daemon_version_path(data_dir).read_text().strip() or None
    except (FileNotFoundError, OSError):
        return None


def read_last_reconcile(data_dir) -> "str | None":
    """The ISO time of the last completed reconcile pass, or None."""
    try:
        return stamp_reconcile_path(data_dir).read_text().strip()
    except (FileNotFoundError, OSError):
        return None


def seconds_since_reconcile(data_dir) -> "float | None":
    """Age in seconds of the last completed reconcile pass, or None if the
    daemon has never stamped one (or the stamp is unreadable/garbled). This is
    the backend-neutral liveness signal: systemd reads it via sd_notify's
    WatchdogSec, a non-systemd supervisor via the WedgeWatchdog self-exit, and
    an OpenRC healthcheck could stat the same file — one 'is reconcile actually
    running' truth, three consumers."""
    last = read_last_reconcile(data_dir)
    if last is None:
        return None
    try:
        t = dt.datetime.fromisoformat(last)
    except ValueError:
        return None
    return (dt.datetime.now(dt.timezone.utc) - t).total_seconds()


# --- daemon death breadcrumb ----------------------------------------------
# Counterpart to the liveness heartbeat above: when `gw run` dies on an
# unrecoverable STARTUP condition (port in use, control plane can't bind, bad
# anchor config), it drops the reason here before exiting. `gw watch` then shows
# WHY the daemon is down instead of a bare "not running" — the fix for a
# near-invisible systemd restart loop. Cleared once a start fully succeeds.

def daemon_fatal_path(data_dir) -> "Path":
    return Path(data_dir) / "daemon_fatal.json"


def write_daemon_fatal(data_dir, reason: str) -> None:
    """Record why the daemon is refusing to start (ISO ts + reason)."""
    try:
        daemon_fatal_path(data_dir).write_text(json.dumps({
            "ts": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat(),
            "reason": reason,
        }))
    except OSError:
        pass


def read_daemon_fatal(data_dir) -> "dict | None":
    """The last startup-fatal breadcrumb ({ts, reason}), or None if the daemon
    isn't recording one (never failed, or a later start cleared it)."""
    try:
        d = json.loads(daemon_fatal_path(data_dir).read_text())
        return d if isinstance(d, dict) and "reason" in d else None
    except (FileNotFoundError, OSError, ValueError):
        return None


def clear_daemon_fatal(data_dir) -> None:
    """Startup fully succeeded — forget any prior death breadcrumb."""
    try:
        daemon_fatal_path(data_dir).unlink(missing_ok=True)
    except OSError:
        pass


def enforce_degraded_path(data_dir) -> "Path":
    return Path(data_dir) / "enforce_degraded.json"


def write_enforce_degraded(data_dir, reason: str) -> None:
    """Record that the daemon is running with enforce_ports=true but WITHOUT port
    enforcement (nftables unusable) — it degrades to open rather than crash-loop,
    so this is the only signal the operator gets that the mesh is unfiltered.
    Surfaced in `gw watch` and the --json snapshot. (H2)"""
    try:
        enforce_degraded_path(data_dir).write_text(json.dumps({
            "ts": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat(),
            "reason": reason,
        }))
    except OSError:
        pass


def read_enforce_degraded(data_dir) -> "dict | None":
    try:
        d = json.loads(enforce_degraded_path(data_dir).read_text())
        return d if isinstance(d, dict) and "reason" in d else None
    except (FileNotFoundError, OSError, ValueError):
        return None


def clear_enforce_degraded(data_dir) -> None:
    """Enforcement is healthy (or deliberately off) — clear the breadcrumb."""
    try:
        enforce_degraded_path(data_dir).unlink(missing_ok=True)
    except OSError:
        pass
