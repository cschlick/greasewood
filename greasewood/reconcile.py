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

# persistent-keepalive (secs) for a healthy or still-probing peer. A peer whose
# endpoint has gone dead past a full probe cycle drops to 0 — see _EndpointTracker.
_KEEPALIVE = 25

# A peer counts as a live link (for the published `reachable` set) if it
# handshaked within this window. ~180s covers WireGuard's ~2-min refresh on an
# idle-but-live tunnel (keepalive=25 keeps it well inside).
_LIVE_LINK_SECS = 180

# Step 6 authorization policy: (local_caps, peer_caps) → bool
Policy = Callable[[list[str], list[str]], bool]


class _Desired(NamedTuple):
    """What one WireGuard peer should look like after this cycle."""
    addr: str                   # the peer's overlay /128
    endpoint: "str | None"      # underlay endpoint to pin (None: peer initiates)
    keepalive: int              # 25, or 0 when backed off (dead endpoint)


class ReconcileResult(NamedTuple):
    trusted: list               # fully-verified records — the ONLY derivable set
    reachable: list             # overlay addrs with a live handshake (published)


def _roles(caps: list[str]) -> set[str]:
    """A node's roles, carried as `role:<name>` tags in its CA-signed caps
    (attested, anchor-assigned, renewed) — no separate wire field. `role:*` is
    the reach-all wildcard (the anchor carries it)."""
    return {c[len("role:"):] for c in caps if c.startswith("role:")}


def default_policy(local_caps: list[str], peer_caps: list[str]) -> bool:
    """The peering decision when the daemon is wired without a GrantPolicy
    (tests, embedding): defer to policy.peers_allowed with no table — the flat
    trusted mesh. The real decision lives in greasewood.policy; enforcement is
    mutual either way (a link needs BOTH ends to install each other, each
    reading the other's roles from its CA-signed credential — a node can't
    talk its way into a role it wasn't issued)."""
    from .policy import peers_allowed
    return peers_allowed(local_caps, peer_caps, None)


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


class _EndpointTracker:
    """Per-peer endpoint fallback state, carried across reconcile cycles.

    WireGuard pins one endpoint per peer and keeps retrying it forever, so a
    peer that advertises a working v4 AND a broken v6 (the common dual-stack
    case) never connects if v6 was chosen. This advances to the peer's NEXT
    advertised endpoint once the current one has gone `dwell` seconds with no
    handshake, round-robining until one sticks. It only ever tries endpoints the
    PEER advertised — still direct-or-fail, no relay. A fresh handshake resets
    the dwell clock, so a healthy link is never disturbed.
    """

    def __init__(self, dwell: float = 20.0, healthy: float = _LIVE_LINK_SECS) -> None:
        self._dwell = dwell
        # A handshake within `healthy` seconds means the current endpoint works
        # (defaults to the shared _LIVE_LINK_SECS window).
        self._healthy = healthy
        self._state: dict[str, _PeerEndpoint] = {}  # keyed by wg_pub_b64

    def _is_healthy(self, hs: int, now: float) -> bool:
        return bool(hs) and (now - hs) <= self._healthy

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
        return st.current

    def is_backoff(self, wg_pub_b64: str) -> bool:
        """True if this peer's endpoint has been dead past a full probe cycle —
        pinned but not worth keepalive traffic (see choose())."""
        st = self._state.get(wg_pub_b64)
        return bool(st and st.dead)


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

    # The ANCHOR (reach-all, role:*) admits expired-but-not-revoked nodes so they
    # can renew over its tunnel — expiry means "re-check-in with the anchor", not
    # "dead" (revocation is the kill switch). Regular nodes NEVER waive expiry, so
    # a stale node stays out of the mesh until the anchor recertifies it.
    is_anchor = "*" in _roles(local_caps)

    for record in directory.all():
        try:
            record.verify(ca_pubs, revoked, allow_expired=is_anchor)
        except ValueError as e:
            log.debug("skip %s: %s", record.hostname, e)
            continue
        if is_anchor and record.id_pub != local_id_pub \
                and dt.datetime.now(dt.timezone.utc) >= record.cred.exp:
            log.info("anchor admitting expired node %s [%s] for recertification "
                     "(not revoked) — it can renew over this tunnel",
                     record.hostname, record.cred.addr)
        trusted.append(record)

        if record.id_pub == local_id_pub:
            continue  # never install self as peer

        # Step 6: authorization policy
        if not policy(local_caps, record.cred.caps):
            log.debug("skip %s: policy denied", record.hostname)
            continue

        wg_pub_b64 = base64.b64encode(record.cred.wg_pub).decode()
        candidates = _endpoint_candidates(record.endpoints, local_families)
        keepalive = _KEEPALIVE
        if endpoint_tracker is not None:
            live_peer = live_peers.get(wg_pub_b64)
            last_handshake = live_peer.latest_handshake if live_peer else 0
            endpoint = endpoint_tracker.choose(wg_pub_b64, candidates,
                                               last_handshake, now)
            if endpoint_tracker.is_backoff(wg_pub_b64):
                keepalive = 0          # dead endpoint: stop the futile 25s poke
        else:
            endpoint = candidates[0] if candidates else None
        desired[wg_pub_b64] = _Desired(record.cred.addr, endpoint, keepalive)
        # Context for the audit trail: name + segments, so every peer command
        # says WHO and WHY, not just a bare pubkey.
        roles = ",".join(sorted(_roles(record.cred.caps))) or "-"
        context[wg_pub_b64] = f"{record.hostname} [{record.cred.addr}] roles={roles}"

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
                wgmod.set_peer(iface, wg_pub, want.addr, want.endpoint,
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
        route_missing = not have.allowed_ips or want.addr not in have.allowed_ips
        keepalive_changed = have.keepalive != want.keepalive  # dead↔alive flips 25↔0
        if endpoint_changed or route_missing or keepalive_changed:
            try:
                why = ("endpoint" if endpoint_changed else
                       "keepalive" if keepalive_changed else "route")
                with audit.context(f"reconcile: ~peer {_who(wg_pub)} ({why})"):
                    wgmod.set_peer(iface, wg_pub, want.addr, want.endpoint,
                                   keepalive=want.keepalive)
            except Exception as e:
                log.warning("update peer ...%s failed: %s", wg_pub[-8:], e)

    for wg_pub in to_remove:
        try:
            # Pass allowed_ip so the kernel route is also removed
            have = live_peers[wg_pub]
            peer_ip = have.allowed_ips.split("/")[0] if have.allowed_ips else None
            with audit.context(f"reconcile: -peer {_who(wg_pub)}"):
                wgmod.remove_peer(iface, wg_pub, peer_ip)
        except Exception as e:
            log.warning("remove peer ...%s failed: %s", wg_pub[-8:], e)

    # The overlay addrs we currently have a LIVE link to (recent handshake). This
    # is what a node publishes as its `reachable` set so the fleet can see which
    # edges are up — an unreachable segment-mate (firewalled) shows as a missing
    # edge from both ends. Session-existence, not direction (a working tunnel is
    # bidirectional regardless of who dialed).
    reachable = sorted(
        want.addr for wg_pub, want in desired.items()
        if (live_peer := live_peers.get(wg_pub)) and live_peer.latest_handshake
        and (now - live_peer.latest_handshake) <= _LIVE_LINK_SECS
    )
    return ReconcileResult(trusted, reachable)


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
        local_families: "set[int] | None" = None,
        ensure_iface: "Callable[[], None] | None" = None,
        data_dir: "Path | None" = None,
        on_reachable: "Callable[[list[str]], None] | None" = None,
        port_enforcer=None,   # portfilter.PortFilter | None (opt-in --enforce-ports)
        policy_refresh=None,  # callable: reload the grant table from disk each cycle
        reachable_min_interval: float = 30.0,
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
        # Underlay families this node can originate on, for peer-endpoint
        # selection (v4/v6). None → pick the first advertised endpoint.
        self._local_families = local_families
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
                self._local_families,
                endpoint_tracker=self._endpoint_tracker,
            )
        except Exception as e:
            log.error("reconcile error: %s", e)
            return  # no verified set this cycle; hosts stays as-is, heals next pass
        self._stamp_reconcile()   # heartbeat: a pass completed (freshness in gw watch)
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


def read_last_reconcile(data_dir) -> "str | None":
    """The ISO time of the last completed reconcile pass, or None."""
    try:
        return stamp_reconcile_path(data_dir).read_text().strip()
    except (FileNotFoundError, OSError):
        return None
