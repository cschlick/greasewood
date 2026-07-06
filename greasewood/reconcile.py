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
import logging
import threading
from pathlib import Path
import time
from typing import Callable

from .directory import Directory
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


def _segments(caps: list[str]) -> set[str]:
    """A node's segments, carried as `segment:<name>` tags in its CA-signed caps
    (attested, anchor-assigned, renewed) — no separate wire field. Every node is in
    `segment:mesh` by default; `segment:*` is the reach-all wildcard (the anchor)."""
    return {c[len("segment:"):] for c in caps if c.startswith("segment:")}


def default_policy(local_caps: list[str], peer_caps: list[str]) -> bool:
    """Two nodes may hold a tunnel iff they **share a segment** (§9). Segments
    are `segment:<name>` tags; the single rule is set intersection:

    - `segment:*` on either side → allowed (the reach-all wildcard: the anchor,
      which must reach every node, and any shared-services node).
    - otherwise                  → allowed iff their segment sets intersect.
    - a node in no segment at all → allowed with no one.

    Every node gets `segment:mesh` at enrollment, so by default the whole fleet
    shares one segment and is a flat mesh. Putting a node in a different segment
    (e.g. `segment:prod`) drops it from `mesh` and isolates it; a node can sit in
    several segments to bridge them. Enforcement is mutual: a link needs both
    ends to install each other, and peer segments are read from the peer's
    CA-signed credential, so a node can't talk its way into a segment it wasn't
    issued.
    """
    local, peer = _segments(local_caps), _segments(peer_caps)
    if not local or not peer:
        return False
    if "*" in local or "*" in peer:
        return True
    return bool(local & peer)


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

    def __init__(self, dwell: float = 20.0, healthy: float = 180.0) -> None:
        self._dwell = dwell
        # A handshake within `healthy` seconds means the current endpoint works.
        # ~180s covers WireGuard's ~2-min handshake refresh on an idle-but-live
        # tunnel (matches the 'LINKED' window gw diagnose uses).
        self._healthy = healthy
        self._state: dict[str, dict] = {}  # wg_pub_b64 → {current, since}

    def _is_healthy(self, hs: int, now: float) -> bool:
        return bool(hs) and (now - hs) <= self._healthy

    def choose(self, wg_pub_b64: str, candidates: list[str],
               hs: int, now: float) -> "str | None":
        if not candidates:
            self._state.pop(wg_pub_b64, None)
            return None
        st = self._state.get(wg_pub_b64)
        if st is None or st["current"] not in candidates:
            # New peer, or it re-advertised a set without our current endpoint.
            # Start the unhealthy clock now if it isn't already handshaking, so
            # the backoff countdown runs from when we first pinned the endpoint.
            healthy = self._is_healthy(hs, now)
            st = {"current": candidates[0], "since": now,
                  "unhealthy_since": None if healthy else now, "dead": False}
            self._state[wg_pub_b64] = st
            return st["current"]
        if self._is_healthy(hs, now):
            # Working link → reset the dwell clock, clear any backoff.
            st.update(since=now, unhealthy_since=None, dead=False)
            return st["current"]
        if st.get("unhealthy_since") is None:
            st["unhealthy_since"] = now
        if len(candidates) > 1 and (now - st["since"]) >= self._dwell:
            i = candidates.index(st["current"])
            st["current"] = candidates[(i + 1) % len(candidates)]
            st["since"] = now
        # Backoff: once we've been unhealthy for a full probe cycle (dwell per
        # advertised endpoint) with no handshake, the endpoint(s) are dead. We
        # keep it pinned for automatic recovery, but the caller drops keepalive
        # to 0 so we stop firing a futile packet every 25s into the void.
        st["dead"] = (now - st["unhealthy_since"]) >= self._dwell * len(candidates)
        return st["current"]

    def is_backoff(self, wg_pub_b64: str) -> bool:
        """True if this peer's endpoint has been dead past a full probe cycle —
        pinned but not worth keepalive traffic (see choose())."""
        st = self._state.get(wg_pub_b64)
        return bool(st and st.get("dead"))


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
) -> list:
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

    Returns the records that passed full verification (steps 1–5, including the
    local node's own record). This is the ONLY set other outputs may be derived
    from — the /etc/hosts block is built from it, so a revoked or expired node
    stops resolving on the same cycle its tunnel comes down. The directory cache
    itself is deliberately looser (structural checks only) so it survives
    re-roots and clock skew; anything user-visible must go through this gate.
    """
    # Live kernel state up front: the endpoint tracker needs each peer's last
    # handshake time to decide whether its current endpoint is working.
    live = wgmod.get_peers(iface)
    now_epoch = time.time() if endpoint_tracker is not None else 0.0

    # Build the desired peer set: wg_pub_b64 → (overlay_addr, endpoint | None)
    desired: dict[str, tuple[str, str | None]] = {}
    meta: dict[str, str] = {}   # wg_pub_b64 → human context for the audit trail
    trusted: list = []

    for record in directory.all():
        try:
            record.verify(ca_pubs, revoked)
        except ValueError as e:
            log.debug("skip %s: %s", record.hostname, e)
            continue
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
            lp = live.get(wg_pub_b64)
            hs = lp.latest_handshake if lp else 0
            endpoint = endpoint_tracker.choose(wg_pub_b64, candidates, hs, now_epoch)
            if endpoint_tracker.is_backoff(wg_pub_b64):
                keepalive = 0          # dead endpoint: stop the futile 25s poke
        else:
            endpoint = candidates[0] if candidates else None
        desired[wg_pub_b64] = (record.cred.addr, endpoint, keepalive)
        # Context for the audit trail: name + segments, so every peer command
        # says WHO and WHY, not just a bare pubkey.
        segs = ",".join(sorted(_segments(record.cred.caps))) or "-"
        meta[wg_pub_b64] = f"{record.hostname} [{record.cred.addr}] seg={segs}"

    # Diff against live kernel state and apply
    live_set = set(live)
    desired_set = set(desired)

    def _who(pub: str) -> str:
        return meta.get(pub, f"...{pub[-8:]}")

    for pub in desired_set - live_set:
        addr, ep, ka = desired[pub]
        try:
            with audit.context(f"reconcile: +peer {_who(pub)}"):
                wgmod.set_peer(iface, pub, addr, ep, keepalive=ka)
        except Exception as e:
            log.warning("add peer ...%s failed: %s", pub[-8:], e)

    for pub in desired_set & live_set:
        addr, ep, ka = desired[pub]
        # ep=None (the peer stopped advertising, e.g. went outbound-only)
        # deliberately does NOT clear a live endpoint: WireGuard roams the
        # endpoint on any authenticated packet anyway, and clearing one would
        # require remove+re-add — tearing down a working session for no gain.
        endpoint_changed = ep and live[pub].endpoint != ep
        route_missing = not live[pub].allowed_ips or addr not in live[pub].allowed_ips
        ka_changed = live[pub].keepalive != ka   # dead↔alive flips keepalive 25↔0
        if endpoint_changed or route_missing or ka_changed:
            try:
                why = ("endpoint" if endpoint_changed else
                       "keepalive" if ka_changed else "route")
                with audit.context(f"reconcile: ~peer {_who(pub)} ({why})"):
                    wgmod.set_peer(iface, pub, addr, ep, keepalive=ka)
            except Exception as e:
                log.warning("update peer ...%s failed: %s", pub[-8:], e)

    for pub in live_set - desired_set:
        try:
            # Pass allowed_ip so the kernel route is also removed
            peer_ip = live[pub].allowed_ips.split("/")[0] if live[pub].allowed_ips else None
            with audit.context(f"reconcile: -peer {_who(pub)}"):
                wgmod.remove_peer(iface, pub, peer_ip)
        except Exception as e:
            log.warning("remove peer ...%s failed: %s", pub[-8:], e)

    # The overlay addrs we currently have a LIVE link to (recent handshake). This
    # is what a node publishes as its `reachable` set so the fleet can see which
    # edges are up — an unreachable segment-mate (firewalled) shows as a missing
    # edge from both ends. Session-existence, not direction (a working tunnel is
    # bidirectional regardless of who dialed).
    hs_now = time.time()
    reachable = sorted(
        addr for pub, (addr, _ep, _ka) in desired.items()
        if (lp := live.get(pub)) and lp.latest_handshake
        and (hs_now - lp.latest_handshake) <= _LIVE_LINK_SECS
    )
    return trusted, reachable


class ReconcileLoop:
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
        reachable_min_interval: float = 30.0,
    ) -> None:
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
        self._interval = interval
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
        self._stop = threading.Event()

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

    def run(self) -> None:
        while not self._stop.wait(self._interval):
            self._cycle()

    def _cycle(self) -> None:
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
        self._maybe_publish_reachable(reachable)
        if self._hosts_domain:
            try:
                from . import hosts
                # Only fully-verified records (never directory.all()): a revoked
                # or expired node must drop out of name resolution on the same
                # cycle its WireGuard peer is removed.
                hosts.sync(trusted, self._hosts_domain)
                self._rename_grace(trusted, hosts)
            except Exception as e:
                log.error("hosts sync error: %s", e)

    def _rename_grace(self, trusted, hosts) -> None:
        """During a rename-mesh grace window, keep the OLD domain's names
        resolving too (dual names, so nothing dials into a void mid-rename);
        at the deadline, retire the old block and the marker."""
        if self._data_dir is None:
            return
        import datetime as dt
        import json
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

    def start(self) -> threading.Thread:
        t = threading.Thread(target=self.run, name="reconcile", daemon=True)
        t.start()
        return t

    def stop(self) -> None:
        self._stop.set()
