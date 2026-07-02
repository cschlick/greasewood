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
from typing import Callable

from .directory import Directory
from . import wg as wgmod

log = logging.getLogger(__name__)

# Step 6 authorization policy: (local_caps, peer_caps) → bool
Policy = Callable[[list[str], list[str]], bool]


def _segments(caps: list[str]) -> set[str]:
    """A node's segments, carried as `segment:<name>` tags in its CA-signed caps
    (attested, hub-assigned, renewed) — no separate wire field. Every node is in
    `segment:mesh` by default; `segment:*` is the reach-all wildcard (the hub)."""
    return {c[len("segment:"):] for c in caps if c.startswith("segment:")}


def default_policy(local_caps: list[str], peer_caps: list[str]) -> bool:
    """Two nodes may hold a tunnel iff they **share a segment** (§9). Segments
    are `segment:<name>` tags; the single rule is set intersection:

    - `segment:*` on either side → allowed (the reach-all wildcard: the hub,
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


def reconcile_once(
    iface: str,
    directory: Directory,
    local_id_pub: bytes,
    local_caps: list[str],
    ca_pubs: list[bytes],
    revoked: set[str],
    policy: Policy = default_policy,
) -> None:
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
    """
    # Build the desired peer set: wg_pub_b64 → (overlay_addr, endpoint | None)
    desired: dict[str, tuple[str, str | None]] = {}

    for record in directory.all():
        if record.id_pub == local_id_pub:
            continue  # never install self as peer

        try:
            record.verify(ca_pubs, revoked)
        except ValueError as e:
            log.debug("skip %s: %s", record.hostname, e)
            continue

        # Step 6: authorization policy
        if not policy(local_caps, record.cred.caps):
            log.debug("skip %s: policy denied", record.hostname)
            continue

        wg_pub_b64 = base64.b64encode(record.cred.wg_pub).decode()
        endpoint = record.endpoints[0] if record.endpoints else None
        desired[wg_pub_b64] = (record.cred.addr, endpoint)

    # Diff against live kernel state and apply
    live = wgmod.get_peers(iface)
    live_set = set(live)
    desired_set = set(desired)

    for pub in desired_set - live_set:
        addr, ep = desired[pub]
        try:
            wgmod.set_peer(iface, pub, addr, ep)
        except Exception as e:
            log.warning("add peer ...%s failed: %s", pub[-8:], e)

    for pub in desired_set & live_set:
        addr, ep = desired[pub]
        endpoint_changed = ep and live[pub].endpoint != ep
        route_missing = not live[pub].allowed_ips or addr not in live[pub].allowed_ips
        if endpoint_changed or route_missing:
            try:
                wgmod.set_peer(iface, pub, addr, ep)
            except Exception as e:
                log.warning("update peer ...%s failed: %s", pub[-8:], e)

    for pub in live_set - desired_set:
        try:
            # Pass allowed_ip so the kernel route is also removed
            peer_ip = live[pub].allowed_ips.split("/")[0] if live[pub].allowed_ips else None
            wgmod.remove_peer(iface, pub, peer_ip)
        except Exception as e:
            log.warning("remove peer ...%s failed: %s", pub[-8:], e)


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
    ) -> None:
        self._iface = iface
        self._directory = directory
        self._local_id_pub = local_id_pub
        self._local_caps = local_caps
        # Both callables, resolved each cycle. The trusted-CA set is static in
        # practice (from config), but the revoke list changes at runtime when
        # the operator runs `gw revoke` — capturing it once would mean a hub
        # restart to pick up a revocation.
        self._get_ca_pubs = get_ca_pubs
        self._get_revoked = get_revoked
        self._interval = interval
        self._policy = policy
        # If set, maintain the /etc/hosts mesh block each cycle (opt-in).
        self._hosts_domain = hosts_domain
        self._stop = threading.Event()

    def run(self) -> None:
        while not self._stop.wait(self._interval):
            try:
                reconcile_once(
                    self._iface,
                    self._directory,
                    self._local_id_pub,
                    self._local_caps,
                    self._get_ca_pubs(),
                    self._get_revoked(),
                    self._policy,
                )
            except Exception as e:
                log.error("reconcile error: %s", e)
            if self._hosts_domain:
                try:
                    from . import hosts
                    hosts.sync(self._directory.all(), self._hosts_domain)
                except Exception as e:
                    log.error("hosts sync error: %s", e)

    def start(self) -> threading.Thread:
        t = threading.Thread(target=self.run, name="reconcile", daemon=True)
        t.start()
        return t

    def stop(self) -> None:
        self._stop.set()
