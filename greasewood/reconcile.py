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


def default_policy(local_caps: list[str], peer_caps: list[str]) -> bool:
    """mesh↔mesh nodes may talk to each other. Extend as needed (§9)."""
    return "mesh" in local_caps and "mesh" in peer_caps


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
        revoked: set[str],
        interval: float = 5.0,
        policy: Policy = default_policy,
    ) -> None:
        self._iface = iface
        self._directory = directory
        self._local_id_pub = local_id_pub
        self._local_caps = local_caps
        # Resolved each cycle — the trusted-CA set grows/shrinks during CA
        # succession (§11), so it cannot be captured once.
        self._get_ca_pubs = get_ca_pubs
        self._revoked = revoked
        self._interval = interval
        self._policy = policy
        self._stop = threading.Event()

    def update_revoked(self, revoked: set[str]) -> None:
        """Thread-safe revoke list refresh (called when root pushes an update)."""
        self._revoked = revoked

    def run(self) -> None:
        while not self._stop.wait(self._interval):
            try:
                reconcile_once(
                    self._iface,
                    self._directory,
                    self._local_id_pub,
                    self._local_caps,
                    self._get_ca_pubs(),
                    self._revoked,
                    self._policy,
                )
            except Exception as e:
                log.error("reconcile error: %s", e)

    def start(self) -> threading.Thread:
        t = threading.Thread(target=self.run, name="reconcile", daemon=True)
        t.start()
        return t

    def stop(self) -> None:
        self._stop.set()
