"""
greasewood.renewal — credential renewal loop (§10.3).

Renews at ~half the remaining TTL plus ±10% jitter, giving several retry
windows before expiry. Jitter spreads load across the fleet so the anchor
doesn't see a thundering herd at the N-hour mark.

On success: embeds the new credential in a fresh NodeRecord (seq bumped),
re-signs it, updates the local directory + cache, AND re-publishes it to the
anchor. The re-publish is essential: peers pull records from the anchor, so a renewed
credential that only lived locally would never reach them — the anchor would keep
serving the about-to-expire record and peers would evict this node at its old
expiry even though it renewed. Pushing the fresh record is what keeps the mesh
from tearing down one credential TTL after start.
"""
from __future__ import annotations

import datetime as dt
import json
import logging
import random
import secrets
import threading
import urllib.error
import urllib.request
from pathlib import Path
from typing import Callable

from .directory import Directory
from .loop import Loop
from .keys import NodeKeys
from .wire import Credential, NodeRecord, RenewRequest

log = logging.getLogger(__name__)
_UTC = dt.timezone.utc


def _do_renew(root_url: str, node_keys: NodeKeys, timeout: float = 15.0) -> Credential:
    req = RenewRequest(
        id_pub=node_keys.id_pub_bytes,
        wg_pub=node_keys.wg_pub_bytes,
        nonce=secrets.token_hex(16),
        ts=dt.datetime.now(_UTC).replace(microsecond=0),
    ).sign(node_keys.id_priv)

    body = json.dumps(req.to_dict()).encode()
    url = f"{root_url.rstrip('/')}/renew"
    http_req = urllib.request.Request(
        url, data=body, headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(http_req, timeout=timeout) as resp:
            data = json.loads(resp.read())
    except urllib.error.URLError as e:
        raise RuntimeError(f"renewal HTTP error: {e}") from e

    if "error" in data:
        raise ValueError(data["error"])
    return Credential.from_dict(data)


class RenewalLoop(Loop):
    def __init__(
        self,
        node_keys: NodeKeys,
        directory: Directory,
        get_anchor_url: "Callable[[], str]",
        current_cred: Credential,
        hostname: str,
        endpoints: list[str],
        cache_path: Path,
        renew_spread: float = 2.0,
        aliases: "list[str] | None" = None,
        on_renew: "Callable[[Credential], None] | None" = None,
    ) -> None:
        # interval is unused (run() is event-driven — see the module docstring)
        super().__init__(0.0, "renewal")
        self._keys = node_keys
        self._directory = directory
        # A callable returning the anchor URL to renew against (the configured anchor).
        self._get_anchor_url = get_anchor_url
        self._cred = current_cred
        self._hostname = hostname
        self._endpoints = endpoints
        self._aliases = list(aliases or [])
        self._cache_path = cache_path
        # Fleet-wide renew hint (see gw renew-all): setting _renew_now wakes the
        # loop early. renew_spread is the jitter window PER NODE — the actual
        # window scales with the mesh size (window = N * renew_spread) so a
        # uniform pick keeps the anchor's renewals/sec roughly constant as the fleet
        # grows, instead of an N-proportional spike.
        self._renew_now = threading.Event()
        self._renew_spread = renew_spread
        self._acted_renew_after: "dt.datetime | None" = None
        # Called with the fresh Credential after a renewal — the daemon adopts
        # any role change the anchor made (via set-roles) into its LIVE peering
        # + port-enforcement decisions, no restart. The renewed cred is the
        # authoritative role source; local_caps follows it.
        self._on_renew = on_renew

    def maybe_renew_after(self, ts: "dt.datetime | None") -> None:
        """Act on the anchor's fleet-wide renew hint. If our current credential was
        issued before `ts`, schedule a renewal after a jittered delay drawn
        uniformly from [0, N * renew_spread] (N = mesh size), so the fleet's
        renewals spread at a size-independent rate. Self-clearing: once we renew,
        our iat passes `ts` and this no-ops; an offline node acts when it returns."""
        if ts is None:
            return
        iat = self._cred.iat
        if iat.tzinfo is None:
            iat = iat.replace(tzinfo=_UTC)
        if iat >= ts:
            return                         # our credential already postdates the hint
        if self._acted_renew_after == ts:
            return                         # already scheduled for this hint
        self._acted_renew_after = ts
        n = max(1, self._directory.size())
        window = n * self._renew_spread
        delay = random.uniform(0.0, window)
        log.info("anchor requested fleet renewal (renew_after=%s); our cred predates "
                 "it — renewing in %.0fs (window %.0fs over %d nodes)",
                 ts, delay, window, n)
        timer = threading.Timer(delay, self._renew_now.set)
        timer.daemon = True
        timer.start()

    def _next_delay(self) -> float:
        """Sleep until ~half the remaining TTL, with ±10% jitter."""
        remaining = (self._cred.exp - dt.datetime.now(_UTC)).total_seconds()
        half = max(30.0, remaining / 2)
        jitter = random.uniform(-half * 0.1, half * 0.1)
        return half + jitter

    def _publish(self, cred: Credential) -> NodeRecord:
        existing = self._directory.get(self._keys.id_pub_hex)
        seq = (existing.seq + 1) if existing else 1
        record = NodeRecord(
            id_pub=self._keys.id_pub_bytes,
            seq=seq,
            endpoints=self._endpoints,
            cred=cred,
            aliases=self._aliases,
            # Preserve the live-link set the reconcile loop maintains, so a
            # renewal doesn't wipe it (it composes via the directory seq).
            reachable=list(existing.reachable) if existing else [],
        ).sign(self._keys.id_priv)
        self._directory.put(record)
        self._directory.save(self._cache_path)
        return record

    def _renew_and_publish(self) -> Credential:
        """Renew the credential, update the local directory, and re-publish the
        fresh record to the anchor (the push is not optional — see the module
        docstring). Raises on any failure so the caller's retry/backoff loop
        re-attempts the whole step."""
        from .sync import push_record
        new_cred = _do_renew(self._get_anchor_url(), self._keys)
        self._cred = new_cred
        record = self._publish(new_cred)
        push_record(self._get_anchor_url(), record)
        if self._on_renew is not None:
            try:
                self._on_renew(new_cred)   # adopt any anchor-side role change, live
            except Exception as e:
                log.warning("on_renew hook failed (roles may need a restart): %s", e)
        return new_cred

    def run(self) -> None:
        # Wait until EITHER the scheduled ~half-TTL time OR an early wake from a
        # fleet renew hint (maybe_renew_after) — then renew. stop() also sets
        # _renew_now so shutdown doesn't block on the long timeout.
        while not self._stop.is_set():
            self._renew_now.wait(timeout=self._next_delay())
            if self._stop.is_set():
                return
            self._renew_now.clear()
            for attempt in range(5):
                try:
                    new_cred = self._renew_and_publish()
                    log.info("credential renewed + republished, expires %s", new_cred.exp)
                    break
                except Exception as e:
                    backoff = 30 * (2 ** attempt)
                    log.warning(
                        "renewal attempt %d failed (%s); retry in %ds", attempt + 1, e, backoff
                    )
                    if self._stop.wait(backoff):
                        return

    # start() comes from Loop; run() is overridden above (event-driven).

    def stop(self) -> None:
        self._stop.set()
        self._renew_now.set()   # wake run() out of its wait for a prompt shutdown
