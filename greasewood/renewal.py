"""
greasewood.renewal — credential renewal loop (§10.3).

Renews at ~half the remaining TTL plus ±10% jitter, giving several retry
windows before expiry. Jitter spreads load across the fleet so the hub
doesn't see a thundering herd at the N-hour mark.

On success: embeds the new credential in a fresh NodeRecord (seq bumped),
re-signs it, updates the local directory + cache, AND re-publishes it to the
hub. The re-publish is essential: peers pull records from the hub, so a renewed
credential that only lived locally would never reach them — the hub would keep
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


class RenewalLoop:
    def __init__(
        self,
        node_keys: NodeKeys,
        directory: Directory,
        get_root_url: "Callable[[], str]",
        current_cred: Credential,
        inbound: str,
        hostname: str,
        endpoints: list[str],
        cache_path: Path,
    ) -> None:
        self._keys = node_keys
        self._directory = directory
        # Resolved each renewal — renewals must follow the active hub so creds
        # get re-signed by the successor CA during succession (§11).
        self._get_root_url = get_root_url
        self._cred = current_cred
        self._inbound = inbound
        self._hostname = hostname
        self._endpoints = endpoints
        self._cache_path = cache_path
        self._stop = threading.Event()

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
            inbound=self._inbound,
            hostname=self._hostname,
            cred=cred,
        ).sign(self._keys.id_priv)
        self._directory.put(record)
        self._directory.save(self._cache_path)
        return record

    def _renew_and_publish(self) -> Credential:
        """Renew the credential, update the local directory, and re-publish the
        fresh record to the hub. The push is not optional: peers pull records
        from the hub, so a credential that only lived locally would never reach
        them and they would evict this node at its old expiry. Raises on any
        failure so the caller's retry/backoff loop re-attempts the whole step."""
        from .sync import push_record
        new_cred = _do_renew(self._get_root_url(), self._keys)
        self._cred = new_cred
        record = self._publish(new_cred)
        push_record(self._get_root_url(), record)
        return new_cred

    def run(self) -> None:
        while not self._stop.wait(self._next_delay()):
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

    def start(self) -> threading.Thread:
        t = threading.Thread(target=self.run, name="renewal", daemon=True)
        t.start()
        return t

    def stop(self) -> None:
        self._stop.set()
