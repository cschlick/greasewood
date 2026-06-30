"""
greasewood.ca — certificate authority operations (root-node only).

The CA signs Credentials only. It never generates or sees any private key
other than ca_priv.

Enrollment is SSH-only: the operator runs `greasewood issue` on the root node,
which calls CA.issue() directly. No token management, no HTTP enrollment
endpoint, no network exposure at enrollment time.

Revoke list: revoked.json — a set of id_pub hex strings.
  Revoking = stopping renewal. The existing credential expires on its own.
  For fast eviction push the updated revoke list to peers (they re-read on
  each reconcile cycle via the reconcile loop's revoked set).

Node caps: stored in nodes/<id_pub_hex>.json so renewal can re-use them
  without a separate config lookup. Written at issue time.
"""
from __future__ import annotations

import datetime as dt
import json
import logging
from pathlib import Path
from typing import Callable

from .keys import CAKeys, derive_addr
from .wire import CAStatement, Credential, RenewRequest

log = logging.getLogger(__name__)
_UTC = dt.timezone.utc

CapPolicy = Callable[[list[str]], list[str]]


class CA:
    def __init__(
        self,
        ca_keys: CAKeys,
        data_dir: Path,
        credential_ttl: dt.timedelta = dt.timedelta(hours=24),
        cap_policy: CapPolicy | None = None,
    ) -> None:
        self._keys = ca_keys
        self._data_dir = data_dir
        self._ttl = credential_ttl
        self._cap_policy: CapPolicy = cap_policy or (lambda caps: caps)
        self._revoke_path = data_dir / "revoked.json"

    # --- credential issuance ---

    def issue(
        self,
        id_pub: bytes,
        wg_pub: bytes,
        hostname: str,
        caps: list[str],
    ) -> Credential:
        """
        Sign a credential for a node. Call from `greasewood issue` on the root.
        Persists node caps so renewal can re-use them without operator input.
        Raises ValueError if id_pub is on the revoke list.
        """
        if self.is_revoked(id_pub):
            raise ValueError("id_pub is on the revoke list")

        caps = self._cap_policy(caps)
        now = dt.datetime.now(_UTC).replace(microsecond=0)
        cred = Credential(
            id_pub=id_pub,
            wg_pub=wg_pub,
            addr=derive_addr(id_pub),
            caps=caps,
            iat=now,
            exp=now + self._ttl,
        )
        signed = cred.sign(self._keys.ca_priv)
        self._save_node_caps(id_pub, hostname, caps)
        log.info("issued credential for %s caps=%s exp=%s", hostname, caps, signed.exp)
        return signed

    # --- renewal (§10.3) ---

    def renew(self, req: RenewRequest) -> Credential:
        """
        Process a renewal request from an already-enrolled node.
        id_priv possession is proven by the self-signature on the request.
        Raises ValueError on any failure.
        """
        req.verify_self_sig()

        skew = abs((dt.datetime.now(_UTC) - req.ts).total_seconds())
        if skew > 300:
            raise ValueError(f"timestamp skew too large ({skew:.0f}s); check NTP")

        if self.is_revoked(req.id_pub):
            raise ValueError("id_pub is on the revoke list")

        node_info = self._load_node_info(req.id_pub)
        if node_info is None:
            raise ValueError("unknown node — issue a credential first")

        hostname, caps = node_info
        log.info("renewing %s", hostname)
        return self.issue(req.id_pub, req.wg_pub, hostname, caps)

    # --- CA succession (§11) ---

    def endorse(
        self,
        subject_pub: bytes,
        hub_endpoint: str,
        ttl: dt.timedelta,
    ) -> CAStatement:
        """
        Sign an endorsement: this CA vouches for subject_pub as a (successor)
        CA and advertises its hub control-plane endpoint. Long-lived by design
        — the chain must stay intact for nodes still rooted at this CA.
        """
        now = dt.datetime.now(_UTC).replace(microsecond=0)
        stmt = CAStatement(
            kind="endorse",
            by_pub=self._keys.ca_pub_bytes,
            subject_pub=subject_pub,
            hub_endpoint=hub_endpoint,
            iat=now,
            exp=now + ttl,
        ).sign(self._keys.ca_priv)
        log.info("endorsed CA %s (endpoint=%s) until %s",
                 subject_pub.hex()[:16], hub_endpoint, stmt.exp)
        return stmt

    def retire(self, subject_pub: bytes, ttl: dt.timedelta) -> CAStatement:
        """
        Sign a retirement: subject_pub is no longer an accepted signer. Use
        after a successor has taken over and the overlap window has elapsed.
        """
        now = dt.datetime.now(_UTC).replace(microsecond=0)
        stmt = CAStatement(
            kind="retire",
            by_pub=self._keys.ca_pub_bytes,
            subject_pub=subject_pub,
            hub_endpoint="",
            iat=now,
            exp=now + ttl,
        ).sign(self._keys.ca_priv)
        log.info("retired CA %s until %s", subject_pub.hex()[:16], stmt.exp)
        return stmt

    # --- revoke list ---

    def is_revoked(self, id_pub: bytes) -> bool:
        return id_pub.hex() in self._load_revoked()

    def add_revoke(self, id_pub: bytes) -> None:
        revoked = self._load_revoked()
        revoked.add(id_pub.hex())
        self._save_revoked(revoked)
        log.info("revoked %s", id_pub.hex()[:16])

    def load_revoked_set(self) -> set[str]:
        return self._load_revoked()

    def _load_revoked(self) -> set[str]:
        if not self._revoke_path.exists():
            return set()
        return set(json.loads(self._revoke_path.read_text()).get("revoked", []))

    def _save_revoked(self, revoked: set[str]) -> None:
        self._revoke_path.write_text(
            json.dumps({"revoked": sorted(revoked)}, indent=2)
        )

    # --- node info (for renewal) ---

    def _node_path(self, id_pub: bytes) -> Path:
        return self._data_dir / "nodes" / f"{id_pub.hex()}.json"

    def _save_node_caps(self, id_pub: bytes, hostname: str, caps: list[str]) -> None:
        p = self._node_path(id_pub)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps({"hostname": hostname, "caps": caps}, indent=2))

    def _load_node_info(self, id_pub: bytes) -> tuple[str, list[str]] | None:
        p = self._node_path(id_pub)
        if not p.exists():
            return None
        d = json.loads(p.read_text())
        return d.get("hostname", ""), d.get("caps", [])
