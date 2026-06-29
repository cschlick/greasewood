"""
greasewood.ca — certificate authority operations (root-node only).

The CA signs Credentials only. It never generates or sees any private key
other than ca_priv — only public material crosses the wire in enrollment.

Token management: one-time enrollment tokens in tokens.json (0600).
  Consuming a token removes it from the list — each token works exactly once.

Revoke list: revoked.json — a set of id_pub hex strings.
  Revoking = stopping renewal. The existing credential expires on its own.
  For emergency eviction before expiry, push an updated revoked.json to peers
  (they re-read it on each reconcile cycle).

Node caps: stored in nodes/<id_pub_hex>.json so renewal can re-use them
  without a separate config lookup.
"""
from __future__ import annotations

import datetime as dt
import json
import logging
import os
import secrets
from pathlib import Path
from typing import Callable

from .keys import CAKeys, derive_addr
from .wire import Credential, EnrollRequest, RenewRequest

log = logging.getLogger(__name__)
_UTC = dt.timezone.utc

# Called with the requested caps, returns the granted caps.
# Default: grant what was requested — override to enforce allowlists.
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
        self._token_path = data_dir / "tokens.json"

    # --- credential issuance ---

    def issue(self, id_pub: bytes, wg_pub: bytes, caps: list[str]) -> Credential:
        now = dt.datetime.now(_UTC).replace(microsecond=0)
        cred = Credential(
            id_pub=id_pub,
            wg_pub=wg_pub,
            addr=derive_addr(id_pub),
            caps=caps,
            iat=now,
            exp=now + self._ttl,
        )
        return cred.sign(self._keys.ca_priv)

    # --- enrollment (§10.1) ---

    def enroll(self, req: EnrollRequest) -> Credential:
        """
        Process an enrollment request. Raises ValueError on any failure.
        Token is consumed (one-time use) on success.
        """
        req.verify_self_sig()

        expected_addr = derive_addr(req.id_pub)
        if req.addr != expected_addr:
            raise ValueError(
                f"addr mismatch: claimed {req.addr}, expected {expected_addr}"
            )

        if self.is_revoked(req.id_pub):
            raise ValueError("id_pub is on the revoke list")

        if not self._consume_token(req.token):
            raise ValueError("invalid or already-used enrollment token")

        caps = self._cap_policy(req.req_caps)
        log.info("enrolling %s caps=%s", req.hostname, caps)
        cred = self.issue(req.id_pub, req.wg_pub, caps)
        self._save_node_caps(req.id_pub, req.hostname, caps)
        return cred

    # --- renewal (§10.3) ---

    def renew(self, req: RenewRequest) -> Credential:
        """
        Process a renewal request. Raises ValueError on any failure.
        id_priv possession is proven by the self-signature on the request.
        """
        req.verify_self_sig()

        # Guard against large clock skew (±5 min)
        skew = abs((dt.datetime.now(_UTC) - req.ts).total_seconds())
        if skew > 300:
            raise ValueError(f"timestamp skew too large ({skew:.0f}s); check NTP")

        if self.is_revoked(req.id_pub):
            raise ValueError("id_pub is on the revoke list")

        caps = self._load_node_caps(req.id_pub)
        if caps is None:
            raise ValueError("unknown node — enroll first")

        log.info("renewing %s", req.id_pub.hex()[:16])
        return self.issue(req.id_pub, req.wg_pub, caps)

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

    # --- one-time enrollment tokens ---

    def generate_token(self) -> str:
        token = secrets.token_urlsafe(32)
        tokens = self._load_tokens()
        tokens.append(token)
        self._save_tokens(tokens)
        return token

    def _consume_token(self, token: str) -> bool:
        tokens = self._load_tokens()
        if token not in tokens:
            return False
        tokens.remove(token)
        self._save_tokens(tokens)
        return True

    def _load_tokens(self) -> list[str]:
        if not self._token_path.exists():
            return []
        return json.loads(self._token_path.read_text()).get("tokens", [])

    def _save_tokens(self, tokens: list[str]) -> None:
        self._token_path.write_text(json.dumps({"tokens": tokens}, indent=2))
        os.chmod(self._token_path, 0o600)

    # --- node caps (for renewal) ---

    def _node_caps_path(self, id_pub: bytes) -> Path:
        return self._data_dir / "nodes" / f"{id_pub.hex()}.json"

    def _save_node_caps(self, id_pub: bytes, hostname: str, caps: list[str]) -> None:
        p = self._node_caps_path(id_pub)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps({"hostname": hostname, "caps": caps}, indent=2))

    def _load_node_caps(self, id_pub: bytes) -> list[str] | None:
        p = self._node_caps_path(id_pub)
        if not p.exists():
            return None
        return json.loads(p.read_text()).get("caps", [])
