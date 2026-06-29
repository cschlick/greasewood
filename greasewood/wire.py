"""
greasewood.wire — the two signed objects that constitute the entire protocol.

Credential (CA-signed, §5.1):
  id_pub, wg_pub, addr, caps, iat, exp → ca_sig covers all of these.
  The only thing the CA ever signs. Short-lived (~24h). Slow path.

NodeRecord (self-signed by id_priv, §5.2):
  id_pub, seq, endpoints, inbound, hostname, cred → sig covers all of these.
  Carries the full credential so any reader can verify without talking to the CA.
  Fast path — a node re-signs when its endpoint changes, no CA involvement.

Both objects use json.dumps(sort_keys=True) as the canonical signing form.
Binary fields (keys, signatures) are standard base64.

EnrollRequest and RenewRequest are the two messages nodes send to the root;
both are self-signed so interception reveals nothing useful.
"""
from __future__ import annotations

import base64
import datetime as dt
import json
import secrets
from dataclasses import dataclass, field, replace
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .keys import derive_addr

_UTC = dt.timezone.utc


def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode()


def _b64d(s: str) -> bytes:
    return base64.b64decode(s)


def _canonical(d: dict) -> bytes:
    """Deterministic JSON — the bytes that signatures cover."""
    return json.dumps(d, sort_keys=True, separators=(",", ":")).encode()


def _ts(t: dt.datetime) -> str:
    """RFC 3339 UTC, second precision. Microseconds would produce different
    canonical bytes depending on how the timestamp was constructed."""
    return t.astimezone(_UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_ts(s: str) -> dt.datetime:
    return dt.datetime.fromisoformat(s.replace("Z", "+00:00"))


# ---------------------------------------------------------------------------
# Credential
# ---------------------------------------------------------------------------

@dataclass
class Credential:
    id_pub: bytes        # 32-byte Ed25519 public key
    wg_pub: bytes        # 32-byte X25519 public key
    addr: str            # overlay IPv6 address
    caps: list[str]
    iat: dt.datetime
    exp: dt.datetime
    ca_sig: bytes = field(default=b"", repr=False)

    def _body_dict(self) -> dict[str, Any]:
        """The dict that ca_sig covers. Order is irrelevant (sort_keys=True)."""
        return {
            "addr": self.addr,
            "caps": sorted(self.caps),
            "exp": _ts(self.exp),
            "iat": _ts(self.iat),
            "id_pub": _b64e(self.id_pub),
            "wg_pub": _b64e(self.wg_pub),
        }

    def sign(self, ca_priv: Ed25519PrivateKey) -> "Credential":
        sig = ca_priv.sign(_canonical(self._body_dict()))
        return replace(self, ca_sig=sig)

    def verify(self, ca_pubs: list[bytes]) -> None:
        """
        Verify CA signature against the trusted set and check expiry.
        ca_pubs is a list of raw 32-byte Ed25519 public keys.
        The set (not a single key) is the load-bearing design for CA migration (§11).
        Raises ValueError on any failure.
        """
        body = _canonical(self._body_dict())
        for raw_pub in ca_pubs:
            pub = Ed25519PublicKey.from_public_bytes(raw_pub)
            try:
                pub.verify(self.ca_sig, body)
            except InvalidSignature:
                continue
            # Signature valid — now check expiry.
            if dt.datetime.now(_UTC) >= self.exp:
                raise ValueError(f"credential expired at {self.exp}")
            return
        raise ValueError("no trusted CA signature found")

    def to_dict(self) -> dict[str, Any]:
        d = self._body_dict()
        d["ca_sig"] = _b64e(self.ca_sig)
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "Credential":
        return cls(
            id_pub=_b64d(d["id_pub"]),
            wg_pub=_b64d(d["wg_pub"]),
            addr=d["addr"],
            caps=d["caps"],
            iat=_parse_ts(d["iat"]),
            exp=_parse_ts(d["exp"]),
            ca_sig=_b64d(d["ca_sig"]),
        )


# ---------------------------------------------------------------------------
# NodeRecord
# ---------------------------------------------------------------------------

@dataclass
class NodeRecord:
    id_pub: bytes        # 32-byte Ed25519 public key
    seq: int             # monotonic; merge takes highest per id_pub
    endpoints: list[str] # ["[v6addr]:port", ...]
    inbound: str         # "yes" | "no" | "unknown"  (§8)
    hostname: str
    cred: Credential
    sig: bytes = field(default=b"", repr=False)

    def _body_dict(self) -> dict[str, Any]:
        return {
            "cred": self.cred.to_dict(),
            "endpoints": self.endpoints,
            "hostname": self.hostname,
            "id_pub": _b64e(self.id_pub),
            "inbound": self.inbound,
            "seq": self.seq,
        }

    def sign(self, id_priv: Ed25519PrivateKey) -> "NodeRecord":
        sig = id_priv.sign(_canonical(self._body_dict()))
        return replace(self, sig=sig)

    def verify(self, ca_pubs: list[bytes], revoked: set[str]) -> None:
        """
        Full record verification — steps 1–5 of the reconcile loop (§7).
        Step 6 (authorization policy) is done by the caller with local caps.
        Raises ValueError on any failure.
        """
        # Steps 1+2: CA signature + expiry
        self.cred.verify(ca_pubs)

        # Step 3: self-signature
        body = _canonical(self._body_dict())
        pub = Ed25519PublicKey.from_public_bytes(self.id_pub)
        try:
            pub.verify(self.sig, body)
        except InvalidSignature:
            raise ValueError("invalid self-signature")

        # Step 4: addr must derive from id_pub
        expected_addr = derive_addr(self.id_pub)
        if self.cred.addr != expected_addr:
            raise ValueError(
                f"addr mismatch: record claims {self.cred.addr}, expected {expected_addr}"
            )

        # Sanity: id_pub in record must match id_pub in credential
        if self.id_pub != self.cred.id_pub:
            raise ValueError("id_pub in record does not match id_pub in credential")

        # Step 5: not on revoke list
        if self.id_pub.hex() in revoked:
            raise ValueError("node is revoked")

    def to_dict(self) -> dict[str, Any]:
        d = self._body_dict()
        d["sig"] = _b64e(self.sig)
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "NodeRecord":
        return cls(
            id_pub=_b64d(d["id_pub"]),
            seq=d["seq"],
            endpoints=d["endpoints"],
            inbound=d["inbound"],
            hostname=d["hostname"],
            cred=Credential.from_dict(d["cred"]),
            sig=_b64d(d["sig"]),
        )


# ---------------------------------------------------------------------------
# Enrollment request
# ---------------------------------------------------------------------------

@dataclass
class EnrollRequest:
    """
    CSR sent by a new node to the root during enrollment (§10.1).
    Self-signed by id_priv — proves the sender holds the private key.
    Interception reveals nothing secret (all public material plus the token).
    The token is the one-time secret that authenticates the operator's intent.
    """
    id_pub: bytes
    wg_pub: bytes
    addr: str
    hostname: str
    req_caps: list[str]
    token: str
    sig: bytes = field(default=b"", repr=False)

    def _body_dict(self) -> dict[str, Any]:
        return {
            "addr": self.addr,
            "hostname": self.hostname,
            "id_pub": _b64e(self.id_pub),
            "req_caps": sorted(self.req_caps),
            "token": self.token,
            "wg_pub": _b64e(self.wg_pub),
        }

    def sign(self, id_priv: Ed25519PrivateKey) -> "EnrollRequest":
        sig = id_priv.sign(_canonical(self._body_dict()))
        return replace(self, sig=sig)

    def verify_self_sig(self) -> None:
        body = _canonical(self._body_dict())
        pub = Ed25519PublicKey.from_public_bytes(self.id_pub)
        try:
            pub.verify(self.sig, body)
        except InvalidSignature:
            raise ValueError("invalid enrollment self-signature")

    def to_dict(self) -> dict[str, Any]:
        d = self._body_dict()
        d["sig"] = _b64e(self.sig)
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "EnrollRequest":
        return cls(
            id_pub=_b64d(d["id_pub"]),
            wg_pub=_b64d(d["wg_pub"]),
            addr=d["addr"],
            hostname=d["hostname"],
            req_caps=d["req_caps"],
            token=d["token"],
            sig=_b64d(d["sig"]),
        )


# ---------------------------------------------------------------------------
# Renewal request
# ---------------------------------------------------------------------------

@dataclass
class RenewRequest:
    """
    Sent by a node at ~half its credential TTL to renew (§10.3).
    id_priv possession is the authentication — no separate session credential.
    nonce prevents replay within the timestamp skew window.
    wg_pub may differ from the current one (free operational-key rotation).
    """
    id_pub: bytes
    wg_pub: bytes
    nonce: str
    ts: dt.datetime
    sig: bytes = field(default=b"", repr=False)

    def _body_dict(self) -> dict[str, Any]:
        return {
            "id_pub": _b64e(self.id_pub),
            "nonce": self.nonce,
            "ts": _ts(self.ts),
            "wg_pub": _b64e(self.wg_pub),
        }

    def sign(self, id_priv: Ed25519PrivateKey) -> "RenewRequest":
        sig = id_priv.sign(_canonical(self._body_dict()))
        return replace(self, sig=sig)

    def verify_self_sig(self) -> None:
        body = _canonical(self._body_dict())
        pub = Ed25519PublicKey.from_public_bytes(self.id_pub)
        try:
            pub.verify(self.sig, body)
        except InvalidSignature:
            raise ValueError("invalid renewal self-signature")

    def to_dict(self) -> dict[str, Any]:
        d = self._body_dict()
        d["sig"] = _b64e(self.sig)
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "RenewRequest":
        return cls(
            id_pub=_b64d(d["id_pub"]),
            wg_pub=_b64d(d["wg_pub"]),
            nonce=d["nonce"],
            ts=_parse_ts(d["ts"]),
            sig=_b64d(d["sig"]),
        )
