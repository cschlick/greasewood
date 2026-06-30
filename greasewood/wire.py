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

RenewRequest is sent by enrolled nodes to the root for credential renewal.
Enrollment is SSH-only (operator runs `greasewood issue` on the root); there
is no HTTP enrollment endpoint.
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


# ---------------------------------------------------------------------------
# CAStatement — the unit of CA succession (§11)
# ---------------------------------------------------------------------------

@dataclass
class CAStatement:
    """
    A signed statement by one CA about another, used to migrate hub/CA status
    without ever moving a private key.

      kind="endorse": by_pub vouches for subject_pub as a (successor) CA, and
                      optionally advertises subject's hub control-plane endpoint.
                      This is how a new CA enters the trusted set.
      kind="retire":  by_pub declares subject_pub no longer a valid signer.
                      This is how the old CA leaves the trusted set fleet-wide
                      without editing every node's config.

    Endorsements are durable facts: an endorsement signed by A while A was
    trusted keeps making subject trusted even after A is itself retired — so a
    successor survives its predecessor's retirement (see trust.resolve_trust).
    """
    kind: str            # "endorse" | "retire"
    by_pub: bytes        # CA making + signing the statement (32-byte Ed25519)
    subject_pub: bytes   # CA being endorsed / retired (32-byte Ed25519)
    hub_endpoint: str     # subject's control-plane URL (endorse only); "" otherwise
    iat: dt.datetime
    exp: dt.datetime
    sig: bytes = field(default=b"", repr=False)

    def _body_dict(self) -> dict[str, Any]:
        return {
            "by_pub": _b64e(self.by_pub),
            "exp": _ts(self.exp),
            "hub_endpoint": self.hub_endpoint,
            "iat": _ts(self.iat),
            "kind": self.kind,
            "subject_pub": _b64e(self.subject_pub),
        }

    def sign(self, by_priv: Ed25519PrivateKey) -> "CAStatement":
        return replace(self, sig=by_priv.sign(_canonical(self._body_dict())))

    def verify_sig(self) -> None:
        """Verify the statement is correctly signed by by_pub. Raises ValueError."""
        if self.kind not in ("endorse", "retire"):
            raise ValueError(f"unknown CAStatement kind: {self.kind!r}")
        pub = Ed25519PublicKey.from_public_bytes(self.by_pub)
        try:
            pub.verify(self.sig, _canonical(self._body_dict()))
        except InvalidSignature:
            raise ValueError("invalid CAStatement signature")

    def is_valid_at(self, now: dt.datetime) -> bool:
        """True if correctly signed and within [iat, exp)."""
        try:
            self.verify_sig()
        except ValueError:
            return False
        return self.iat <= now < self.exp

    def ident(self) -> str:
        """Stable identity for de-duplication (the signature is unique)."""
        return _b64e(self.sig)

    def to_dict(self) -> dict[str, Any]:
        d = self._body_dict()
        d["sig"] = _b64e(self.sig)
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "CAStatement":
        return cls(
            kind=d["kind"],
            by_pub=_b64d(d["by_pub"]),
            subject_pub=_b64d(d["subject_pub"]),
            hub_endpoint=d.get("hub_endpoint", ""),
            iat=_parse_ts(d["iat"]),
            exp=_parse_ts(d["exp"]),
            sig=_b64d(d["sig"]),
        )


# ---------------------------------------------------------------------------
# CertRequest — a node asking the hub for an x509 TLS cert (§12)
# ---------------------------------------------------------------------------

@dataclass
class CertRequest:
    """
    Sent by an enrolled node to the hub to obtain an x509 TLS certificate for a
    local service. id_priv possession authenticates the requester (same model
    as RenewRequest); the leaf private key never leaves the node — only leaf_pub
    is sent. nonce + ts bound replay.
    """
    id_pub: bytes        # requesting node identity (Ed25519, 32 bytes)
    leaf_pub: bytes      # the service's TLS public key (Ed25519, 32 bytes)
    cn: str              # subject common name
    dns: list[str]       # requested DNS SANs
    ips: list[str]       # requested IP SANs
    nonce: str
    ts: dt.datetime
    sig: bytes = field(default=b"", repr=False)

    def _body_dict(self) -> dict[str, Any]:
        return {
            "cn": self.cn,
            "dns": self.dns,
            "id_pub": _b64e(self.id_pub),
            "ips": self.ips,
            "leaf_pub": _b64e(self.leaf_pub),
            "nonce": self.nonce,
            "ts": _ts(self.ts),
        }

    def sign(self, id_priv: Ed25519PrivateKey) -> "CertRequest":
        return replace(self, sig=id_priv.sign(_canonical(self._body_dict())))

    def verify_self_sig(self) -> None:
        pub = Ed25519PublicKey.from_public_bytes(self.id_pub)
        try:
            pub.verify(self.sig, _canonical(self._body_dict()))
        except InvalidSignature:
            raise ValueError("invalid cert-request self-signature")

    def to_dict(self) -> dict[str, Any]:
        d = self._body_dict()
        d["sig"] = _b64e(self.sig)
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "CertRequest":
        return cls(
            id_pub=_b64d(d["id_pub"]),
            leaf_pub=_b64d(d["leaf_pub"]),
            cn=d["cn"],
            dns=list(d.get("dns", [])),
            ips=list(d.get("ips", [])),
            nonce=d["nonce"],
            ts=_parse_ts(d["ts"]),
            sig=_b64d(d["sig"]),
        )
