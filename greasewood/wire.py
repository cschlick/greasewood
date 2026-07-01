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

RenewRequest is sent by enrolled nodes to the hub for credential renewal.
Enrollment is out of band over the transient WireGuard "door" (`gw invite` /
`gw join`, see greasewood.door / greasewood.enroll); the control plane has no
network-reachable enrollment endpoint.
"""
from __future__ import annotations

import base64
import datetime as dt
import ipaddress
import json
import secrets
from dataclasses import dataclass, field, replace
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .keys import derive_addr, host_bits

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
    hostname: str        # CA-attested mesh hostname (§ level-b)
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
            "hostname": self.hostname,
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
        The set (not a single key) is what lets you re-root: trust old + new
        CA during a migration overlap.
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
            hostname=d["hostname"],
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
    inbound: str         # "yes" | "no"  (§8)
    cred: Credential
    sig: bytes = field(default=b"", repr=False)

    @property
    def hostname(self) -> str:
        """The mesh hostname, from the CA-signed credential (§ level-b). Not a
        separate field, so it can't be self-asserted independently of the CA."""
        return self.cred.hostname

    def _body_dict(self) -> dict[str, Any]:
        return {
            "cred": self.cred.to_dict(),
            "endpoints": self.endpoints,
            "id_pub": _b64e(self.id_pub),
            "inbound": self.inbound,
            "seq": self.seq,
        }

    def sign(self, id_priv: Ed25519PrivateKey) -> "NodeRecord":
        sig = id_priv.sign(_canonical(self._body_dict()))
        return replace(self, sig=sig)

    def verify_structural(self) -> None:
        """
        CA- and clock-independent integrity checks: self-signature, addr
        derivation, and id_pub/credential consistency. These hold for any
        genuine record regardless of which CA is currently trusted or what the
        clock says, so they are the right gate for accepting a record into the
        directory/cache (directory.merge). A forged record fails here because
        the attacker lacks the victim's id_priv — which is what stops a bad
        directory response from shadowing a real record with a high-seq fake.
        Raises ValueError on any failure.
        """
        # Self-signature (step 3)
        body = _canonical(self._body_dict())
        pub = Ed25519PublicKey.from_public_bytes(self.id_pub)
        try:
            pub.verify(self.sig, body)
        except InvalidSignature:
            raise ValueError("invalid self-signature")

        # addr must derive from id_pub (step 4) — prefix-agnostic: bind only the
        # 64-bit HOST portion to the identity (that's the self-certifying part).
        # The network /64 is attested by the CA signature, so different fleets
        # can use different prefixes and a cred stays verifiable.
        try:
            addr_host = ipaddress.IPv6Address(self.cred.addr).packed[8:]
        except (ValueError, ipaddress.AddressValueError):
            raise ValueError(f"credential addr is not a valid IPv6 address: {self.cred.addr!r}")
        if addr_host != host_bits(self.id_pub):
            raise ValueError(
                f"addr host portion of {self.cred.addr} not derived from id_pub"
            )

        # id_pub in record must match id_pub in credential
        if self.id_pub != self.cred.id_pub:
            raise ValueError("id_pub in record does not match id_pub in credential")

    def verify(self, ca_pubs: list[bytes], revoked: set[str]) -> None:
        """
        Full record verification — steps 1–5 of the reconcile loop (§7).
        Step 6 (authorization policy) is done by the caller with local caps.
        Raises ValueError on any failure.
        """
        # Steps 1+2: CA signature + expiry
        self.cred.verify(ca_pubs)

        # Steps 3+4 + id_pub/cred consistency
        self.verify_structural()

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
    hostname, when set, requests a rename (`gw rename`): the hub re-issues under
    the new name, enforcing uniqueness. It is omitted from the signed body when
    empty, so an ordinary renewal produces exactly the pre-rename wire form.
    """
    id_pub: bytes
    wg_pub: bytes
    nonce: str
    ts: dt.datetime
    hostname: str = ""
    sig: bytes = field(default=b"", repr=False)

    def _body_dict(self) -> dict[str, Any]:
        d = {
            "id_pub": _b64e(self.id_pub),
            "nonce": self.nonce,
            "ts": _ts(self.ts),
            "wg_pub": _b64e(self.wg_pub),
        }
        if self.hostname:
            d["hostname"] = self.hostname
        return d

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
            hostname=d.get("hostname", ""),
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
