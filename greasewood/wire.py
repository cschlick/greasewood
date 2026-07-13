"""
greasewood.wire — the signed objects that constitute the protocol.

Two are mesh STATE (what a reader trusts):

Credential (CA-signed, §5.1):
  id_pub, wg_pub, addr, hostname, caps, iat, exp → ca_sig covers all of these.
  The only thing the CA ever signs. Short-lived (~24h). Slow path.

NodeRecord (self-signed by id_priv, §5.2):
  id_pub, seq, endpoints, cred (+ optional aliases/reachable) → sig covers all
  of these; hostname lives inside cred.
  Carries the full credential so any reader can verify without talking to the CA.
  Fast path — a node re-signs when its endpoints/links change, no CA involvement.

Two are self-signed REQUESTS to the anchor (proof of id_priv possession +
nonce/ts against replay): RenewRequest (renew a credential) and CertRequest
(issue a TLS leaf cert). Enrollment itself is out of band over the transient
WireGuard "door" (`gw invite` / `gw join`, see greasewood.door /
greasewood.enroll); the control plane has no network-reachable enroll endpoint.

Canonical signing form for all four: json.dumps(sort_keys=True,
separators=(",", ":")) — the exact bytes a signature covers, so any second
implementation must reproduce them. Binary fields (keys, sigs) are base64.
"""
from __future__ import annotations

import base64
import datetime as dt
import ipaddress
import json
from dataclasses import dataclass, field, replace
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .keys import host_bits

_UTC = dt.timezone.utc


def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode()


def _b64d(s: str) -> bytes:
    return base64.b64decode(s)


def _canonical(d: dict) -> bytes:
    """Deterministic JSON — the bytes that signatures cover."""
    return json.dumps(d, sort_keys=True, separators=(",", ":")).encode()


def enroll_pop_body(id_pub: bytes, wg_pub: bytes, hostname: str) -> bytes:
    """Canonical bytes a joiner self-signs with id_priv at door enrollment, to
    PROVE it holds the private key for the id_pub it presents (proof-of-
    possession). The door seed authorizes *that someone* may enroll; this binds
    the enrollment to an identity the joiner actually controls. Binding id_pub ↔
    wg_pub ↔ hostname means a token holder cannot enroll under another node's
    public id_pub (it lacks that id_priv), nor replay a captured signature with a
    different wg_pub. ONE definition, imported by both `gw join` (signer) and the
    enroll server (verifier) so the two can never drift."""
    return _canonical({
        "hostname": hostname or "",
        "id_pub": _b64e(id_pub),
        "wg_pub": _b64e(wg_pub),
    })


def _ts(t: dt.datetime) -> str:
    """RFC 3339 UTC, second precision. Microseconds would produce different
    canonical bytes depending on how the timestamp was constructed."""
    return t.astimezone(_UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _str(value: Any, field: str) -> str:
    """A field that must be a string. Same discipline as _parse_ts: reject a
    hostile/wrong JSON type HERE with a clean ValueError, so it becomes a 400
    at the network boundary instead of a str-method AttributeError or a
    sorted() TypeError deep in verification (an unhandled 500)."""
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a string, got {type(value).__name__}")
    return value


def _str_list(value: Any, field: str) -> list[str]:
    """A field that must be a list of strings (caps, SANs, endpoints, aliases).
    Guards the sorted()/endswith() paths that would otherwise raise TypeError/
    AttributeError on `[1, 2]` or a bare scalar — see _str."""
    if not isinstance(value, list) or not all(isinstance(x, str) for x in value):
        raise ValueError(f"{field} must be a list of strings")
    return list(value)


def _parse_ts(s: str) -> dt.datetime:
    if not isinstance(s, str):
        # A non-string (e.g. JSON null/number) would raise AttributeError on
        # .replace below — a 500. Normalize to the clean ValueError → 400 path.
        raise ValueError(f"timestamp must be an RFC 3339 string, got {type(s).__name__}")
    t = dt.datetime.fromisoformat(s.replace("Z", "+00:00"))
    if t.tzinfo is None:
        # Reject here, at parse: a naive timestamp survives until the skew
        # check compares it against an aware clock and raises TypeError — an
        # unhandled 500 instead of the clean ValueError → 400 path.
        raise ValueError(f"timestamp {s!r} lacks a timezone (want RFC 3339, e.g. ...Z)")
    return t


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

    def verify(self, ca_pubs: list[bytes], allow_expired: bool = False) -> None:
        """
        Verify CA signature against the trusted set and check expiry.
        ca_pubs is a list of raw 32-byte Ed25519 public keys.
        The set (not a single key) is what lets you re-root: trust old + new
        CA during a migration overlap.
        Raises ValueError on any failure.

        `allow_expired` skips ONLY the expiry check (the CA signature is always
        required). It exists for the ANCHOR's recertification path: expiry means
        "this node must re-check-in with the anchor", not "permanently dead", so
        the anchor admits an expired-but-otherwise-valid node long enough to
        renew it. Revocation — the actual kill switch — is enforced separately
        (see NodeRecord.verify), and peers never pass allow_expired, so a stale
        node stays out of the mesh until it recertifies.
        """
        body = _canonical(self._body_dict())
        for raw_pub in ca_pubs:
            pub = Ed25519PublicKey.from_public_bytes(raw_pub)
            try:
                pub.verify(self.ca_sig, body)
            except InvalidSignature:
                continue
            # Signature valid — now check expiry (unless the anchor is recertifying).
            if not allow_expired and dt.datetime.now(_UTC) >= self.exp:
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
            addr=_str(d["addr"], "addr"),
            hostname=_str(d["hostname"], "hostname"),
            caps=_str_list(d["caps"], "caps"),
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
    cred: Credential
    aliases: list[str] = field(default_factory=list)
    # Overlay addresses this node currently has a LIVE link to (recent handshake,
    # not backed off). Self-observed, rate-limited, optional (omitted from the
    # signed body when empty — same shape as aliases, so old/new records
    # interop). Rides the existing directory sync so `gw watch` can render
    # fleet-wide per-segment connectivity without any new channel.
    reachable: list[str] = field(default_factory=list)
    sig: bytes = field(default=b"", repr=False)

    @property
    def hostname(self) -> str:
        """The mesh hostname, from the CA-signed credential (§ level-b). Not a
        separate field, so it can't be self-asserted independently of the CA."""
        return self.cred.hostname

    def _body_dict(self) -> dict[str, Any]:
        d = {
            "cred": self.cred.to_dict(),
            "endpoints": self.endpoints,
            "id_pub": _b64e(self.id_pub),
            "seq": self.seq,
        }
        # Extra service names the node publishes, as bare labels under its OWN
        # mesh name (readers expand <label>.<attested-name>, so a node can only
        # name things in its own namespace). Omitted when empty so an
        # ordinary record's wire form is unchanged.
        if self.aliases:
            d["aliases"] = sorted(self.aliases)
        if self.reachable:                       # live link set (optional)
            d["reachable"] = sorted(self.reachable)
        return d

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

    def verify(self, ca_pubs: list[bytes], revoked: set[str],
               allow_expired: bool = False) -> None:
        """
        Full record verification — steps 1–5 of the reconcile loop (§7).
        Step 6 (authorization policy) is done by the caller with local caps.
        Raises ValueError on any failure.

        `allow_expired` relaxes ONLY the expiry check (the anchor's recert path);
        the CA signature, structural checks, and REVOCATION are always enforced.
        So an expired node can be admitted by the anchor to renew, but a revoked
        one never is.
        """
        # Steps 1+2: CA signature + expiry (expiry waived only for anchor recert)
        self.cred.verify(ca_pubs, allow_expired=allow_expired)

        # Steps 3+4 + id_pub/cred consistency
        self.verify_structural()

        # Step 5: not on revoke list — the kill switch, never waived
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
            endpoints=_str_list(d["endpoints"], "endpoints"),
            cred=Credential.from_dict(d["cred"]),
            aliases=_str_list(d.get("aliases", []), "aliases"),
            reachable=_str_list(d.get("reachable", []), "reachable"),
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
    hostname, when set, requests a rename (`gw rename`): the anchor re-issues under
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
# CertRequest — a node asking the anchor for an x509 TLS cert (§12)
# ---------------------------------------------------------------------------

@dataclass
class CertRequest:
    """
    Sent by an enrolled node to the anchor to obtain an x509 TLS certificate for a
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
        sig = id_priv.sign(_canonical(self._body_dict()))
        return replace(self, sig=sig)

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
            cn=_str(d["cn"], "cn"),
            # dns/ips are ALWAYS in the signed body (unlike aliases/reachable,
            # which .get() signals as omitted-when-empty) — so index, don't .get.
            dns=_str_list(d["dns"], "dns"),
            ips=_str_list(d["ips"], "ips"),
            nonce=_str(d["nonce"], "nonce"),
            ts=_parse_ts(d["ts"]),
            sig=_b64d(d["sig"]),
        )

# ---------------------------------------------------------------------------
# GrantTable — the mesh's access policy (§ roles & grants)
# ---------------------------------------------------------------------------

def _validate_grant(g: dict, i: int) -> dict:
    """Normalize + validate one [[grant]] record. Allow-only by construction:
    there is no action/deny field to validate — a deny rule is not expressible.
    Unknown keys are a hard error (catches typos like `form =` before they
    silently change the fleet's topology)."""
    if not isinstance(g, dict):
        raise ValueError(f"grant #{i}: must be a table of from/to/ports")
    unknown = set(g) - {"from", "to", "ports"}
    if unknown:
        raise ValueError(f"grant #{i}: unknown key(s) {sorted(unknown)} "
                         f"(allowed: from, to, ports)")
    src = _str_list(g.get("from"), f"grant #{i} from")
    dst = _str_list(g.get("to"), f"grant #{i} to")
    ports = _str_list(g.get("ports", ["*"]), f"grant #{i} ports")
    if not src or not dst:
        raise ValueError(f"grant #{i}: from and to must be non-empty")
    for p in ports:
        if p == "*":
            continue
        proto, _, num = p.partition("/")
        if proto not in ("tcp", "udp") or not num.isdigit() \
                or not (1 <= int(num) <= 65535):
            raise ValueError(f"grant #{i}: bad port {p!r} "
                             f"(want 'tcp/5432', 'udp/51900', or '*')")
    return {"from": sorted(src), "to": sorted(dst), "ports": sorted(ports)}


@dataclass
class GrantTable:
    """
    The mesh's signed access policy: an allow-only list of grants,
    `from-roles → to-roles : ports`. CA-signed and distributed via the
    directory sync, so nodes adopt it like any other signed fact.

    This table DERIVES the tunnel topology (a peer link exists iff some grant
    connects two nodes' roles — see policy.peers_allowed), with one rule
    hardwired BENEATH it in code, deliberately not expressible here: every
    node always peers with the anchor (role/segment `*`). The channel that
    carries the policy must never be prunable by the policy.

    seq is monotonic: nodes adopt a table only if its seq exceeds the one they
    hold, so an old table can't be replayed to reopen a deleted grant.
    """
    seq: int
    grants: list          # normalized [{"from": [...], "to": [...], "ports": [...]}]
    ca_sig: bytes = field(default=b"", repr=False)

    def _body_dict(self) -> dict[str, Any]:
        return {"grants": self.grants, "seq": self.seq}

    def sign(self, ca_priv: Ed25519PrivateKey) -> "GrantTable":
        sig = ca_priv.sign(_canonical(self._body_dict()))
        return replace(self, ca_sig=sig)

    def verify(self, ca_pubs: list[bytes]) -> None:
        """Verify the CA signature against the trusted set (any match).
        Raises ValueError on failure."""
        body = _canonical(self._body_dict())
        for raw_pub in ca_pubs:
            pub = Ed25519PublicKey.from_public_bytes(raw_pub)
            try:
                pub.verify(self.ca_sig, body)
                return
            except InvalidSignature:
                continue
        raise ValueError("policy: no trusted CA signature found")

    def to_dict(self) -> dict[str, Any]:
        d = self._body_dict()
        d["ca_sig"] = _b64e(self.ca_sig)
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "GrantTable":
        seq = d["seq"]
        if not isinstance(seq, int) or seq < 0:
            raise ValueError("policy seq must be a non-negative integer")
        raw_grants = d["grants"]
        if not isinstance(raw_grants, list):
            raise ValueError("policy grants must be a list")
        grants = [_validate_grant(g, i) for i, g in enumerate(raw_grants)]
        return cls(seq=seq, grants=grants, ca_sig=_b64d(d["ca_sig"]))
