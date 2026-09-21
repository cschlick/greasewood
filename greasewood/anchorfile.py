"""
greasewood.anchorfile — the anchor as a FILE, not a machine.

`<data_dir>/anchor.gwa` holds the mesh's two root secrets — the CA private
key (signs credentials, statements, policy, TLS certs) and the door private
key (its public half is baked into every outstanding invite token). Any node
whose data dir holds this file performs anchor duties; several can hold it at
once (active/active — every membership decision they mint is a replicated,
CA-signed statement, and issuance reads the replicated directory, so holders
need no coordination and no state handover).

  transfer   = copy the file (over YOUR channel — ssh/scp; the root key
               never rides the mesh it anchors)
  redundancy = keep it on several machines
  de-anchor  = `gw anchor drop` (delete the file) — the cooperative exit,
               `gw leave` for anchors. It proves nothing about copies: a
               machine you no longer TRUST needs the re-root (rotate the CA
               key and walk trusted_pubs), because knowledge can't be revoked.

Format: one JSON object, 0600 root — {"v": 1, "mesh_domain", "ca_key_pem",
"door_key_b64", "created"}. Plaintext at rest, exactly like the ca.key it
replaces; wrap exports with `gw anchor-backup` (AES-GCM + scrypt) when they
leave the machine. Legacy anchors (role=anchor + ca_key_file) keep working
untouched; `gw anchor init` folds their ca.key + door.key into the file.
"""
from __future__ import annotations

import datetime as dt
import json
import logging
from dataclasses import dataclass
from pathlib import Path

from .keys import CAKeys, atomic_write

log = logging.getLogger(__name__)

ANCHOR_BASENAME = "anchor.gwa"


def anchor_path(data_dir) -> Path:
    return Path(data_dir) / ANCHOR_BASENAME


@dataclass
class AnchorFile:
    mesh_domain: str
    ca_key_pem: str        # PKCS8 PEM, unencrypted (0600 at rest)
    door_key_b64: str      # raw X25519 private key, base64
    created: str           # ISO time the file was first minted (informational)
    path: "Path | None" = None    # where it was loaded from (None = unsaved)

    def ca_keys(self) -> CAKeys:
        return CAKeys.from_pem(self.ca_key_pem.encode())

    def door_key_raw(self) -> bytes:
        import base64
        return base64.b64decode(self.door_key_b64)

    def save(self, data_dir) -> Path:
        p = anchor_path(data_dir)
        atomic_write(p, json.dumps({
            "v": 1,
            "mesh_domain": self.mesh_domain,
            "ca_key_pem": self.ca_key_pem,
            "door_key_b64": self.door_key_b64,
            "created": self.created,
        }, indent=2), mode=0o600)
        self.path = p
        return p

    def to_bytes(self) -> bytes:
        """The transferable form (what `gw anchor export` emits)."""
        return json.dumps({
            "v": 1, "mesh_domain": self.mesh_domain,
            "ca_key_pem": self.ca_key_pem, "door_key_b64": self.door_key_b64,
            "created": self.created,
        }, indent=2).encode()

    @classmethod
    def from_bytes(cls, raw: bytes, path: "Path | None" = None) -> "AnchorFile":
        try:
            d = json.loads(raw)
        except ValueError as e:
            raise ValueError(f"not an anchor file (bad JSON): {e}") from e
        if not isinstance(d, dict) or d.get("v") != 1:
            raise ValueError("not an anchor file (missing/unknown version)")
        for field in ("mesh_domain", "ca_key_pem", "door_key_b64"):
            if not isinstance(d.get(field), str) or not d[field]:
                raise ValueError(f"not an anchor file (missing {field})")
        af = cls(mesh_domain=d["mesh_domain"], ca_key_pem=d["ca_key_pem"],
                 door_key_b64=d["door_key_b64"],
                 created=d.get("created", ""), path=path)
        af.ca_keys()          # parse now: a corrupt key fails HERE, loudly,
        af.door_key_raw()     # not at the first issuance
        return af

    @classmethod
    def build(cls, mesh_domain: str, ca_keys: CAKeys,
              door_key_raw: bytes) -> "AnchorFile":
        import base64
        return cls(
            mesh_domain=mesh_domain,
            ca_key_pem=ca_keys.to_pem().decode(),
            door_key_b64=base64.b64encode(door_key_raw).decode(),
            created=dt.datetime.now(dt.timezone.utc)
                      .replace(microsecond=0).isoformat(),
        )


OFFER_BASENAME = "anchor_offer.json"
OFFER_TTL = dt.timedelta(minutes=15)

_SEAL_INFO = b"greasewood anchor seal v1"


def offer_path(data_dir) -> Path:
    return Path(data_dir) / OFFER_BASENAME


def seal_to_wg(recipient_wg_pub: bytes, plaintext: bytes) -> dict:
    """Seal bytes to a node's X25519 WireGuard public key (ephemeral ECDH →
    HKDF → AES-GCM). Only the holder of the matching wg_priv can open it, so
    the ciphertext may ride the mesh — or any channel — safely: this is what
    lets a holder OFFER the anchor file over the control plane instead of the
    operator shuttling a root-key file through scp and permission dances. The
    recipient key comes from the target's CA-attested credential, so the
    operator's `gw anchor offer <name>` binds to the machine the CA says owns
    that name."""
    import base64
    import os as _os
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey, X25519PublicKey)
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes, serialization
    eph = X25519PrivateKey.generate()
    shared = eph.exchange(X25519PublicKey.from_public_bytes(recipient_wg_pub))
    eph_pub = eph.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    # Ephemeral + recipient pubs in the KDF info bind the key to this exact
    # pair, so a transcript can't be re-targeted.
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
               info=_SEAL_INFO + eph_pub + recipient_wg_pub).derive(shared)
    nonce = _os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, plaintext, _SEAL_INFO)
    b64 = lambda b: base64.b64encode(b).decode()      # noqa: E731
    return {"v": 1, "eph_pub": b64(eph_pub), "nonce": b64(nonce),
            "ct": b64(ct)}


def unseal_with_wg(sealed: dict, wg_priv) -> bytes:
    """Open a seal_to_wg envelope with this node's wg_priv. Raises ValueError
    on anything but a clean open — including an envelope sealed to a DIFFERENT
    node (the common operator mistake this design makes impossible to act on)."""
    import base64
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes, serialization
    if not isinstance(sealed, dict) or sealed.get("v") != 1:
        raise ValueError("not a sealed anchor offer (missing/unknown version)")
    try:
        eph_pub = base64.b64decode(sealed["eph_pub"])
        nonce = base64.b64decode(sealed["nonce"])
        ct = base64.b64decode(sealed["ct"])
    except (KeyError, ValueError, TypeError) as e:
        raise ValueError(f"malformed sealed offer: {e}") from e
    if len(eph_pub) != 32:
        raise ValueError("malformed sealed offer: bad ephemeral key length")
    my_pub = wg_priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    shared = wg_priv.exchange(X25519PublicKey.from_public_bytes(eph_pub))
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
               info=_SEAL_INFO + eph_pub + my_pub).derive(shared)
    try:
        return AESGCM(key).decrypt(nonce, ct, _SEAL_INFO)
    except InvalidTag:
        raise ValueError(
            "could not open the offer with this node's WireGuard key — it was "
            "sealed to a different node (or this node re-keyed since the offer "
            "was minted). Re-run `gw anchor offer <this-node>` on the holder.")


def write_offer(data_dir, to_id_hex: str, to_hostname: str,
                sealed: dict) -> Path:
    """Persist a single-use, time-boxed offer for the daemon's control plane
    to serve (POST /anchor-claim). One offer at a time — minting a new one
    replaces any outstanding one."""
    from .keys import atomic_write
    p = offer_path(data_dir)
    expires = (dt.datetime.now(dt.timezone.utc) + OFFER_TTL)\
        .replace(microsecond=0).isoformat()
    atomic_write(p, json.dumps({
        "v": 1, "to_id": to_id_hex, "to_hostname": to_hostname,
        "sealed": sealed, "expires": expires,
    }, indent=2), mode=0o600)
    return p


def read_offer(data_dir) -> "dict | None":
    """The outstanding offer, or None when absent/expired/corrupt (an expired
    or unreadable offer is deleted — it can never become servable again)."""
    p = offer_path(data_dir)
    try:
        d = json.loads(p.read_text())
        expires = dt.datetime.fromisoformat(d["expires"])
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=dt.timezone.utc)
        if dt.datetime.now(dt.timezone.utc) >= expires:
            raise ValueError("expired")
        if not isinstance(d.get("to_id"), str) or "sealed" not in d:
            raise ValueError("malformed")
        return d
    except FileNotFoundError:
        return None
    except (ValueError, KeyError, TypeError, OSError) as e:
        log.info("dropping unusable anchor offer: %s", e)
        consume_offer(data_dir)
        return None


def consume_offer(data_dir) -> None:
    """Single-use: delete the offer (on a successful claim, or when unusable)."""
    try:
        offer_path(data_dir).unlink()
    except OSError:
        pass


def load(data_dir) -> "AnchorFile | None":
    """The anchor file at <data_dir>/anchor.gwa, or None. A present-but-
    corrupt file raises — holding a broken root key must never silently read
    as 'not an anchor'."""
    p = anchor_path(data_dir)
    try:
        raw = p.read_bytes()
    except FileNotFoundError:
        return None
    return AnchorFile.from_bytes(raw, path=p)
