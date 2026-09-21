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
