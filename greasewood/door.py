"""
greasewood.door — door enrollment protocol: key derivation and token encoding.

The door is a transient WireGuard interface the hub uses to admit a joining node
without SSH, without exposing the main mesh, and without any HTTP reachable from
the underlay network.  A join token is a high-entropy 32-byte seed; everything
else — guest keypair, PSK — is derived deterministically from it by both sides
independently.  The door UDP port is a single port (configurable per hub,
default DOOR_PORT), carried in the token so a brand-new node can reach it.

Token wire format:
  "gw1." + base64url_nopad(
      hub_door_pub : 32 bytes   (hub's persistent door WG pubkey)
      ca_pub       : 32 bytes   (CA public key — so join needs no --ca-pub flag)
      door_port    : 2 bytes BE (hub's door UDP port)
      host_len     : 1 byte
      hub_host     : host_len bytes  (underlay host)
      seed         : 32 bytes   (the only secret)
  )

Derivation uses HKDF-SHA256 with salt="greasewood-door-v1":
  guest_priv → node's ephemeral X25519 key for the door WG tunnel
  psk        → WireGuard pre-shared key for the door tunnel

Distinct info strings make the two outputs independent: knowing one reveals
nothing about the other.  The seed is necessary and sufficient — possessing it
gives door access; nothing else does.
"""
from __future__ import annotations

import base64
import os
import struct
from dataclasses import dataclass
from pathlib import Path

_SALT = b"greasewood-door-v1"
_INFO_GUEST = b"gw/door/guest-x25519/v1"
_INFO_PSK = b"gw/door/psk/v1"

# Door subnet — a throwaway /64 used only during the enrollment window.
HUB_DOOR_IP = "fd8d:e5c1:db1a:d::1"
GUEST_DOOR_IP = "fd8d:e5c1:db1a:d::2"
DOOR_SUBNET = "fd8d:e5c1:db1a:d::/64"

# Policy-routing isolation (set once at hub setup, never changed again).
DOOR_TABLE = 51820
DOOR_RULE_PRIO = 100

# Door port — adjacent to the mesh port so all four greasewood ports form one
# contiguous block (UDP 51900/51901, TCP 51902/51903), clear of the WireGuard
# default (51820) and Docker Swarm/Serf (7946).
DOOR_PORT = 51901

ENROLL_PORT = 51903
DOOR_IFACE = "gw-door"
TOKEN_PREFIX = "gw1."


@dataclass
class DoorParams:
    guest_priv_bytes: bytes  # 32-byte X25519 private key (RFC 7748-clamped)
    guest_pub_b64: str       # base64 WG public key — hub adds this as its peer
    psk_b64: str             # base64 pre-shared key for the door WG tunnel


def derive_door_params(seed: bytes) -> DoorParams:
    """
    Derive door parameters from a 32-byte seed using HKDF-SHA256.
    Hub (at invite) and node (at join) run this identically — no extra comm needed.
    """
    import hmac
    import hashlib
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives import serialization

    # HKDF-Extract (RFC 5869 §2.2): salt is the HMAC key, IKM is the message.
    prk = hmac.new(_SALT, seed, hashlib.sha256).digest()

    def _expand(info: bytes, length: int) -> bytes:
        # HKDF-Expand (RFC 5869 §2.3)
        t, okm, i = b"", b"", 1
        while len(okm) < length:
            t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
            okm += t
            i += 1
        return okm[:length]

    # guest_priv: 32-byte X25519 private key with RFC 7748 clamping.
    raw = bytearray(_expand(_INFO_GUEST, 32))
    raw[0] &= 248
    raw[31] &= 127
    raw[31] |= 64
    guest_priv_bytes = bytes(raw)

    guest_pub_bytes = (
        X25519PrivateKey.from_private_bytes(guest_priv_bytes)
        .public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    )
    guest_pub_b64 = base64.b64encode(guest_pub_bytes).decode()

    psk_b64 = base64.b64encode(_expand(_INFO_PSK, 32)).decode()

    return DoorParams(
        guest_priv_bytes=guest_priv_bytes,
        guest_pub_b64=guest_pub_b64,
        psk_b64=psk_b64,
    )


def generate_seed() -> bytes:
    """Return 32 cryptographically random bytes."""
    return os.urandom(32)


def encode_token(
    hub_door_pub_bytes: bytes,
    ca_pub_bytes: bytes,
    hub_host: str,
    seed: bytes,
    door_port: int = DOOR_PORT,
) -> str:
    """Encode a join token. Carries the hub's door UDP port so a brand-new node
    (which has only the token) can reach the door wherever the hub configured it.

    Layout: hub_door_pub[32] ca_pub[32] door_port[2 BE] host_len[1] host seed[32]
    """
    host_bytes = hub_host.encode()
    payload = (
        hub_door_pub_bytes + ca_pub_bytes
        + struct.pack(">H", door_port)
        + bytes([len(host_bytes)]) + host_bytes + seed
    )
    return TOKEN_PREFIX + base64.urlsafe_b64encode(payload).rstrip(b"=").decode()


def decode_token(token: str) -> tuple[bytes, bytes, str, bytes, int]:
    """
    Decode a join token.
    Returns (hub_door_pub_bytes, ca_pub_bytes, hub_host, seed, door_port).
    Raises ValueError on malformed input.
    """
    if not token.startswith(TOKEN_PREFIX):
        raise ValueError(f"token must start with {TOKEN_PREFIX!r}")
    b64 = token[len(TOKEN_PREFIX):]
    payload = base64.urlsafe_b64decode(b64 + "=" * ((-len(b64)) % 4))

    # hub_door_pub + ca_pub + door_port + host_len + seed (minimum, empty host)
    if len(payload) < 32 + 32 + 2 + 1 + 32:
        raise ValueError("token payload too short")

    hub_door_pub = payload[:32]
    ca_pub = payload[32:64]
    door_port = struct.unpack(">H", payload[64:66])[0]
    host_len = payload[66]
    if len(payload) < 67 + host_len + 32:
        raise ValueError("token payload truncated")
    hub_host = payload[67:67 + host_len].decode()
    # The truncation check above guarantees ≥32 trailing bytes, so this slice is
    # always exactly the 32-byte seed.
    seed = payload[67 + host_len:67 + host_len + 32]

    return hub_door_pub, ca_pub, hub_host, seed, door_port


# ---------------------------------------------------------------------------
# Hub door key — persisted X25519 keypair for the door WG interface.
# Its public key is the hub_door_pub baked into every token, so it is stable
# across invite calls.  Lose it and you must re-issue all outstanding tokens.
# ---------------------------------------------------------------------------

def load_or_generate_door_key(data_dir: Path) -> bytes:
    """
    Load the hub's door WG private key (raw 32 bytes).
    Generates and saves it at 0600 if it doesn't exist.
    """
    key_path = data_dir / "door.key"
    if key_path.exists():
        return base64.b64decode(key_path.read_bytes().strip())

    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    priv = X25519PrivateKey.generate()
    raw = priv.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    _write_key_b64(data_dir / "door.key", raw)
    return raw


def window_path(data_dir: Path) -> Path:
    """Path to the single door-window file the hub uses as its enrollment slot."""
    return data_dir / "door_window.json"


def active_window_expiry(data_dir: Path) -> str | None:
    """
    Return the 'expires' string of the current door window if one is open and
    unexpired, else None.

    The door admits one node at a time, so this doubles as a "slot occupied?"
    check: `gw invite` uses it to warn before clobbering a live window, and an
    orderly provisioner can poll it to know when the door is free again (the
    window file is removed by the hub when an enrollment completes).
    """
    import datetime as dt
    import json

    p = window_path(data_dir)
    if not p.exists():
        return None
    try:
        data = json.loads(p.read_text())
        exp = dt.datetime.fromisoformat(data["expires"].replace("Z", "+00:00"))
    except Exception:
        return None
    if dt.datetime.now(dt.timezone.utc) >= exp:
        return None
    return data["expires"]


def door_pub_bytes_from_key(raw_priv: bytes) -> bytes:
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    return (
        X25519PrivateKey.from_private_bytes(raw_priv)
        .public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    )


def _write_key_b64(path: Path, raw: bytes) -> None:
    """Atomic write of base64-encoded key bytes at mode 0600."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, base64.b64encode(raw) + b"\n")
    finally:
        os.close(fd)
    os.replace(tmp, path)
    os.chmod(path, 0o600)
