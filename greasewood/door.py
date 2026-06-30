"""
greasewood.door — door enrollment protocol: key derivation and token encoding.

The door is a transient WireGuard interface the hub uses to admit a joining node
without SSH, without exposing the main mesh, and without any HTTP reachable from
the underlay network.  A join token is a high-entropy 32-byte seed; everything
else — guest keypair, PSK, UDP port — is derived deterministically from it by
both sides independently.

Token wire format:
  "gw1." + base64url_nopad(
      hub_door_pub : 32 bytes   (hub's persistent door WG pubkey)
      ca_pub       : 32 bytes   (CA public key — so join needs no --ca-pub flag)
      host_len     : 1 byte
      hub_host     : host_len bytes  (underlay host, no port — port is derived)
      seed         : 32 bytes   (the only secret)
  )

Derivation uses HKDF-SHA256 with salt="greasewood-door-v1":
  guest_priv → node's ephemeral X25519 key for the door WG tunnel
  psk        → WireGuard pre-shared key for the door tunnel
  door_port  → UDP listen port for the hub's door interface

Distinct info strings make the three outputs independent: knowing one reveals
nothing about the others.  The seed is necessary and sufficient — possessing it
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
_INFO_PORT = b"gw/door/port/v1"

# Door subnet — a throwaway /64 used only during the enrollment window.
HUB_DOOR_IP = "fd8d:e5c1:db1a:d::1"
GUEST_DOOR_IP = "fd8d:e5c1:db1a:d::2"
DOOR_SUBNET = "fd8d:e5c1:db1a:d::/64"

# Policy-routing isolation (set once at hub setup, never changed again).
DOOR_TABLE = 51820
DOOR_RULE_PRIO = 100

# Port range below the Linux ephemeral range (32768+) to avoid collision with
# the hub's outbound sockets.
DOOR_PORT_MIN = 20000
DOOR_PORT_MAX = 32000

ENROLL_PORT = 7947
DOOR_IFACE = "gw-door"
TOKEN_PREFIX = "gw1."


@dataclass
class DoorParams:
    guest_priv_bytes: bytes  # 32-byte X25519 private key (RFC 7748-clamped)
    guest_pub_b64: str       # base64 WG public key — hub adds this as its peer
    psk_b64: str             # base64 pre-shared key for the door WG tunnel
    door_port: int           # UDP port the hub's door interface listens on


def derive_door_params(seed: bytes) -> DoorParams:
    """
    Derive all door parameters from a 32-byte seed using HKDF-SHA256.
    Hub (at mint) and node (at join) run this identically — no extra comm needed.
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

    port_raw = struct.unpack(">H", _expand(_INFO_PORT, 2))[0]
    door_port = DOOR_PORT_MIN + (port_raw % (DOOR_PORT_MAX - DOOR_PORT_MIN))

    return DoorParams(
        guest_priv_bytes=guest_priv_bytes,
        guest_pub_b64=guest_pub_b64,
        psk_b64=psk_b64,
        door_port=door_port,
    )


def generate_seed() -> bytes:
    """Return 32 cryptographically random bytes."""
    return os.urandom(32)


def encode_token(hub_door_pub_bytes: bytes, ca_pub_bytes: bytes, hub_host: str, seed: bytes) -> str:
    """Encode a join token from its constituent parts."""
    host_bytes = hub_host.encode()
    payload = hub_door_pub_bytes + ca_pub_bytes + bytes([len(host_bytes)]) + host_bytes + seed
    return TOKEN_PREFIX + base64.urlsafe_b64encode(payload).rstrip(b"=").decode()


def decode_token(token: str) -> tuple[bytes, bytes, str, bytes]:
    """
    Decode a join token.
    Returns (hub_door_pub_bytes, ca_pub_bytes, hub_host, seed).
    Raises ValueError on malformed input.
    """
    if not token.startswith(TOKEN_PREFIX):
        raise ValueError(f"token must start with {TOKEN_PREFIX!r}")
    b64 = token[len(TOKEN_PREFIX):]
    payload = base64.urlsafe_b64decode(b64 + "=" * ((-len(b64)) % 4))

    if len(payload) < 64 + 1 + 32:  # hub_door_pub + ca_pub + host_len + seed (minimum)
        raise ValueError("token payload too short")

    hub_door_pub = payload[:32]
    ca_pub = payload[32:64]
    host_len = payload[64]
    if len(payload) < 65 + host_len + 32:
        raise ValueError("token payload truncated")
    hub_host = payload[65:65 + host_len].decode()
    seed = payload[65 + host_len:65 + host_len + 32]
    if len(seed) != 32:
        raise ValueError("seed must be 32 bytes")

    return hub_door_pub, ca_pub, hub_host, seed


# ---------------------------------------------------------------------------
# Hub door key — persisted X25519 keypair for the door WG interface.
# Its public key is the hub_door_pub baked into every token, so it is stable
# across mint calls.  Lose it and you must re-mint all outstanding tokens.
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
