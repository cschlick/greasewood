"""
greasewood.door — door enrollment protocol: key derivation and token encoding.

The door is a transient WireGuard interface the anchor uses to admit a joining node
without SSH, without exposing the main mesh, and without any HTTP reachable from
the underlay network.  A join token is a high-entropy 32-byte seed; everything
else — guest keypair, PSK — is derived deterministically from it by both sides
independently.  The door UDP port is a single port (configurable per anchor,
default DOOR_PORT), carried in the token so a brand-new node can reach it.

Token wire format:
  "gw1." + base64url_nopad(
      anchor_door_pub : 32 bytes   (anchor's persistent door WG pubkey)
      ca_pub       : 32 bytes   (CA public key — so join needs no --ca-pub flag)
      door_port    : 2 bytes BE (anchor's door UDP port)
      host_len     : 1 byte
      anchor_host     : host_len bytes  (underlay host)
      seed         : 32 bytes   (the only secret)
      domain_len   : 1 byte
      mesh_domain  : domain_len bytes  (the mesh's ONE name domain)
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
import datetime as dt
import json
import os
import struct
from typing import NamedTuple
from dataclasses import dataclass
from pathlib import Path

from .keys import atomic_write

# The enrollment exchange's framing: 4-byte big-endian length + JSON. The ONE
# definition — both sides (enroll.EnrollServer and `gw join`) import these, so
# the framing can never drift between server and client.
_MAX_MSG = 64 * 1024


def _recvall(sock, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError(f"short read: {len(buf)}/{n} bytes")
        buf += chunk
    return buf


def recv_msg(sock) -> dict:
    length = struct.unpack(">I", _recvall(sock, 4))[0]
    if length > _MAX_MSG:
        raise ValueError(f"message too large: {length}")
    return json.loads(_recvall(sock, length))


def send_msg(sock, data: dict) -> None:
    body = json.dumps(data, separators=(",", ":")).encode()
    sock.sendall(struct.pack(">I", len(body)) + body)


_SALT = b"greasewood-door-v1"
_INFO_GUEST = b"gw/door/guest-x25519/v1"
_INFO_PSK = b"gw/door/psk/v1"

# Door subnet — a throwaway /64 used only during the enrollment window.
ANCHOR_DOOR_IP = "fd8d:e5c1:db1a:d::1"
GUEST_DOOR_IP = "fd8d:e5c1:db1a:d::2"
DOOR_SUBNET = "fd8d:e5c1:db1a:d::/64"

# Policy-routing isolation (set once at anchor setup, never changed again).
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
    guest_pub_b64: str       # base64 WG public key — anchor adds this as its peer
    psk_b64: str             # base64 pre-shared key for the door WG tunnel


def derive_door_params(seed: bytes) -> DoorParams:
    """
    Derive door parameters from a 32-byte seed using HKDF-SHA256.
    Anchor (at invite) and node (at join) run this identically — no extra comm needed.
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
    anchor_door_pub_bytes: bytes,
    ca_pub_bytes: bytes,
    anchor_host: str,
    seed: bytes,
    door_port: int = DOOR_PORT,
    mesh_domain: str = "",
    self_roles: "list | tuple" = (),
) -> str:
    """Encode a join token. Carries the anchor's door UDP port so a brand-new node
    (which has only the token) can reach the door wherever the anchor configured it.

    Also carries the mesh's name domain: joiners adopt it (a mesh has ONE
    domain everywhere), and check it against existing memberships BEFORE the
    door dance — so a domain collision refuses without burning the invite.

    self_roles is the role MENU (from `gw invite --self-roles`): the roles a
    joiner may self-select from. It's a client-side hint for `gw join` — the
    anchor's door window is authoritative and re-checks — so tampering it only
    misleads the tamperer.

    Layout: anchor_door_pub[32] ca_pub[32] door_port[2 BE] host_len[1] host
            seed[32] domain_len[1] domain menu_len[1] menu
    """
    host_bytes = anchor_host.encode()
    domain_bytes = (mesh_domain or "").encode()
    menu_bytes = ",".join(self_roles).encode()
    # Each of these three fields is length-prefixed by ONE byte, so 255 is the
    # hard cap. Reject an over-long field with a clear, field-named error instead
    # of the cryptic `bytes([256])` ValueError from the payload assembly below.
    for _label, _b in (("endpoint/host", host_bytes),
                       ("mesh domain", domain_bytes),
                       ("role menu (--self-roles)", menu_bytes)):
        if len(_b) > 255:
            raise ValueError(
                f"{_label} is {len(_b)} bytes; the token encodes it with a "
                f"one-byte length, so the limit is 255. "
                + ("Trim the menu — the comma-joined role names (plus commas) "
                   "must total ≤ 255 bytes (~25–40 roles)."
                   if _label.startswith("role menu")
                   else "Shorten it."))
    payload = (
        anchor_door_pub_bytes + ca_pub_bytes
        + struct.pack(">H", door_port)
        + bytes([len(host_bytes)]) + host_bytes + seed
        + bytes([len(domain_bytes)]) + domain_bytes
        + bytes([len(menu_bytes)]) + menu_bytes
    )
    return TOKEN_PREFIX + base64.urlsafe_b64encode(payload).rstrip(b"=").decode()


class DecodedToken(NamedTuple):
    """A join token's contents, named. It stays a tuple, so existing positional
    unpacks (`a, b, c, d, e, f = decode_token(...)`) keep working while the
    fields self-document — field 3 is the SECRET seed, not just 'the 4th thing'."""
    anchor_door_pub: bytes   # anchor's X25519 door public key (32 bytes)
    ca_pub: bytes            # mesh CA Ed25519 public key (32 bytes) — routes the join
    anchor_host: str         # underlay host(s) to dial the door, comma-separated
    seed: bytes              # 32-byte shared secret → door PSK + guest key (HKDF)
    door_port: int           # UDP port the anchor's door listens on
    mesh_domain: str         # the mesh's name domain (adopted by the joiner)
    self_roles: list         # role menu a joiner may self-select from ([] = none)


def decode_token(token: str) -> "DecodedToken":
    """Decode a join token into a DecodedToken. Raises ValueError on malformed
    input."""
    if not token.startswith(TOKEN_PREFIX):
        raise ValueError(f"token must start with {TOKEN_PREFIX!r}")
    b64 = token[len(TOKEN_PREFIX):]
    payload = base64.urlsafe_b64decode(b64 + "=" * ((-len(b64)) % 4))

    # anchor_door_pub + ca_pub + door_port + host_len + seed + domain_len (minimum)
    if len(payload) < 32 + 32 + 2 + 1 + 32 + 1:
        raise ValueError("token payload too short")

    anchor_door_pub = payload[:32]
    ca_pub = payload[32:64]
    door_port = struct.unpack(">H", payload[64:66])[0]
    host_len = payload[66]
    if len(payload) < 67 + host_len + 32 + 1:
        raise ValueError("token payload truncated")
    anchor_host = payload[67:67 + host_len].decode()
    seed = payload[67 + host_len:67 + host_len + 32]
    dlen_at = 67 + host_len + 32
    domain_len = payload[dlen_at]
    if len(payload) < dlen_at + 1 + domain_len:
        raise ValueError("token payload truncated (domain)")
    mesh_domain = payload[dlen_at + 1:dlen_at + 1 + domain_len].decode()

    # menu (allowed self-roles) — an optional trailing field; [] when absent
    # (a token minted without --self-roles, or by an older anchor).
    self_roles: list = []
    mlen_at = dlen_at + 1 + domain_len
    if len(payload) > mlen_at:
        menu_len = payload[mlen_at]
        if len(payload) >= mlen_at + 1 + menu_len:
            menu = payload[mlen_at + 1:mlen_at + 1 + menu_len].decode()
            self_roles = [r for r in menu.split(",") if r]

    return DecodedToken(anchor_door_pub, ca_pub, anchor_host, seed,
                        door_port, mesh_domain, self_roles)


# ---------------------------------------------------------------------------
# Anchor door key — persisted X25519 keypair for the door WG interface.
# Its public key is the anchor_door_pub baked into every token, so it is stable
# across invite calls.  Lose it and you must re-issue all outstanding tokens.
# ---------------------------------------------------------------------------

def load_or_generate_door_key(data_dir: Path) -> bytes:
    """
    Load the anchor's door WG private key (raw 32 bytes).
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
    """Path to the single door-window file the anchor uses as its enrollment slot."""
    return data_dir / "door_window.json"


@dataclass
class Window:
    """A parsed door window — and the ONE definition of window liveness:
    STANDING never expires (closed only by `gw close-door` or a superseding
    invite); otherwise live while its expiry is in the future. Both
    read_window (invite/watch) and the DoorWatcher build on this, so the rule
    can't drift between them."""
    standing: bool
    expires: "dt.datetime | None"    # None for a standing window
    expires_str: "str | None"        # raw string — a window's session identity
    caps: list                       # the BASE grant (fixed roles + abilities)
    allowed_roles: list              # role menu joiners may self-select from ([] = none)
    hostname: "str | None"           # pinned at invite, or None
    guest_pub: "str | None"          # standing only: door re-erection material
    psk: "str | None"

    def live(self, now: "dt.datetime | None" = None) -> bool:
        if self.standing:
            return True
        if self.expires is None:
            return False
        return (now or dt.datetime.now(dt.timezone.utc)) < self.expires


def parse_window(data: dict) -> "Window | None":
    """dict → Window, or None if malformed."""
    standing = bool(data.get("standing"))
    expires = None
    if not standing:
        try:
            expires = dt.datetime.fromisoformat(
                data["expires"].replace("Z", "+00:00"))
        except Exception:
            return None
    return Window(standing=standing, expires=expires,
                  expires_str=data.get("expires"),
                  caps=list(data.get("caps") or ["role:node"]),
                  allowed_roles=list(data.get("allowed_roles") or []),
                  hostname=data.get("hostname"),
                  guest_pub=data.get("guest_pub"), psk=data.get("psk"))


def read_window(data_dir: Path) -> "dict | None":
    """The current door window's raw dict if it is live, else None (liveness
    per Window.live)."""
    p = window_path(data_dir)
    if not p.exists():
        return None
    try:
        data = json.loads(p.read_text())
    except (OSError, ValueError):
        return None
    w = parse_window(data)
    return data if w is not None and w.live() else None


# ---------------------------------------------------------------------------
# Door status/history — a small record of the door's lifecycle the anchor daemon
# maintains (open/close times + reason, failed attempts + source IPs, the last
# enrollment). `gw watch` reads it to show what the door is doing. Written 0600
# because it contains source IP addresses.
# ---------------------------------------------------------------------------

def door_status_path(data_dir: Path) -> Path:
    return Path(data_dir) / "door_status.json"


def read_door_status(data_dir: Path) -> "dict | None":
    """The door's current/last-known status, or None if it has never opened."""
    try:
        return json.loads(door_status_path(data_dir).read_text())
    except (FileNotFoundError, ValueError):
        return None


def _status_now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def _write_door_status(data_dir: Path, data: dict) -> None:
    atomic_write(door_status_path(data_dir), json.dumps(data, indent=2))


def mark_door_opened(data_dir: Path, expires_iso: "str | None", *, caps=None,
                     allowed_roles=None,
                     pinned_hostname=None, max_attempts: int = 3,
                     standing: bool = False) -> None:
    """Record that an enrollment window just opened (resets per-window counters).
    A standing window has no expiry and keeps a running enrollment count."""
    _write_door_status(data_dir, {
        "state": "open",
        "standing": standing,
        "opened_at": _status_now_iso(),
        "expires": expires_iso,
        "max_attempts": max_attempts,
        "caps": list(caps or []),
        "allowed_roles": list(allowed_roles or []),
        "pinned_hostname": pinned_hostname,
        "attempts": [],          # failed attempts this window: {ts, ip, reason}
        "enrolled": None,        # {ts, ip, hostname} of the LAST success
        "enroll_count": 0,       # total successes this window (standing: many)
        "closed_at": None,
        "close_reason": None,
    })


def mark_door_attempt(data_dir: Path, ip: str, reason: str) -> None:
    cur = read_door_status(data_dir) or {}
    cur.setdefault("attempts", []).append(
        {"ts": _status_now_iso(), "ip": ip, "reason": reason})
    _write_door_status(data_dir, cur)


def mark_door_enrolled(data_dir: Path, ip: str, hostname: str) -> None:
    cur = read_door_status(data_dir) or {}
    cur["enrolled"] = {"ts": _status_now_iso(), "ip": ip, "hostname": hostname}
    cur["enroll_count"] = int(cur.get("enroll_count") or 0) + 1
    _write_door_status(data_dir, cur)


def mark_door_closed(data_dir: Path, reason: str) -> None:
    cur = read_door_status(data_dir) or {}
    if cur.get("state") == "closed":
        return  # keep the first close reason if several paths race to close
    cur["state"] = "closed"
    cur["closed_at"] = _status_now_iso()
    cur["close_reason"] = reason
    cur["expires"] = None
    _write_door_status(data_dir, cur)


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
    atomic_write(path, base64.b64encode(raw) + b"\n")
