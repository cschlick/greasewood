"""
greasewood.keys — node identity keypairs and overlay address derivation.

Two keypairs per node (design §4):
  id_priv/id_pub (Ed25519): durable identity. Derives the overlay address and
    authorizes credential renewal. Never rotates — rotating it means "new node."
    Protect as hard as the platform allows (TPM where available, tight perms
    where not). Treat a leak as catastrophic: it is not self-limiting.

  wg_priv/wg_pub (X25519): hot WireGuard tunnel key. Must survive unattended
    reboots, so necessarily on disk. A leak is self-limiting: attacker's use of
    the key expires with the credential; peers tear down the stale entry on the
    next reconcile. Lives in a separate file so it is never confused with id_priv.
"""
from __future__ import annotations

import base64
import hashlib
import ipaddress
import os
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey


def _raw_pub(priv) -> bytes:
    """The 32 raw public-key bytes of an Ed25519/X25519 private key."""
    return priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )


# Default overlay /64 (8 bytes). Configurable per fleet via [network]
# overlay_prefix; this is just the default a fresh create uses.
OVERLAY_PREFIX_BYTES = bytes([0xfd, 0x8d, 0xe5, 0xc1, 0xdb, 0x1a, 0x00, 0x07])

# Process-wide active prefix used to CONSTRUCT addresses (a node's own address,
# the CA issuing creds). One daemon serves one mesh, so a process-global is the
# right scope — set it from config at startup (config.load_config does this).
# Note: address VERIFICATION is prefix-agnostic (see host_bits / derive_host),
# so this global never gates trust; it only decides which /64 new addresses get.
_active_prefix = OVERLAY_PREFIX_BYTES


def set_overlay_prefix(prefix: bytes) -> None:
    """Set the process-wide overlay /64 (8 bytes)."""
    global _active_prefix
    if len(prefix) != 8:
        raise ValueError("overlay prefix must be 8 bytes (a /64)")
    _active_prefix = prefix


def overlay_prefix() -> bytes:
    """The active overlay /64 (8 bytes)."""
    return _active_prefix


def parse_overlay_prefix(text: str) -> bytes:
    """8-byte /64 from 'fd8d:e5c1:db1a:7::' or 'fd8d:e5c1:db1a:7::/64'."""
    return ipaddress.IPv6Address(text.split("/")[0].strip()).packed[:8]


def format_overlay_prefix(prefix: bytes) -> str:
    """'fd8d:e5c1:db1a:7::' from an 8-byte /64."""
    return str(ipaddress.IPv6Address(prefix + bytes(8)))


def host_bits(id_pub_bytes: bytes) -> bytes:
    """
    The 64-bit host portion of a node's address: truncate64(blake2s(id_pub)).

    This is the self-certifying part — it binds the address to the identity, and
    it's what verification checks. Because it's independent of the network
    prefix, different fleets can run different /64s and a node's cred is still
    verifiable anywhere (the CA signature attests the prefix; host_bits attests
    the identity binding). Anchored to id_pub, not wg_pub, so wg rotation never
    changes the address.
    """
    return hashlib.blake2s(id_pub_bytes).digest()[:8]


def derive_addr(id_pub_bytes: bytes, prefix: bytes | None = None) -> str:
    """addr = prefix : host_bits(id_pub). Uses the active process prefix unless
    one is given explicitly."""
    p = prefix if prefix is not None else _active_prefix
    return str(ipaddress.IPv6Address(p + host_bits(id_pub_bytes)))


@dataclass
class NodeKeys:
    """Both keypairs for a node. wg_priv is the only key loaded into the kernel."""

    id_priv: Ed25519PrivateKey
    id_pub_bytes: bytes   # 32-byte raw Ed25519 public key
    wg_priv: X25519PrivateKey
    wg_pub_bytes: bytes   # 32-byte raw X25519 public key

    @property
    def addr(self) -> str:
        return derive_addr(self.id_pub_bytes)

    @property
    def id_pub_hex(self) -> str:
        return self.id_pub_bytes.hex()

    @property
    def wg_pub_b64(self) -> str:
        """WireGuard base64 public key — format the wg tool expects."""
        return base64.b64encode(self.wg_pub_bytes).decode()

    @classmethod
    def generate(cls) -> "NodeKeys":
        id_priv = Ed25519PrivateKey.generate()
        id_pub_bytes = _raw_pub(id_priv)
        wg_priv = X25519PrivateKey.generate()
        wg_pub_bytes = _raw_pub(wg_priv)
        return cls(
            id_priv=id_priv,
            id_pub_bytes=id_pub_bytes,
            wg_priv=wg_priv,
            wg_pub_bytes=wg_pub_bytes,
        )

    def save(self, data_dir: Path, passphrase: bytes | None = None) -> None:
        """
        Write both keys to data_dir at 0600.

        id_priv.pem — PKCS8 PEM, optionally passphrase-encrypted.
          Keep this file away from routine backups and never paste it.
        wg.key — raw base64 (wg-tool format), no encryption.
          This is the self-limiting key; on-disk exposure is an accepted risk.
        """
        data_dir.mkdir(parents=True, exist_ok=True)
        try:
            # 0755: the dir also holds world-readable public files that root-free
            # commands (gw watch --snapshot) read; every secret is its own 0600 file.
            os.chmod(data_dir, 0o755)
        except PermissionError:
            pass  # files are 0600; dir perms are best-effort

        enc = (
            serialization.BestAvailableEncryption(passphrase)
            if passphrase
            else serialization.NoEncryption()
        )
        atomic_write(
            data_dir / "id_priv.pem",
            self.id_priv.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, enc
            ),
        )
        wg_raw = self.wg_priv.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
        atomic_write(data_dir / "wg.key", base64.b64encode(wg_raw) + b"\n")

        # Public material — world-readable, for diagnostics
        (data_dir / "id_pub.hex").write_text(self.id_pub_hex + "\n")
        os.chmod(data_dir / "id_pub.hex", 0o644)
        (data_dir / "wg_pub.b64").write_text(self.wg_pub_b64 + "\n")
        os.chmod(data_dir / "wg_pub.b64", 0o644)

    @classmethod
    def load(cls, data_dir: Path, passphrase: bytes | None = None) -> "NodeKeys":
        id_priv = serialization.load_pem_private_key(
            (data_dir / "id_priv.pem").read_bytes(), password=passphrase
        )
        id_pub_bytes = _raw_pub(id_priv)
        wg_raw = base64.b64decode((data_dir / "wg.key").read_text().strip())
        wg_priv = X25519PrivateKey.from_private_bytes(wg_raw)
        wg_pub_bytes = _raw_pub(wg_priv)
        return cls(
            id_priv=id_priv,
            id_pub_bytes=id_pub_bytes,
            wg_priv=wg_priv,
            wg_pub_bytes=wg_pub_bytes,
        )

    @classmethod
    def load_or_generate(cls, data_dir: Path, passphrase: bytes | None = None) -> "NodeKeys":
        if (data_dir / "id_priv.pem").exists():
            return cls.load(data_dir, passphrase)
        k = cls.generate()
        k.save(data_dir, passphrase)
        return k


@dataclass
class CAKeys:
    """CA keypair — held only on the anchor. ca_priv is the root of all trust."""

    ca_priv: Ed25519PrivateKey
    ca_pub_bytes: bytes  # 32-byte raw

    @property
    def ca_pub_hex(self) -> str:
        return self.ca_pub_bytes.hex()

    @classmethod
    def generate(cls) -> "CAKeys":
        priv = Ed25519PrivateKey.generate()
        pub_bytes = _raw_pub(priv)
        return cls(ca_priv=priv, ca_pub_bytes=pub_bytes)

    def save(self, key_path: Path, passphrase: bytes | None = None) -> None:
        enc = (
            serialization.BestAvailableEncryption(passphrase)
            if passphrase
            else serialization.NoEncryption()
        )
        atomic_write(
            key_path,
            self.ca_priv.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, enc
            ),
        )
        # Public key beside the private key — world-readable (it's the trust anchor)
        pub_path = key_path.with_suffix(".pub")
        pub_path.write_text(self.ca_pub_bytes.hex() + "\n")
        os.chmod(pub_path, 0o644)

    @classmethod
    def load(cls, key_path: Path, passphrase: bytes | None = None) -> "CAKeys":
        priv = serialization.load_pem_private_key(
            key_path.read_bytes(), password=passphrase
        )
        pub_bytes = _raw_pub(priv)
        return cls(ca_priv=priv, ca_pub_bytes=pub_bytes)


def atomic_write(path: Path, data: "bytes | str", mode: int = 0o600) -> None:
    """The one atomic file write (temp + rename), used for every piece of state
    greasewood persists — keys, registry, revoke list, directory cache, door
    window, certs, backups. The temp is UNIQUE (mkstemp) and in the SAME dir:
    unique because a CLI process can race the daemon on the same file (e.g.
    `gw revoke` vs the control plane) and a shared '.tmp' name would interleave
    or move each other's temp; same-dir so os.replace is a real atomic rename,
    not a cross-device copy. mkstemp creates 0600, so key material is never
    world-readable even mid-write; `mode` is applied before the rename."""
    import tempfile
    path = Path(path)
    if isinstance(data, str):
        data = data.encode()
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=path.name + ".", suffix=".tmp")
    try:
        try:
            os.write(fd, data)
        finally:
            os.close(fd)
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise


def _key_file_warnings(paths, expect_uid: int = 0) -> list:
    """Sanity-check secret key files: each should be owned by `expect_uid`
    (root) and readable by owner only. A key owned by another user means that
    account can read it — for the CA key, mint mesh credentials — usually a
    leftover from a pre-1.0 create that chowned the data dir to the operator.
    Returns human-readable warnings; missing files are fine (not all roles have
    all keys)."""
    import stat as statmod
    warns = []
    for p in paths:
        if p is None:
            continue
        try:
            st = os.stat(p)
        except OSError:
            continue
        if st.st_uid != expect_uid:
            warns.append(
                f"SECURITY: {p} is owned by uid {st.st_uid}, not root — that "
                f"account can read this key"
                + (" and mint mesh credentials" if "ca" in Path(p).name else "")
                + f". Fix: chown root:root {p}")
        if statmod.S_IMODE(st.st_mode) & 0o077:
            warns.append(f"SECURITY: {p} is group/world-accessible "
                         f"(mode {statmod.S_IMODE(st.st_mode):o}). "
                         f"Fix: chmod 600 {p}")
    return warns


def _secret_key_paths(cfg) -> list:
    """The secret key files this install may have (missing ones are skipped)."""
    return [cfg.data_dir / "id_priv.pem", cfg.data_dir / "wg.key",
            cfg.data_dir / "door.key", getattr(cfg, "ca_key_file", None)]


def _own_identity(data_dir: "Path") -> "tuple[str | None, str | None]":
    """(id_pub_hex, overlay_addr) from the world-readable id_pub.hex — never the
    private key. Read-only commands (nodes, diagnose) use this so they work
    without sudo: the public id is enough to mark 'self' and derive the addr."""
    from .keys import derive_addr
    try:
        h = (data_dir / "id_pub.hex").read_text().strip()
        return h, derive_addr(bytes.fromhex(h))
    except (FileNotFoundError, ValueError):
        return None, None
