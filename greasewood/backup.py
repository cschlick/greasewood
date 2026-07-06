"""
greasewood.backup — encrypted anchor trust-state backup (`gw anchor-backup` / restore).

An anchor's whole trust state is a handful of files: the CA private key, the
`nodes/` registry (hostname + caps per enrolled node, needed for renewal and
name uniqueness), the revoke list, and the door key (its public half is baked
into every outstanding join token). This packs them into ONE passphrase-
encrypted blob so the RUNBOOK's "back up ca.key encrypted + offline" is a
single command.

Format (all one file, no container library):
    MAGIC (b"GWBK2\n")  |  log2n[1]  |  salt[16]  |  nonce[12]  |  AES-GCM ct
    key = scrypt(passphrase, salt, n=2**log2n, r=8, p=1) -> 32 bytes
    plaintext = gzip(tar) of the collected files
    AES-GCM associated data = MAGIC + log2n  (binds the work factor)

The scrypt work factor lives in the header (log2n) so it can be raised over
time without a format break; unpack still reads a legacy GWBK1 archive (fixed
n=2**15). log2n is range-checked before the KDF runs, so a hostile header
can't force an unbounded scrypt (a memory DoS on restore).

AES-GCM authenticates the whole archive, so a wrong passphrase or a tampered
byte fails cleanly (BackupError) rather than yielding garbage. This passphrase
is the SINGLE factor protecting the CA key (and the anchor's id_priv) at rest, so
its strength is the whole story — `gw anchor-backup` warns on a short one.
Restoring the SAME CA key onto a new host changes no trust relationship — it is
a restore, not a re-root.

The directory cache (directory.json) is deliberately NOT included: it is
rebuilt from live node records on the first sync, and pinning a stale copy
would only risk resurrecting departed peers.
"""
from __future__ import annotations

import gzip
import io
import os
import tarfile
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

MAGIC = b"GWBK2\n"          # current format: work factor stored in the header
_MAGIC_V1 = b"GWBK1\n"      # legacy: fixed n=2**15, AAD = magic only
_SALT_LEN = 16
_NONCE_LEN = 12
_SCRYPT_N = 2 ** 17         # OWASP 'sensitive' floor (~128 MiB); was 2**15
_SCRYPT_R = 8
_SCRYPT_P = 1
_V1_N = 2 ** 15
# Range for a header-supplied log2(N): >=14 keeps it meaningfully costly; <=20
# caps scrypt memory (~1 GiB at r=8) so a hostile header can't OOM a restore.
_LOG2N_MIN = 14
_LOG2N_MAX = 20

# Files that constitute anchor state, relative to the data dir. ca.key is handled
# separately (its path is configurable). Globs expand at collect time.
#
# id_priv.pem + wg.key are the anchor's OWN node identity — included so a restore
# reproduces the anchor's overlay address, keeping address-based seeds/root_url
# working (a re-generated identity would give the anchor a new address). They're
# anchor secrets living in the same encrypted blob, so no extra exposure.
_ANCHOR_STATE = ["ca.key.pub", "ca.cert.pem", "door.key", "revoked.json",
                 "id_priv.pem", "wg.key"]
_ANCHOR_STATE_GLOBS = ["nodes/*.json"]


class BackupError(Exception):
    """Malformed archive, wrong passphrase, tamper, or unsafe restore path."""


def _derive_key(passphrase: bytes, salt: bytes, n: int) -> bytes:
    return Scrypt(salt=salt, length=32, n=n, r=_SCRYPT_R, p=_SCRYPT_P) \
        .derive(passphrase)


def pack(files: dict[str, bytes], passphrase: bytes) -> bytes:
    """Encrypt a name->bytes mapping into a single backup blob."""
    tar_buf = io.BytesIO()
    with tarfile.open(fileobj=tar_buf, mode="w") as tar:
        for name in sorted(files):
            data = files[name]
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = 0o600
            tar.addfile(info, io.BytesIO(data))
    plaintext = gzip.compress(tar_buf.getvalue())

    log2n = _SCRYPT_N.bit_length() - 1
    header = MAGIC + bytes([log2n])
    salt = os.urandom(_SALT_LEN)
    nonce = os.urandom(_NONCE_LEN)
    # Header (magic + work factor) is the GCM associated data, so tampering
    # with the advertised work factor is detected.
    ct = AESGCM(_derive_key(passphrase, salt, _SCRYPT_N)).encrypt(nonce, plaintext, header)
    return header + salt + nonce + ct


def unpack(blob: bytes, passphrase: bytes) -> dict[str, bytes]:
    """Decrypt and extract a backup blob into a name->bytes mapping."""
    if blob.startswith(MAGIC):
        rest = blob[len(MAGIC):]
        if not rest:
            raise BackupError("backup truncated")
        log2n = rest[0]
        if not (_LOG2N_MIN <= log2n <= _LOG2N_MAX):
            raise BackupError(f"implausible scrypt work factor 2**{log2n}")
        n = 1 << log2n
        aad = MAGIC + bytes([log2n])
        body = rest[1:]
    elif blob.startswith(_MAGIC_V1):
        n = _V1_N
        aad = _MAGIC_V1
        body = blob[len(_MAGIC_V1):]
    else:
        raise BackupError("not a greasewood backup (bad magic)")

    if len(body) < _SALT_LEN + _NONCE_LEN:
        raise BackupError("backup truncated")
    salt = body[:_SALT_LEN]
    nonce = body[_SALT_LEN:_SALT_LEN + _NONCE_LEN]
    ct = body[_SALT_LEN + _NONCE_LEN:]
    try:
        plaintext = AESGCM(_derive_key(passphrase, salt, n)).decrypt(nonce, ct, aad)
    except InvalidTag:
        raise BackupError("wrong passphrase or corrupted/tampered backup")

    out: dict[str, bytes] = {}
    with tarfile.open(fileobj=io.BytesIO(gzip.decompress(plaintext)),
                      mode="r") as tar:
        for member in tar.getmembers():
            if not member.isfile():
                continue
            f = tar.extractfile(member)
            if f is not None:
                out[member.name] = f.read()
    return out


def collect_anchor_state(data_dir, ca_key_file) -> dict[str, bytes]:
    """Read the anchor's trust-state files into a name->bytes mapping. ca_key_file
    may live outside data_dir (configurable path); it is always stored as
    'ca.key' in the archive so restore is location-independent."""
    data_dir = Path(data_dir)
    files: dict[str, bytes] = {}

    ca_key_file = Path(ca_key_file)
    if ca_key_file.exists():
        files["ca.key"] = ca_key_file.read_bytes()

    for rel in _ANCHOR_STATE:
        p = data_dir / rel
        if p.exists():
            files[rel] = p.read_bytes()
    for pattern in _ANCHOR_STATE_GLOBS:
        for p in sorted(data_dir.glob(pattern)):
            files[str(p.relative_to(data_dir))] = p.read_bytes()
    return files


def restore_files(data_dir, files: dict[str, bytes]) -> list[str]:
    """Write extracted files under data_dir at 0600, creating parents. Refuses
    any archive name that would escape data_dir (path traversal). Returns the
    written relative names."""
    data_dir = Path(data_dir).resolve()
    written = []
    for name, data in files.items():
        dest = (data_dir / name).resolve()
        if dest != data_dir and data_dir not in dest.parents:
            raise BackupError(f"unsafe path in backup: {name!r}")
        dest.parent.mkdir(parents=True, exist_ok=True)
        # 0600 write: this is key material.
        fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, data)
        finally:
            os.close(fd)
        written.append(name)
    return written
