"""
Anchor backup/restore. The RUNBOOK's headline SOP is "back up ca.key encrypted +
offline" — this makes it one command instead of a manual ritual. The archive is
a single passphrase-encrypted blob (AES-GCM, scrypt-derived key) holding the
anchor's whole trust state: CA key, the nodes/ registry, the revoke list, the door
key. Restoring the SAME key onto a new host is a non-event trust-wise (no
re-root), so this turns "anchor died" into a chore.
"""
import pytest

from greasewood import backup


def _state() -> dict:
    return {
        "ca.key": b"-----BEGIN PRIVATE KEY-----\nfake\n-----END PRIVATE KEY-----\n",
        "ca.key.pub": b"deadbeef\n",
        "revoked.json": b'{"revoked": ["aa", "bb"]}',
        "door.key": b"Zm9vYmFy\n",
        "nodes/1111.json": b'{"hostname": "db", "caps": ["segment:mesh"]}',
        "nodes/2222.json": b'{"hostname": "web", "caps": ["segment:mesh", "tls"]}',
    }


def test_pack_unpack_roundtrip():
    files = _state()
    blob = backup.pack(files, passphrase=b"correct horse")
    assert blob.startswith(backup.MAGIC)
    assert backup.unpack(blob, passphrase=b"correct horse") == files


def test_current_format_stores_a_strong_work_factor():
    # The header records log2(N) right after the magic; it must be the current
    # (strengthened) factor so the parameter can be raised later without a
    # format break.
    blob = backup.pack(_state(), passphrase=b"pw")
    log2n = blob[len(backup.MAGIC)]
    assert 1 << log2n == backup._SCRYPT_N
    assert log2n >= 17            # OWASP 'sensitive' floor


def test_reads_legacy_v1_archive():
    # A GWBK1 archive (fixed N=2**15, AAD = magic only) must still open, so an
    # older backup isn't orphaned by the work-factor bump.
    import os
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    files = _state()
    # Rebuild a v1 blob by hand.
    import gzip, io, tarfile
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for name in sorted(files):
            info = tarfile.TarInfo(name); info.size = len(files[name])
            tar.addfile(info, io.BytesIO(files[name]))
    pt = gzip.compress(buf.getvalue())
    salt, nonce = os.urandom(16), os.urandom(12)
    key = Scrypt(salt=salt, length=32, n=2**15, r=8, p=1).derive(b"pw")
    ct = AESGCM(key).encrypt(nonce, pt, backup._MAGIC_V1)
    v1 = backup._MAGIC_V1 + salt + nonce + ct
    assert backup.unpack(v1, passphrase=b"pw") == files


def test_implausible_work_factor_rejected():
    # A corrupt/hostile header must not force an unbounded scrypt (memory DoS on
    # restore) before the tag check — the work factor is range-checked first.
    blob = bytearray(backup.pack(_state(), passphrase=b"pw"))
    blob[len(backup.MAGIC)] = 40            # 2**40 → absurd
    with pytest.raises(backup.BackupError):
        backup.unpack(bytes(blob), passphrase=b"pw")


def test_wrong_passphrase_rejected():
    blob = backup.pack(_state(), passphrase=b"right")
    with pytest.raises(backup.BackupError):
        backup.unpack(blob, passphrase=b"wrong")


def test_tampered_ciphertext_rejected():
    blob = bytearray(backup.pack(_state(), passphrase=b"pw"))
    blob[-1] ^= 0xFF  # flip a ciphertext bit → GCM auth must fail
    with pytest.raises(backup.BackupError):
        backup.unpack(bytes(blob), passphrase=b"pw")


def test_not_a_backup_rejected():
    with pytest.raises(backup.BackupError):
        backup.unpack(b"not a greasewood backup", passphrase=b"pw")


def test_collect_and_restore_files(tmp_path):
    # Lay out an anchor data dir, collect it, restore into a fresh dir, compare.
    src = tmp_path / "anchor"
    (src / "nodes").mkdir(parents=True)
    (src / "ca.key").write_bytes(b"KEYDATA")
    (src / "ca.key.pub").write_text("pub\n")
    (src / "revoked.json").write_text('{"revoked": []}')
    (src / "door.key").write_text("door\n")
    (src / "id_priv.pem").write_text("ANCHORID\n")  # anchor's own identity → same addr
    (src / "wg.key").write_text("ANCHORWG\n")
    (src / "nodes" / "abcd.json").write_text('{"hostname": "n1", "caps": []}')
    (src / "directory.json").write_text("[]")  # NOT anchor state — excluded

    files = backup.collect_anchor_state(src, ca_key_file=src / "ca.key")
    assert "ca.key" in files and "nodes/abcd.json" in files
    assert "id_priv.pem" in files  # anchor's overlay address is preserved on restore
    assert "directory.json" not in files  # rebuilt from live records on sync

    dst = tmp_path / "restored"
    written = backup.restore_files(dst, files)
    assert (dst / "ca.key").read_bytes() == b"KEYDATA"
    assert (dst / "nodes" / "abcd.json").read_text() == '{"hostname": "n1", "caps": []}'
    assert set(written) == set(files)


def test_restore_refuses_path_traversal():
    # A crafted archive name must never escape the target dir.
    with pytest.raises(backup.BackupError):
        backup.restore_files("/tmp/whatever", {"../evil": b"x"})
