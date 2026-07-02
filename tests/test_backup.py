"""
Hub backup/restore. The RUNBOOK's headline SOP is "back up ca.key encrypted +
offline" — this makes it one command instead of a manual ritual. The archive is
a single passphrase-encrypted blob (AES-GCM, scrypt-derived key) holding the
hub's whole trust state: CA key, the nodes/ registry, the revoke list, the door
key. Restoring the SAME key onto a new host is a non-event trust-wise (no
re-root), so this turns "hub died" into a chore.
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
    # Lay out a hub data dir, collect it, restore into a fresh dir, compare.
    src = tmp_path / "hub"
    (src / "nodes").mkdir(parents=True)
    (src / "ca.key").write_bytes(b"KEYDATA")
    (src / "ca.key.pub").write_text("pub\n")
    (src / "revoked.json").write_text('{"revoked": []}')
    (src / "door.key").write_text("door\n")
    (src / "id_priv.pem").write_text("HUBID\n")  # hub's own identity → same addr
    (src / "wg.key").write_text("HUBWG\n")
    (src / "nodes" / "abcd.json").write_text('{"hostname": "n1", "caps": []}')
    (src / "directory.json").write_text("[]")  # NOT hub state — excluded

    files = backup.collect_hub_state(src, ca_key_file=src / "ca.key")
    assert "ca.key" in files and "nodes/abcd.json" in files
    assert "id_priv.pem" in files  # hub's overlay address is preserved on restore
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
