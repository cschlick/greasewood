"""
Unit tests for `gw anchor-backup` / `gw anchor-restore` (CLI wiring around
greasewood.backup). The module-level roundtrip/crypto is covered in
test_backup.py; here we check the command plumbing: role guard, passphrase via
env, the produced file, and a full backup→restore of a real anchor data dir onto a
fresh dir with the same CA key.
"""
import types

import pytest

from greasewood import cli
from greasewood.ca import CA
from greasewood.keys import CAKeys, NodeKeys


def _anchor_cfg(tmp_path, ca_key, role="anchor"):
    p = tmp_path / "gw.toml"
    p.write_text(f'''[node]
hostname = "anchor"
data_dir = "{tmp_path}"
role = "{role}"
[network]
seeds = []
root_url = ""
[anchor]
ca_key_file = "{ca_key}"
''')
    return p


def _make_anchor(tmp_path):
    ca_keys = CAKeys.generate()
    ca_key = tmp_path / "ca.key"
    ca_keys.save(ca_key)
    ca = CA(ca_keys, tmp_path)
    node = NodeKeys.generate()
    ca.issue(node.id_pub_bytes, node.wg_pub_bytes, "db", ["segment:mesh"])
    ca.add_revoke(NodeKeys.generate().id_pub_bytes)  # a revoke entry to preserve
    (tmp_path / "door.key").write_text("ZG9vcg==\n")
    return ca_keys, ca_key


def test_backup_then_restore_roundtrip(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)   # gated command
    ca_keys, ca_key = _make_anchor(tmp_path)
    cfg = _anchor_cfg(tmp_path, ca_key)
    monkeypatch.setenv("GW_BACKUP_PASSPHRASE", "s3kret")

    out = tmp_path / "anchor.gwbk"
    rc = cli.cmd_anchor_backup(types.SimpleNamespace(config=str(cfg), out=str(out)))
    assert rc == 0 and out.exists()
    assert "enrolled node" in capsys.readouterr().out

    # Restore into a pristine dir; skip the root check.
    monkeypatch.setattr(cli, "_require_root", lambda *_a, **_k: None)
    dst = tmp_path / "new-anchor"
    rc = cli.cmd_anchor_restore(types.SimpleNamespace(
        archive=str(out), data_dir=str(dst), force=False))
    assert rc == 0

    # Same CA key bytes, the node registry, and the revoke list all came back.
    assert (dst / "ca.key").read_bytes() == ca_key.read_bytes()
    restored_ca = CA(CAKeys.load(dst / "ca.key"), dst)
    node_files = list((dst / "nodes").glob("*.json"))
    assert len(node_files) == 1
    assert restored_ca.load_revoked_set()          # revoke list survived


def test_backup_refuses_non_anchor(tmp_path, monkeypatch):
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)   # gate passes; role check fires
    _, ca_key = _make_anchor(tmp_path)
    cfg = _anchor_cfg(tmp_path, ca_key, role="node")
    with pytest.raises(SystemExit, match="must be run on the anchor"):
        cli.cmd_anchor_backup(types.SimpleNamespace(config=str(cfg), out=None))


def test_restore_refuses_overwrite_without_force(tmp_path, monkeypatch):
    ca_keys, ca_key = _make_anchor(tmp_path)
    cfg = _anchor_cfg(tmp_path, ca_key)
    monkeypatch.setenv("GW_BACKUP_PASSPHRASE", "pw")
    monkeypatch.setattr(cli, "_require_root", lambda *_a, **_k: None)
    out = tmp_path / "anchor.gwbk"
    cli.cmd_anchor_backup(types.SimpleNamespace(config=str(cfg), out=str(out)))

    # data_dir already has a ca.key (it's the live anchor) → refuse without --force.
    with pytest.raises(SystemExit, match="refusing to overwrite"):
        cli.cmd_anchor_restore(types.SimpleNamespace(
            archive=str(out), data_dir=str(tmp_path), force=False))
