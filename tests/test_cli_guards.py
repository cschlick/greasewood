"""
Tests for the CLI privilege guards and read-only-without-sudo behavior.

Two guarantees:
  * commands that need root exit cleanly with a hint (not an EACCES traceback);
  * read-only commands (status) work without sudo — they read the public
    id_pub.hex, never the 0600 private key.
"""
import json

import pytest

from greasewood import cli
from greasewood.keys import NodeKeys, derive_addr


def _as_root(monkeypatch):
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)


def _as_user(monkeypatch):
    monkeypatch.setattr(cli.os, "geteuid", lambda: 1000)


@pytest.mark.parametrize("cmd", ["run", "create", "join", "invite", "purge",
                                 "hub-promote", "set-inbound"])
def test_privileged_commands_exit_cleanly_without_root(cmd, monkeypatch):
    _as_user(monkeypatch)
    with pytest.raises(SystemExit) as e:
        cli._require_root(cmd)
    msg = str(e.value)
    assert "needs root" in msg and f"sudo gw {cmd}" in msg


def test_require_root_passes_as_root(monkeypatch):
    _as_root(monkeypatch)
    assert cli._require_root("run") is None  # no raise


def test_own_identity_reads_public_key_only(tmp_path):
    """_own_identity must not touch the private key — even if it's unreadable."""
    keys = NodeKeys.generate()
    keys.save(tmp_path)
    # Make the private key unreadable to prove we never open it.
    (tmp_path / "id_priv.pem").chmod(0o000)
    try:
        h, addr = cli._own_identity(tmp_path)
        assert h == keys.id_pub_hex
        assert addr == derive_addr(keys.id_pub_bytes)
    finally:
        (tmp_path / "id_priv.pem").chmod(0o600)


def test_own_identity_missing_returns_none(tmp_path):
    assert cli._own_identity(tmp_path) == (None, None)


def test_status_works_without_private_key(tmp_path, capsys, monkeypatch):
    """`gw nodes` as a non-root user (no access to id_priv) must still work."""
    _as_user(monkeypatch)
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    keys = NodeKeys.generate()
    keys.save(data_dir)
    (data_dir / "id_priv.pem").chmod(0o000)  # simulate root-owned 0600 key

    cfg = tmp_path / "gw.toml"
    cfg.write_text(f"""[node]
hostname = "n1"
data_dir = "{data_dir}"
role = "node"
caps = ["mesh"]

[network]
interface = "gw-mesh"
listen_port = 51900
seeds = []
root_url = ""
""")
    # An empty directory cache so status prints the table path cleanly.
    (data_dir / "directory.json").write_text("[]")

    import types
    rc = cli.cmd_nodes(types.SimpleNamespace(config=str(cfg)))
    (data_dir / "id_priv.pem").chmod(0o600)
    out = capsys.readouterr().out
    assert rc == 0
    assert derive_addr(keys.id_pub_bytes) in out  # self addr shown
