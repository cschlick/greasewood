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
                                 "anchor-promote", "set-inbound"])
def test_privileged_commands_exit_cleanly_without_root(cmd, monkeypatch):
    _as_user(monkeypatch)
    with pytest.raises(SystemExit) as e:
        cli._require_root(cmd)
    msg = str(e.value)
    assert "needs root" in msg and f"sudo gw {cmd}" in msg


@pytest.mark.parametrize("cmd,fn", [
    ("revoke", "cmd_revoke"),
    ("set-caps", "cmd_set_caps"),
    ("set-segments", "cmd_set_segments"),
    ("renew-all", "cmd_renew_all"),
    ("cert-request", "cmd_cert_request"),
    ("anchor-backup", "cmd_anchor_backup"),
])
def test_registry_commands_complain_loudly_without_root(cmd, fn, monkeypatch):
    """The anchor registry/key commands gate on root FIRST — before touching config
    or any file — so a non-root run gets 'needs root … try sudo', never a
    partial failure like the historical \"no node named X\" (an unreadable
    registry scanning as empty)."""
    import types
    _as_user(monkeypatch)
    ns = types.SimpleNamespace(config="/nonexistent/gw.toml")   # never read
    with pytest.raises(SystemExit) as e:
        getattr(cli, fn)(ns)
    msg = str(e.value)
    assert "needs root" in msg and f"sudo gw {cmd}" in msg


def test_require_root_passes_as_root(monkeypatch):
    _as_root(monkeypatch)
    assert cli._require_root("run") is None  # no raise


@pytest.mark.parametrize("cmd,fn", [
    ("revoke", "cmd_revoke"),
    ("set-caps", "cmd_set_caps"),
    ("set-segments", "cmd_set_segments"),
    ("renew-all", "cmd_renew_all"),
])
def test_anchor_commands_refuse_non_anchor(cmd, fn, tmp_path, monkeypatch):
    """Every anchor-only command run on a role=node config exits with the same clear
    'must be run on the anchor' message — the root gate passes (faked), then the
    role check fires before any mutation."""
    import types
    _as_root(monkeypatch)
    cfg = tmp_path / "gw.toml"
    cfg.write_text(f"""[node]
hostname = "n1"
data_dir = "{tmp_path}"
role = "node"
[network]
interface = "gw-mesh"
seeds = []
[ca]
trusted_pubs = []
""")
    ns = types.SimpleNamespace(config=str(cfg), id_pub_hex="00" * 32,
                              node="n1", caps="tls", segments="mesh")
    with pytest.raises(SystemExit) as e:
        getattr(cli, fn)(ns)
    assert "must be run on the anchor" in str(e.value)
    # nothing was written (e.g. renew-all's hint file)
    assert not (tmp_path / "renew_after").exists()


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
    """`gw status` as a non-root user (no access to id_priv) must still work."""
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
    rc = cli.cmd_watch(types.SimpleNamespace(config=str(cfg)))
    (data_dir / "id_priv.pem").chmod(0o600)
    out = capsys.readouterr().out
    assert rc == 0
    assert derive_addr(keys.id_pub_bytes) in out  # self addr shown


def test_key_file_warnings_flags_foreign_owner_and_loose_mode(tmp_path):
    """Secrets owned by a non-root uid, or readable past their owner, get a
    SECURITY warning naming the fix. (expect_uid parameterizes 'root' so the
    test can run unprivileged: files here are owned by the test uid ≠ 0.)"""
    import os
    key = tmp_path / "ca.key"
    key.write_text("k")
    key.chmod(0o600)
    warns = cli._key_file_warnings([key], expect_uid=0)      # test uid ≠ 0 → foreign
    assert len(warns) == 1
    assert "owned by uid" in warns[0] and "mint mesh credentials" in warns[0]
    assert f"chown root:root {key}" in warns[0]

    key.chmod(0o644)                                          # loose mode too
    warns = cli._key_file_warnings([key], expect_uid=0)
    assert len(warns) == 2 and any("group/world-accessible" in w for w in warns)

    key.chmod(0o600)                                          # owned right + tight = quiet
    assert cli._key_file_warnings([key], expect_uid=os.geteuid()) == []
    assert cli._key_file_warnings([tmp_path / "missing.key", None]) == []


def test_status_says_truth_when_data_dir_unreadable(tmp_path, capsys):
    """A 0700 root data dir (legacy install) must produce an honest 'can't
    read … try sudo / chmod 755' exit — not 'directory is empty' or 'keys not
    generated' (what the invisible failed reads used to yield)."""
    import types
    import pytest as _pytest
    data = tmp_path / "data"
    data.mkdir()
    cfg = tmp_path / "gw.toml"
    cfg.write_text(f"""[node]
hostname = "n1"
data_dir = "{data}"
role = "node"
[network]
seeds = []
[ca]
trusted_pubs = []
""")
    data.chmod(0o000)                                        # untraversable
    try:
        with _pytest.raises(SystemExit) as e:
            cli.cmd_watch(types.SimpleNamespace(config=str(cfg), by_segment=False))
        msg = str(e.value)
        assert "can't read the public state" in msg
        assert "sudo gw watch" in msg and "chmod 755" in msg
    finally:
        data.chmod(0o755)


def _anchor_cfg(tmp_path):
    (tmp_path / "ca.key").write_text("placeholder")
    cfg = tmp_path / "gw.toml"
    cfg.write_text(f"""[node]
hostname = "anchor"
data_dir = "{tmp_path}"
role = "anchor"
[network]
interface = "gw-mesh"
seeds = []
[anchor]
ca_key_file = "{tmp_path}/ca.key"
[ca]
trusted_pubs = []
""")
    import types
    return types.SimpleNamespace(config=str(cfg), quiet=True, endpoint=None,
                                 segments=None, caps=None, hostname=None)


def test_invite_preflight_requires_mesh_interface(tmp_path, monkeypatch):
    """A token is only redeemable if the daemon (which hosts the enroll server)
    is up with its mesh interface present. invite must catch a missing
    interface NOW — not let the joiner discover it as a cryptic rejection."""
    _as_root(monkeypatch)
    monkeypatch.setattr("greasewood.wg.interface_exists", lambda iface: False)
    with pytest.raises(SystemExit) as e:
        cli.cmd_invite(_anchor_cfg(tmp_path))
    msg = str(e.value)
    assert "mesh interface 'gw-mesh' doesn't exist" in msg
    assert "systemctl start greasewood" in msg


def test_invite_preflight_requires_answering_daemon(tmp_path, monkeypatch):
    """Interface present but no daemon answering on loopback (kernel keeps the
    interface after the daemon dies) — invite must refuse with the reason."""
    _as_root(monkeypatch)
    monkeypatch.setattr("greasewood.wg.interface_exists", lambda iface: True)
    import urllib.request

    def refuse(url, timeout=None):
        raise OSError("connection refused")
    monkeypatch.setattr(urllib.request, "urlopen", refuse)
    with pytest.raises(SystemExit) as e:
        cli.cmd_invite(_anchor_cfg(tmp_path))
    msg = str(e.value)
    assert "isn't answering on loopback" in msg
    assert "token could never be redeemed" in msg
