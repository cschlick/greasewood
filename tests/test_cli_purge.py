"""
Unit tests for `gw purge` (cmd_purge) — a destructive command (tears down the
interface, rmtree's the data dir, unlinks config, removes the /etc/hosts block).
subprocess (ip link) and hosts.remove_block are stubbed so nothing real is
touched; only tmp paths are actually removed.
"""
import subprocess as _subprocess
import types

import pytest

from greasewood import cli
from greasewood import hosts as _hosts


@pytest.fixture(autouse=True)
def _as_root(monkeypatch):
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)


@pytest.fixture(autouse=True)
def _no_hosts(monkeypatch):
    # Never touch the real /etc/hosts.
    monkeypatch.setattr(_hosts, "remove_block", lambda *a, **k: False)


@pytest.fixture(autouse=True)
def _isolate_system(monkeypatch, tmp_path):
    # Keep purge off real /etc/systemd + real membership discovery. Default:
    # this is the only mesh (empty remaining), template present in a tmp dir.
    units = tmp_path / "units"
    units.mkdir(exist_ok=True)
    (units / "greasewood@.service").write_text("template")
    monkeypatch.setattr(cli, "_UNIT_DIR", units)
    monkeypatch.setattr(cli, "_memberships", lambda etc=None: [])
    return units


def _cfg(tmp_path, data_dir):
    p = tmp_path / "gw.toml"
    p.write_text(f'''[node]
hostname = "n1"
data_dir = "{data_dir}"
role = "node"
[network]
interface = "gw-mesh"
mesh_domain = "internal"
seeds = []
root_url = ""
''')
    return p


def _fake_run(recorder, iface_present):
    def run(cmd, *a, **k):
        recorder.append(cmd)
        is_show = cmd[:3] == ["ip", "link", "show"]
        rc = 0 if (is_show and iface_present) else (1 if is_show else 0)
        return _subprocess.CompletedProcess(cmd, rc)
    return run


def test_purge_yes_removes_data_dir_and_config(tmp_path, monkeypatch):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    (data_dir / "id_priv.pem").write_text("k")
    cfg = _cfg(tmp_path, data_dir)
    monkeypatch.setattr(_subprocess, "run", _fake_run([], iface_present=False))

    args = types.SimpleNamespace(config=str(cfg), yes=True)
    assert cli.cmd_purge(args) == 0
    assert not data_dir.exists()
    assert not cfg.exists()


def test_purge_aborts_on_no(tmp_path, monkeypatch, capsys):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    cfg = _cfg(tmp_path, data_dir)
    monkeypatch.setattr(_subprocess, "run", _fake_run([], iface_present=False))
    monkeypatch.setattr("builtins.input", lambda *a: "n")

    args = types.SimpleNamespace(config=str(cfg), yes=False)
    assert cli.cmd_purge(args) == 1
    assert data_dir.exists() and cfg.exists()  # nothing removed
    assert "Aborted" in capsys.readouterr().out


def test_purge_tears_down_present_interface(tmp_path, monkeypatch):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    cfg = _cfg(tmp_path, data_dir)
    calls = []
    monkeypatch.setattr(_subprocess, "run", _fake_run(calls, iface_present=True))

    args = types.SimpleNamespace(config=str(cfg), yes=True)
    assert cli.cmd_purge(args) == 0
    assert ["ip", "link", "set", "gw-mesh", "down"] in calls
    assert ["ip", "link", "delete", "gw-mesh"] in calls


def test_purge_last_mesh_removes_template(tmp_path, monkeypatch, _isolate_system):
    """Single-mesh host: purge is a full reset — it stops+disables the instance
    AND removes the shared systemd template (no other mesh needs it)."""
    data_dir = tmp_path / "data"; data_dir.mkdir()
    cfg = _cfg(tmp_path, data_dir)
    calls = []
    monkeypatch.setattr(_subprocess, "run", _fake_run(calls, iface_present=False))
    # _memberships already [] (this mesh's config is unlinked before the check).
    assert cli.cmd_purge(types.SimpleNamespace(config=str(cfg), yes=True)) == 0
    assert not (_isolate_system / "greasewood@.service").exists()   # template gone
    assert any("disable" in c for c in calls if isinstance(c, list))  # instance disabled


def test_purge_keeps_template_when_other_mesh_remains(tmp_path, monkeypatch, capsys, _isolate_system):
    """Multi-mesh host: purging one mesh disables its instance but LEAVES the
    template (another mesh still runs off it) and says so."""
    data_dir = tmp_path / "data"; data_dir.mkdir()
    cfg = _cfg(tmp_path, data_dir)
    monkeypatch.setattr(cli, "_memberships",
                        lambda etc=None: [("other", tmp_path / "greasewood_other.toml")])
    monkeypatch.setattr(_subprocess, "run", _fake_run([], iface_present=False))
    assert cli.cmd_purge(types.SimpleNamespace(config=str(cfg), yes=True)) == 0
    out = capsys.readouterr().out
    assert (_isolate_system / "greasewood@.service").exists()       # template kept
    assert "kept greasewood@.service" in out and "other" in out
