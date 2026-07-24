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
    # Pretend systemctl is present regardless of the host (these tests cover the
    # systemd-managed purge path; a container without systemd would skip it).
    monkeypatch.setattr(cli.shutil, "which",
                        lambda name: "/bin/systemctl" if name == "systemctl" else None)
    # Pin the backend too: service.detect() checks /run/systemd/system, so on a
    # non-systemd host (macOS dev box) purge would see no backend at all.
    from greasewood import service as _service
    monkeypatch.setattr(cli, "_service_backend",
                        lambda: _service.SystemdManager(units))
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


# ---------------------------------------------------------------------------
# stray-daemon handling: kill THIS mesh's daemons, never another mesh's
# ---------------------------------------------------------------------------

def _pgrep_stub(lines):
    """A subprocess.run stub that answers `pgrep -af run` with `lines` and
    treats `ip link show` as absent; everything else is a rc=0 no-op."""
    def run(cmd, *a, **k):
        if cmd[:1] == ["pgrep"]:
            return _subprocess.CompletedProcess(cmd, 0, "\n".join(lines), "")
        if cmd[:3] == ["ip", "link", "show"]:
            return _subprocess.CompletedProcess(cmd, 1, "", "")
        return _subprocess.CompletedProcess(cmd, 0, "", "")
    return run


def test_gw_daemons_split_this_mesh_from_others(monkeypatch, tmp_path):
    cfg = _cfg(tmp_path, tmp_path / "data")           # basename gw.toml
    monkeypatch.setattr(_subprocess, "run", _pgrep_stub([
        f"111 /usr/local/bin/gw -c {cfg} run",        # this mesh (by config)
        "222 gw run",                                 # bare → single-mesh → this mesh
        "333 /usr/local/bin/gw -c /etc/greasewood_other.toml run",  # another mesh
        "444 /usr/bin/python somethingelse run",      # not greasewood
    ]))
    from pathlib import Path
    mine, others = cli._gw_daemons_for_mesh(Path(str(cfg)))
    assert set(mine) == {111, 222}
    assert others == [333]


def test_purge_kills_this_mesh_stray_but_not_others(tmp_path, monkeypatch, capsys):
    cfg = _cfg(tmp_path, tmp_path / "data")
    (tmp_path / "data").mkdir()
    monkeypatch.setattr(_subprocess, "run", _pgrep_stub([
        f"111 /usr/local/bin/gw -c {cfg} run",
        "333 /usr/local/bin/gw -c /etc/greasewood_other.toml run",
    ]))
    killed = []
    monkeypatch.setattr(cli.os, "kill", lambda pid, sig: killed.append((pid, sig)))
    monkeypatch.setattr(cli, "_pid_alive", lambda pid: False)   # exits on SIGTERM

    args = types.SimpleNamespace(config=str(cfg), yes=True)
    assert cli.cmd_purge(args) == 0
    out = capsys.readouterr().out
    assert any(pid == 111 for pid, _ in killed)      # this mesh's daemon killed
    assert all(pid != 333 for pid, _ in killed)      # the OTHER mesh untouched
    assert "333" in out and "different mesh" in out  # and it's reported, not killed


def test_teardown_door_routing_removes_rule_and_table(monkeypatch):
    from greasewood import wg
    calls = []

    def fake_run(*args, check=True):
        calls.append(list(args))
        # First rule-show reports the table present; second reports it gone.
        show = list(args)[:3] == ["ip", "-6", "rule"]
        n_shows = sum(1 for c in calls if c[:3] == ["ip", "-6", "rule"] and "show" in c)
        out = "51820" if (show and "show" in args and n_shows == 1) else ""
        return _subprocess.CompletedProcess(args, 0, out, "")

    monkeypatch.setattr(wg, "_run", fake_run)
    wg.teardown_door_routing()
    flat = [" ".join(c) for c in calls]
    assert any("rule del" in f and "51820" in f for f in flat)   # rule removed
    assert any("route flush table 51820" in f for f in flat)     # table flushed


# ---------------------------------------------------------------------------
# anchor purge — a second, explicit confirmation (dissolves the mesh)
# ---------------------------------------------------------------------------

def _anchor_cfg(tmp_path, data_dir):
    p = tmp_path / "gw.toml"
    p.write_text(f'''[node]
hostname = "anchor"
data_dir = "{data_dir}"
role = "anchor"
[network]
interface = "gw-pm"
mesh_domain = "internal"
seeds = []
root_url = ""
''')
    return p


def test_anchor_purge_second_confirm_yes_proceeds(tmp_path, monkeypatch):
    data_dir = tmp_path / "data"; data_dir.mkdir()
    cfg = _anchor_cfg(tmp_path, data_dir)
    monkeypatch.setattr(_subprocess, "run", _fake_run([], iface_present=False))
    monkeypatch.setattr(cli, "_other_peer_count", lambda c: 3)
    answers = iter(["y", "y"])
    monkeypatch.setattr("builtins.input", lambda *a: next(answers))
    args = types.SimpleNamespace(config=str(cfg), yes=False)
    assert cli.cmd_purge(args) == 0
    assert not data_dir.exists()                 # both confirmed → purged


def test_anchor_purge_second_confirm_no_aborts(tmp_path, monkeypatch, capsys):
    data_dir = tmp_path / "data"; data_dir.mkdir()
    cfg = _anchor_cfg(tmp_path, data_dir)
    monkeypatch.setattr(_subprocess, "run", _fake_run([], iface_present=False))
    monkeypatch.setattr(cli, "_other_peer_count", lambda c: 3)
    answers = iter(["y", "n"])                    # first yes, second no
    monkeypatch.setattr("builtins.input", lambda *a: next(answers))
    args = types.SimpleNamespace(config=str(cfg), yes=False)
    assert cli.cmd_purge(args) == 1
    assert data_dir.exists()                     # NOT purged
    out = capsys.readouterr().out
    assert "THIS HOST IS THE ANCHOR" in out and "3 other peers" in out


def test_anchor_purge_no_other_peers_only_one_prompt(tmp_path, monkeypatch):
    data_dir = tmp_path / "data"; data_dir.mkdir()
    cfg = _anchor_cfg(tmp_path, data_dir)
    monkeypatch.setattr(_subprocess, "run", _fake_run([], iface_present=False))
    monkeypatch.setattr(cli, "_other_peer_count", lambda c: 0)
    calls = []
    monkeypatch.setattr("builtins.input", lambda *a: calls.append(1) or "y")
    args = types.SimpleNamespace(config=str(cfg), yes=False)
    assert cli.cmd_purge(args) == 0
    assert len(calls) == 1                        # solo anchor → no second prompt


def test_anchor_purge_yes_flag_skips_both_prompts(tmp_path, monkeypatch):
    data_dir = tmp_path / "data"; data_dir.mkdir()
    cfg = _anchor_cfg(tmp_path, data_dir)
    monkeypatch.setattr(_subprocess, "run", _fake_run([], iface_present=False))
    monkeypatch.setattr(cli, "_other_peer_count", lambda c: 5)
    def boom(*a):
        raise AssertionError("-y must not prompt")
    monkeypatch.setattr("builtins.input", boom)
    args = types.SimpleNamespace(config=str(cfg), yes=True)
    assert cli.cmd_purge(args) == 0              # scripted purge unaffected
