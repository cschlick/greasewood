"""
Tests for `gw upgrade` — the clean pipx reinstall.

The command exists because `pipx upgrade` was unreliable in the field (stale
__pycache__ from the previous version left in the venv, so the running code
didn't match what was installed). It uninstalls and installs instead, which
means it briefly removes `gw` from a machine the operator may be connected
through — so what it will run is printed and confirmed BEFORE anything happens,
and a failure names the recovery command.

The things worth pinning: it targets the pipx home this install actually came
from (fleet nodes use /opt/pipx, not the default), it builds the right spec for
each source, and a declined prompt changes nothing.
"""
from argparse import Namespace

import pytest

from greasewood import cli


def _cfg(tmp_path):
    p = tmp_path / "gw.toml"
    p.write_text(f'''[node]
hostname = "n1"
data_dir = "{tmp_path / 'data'}"
role = "node"
[network]
interface = "gw-mesh"
mesh_domain = "home.internal"
seeds = []
root_url = ""
''')
    (tmp_path / "data").mkdir(exist_ok=True)
    return p


def _args(tmp_path, **kw):
    base = dict(config=str(_cfg(tmp_path)), source="pypi", ref=None, yes=True)
    base.update(kw)
    return Namespace(**base)


@pytest.fixture
def pipx_layout(tmp_path, monkeypatch):
    """Pretend we're running from /opt/pipx/venvs/greasewood with gw linked into
    /usr/local/bin — the fleet's layout, not pipx's default."""
    home = tmp_path / "opt" / "pipx"
    venv = home / "venvs" / "greasewood"
    venv.mkdir(parents=True)
    bin_dir = tmp_path / "usr" / "local" / "bin"
    bin_dir.mkdir(parents=True)
    (bin_dir / "gw").write_text("#!/bin/sh\n")
    monkeypatch.setattr(cli.sys, "prefix", str(venv))
    monkeypatch.setattr(cli.shutil, "which",
                        lambda n: str(bin_dir / "gw") if n in ("gw", "git") else None)
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)
    return home, bin_dir


class _Runs:
    """Records subprocess.run calls; succeeds unless told otherwise."""

    def __init__(self, rc=0):
        self.calls, self.envs, self.rc = [], [], rc

    def __call__(self, cmd, *a, **kw):
        self.calls.append(list(cmd))
        self.envs.append(kw.get("env") or {})
        if kw.get("capture_output"):
            return type("R", (), {"returncode": 0, "stdout": "greasewood 9.9.9"})()
        return type("R", (), {"returncode": self.rc})()


def _patch_run(monkeypatch, runs):
    monkeypatch.setattr(cli.subprocess, "run", runs)
    monkeypatch.setattr(cli, "_service_restart", lambda key, why="": True)


def test_refuses_when_not_a_pipx_install(tmp_path, monkeypatch):
    # A distro package or a dev checkout: reinstalling via pipx would be wrong,
    # and silently creating a pipx copy alongside it would be worse.
    monkeypatch.setattr(cli.sys, "prefix", str(tmp_path / "usr"))
    with pytest.raises(SystemExit) as e:
        cli.cmd_upgrade(_args(tmp_path))
    assert "isn't one" in str(e.value)


def test_targets_the_pipx_home_this_install_came_from(tmp_path, monkeypatch,
                                                      pipx_layout):
    # Fleet installs use PIPX_HOME=/opt/pipx so root's copy isn't in a user's
    # home. Guessing pipx's default would install a SECOND copy elsewhere while
    # the service kept running the old one.
    home, bin_dir = pipx_layout
    runs = _Runs()
    _patch_run(monkeypatch, runs)
    assert cli.cmd_upgrade(_args(tmp_path)) == 0
    env = runs.envs[0]
    assert env["PIPX_HOME"] == str(home)
    assert env["PIPX_BIN_DIR"] == str(bin_dir)
    assert runs.calls[0] == ["pipx", "uninstall", "greasewood"]
    assert runs.calls[1] == ["pipx", "install", "greasewood"]


def test_github_source_builds_a_git_spec(tmp_path, monkeypatch, pipx_layout):
    runs = _Runs()
    _patch_run(monkeypatch, runs)
    cli.cmd_upgrade(_args(tmp_path, source="github", ref="main"))
    assert runs.calls[1] == ["pipx", "install", f"git+{cli._REPO_URL}@main"]


def test_github_defaults_to_main(tmp_path, monkeypatch, pipx_layout):
    runs = _Runs()
    _patch_run(monkeypatch, runs)
    cli.cmd_upgrade(_args(tmp_path, source="github"))
    assert runs.calls[1] == ["pipx", "install", f"git+{cli._REPO_URL}@main"]


def test_pypi_ref_pins_an_exact_version(tmp_path, monkeypatch, pipx_layout):
    runs = _Runs()
    _patch_run(monkeypatch, runs)
    cli.cmd_upgrade(_args(tmp_path, ref="0.3.1"))
    assert runs.calls[1] == ["pipx", "install", "greasewood==0.3.1"]


def test_declining_the_prompt_changes_nothing(tmp_path, monkeypatch, pipx_layout):
    runs = _Runs()
    _patch_run(monkeypatch, runs)
    monkeypatch.setattr("builtins.input", lambda *_: "n")
    assert cli.cmd_upgrade(_args(tmp_path, yes=False)) == 1
    assert runs.calls == []


def test_the_plan_is_printed_before_the_prompt(tmp_path, monkeypatch,
                                               pipx_layout, capsys):
    # The operator must be able to read exactly what will run — including that
    # gw disappears for a moment — before answering.
    runs = _Runs()
    _patch_run(monkeypatch, runs)
    monkeypatch.setattr("builtins.input", lambda *_: "n")
    cli.cmd_upgrade(_args(tmp_path, yes=False))
    out = capsys.readouterr().out
    assert "pipx uninstall greasewood" in out and "pipx install greasewood" in out
    assert "PIPX_HOME=" in out and "removes 'gw'" in out


def test_a_failed_install_names_the_recovery_command(tmp_path, monkeypatch,
                                                     pipx_layout):
    # The window where `gw` is uninstalled is the dangerous part — if the
    # install fails there, the operator must be told exactly how to get back.
    runs = _Runs(rc=1)
    _patch_run(monkeypatch, runs)
    with pytest.raises(SystemExit) as e:
        cli.cmd_upgrade(_args(tmp_path))
    msg = str(e.value)
    assert "may be uninstalled" in msg and "pipx install greasewood" in msg


def test_non_root_is_refused_before_anything_runs(tmp_path, monkeypatch,
                                                  pipx_layout):
    runs = _Runs()
    _patch_run(monkeypatch, runs)
    monkeypatch.setattr(cli.os, "geteuid", lambda: 1000)
    with pytest.raises(SystemExit) as e:
        cli.cmd_upgrade(_args(tmp_path))
    assert "needs root" in str(e.value)
    assert runs.calls == []
