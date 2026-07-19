"""
Bare `gw` — the dashboard, not a usage error.

The routing contract:
  * unconfigured host → quickstart + the everyday-commands index, rc 0
  * multi-mesh host  → the -c listing + commands, rc 0 (no guessing)
  * one mesh, no root / no tty → watch SNAPSHOT with the commands below
  * one mesh, root + tty → the live watch TUI (no text dump after)
  * `gw --help` keeps the full argparse reference, untouched
"""
import argparse
import pathlib
import types

import pytest

from greasewood import cli


def test_bare_unconfigured_prints_quickstart_and_commands(monkeypatch, capsys):
    monkeypatch.setattr(cli, "_memberships", lambda etc=None: [])
    monkeypatch.setattr(cli, "_require_supported_os", lambda: None)
    assert cli.main([]) == 0
    out = capsys.readouterr().out
    assert "no greasewood mesh is configured" in out
    assert "sudo gw create" in out and "sudo gw join" in out
    assert "everyday commands:" in out and "gw --help" in out


def test_bare_multi_mesh_lists_configs(monkeypatch, capsys):
    monkeypatch.setattr(cli, "_memberships", lambda etc=None: [
        ("home", pathlib.Path("/etc/greasewood_home.toml")),
        ("work", pathlib.Path("/etc/greasewood_work.toml"))])
    called = []
    monkeypatch.setattr(cli, "cmd_watch", lambda a: called.append(a) or 0)
    monkeypatch.setattr(cli, "_require_supported_os", lambda: None)
    assert cli.main([]) == 0
    out = capsys.readouterr().out
    assert "2 meshes" in out and "greasewood_home.toml" in out
    assert "everyday commands:" in out
    assert not called                               # never guesses a mesh


def test_bare_single_mesh_snapshot_plus_commands(monkeypatch, capsys):
    monkeypatch.setattr(cli, "_memberships", lambda etc=None: [
        ("home", pathlib.Path("/etc/greasewood_home.toml"))])
    monkeypatch.setattr(cli, "_require_supported_os", lambda: None)
    monkeypatch.setattr(cli.os, "geteuid", lambda: 1000)   # not root → snapshot
    seen = []
    monkeypatch.setattr(cli, "cmd_watch",
                        lambda a: seen.append(a) or print("<the roster>") or 0)
    assert cli.main([]) == 0
    assert seen[0].snapshot is True
    assert seen[0].config == "/etc/greasewood_home.toml"
    out = capsys.readouterr().out
    # the peer table first, the commands BELOW it
    assert out.index("<the roster>") < out.index("everyday commands:")


def test_bare_root_tty_goes_live_without_text_dump(monkeypatch, capsys):
    monkeypatch.setattr(cli, "_memberships", lambda etc=None: [
        ("home", pathlib.Path("/etc/greasewood_home.toml"))])
    monkeypatch.setattr(cli, "_require_supported_os", lambda: None)
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)
    monkeypatch.setattr(cli.sys.stdout, "isatty", lambda: True)
    seen = []
    monkeypatch.setattr(cli, "cmd_watch", lambda a: seen.append(a) or 0)
    assert cli.main([]) == 0
    assert seen[0].snapshot is False                # the live TUI
    assert "everyday commands:" not in capsys.readouterr().out


def test_bare_honors_explicit_config(monkeypatch, capsys):
    monkeypatch.setattr(cli, "_require_supported_os", lambda: None)
    monkeypatch.setattr(cli.os, "geteuid", lambda: 1000)
    seen = []
    monkeypatch.setattr(cli, "cmd_watch", lambda a: seen.append(a) or 0)
    assert cli.main(["-c", "/etc/greasewood_work.toml"]) == 0
    assert seen[0].config == "/etc/greasewood_work.toml"


def test_dash_h_keeps_the_full_reference(capsys):
    with pytest.raises(SystemExit) as e:
        cli.main(["--help"])
    assert e.value.code == 0
    out = capsys.readouterr().out
    assert "watch" in out and "revoke" in out       # the full subcommand list
