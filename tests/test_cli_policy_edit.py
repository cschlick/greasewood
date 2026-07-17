"""
`gw policy edit` — the low-friction path into grants.toml: resolve the file
from config (no path-typing), open the operator's editor, validate on save
(visudo-style re-edit loop), then offer the apply preview. The guarantees:
  * never runs on a non-anchor (grants.toml is authored on the anchor)
  * a parse error can't land silently — re-edit or exit loudly
  * declining the apply leaves the file edited but the policy untouched
  * editor resolution: $SUDO_EDITOR > $VISUAL > $EDITOR > nano > vi
"""
import types

import pytest

from greasewood import cli


def _cfg(tmp_path, *, role="anchor"):
    anchor = ""
    if role == "anchor":
        anchor = ('\n[anchor]\ncontrol_listen = ":51902"\ndoor_port = 51901\n'
                  f'ca_key_file = "{tmp_path}/ca.key"\n')
    p = tmp_path / "gw.toml"
    p.write_text(f'[node]\nhostname = "a"\ndata_dir = "{tmp_path}"\nrole = "{role}"\n'
                 f'[network]\nmesh_domain = "pm.internal"\n[ca]\ntrusted_pubs = []{anchor}')
    return p


def _args(cfg_path, **kw):
    return types.SimpleNamespace(action="edit", config=str(cfg_path), file=None,
                                 yes=False, **kw)


def _editor_script(tmp_path, body):
    """A fake $EDITOR: a script that receives the grants path as $1."""
    s = tmp_path / "fake-editor.sh"
    s.write_text(f"#!/bin/sh\n{body}\n")
    s.chmod(0o755)
    return str(s)


def _answers(monkeypatch, *replies):
    it = iter(replies)
    monkeypatch.setattr("builtins.input", lambda *a: next(it))


def test_edit_refuses_on_a_non_anchor(tmp_path, monkeypatch):
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)
    with pytest.raises(SystemExit, match="anchor"):
        cli.cmd_policy(_args(_cfg(tmp_path, role="node")))


def test_edit_writes_validates_and_declining_apply_keeps_policy_untouched(
        tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)
    cfg = _cfg(tmp_path)
    ed = _editor_script(tmp_path, 'printf \'[[grant]]\\nfrom = ["host:bb"]\\n'
                                  'to = ["host:nas"]\\nports = ["tcp/2049"]\\n\' > "$1"')
    monkeypatch.setenv("SUDO_EDITOR", ed)
    _answers(monkeypatch, "n")                      # decline the apply preview
    assert cli.cmd_policy(_args(cfg)) == 0
    out = capsys.readouterr().out
    assert str(tmp_path / "grants.toml") in out     # the path is printed
    assert "host:bb" in (tmp_path / "grants.toml").read_text()
    assert not (tmp_path / "policy.json").exists()  # nothing signed/applied
    assert "inert until" in out


def test_edit_seeds_the_default_template_when_missing(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)
    cfg = _cfg(tmp_path)
    assert not (tmp_path / "grants.toml").exists()
    monkeypatch.setenv("SUDO_EDITOR", _editor_script(tmp_path, "true"))  # no-op editor
    _answers(monkeypatch, "n")
    cli.cmd_policy(_args(cfg))
    text = (tmp_path / "grants.toml").read_text()
    assert "[[grant]]" in text and "default-closed" in capsys.readouterr().out.lower()


def test_edit_invalid_save_loops_then_exits_loudly(tmp_path, monkeypatch):
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)
    cfg = _cfg(tmp_path)
    ed = _editor_script(tmp_path, 'printf \'[[grant]]\\nfrom = ["hosts:typo"]\\n'
                                  'to = ["*"]\\n\' > "$1"')
    monkeypatch.setenv("SUDO_EDITOR", ed)
    _answers(monkeypatch, "n")                      # decline the re-edit
    with pytest.raises(SystemExit, match="INVALID"):
        cli.cmd_policy(_args(cfg))


def test_edit_failed_editor_changes_nothing(tmp_path, monkeypatch):
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)
    cfg = _cfg(tmp_path)
    (tmp_path / "grants.toml").write_text("# untouched\n")
    monkeypatch.setenv("SUDO_EDITOR", _editor_script(tmp_path, "exit 3"))
    with pytest.raises(SystemExit, match="exited 3"):
        cli.cmd_policy(_args(cfg))
    assert (tmp_path / "grants.toml").read_text() == "# untouched\n"


def test_resolve_editor_precedence_and_fallback(tmp_path, monkeypatch):
    a = _editor_script(tmp_path, "true")
    b = _editor_script(tmp_path, "true").replace("fake-editor", "fake-editor")  # same file ok
    monkeypatch.setenv("SUDO_EDITOR", a)
    monkeypatch.setenv("VISUAL", "/nonexistent-editor")
    monkeypatch.setenv("EDITOR", "/nonexistent-editor")
    assert cli._resolve_editor() == [a]             # SUDO_EDITOR wins
    monkeypatch.delenv("SUDO_EDITOR")
    monkeypatch.setenv("VISUAL", f"{a} --wait")
    assert cli._resolve_editor() == [a, "--wait"]   # args survive shlex
    for var in ("VISUAL", "EDITOR"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr(cli.shutil, "which",
                        lambda t: "/usr/bin/nano" if t == "nano" else None)
    assert cli._resolve_editor() == ["nano"]        # fallback
