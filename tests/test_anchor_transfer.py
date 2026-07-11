"""
anchor-transfer: hand the anchor role to another host over SSH (same CA, no
re-root). The safety-critical core is the HANDOFF — stop here, start there, and
ROLL BACK (restart here) if the target doesn't come up, so a failed transfer
never leaves the fleet anchorless.
"""
import types

import pytest

from greasewood import cli

_U = "greasewood@pm"


def _handoff(*, start_remote_ok, remote_active_ok):
    calls = []
    ok = cli._do_handoff(
        _U,
        stop_local=lambda u: calls.append(("stop_local", u)),
        start_remote=lambda u: (calls.append(("start_remote", u)) or start_remote_ok),
        remote_active=lambda u: (calls.append(("remote_active", u)) or remote_active_ok),
        start_local=lambda u: calls.append(("start_local", u)),
    )
    return ok, calls


def test_handoff_success_no_rollback():
    ok, calls = _handoff(start_remote_ok=True, remote_active_ok=True)
    assert ok is True
    assert calls == [("stop_local", _U), ("start_remote", _U), ("remote_active", _U)]
    assert ("start_local", _U) not in calls          # never rolled back


def test_handoff_rolls_back_when_remote_start_fails():
    ok, calls = _handoff(start_remote_ok=False, remote_active_ok=True)
    assert ok is False
    assert ("start_local", _U) in calls              # the original anchor is back
    assert ("remote_active", _U) not in calls        # short-circuit: never checked health


def test_handoff_rolls_back_when_remote_never_active():
    ok, calls = _handoff(start_remote_ok=True, remote_active_ok=False)
    assert ok is False
    assert calls[-1] == ("start_local", _U)          # rollback is the last thing done


# --- preflight guards (exit before touching anything) ---

def _cfg(tmp_path, *, role="anchor", ca=True):
    anchor = ""
    if role == "anchor":
        anchor = ('\n[anchor]\ncontrol_listen = ":51902"\ndoor_port = 51901\n'
                  + (f'ca_key_file = "{tmp_path}/ca.key"\n' if ca else ""))
    p = tmp_path / "gw.toml"
    p.write_text(f'[node]\nhostname = "a"\ndata_dir = "{tmp_path}"\nrole = "{role}"\n'
                 f'[network]\nmesh_domain = "pm.internal"\n[ca]\ntrusted_pubs = []{anchor}')
    return p


def _args(cfg_path):
    return types.SimpleNamespace(config=str(cfg_path), dest="h", ssh_opts=None,
                                 force=False, yes=True)


def test_transfer_refuses_on_a_non_anchor(tmp_path, monkeypatch):
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)
    with pytest.raises(SystemExit, match="role = anchor"):
        cli.cmd_anchor_transfer(_args(_cfg(tmp_path, role="node")))


def test_transfer_refuses_without_ca_key_file(tmp_path, monkeypatch):
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)
    with pytest.raises(SystemExit, match="ca_key_file"):
        cli.cmd_anchor_transfer(_args(_cfg(tmp_path, ca=False)))


def test_transfer_refuses_without_systemd(tmp_path, monkeypatch):
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)
    monkeypatch.setattr(cli, "_systemd_available", lambda: False)
    with pytest.raises(SystemExit, match="systemd"):
        cli.cmd_anchor_transfer(_args(_cfg(tmp_path)))


def test_dest_overlay_guard_classifies():
    cfg = types.SimpleNamespace(mesh_domain="pm.internal",
                                overlay_prefix="fd8d:e5c1:db1a:7::")
    # OVERLAY (refuse): mesh-domain name, or an IPv6 in the mesh's overlay /64
    assert cli._dest_is_overlay("db1.pm.internal", cfg)
    assert cli._dest_is_overlay("root@db1.pm.internal", cfg)
    assert cli._dest_is_overlay("fd8d:e5c1:db1a:7::5", cfg)
    assert cli._dest_is_overlay("[fd8d:e5c1:db1a:7::5]", cfg)
    # UNDERLAY (allow): real address / external name / a DIFFERENT ULA (underlay)
    assert not cli._dest_is_overlay("10.0.0.9", cfg)
    assert not cli._dest_is_overlay("newbox.example.com", cfg)
    assert not cli._dest_is_overlay("fd52:ba5e::5", cfg)     # different ULA = underlay
    assert not cli._dest_is_overlay("user@2001:db8::1", cfg)


def test_transfer_refuses_an_overlay_dest(tmp_path, monkeypatch):
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)
    monkeypatch.setattr(cli, "_systemd_available", lambda: True)
    args = _args(_cfg(tmp_path))
    args.dest = "anchor.pm.internal"                          # an overlay name
    with pytest.raises(SystemExit, match="OVERLAY"):
        cli.cmd_anchor_transfer(args)
