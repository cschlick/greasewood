"""
`gw join` refuses on an ANCHOR host, loudly. The door plane (gw-door, subnet
fd8d:e5c1:db1a:d::/64, table 51820) is a shared singleton, so an anchor's
permanent door isolation would blackhole any join the host attempts — it hangs
forever at 'connecting to enroll daemon'. Unsupported, so fail fast with the
reason instead of a mystery hang.
"""
from pathlib import Path
import types

import pytest

from greasewood import cli


def _write_cfg(etc, key, role):
    (etc / f"greasewood_{key}.toml").write_text(
        f'[node]\nhostname = "{key}h"\ndata_dir = "{etc}/{key}"\nrole = "{role}"\n'
        f'[network]\nmesh_domain = "{key}.internal"\n[ca]\ntrusted_pubs = []\n'
        + ('[anchor]\ncontrol_listen = ":51902"\ndoor_port = 51901\n'
           f'ca_key_file = "{etc}/{key}.key"\n' if role == "anchor" else ""))


def test_anchor_membership_finds_the_anchor(tmp_path):
    _write_cfg(tmp_path, "pm", "anchor")
    _write_cfg(tmp_path, "web", "node")
    found = cli._anchor_membership(etc=tmp_path)
    assert found is not None
    assert found[0] == "pm" and found[1] == tmp_path / "greasewood_pm.toml"


def test_anchor_membership_none_when_only_nodes(tmp_path):
    _write_cfg(tmp_path, "web", "node")
    _write_cfg(tmp_path, "db", "node")
    assert cli._anchor_membership(etc=tmp_path) is None


def test_anchor_membership_none_on_empty_host(tmp_path):
    assert cli._anchor_membership(etc=tmp_path) is None


def test_cmd_join_refuses_on_anchor_host(monkeypatch):
    monkeypatch.setattr(cli, "_require_root", lambda *a, **k: None)
    monkeypatch.setattr(cli, "_anchor_membership",
                        lambda *a, **k: ("pm", Path("/etc/greasewood_pm.toml")))
    import greasewood.door as door
    monkeypatch.setattr(door, "decode_token", lambda t: (
        b"\x00" * 32, b"\x11" * 32, "anchor.host", b"s" * 32, 51901,
        "home.internal", []))
    args = types.SimpleNamespace(token="gw1.sometoken", roles=None)
    with pytest.raises(SystemExit) as ei:
        cli.cmd_join(args)
    msg = str(ei.value)
    assert "anchor for mesh 'pm'" in msg
    assert "blackhole" in msg and "gw-door" in msg          # names the reason
    assert "ip -6 rule del" in msg                          # gives the override
