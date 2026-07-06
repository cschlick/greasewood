"""
`gw config` — machine-readable resolved facts for scripting (get the mesh
interface name etc. programmatically).
"""
import types

import pytest

from greasewood import cli


def _cfg(tmp_path, role="node"):
    p = tmp_path / "gw.toml"
    extra = '\n[anchor]\ncontrol_listen = ":51902"\ndoor_port = 51901\nca_key_file = "/x"' if role == "anchor" else ""
    p.write_text(f"""[node]
hostname = "db01"
data_dir = "{tmp_path}"
role = "{role}"
[network]
interface = "gw_pm"
listen_port = 51900
seeds = []
root_url = "http://[fd8d::1]:51902"
mesh_domain = "pm.internal"
[ca]
trusted_pubs = []{extra}
""")
    return p


def test_config_single_key_is_bare_value(tmp_path, capsys):
    cfg = _cfg(tmp_path)
    assert cli.cmd_config(types.SimpleNamespace(config=str(cfg),
                                                key="interface")) == 0
    assert capsys.readouterr().out == "gw_pm\n"     # bare, scriptable


def test_config_all_is_key_tab_value(tmp_path, capsys):
    cfg = _cfg(tmp_path)
    cli.cmd_config(types.SimpleNamespace(config=str(cfg), key=None))
    out = capsys.readouterr().out
    facts = dict(line.split("\t", 1) for line in out.strip().splitlines())
    assert facts["interface"] == "gw_pm"
    assert facts["mesh_domain"] == "pm.internal"
    assert facts["listen_port"] == "51900"
    assert "control_port" not in facts              # node → no anchor-only facts


def test_config_anchor_has_control_and_door_ports(tmp_path, capsys):
    cfg = _cfg(tmp_path, role="anchor")
    cli.cmd_config(types.SimpleNamespace(config=str(cfg), key=None))
    out = capsys.readouterr().out
    assert "control_port\t51902" in out and "door_port\t51901" in out


def test_config_unknown_key_errors(tmp_path):
    cfg = _cfg(tmp_path)
    with pytest.raises(SystemExit) as e:
        cli.cmd_config(types.SimpleNamespace(config=str(cfg), key="nope"))
    assert "unknown config key 'nope'" in str(e.value)
