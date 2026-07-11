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
interface = "gw-pm"
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
    assert capsys.readouterr().out == "gw-pm\n"     # bare, scriptable


def test_config_all_is_key_tab_value(tmp_path, capsys):
    cfg = _cfg(tmp_path)
    cli.cmd_config(types.SimpleNamespace(config=str(cfg), key=None))
    out = capsys.readouterr().out
    facts = dict(line.split("\t", 1) for line in out.strip().splitlines())
    assert facts["interface"] == "gw-pm"
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


# The `gw firewall` subcommand is gone; the recommended-posture printer it used
# lives on (create/join print it at setup), and the host-firewall port CHECK
# moved to gw watch (see test_watch_main_firewall.py).
def test_firewall_help_enforce_on_recommends_two_udp_plus_coarse_admit(capsys):
    cli._print_firewall_help(51900, 51902, "gw-pm", enforce_ports=True)
    out = capsys.readouterr().out
    assert "51900, 51901" in out                        # the two underlay UDP ports
    assert 'iifname "gw-*" accept' in out               # coarse admit — greasewood filters
    # the overlay ports are greasewood's table's job now, not the firewall's
    assert 'iifname "gw-pm" tcp dport 51902' not in out
    assert 'iifname "gw-door" tcp dport 51903' not in out


def test_firewall_help_node_role_omits_the_anchor_only_door_port(capsys):
    # A plain node needs just its mesh UDP port + the coarse overlay admit; the
    # enrollment door (51901) is the anchor's alone.
    cli._print_firewall_help(51900, mesh_iface="gw-pm", role="node")
    out = capsys.readouterr().out
    assert "udp dport 51900 accept" in out
    assert "51901" not in out                          # NOT the door port
    assert 'iifname "gw-*" accept' in out              # coarse overlay admit


def test_firewall_help_enforce_off_recommends_the_four_ports(capsys):
    cli._print_firewall_help(51900, 51902, "gw-pm", enforce_ports=False)
    out = capsys.readouterr().out
    # enforcement off → the operator gates the overlay ports themselves
    assert "51900, 51901" in out
    assert 'iifname "gw-pm" tcp dport 51902' in out     # control plane
    assert 'iifname "gw-door" tcp dport 51903' in out   # enrollment
    assert 'iifname "gw-door" drop' in out              # door lockdown stays operator's job
