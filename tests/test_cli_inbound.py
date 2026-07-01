"""
Unit tests for the inbound/reachability CLI plumbing: set-inbound rewrites
config, and hub-promote refuses an outbound-only node.
"""
import types

import pytest

from greasewood import cli


@pytest.fixture(autouse=True)
def _as_root(monkeypatch):
    """These tests exercise command logic, not the privilege guard — run them
    as if root so _require_root() doesn't short-circuit."""
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)


def _write_cfg(path, inbound="yes", role="node"):
    path.write_text(f"""[node]
hostname = "n1"
data_dir = "/var/lib/greasewood"
role = "{role}"
inbound = "{inbound}"
caps = ["mesh"]

[network]
interface = "gw-mesh"
listen_port = 51900
seeds = []
root_url = ""
""")


def test_set_inbound_to_no_rewrites_config(tmp_path):
    cfg = tmp_path / "gw.toml"
    _write_cfg(cfg, "yes")
    args = types.SimpleNamespace(config=str(cfg), value="no")
    assert cli.cmd_set_inbound(args) == 0
    assert 'inbound = "no"' in cfg.read_text()


def test_set_inbound_to_yes_rewrites_config(tmp_path):
    cfg = tmp_path / "gw.toml"
    _write_cfg(cfg, "no")
    args = types.SimpleNamespace(config=str(cfg), value="yes")
    assert cli.cmd_set_inbound(args) == 0
    assert 'inbound = "yes"' in cfg.read_text()


def test_hub_promote_refuses_outbound_only(tmp_path):
    cfg = tmp_path / "gw.toml"
    _write_cfg(cfg, "no")
    args = types.SimpleNamespace(config=str(cfg), control_port=51902,
                                 credential_ttl="24h")
    with pytest.raises(SystemExit) as e:
        cli.cmd_hub_promote(args)
    assert "outbound-only" in str(e.value)
