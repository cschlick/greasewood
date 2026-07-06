"""
Reachability is emergent now (a node advertises an endpoint, or it doesn't) —
there is no inbound flag and no set-inbound command. What remains to enforce:
anchor-promote refuses a node that advertises no endpoint, since an anchor must
be reachable to serve the control plane.
"""
import types

import pytest

from greasewood import cli


@pytest.fixture(autouse=True)
def _as_root(monkeypatch):
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)


def _write_cfg(path, *, endpoints="[]", role="node"):
    path.write_text(f"""[node]
hostname = "n1"
data_dir = "/var/lib/greasewood"
role = "{role}"
caps = ["mesh"]
endpoints = {endpoints}

[network]
interface = "gw-mesh"
listen_port = 51900
seeds = []
root_url = ""
""")


def test_anchor_promote_refuses_node_without_endpoint(tmp_path):
    cfg = tmp_path / "gw.toml"
    _write_cfg(cfg, endpoints="[]")           # advertises nothing → unreachable
    args = types.SimpleNamespace(config=str(cfg), control_port=51902,
                                 credential_ttl="24h")
    with pytest.raises(SystemExit) as e:
        cli.cmd_anchor_promote(args)
    assert "no endpoint" in str(e.value) and "anchor must be reachable" in str(e.value)
