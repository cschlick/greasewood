"""
Unit tests for `gw revoke` (cmd_revoke) — the CLI wrapper around CA.add_revoke.
Covers the happy path (id added to revoked.json + hostname freed), bad-hex
validation, and the missing-ca_key_file refusal.
"""
import json
import types

import pytest

from greasewood import cli
from greasewood.ca import CA
from greasewood.keys import CAKeys, NodeKeys


def _hub_cfg(tmp_path, ca_key):
    p = tmp_path / "gw.toml"
    p.write_text(f'''[node]
hostname = "hub"
data_dir = "{tmp_path}"
role = "hub"
[network]
seeds = []
root_url = ""
[hub]
ca_key_file = "{ca_key}"
''')
    return p


def test_revoke_adds_id_and_frees_hostname(tmp_path, capsys):
    ca_keys = CAKeys.generate()
    ca_key = tmp_path / "ca.key"
    ca_keys.save(ca_key)
    # Issue a node first so nodes/<id>.json exists → revoke frees its hostname.
    ca = CA(ca_keys, tmp_path)
    node = NodeKeys.generate()
    ca.issue(node.id_pub_bytes, node.wg_pub_bytes, "db", ["mesh"])

    cfg = _hub_cfg(tmp_path, ca_key)
    args = types.SimpleNamespace(config=str(cfg), id_pub_hex=node.id_pub_hex)
    assert cli.cmd_revoke(args) == 0

    revoked = json.loads((tmp_path / "revoked.json").read_text())["revoked"]
    assert node.id_pub_hex in revoked
    out = capsys.readouterr().out
    assert "revoked:" in out and "free for reuse" in out


def test_revoke_bad_hex_exits(tmp_path):
    ca_keys = CAKeys.generate()
    ca_key = tmp_path / "ca.key"
    ca_keys.save(ca_key)
    cfg = _hub_cfg(tmp_path, ca_key)
    args = types.SimpleNamespace(config=str(cfg), id_pub_hex="not-hex")
    with pytest.raises(SystemExit):
        cli.cmd_revoke(args)


def test_revoke_without_ca_key_exits(tmp_path):
    p = tmp_path / "gw.toml"
    p.write_text('[node]\nhostname = "n1"\nrole = "node"\n')
    args = types.SimpleNamespace(config=str(p), id_pub_hex="ab" * 32)
    with pytest.raises(SystemExit):
        cli.cmd_revoke(args)
