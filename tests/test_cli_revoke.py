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


def _anchor_cfg(tmp_path, ca_key):
    p = tmp_path / "gw.toml"
    p.write_text(f'''[node]
hostname = "anchor"
data_dir = "{tmp_path}"
role = "anchor"
[network]
seeds = []
root_url = ""
mesh_domain = "test.internal"
[anchor]
ca_key_file = "{ca_key}"
''')
    return p


def test_revoke_adds_id_and_frees_hostname(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)   # gated command
    ca_keys = CAKeys.generate()
    ca_key = tmp_path / "ca.key"
    ca_keys.save(ca_key)
    # Issue a node first so nodes/<id>.json exists → revoke frees its hostname.
    ca = CA(ca_keys, tmp_path)
    node = NodeKeys.generate()
    ca.issue(node.id_pub_bytes, node.wg_pub_bytes, "db", ["mesh"])

    cfg = _anchor_cfg(tmp_path, ca_key)
    args = types.SimpleNamespace(config=str(cfg), node=node.id_pub_hex)
    assert cli.cmd_revoke(args) == 0

    revoked = json.loads((tmp_path / "revoked.json").read_text())["revoked"]
    assert node.id_pub_hex in revoked
    out = capsys.readouterr().out
    assert "revoked:" in out and "free for reuse" in out


def test_revoke_by_hostname(tmp_path, capsys, monkeypatch):
    """revoke accepts a bare hostname AND a full <host>.<mesh_domain> mesh name,
    resolved via the anchor registry (two fresh nodes, one form each)."""
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)
    ca_keys = CAKeys.generate()
    ca_key = tmp_path / "ca.key"
    ca_keys.save(ca_key)
    ca = CA(ca_keys, tmp_path)
    a, b = NodeKeys.generate(), NodeKeys.generate()
    ca.issue(a.id_pub_bytes, a.wg_pub_bytes, "db01", ["mesh"])
    ca.issue(b.id_pub_bytes, b.wg_pub_bytes, "web1", ["mesh"])
    cfg = _anchor_cfg(tmp_path, ca_key)     # mesh_domain = test.internal

    assert cli.cmd_revoke(types.SimpleNamespace(config=str(cfg), node="db01")) == 0
    assert cli.cmd_revoke(types.SimpleNamespace(
        config=str(cfg), node="web1.test.internal")) == 0     # full mesh name

    revoked = json.loads((tmp_path / "revoked.json").read_text())["revoked"]
    assert a.id_pub_hex in revoked and b.id_pub_hex in revoked
    out = capsys.readouterr().out
    assert "db01" in out and "web1" in out  # names echoed, not just the hex


def test_revoke_raw_id_not_enrolled(tmp_path, capsys, monkeypatch):
    """A raw id hex is honored even if the node was never/no-longer enrolled —
    defensive revocation shouldn't require a registry entry."""
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)
    ca_keys = CAKeys.generate()
    ca_key = tmp_path / "ca.key"
    ca_keys.save(ca_key)
    CA(ca_keys, tmp_path)                    # empty registry
    cfg = _anchor_cfg(tmp_path, ca_key)
    stray = "ab" * 32
    assert cli.cmd_revoke(types.SimpleNamespace(config=str(cfg), node=stray)) == 0
    assert stray in json.loads((tmp_path / "revoked.json").read_text())["revoked"]


def test_revoke_unknown_hostname_exits(tmp_path, monkeypatch):
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)
    ca_keys = CAKeys.generate()
    ca_key = tmp_path / "ca.key"
    ca_keys.save(ca_key)
    CA(ca_keys, tmp_path)
    cfg = _anchor_cfg(tmp_path, ca_key)
    with pytest.raises(SystemExit) as e:
        cli.cmd_revoke(types.SimpleNamespace(config=str(cfg), node="ghost"))
    assert "no node named 'ghost'" in str(e.value)


def test_set_caps_and_roles_echo_resolved_id(tmp_path, capsys, monkeypatch):
    """set-caps / set-roles resolve a hostname (or mesh name) and echo the
    resolved node name AND its id, like revoke."""
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)
    ca_keys = CAKeys.generate()
    ca_key = tmp_path / "ca.key"
    ca_keys.save(ca_key)
    ca = CA(ca_keys, tmp_path)
    n = NodeKeys.generate()
    ca.issue(n.id_pub_bytes, n.wg_pub_bytes, "db01", ["role:mesh"])
    cfg = _anchor_cfg(tmp_path, ca_key)     # mesh_domain = test.internal

    assert cli.cmd_set_caps(types.SimpleNamespace(
        config=str(cfg), node="db01", caps="role:mesh,tls")) == 0
    out = capsys.readouterr().out
    assert "db01" in out and n.id_pub_hex in out

    assert cli.cmd_set_roles(types.SimpleNamespace(
        config=str(cfg), node="db01.test.internal", roles="prod")) == 0
    out = capsys.readouterr().out
    assert "db01" in out and n.id_pub_hex in out          # by full mesh name too


def test_revoke_without_ca_key_exits(tmp_path):
    p = tmp_path / "gw.toml"
    p.write_text('[node]\nhostname = "n1"\nrole = "node"\n')
    args = types.SimpleNamespace(config=str(p), node="ab" * 32)
    with pytest.raises(SystemExit):
        cli.cmd_revoke(args)
