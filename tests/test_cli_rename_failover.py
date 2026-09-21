"""
gw rename-node in the anchor-set world: any holder can serve the rename (it
is a renewal with a hostname), a dead holder costs a timeout rather than the
rename — and a holder's REFUSAL is final, never shopped to the next holder.
"""
import datetime as dt
import types

import pytest

from greasewood import cli
from greasewood.ca import CA
from greasewood.directory import Directory
from greasewood.keys import CAKeys, NodeKeys
from greasewood.server import ControlServer
from tests._membership import enroll_record

_UTC = dt.timezone.utc


def _node_cfg(tmp_path, hostname, root_url, seeds=()):
    p = tmp_path / "gw.toml"
    p.write_text(f'''[node]
hostname = "{hostname}"
data_dir = "{tmp_path}"
role = "node"
[network]
seeds = {list(seeds)!r}
root_url = "{root_url}"
mesh_domain = "test.internal"
[ca]
''')
    return p


def _holder(tmp_path, ca_keys, directory):
    srv = ControlServer(
        listen="[::1]:0", directory=directory,
        get_ca_pubs=lambda: [ca_keys.ca_pub_bytes], get_revoked=set,
        ca=CA(ca_keys, tmp_path, directory=directory,
              get_ca_pubs=lambda: [ca_keys.ca_pub_bytes]),
    )
    srv.start()
    return srv, srv._server.server_address[1]


def test_rename_fails_over_past_a_dead_holder(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(cli, "_require_root", lambda *a, **k: None)
    monkeypatch.setattr(cli, "_service_restart", lambda *a, **k: True)
    ca_keys = CAKeys.generate()
    keys = NodeKeys.load_or_generate(tmp_path)
    enroll_record(ca_keys, tmp_path, keys, "oldname", caps=["role:node"])

    holder_dir = Directory()
    holder_dir.put(Directory.load(tmp_path / "directory.json").all()[0])
    srv, port = _holder(tmp_path / "holder-data", ca_keys, holder_dir)
    (tmp_path / "holder-data").mkdir(exist_ok=True)
    try:
        # root_url points at a DEAD holder; the live one is in seeds.
        cfg = _node_cfg(tmp_path, "oldname",
                        root_url="http://[::1]:1",
                        seeds=[f"http://[::1]:{port}"])
        rc = cli.cmd_rename_node(types.SimpleNamespace(
            config=str(cfg), hostname="newname"))
        assert rc == 0
    finally:
        srv.stop()
    out = capsys.readouterr().out
    assert "trying the next holder" in out
    assert "renamed 'oldname' -> 'newname'" in out
    assert 'hostname = "newname"' in cfg.read_text()


def test_rename_refusal_is_final_not_shopped(tmp_path, monkeypatch):
    """A live holder's refusal (here: the target name is taken) must end the
    attempt — every holder answers from the same replicated view, so retrying
    elsewhere would only race the uniqueness check that just refused."""
    monkeypatch.setattr(cli, "_require_root", lambda *a, **k: None)
    ca_keys = CAKeys.generate()
    keys = NodeKeys.load_or_generate(tmp_path)
    enroll_record(ca_keys, tmp_path, keys, "oldname", caps=["role:node"])
    enroll_record(ca_keys, tmp_path, NodeKeys.generate(), "taken",
                  caps=["role:node"])

    holder_dir = Directory()
    for r in Directory.load(tmp_path / "directory.json").all():
        holder_dir.put(r)
    (tmp_path / "holder-data").mkdir(exist_ok=True)
    srv, port = _holder(tmp_path / "holder-data", ca_keys, holder_dir)
    try:
        cfg = _node_cfg(tmp_path, "oldname",
                        root_url=f"http://[::1]:{port}")
        with pytest.raises(SystemExit, match="already in use"):
            cli.cmd_rename_node(types.SimpleNamespace(
                config=str(cfg), hostname="taken"))
    finally:
        srv.stop()
    assert 'hostname = "oldname"' in cfg.read_text()   # nothing changed locally
