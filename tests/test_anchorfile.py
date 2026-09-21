"""
The anchor FILE — the mesh's portable authority. Possession = anchor duties;
copy = transfer; delete = cooperative de-anchor. These tests pin the file
format, the holder-detection seam, the adopt/drop role statements, and the
door key riding in the file so any holder serves any token.
"""
import datetime as dt
import types

import pytest

from greasewood import anchorfile, cli
from greasewood.directory import Directory
from greasewood.door import load_or_generate_door_key
from greasewood.keys import CAKeys, NodeKeys
from greasewood.statements import StatementLog
from tests._membership import enroll_record

_UTC = dt.timezone.utc


def _af(mesh="test.internal"):
    return anchorfile.AnchorFile.build(mesh, CAKeys.generate(), b"d" * 32)


# ---------------------------------------------------------------------------
# format + load semantics
# ---------------------------------------------------------------------------

def test_roundtrip_and_key_material(tmp_path):
    af = _af()
    p = af.save(tmp_path)
    assert p.name == "anchor.gwa"
    assert (p.stat().st_mode & 0o777) == 0o600      # root secrets
    loaded = anchorfile.load(tmp_path)
    assert loaded.mesh_domain == "test.internal"
    assert loaded.ca_keys().ca_pub_hex == af.ca_keys().ca_pub_hex
    assert loaded.door_key_raw() == b"d" * 32
    # transferable form == what a fresh save writes
    assert anchorfile.AnchorFile.from_bytes(loaded.to_bytes()).ca_key_pem \
        == af.ca_key_pem


def test_absent_is_none_but_corrupt_raises(tmp_path):
    assert anchorfile.load(tmp_path) is None
    anchorfile.anchor_path(tmp_path).write_text("{}")
    with pytest.raises(ValueError, match="not an anchor file"):
        anchorfile.load(tmp_path)         # holding a broken root key is LOUD


def test_door_key_rides_in_the_file(tmp_path):
    """load_or_generate_door_key prefers the anchor file, so every holder
    serves the same door_pub and any holder's invite verifies against any
    holder's file — no separate door.key hand-off."""
    _af().save(tmp_path)
    assert load_or_generate_door_key(tmp_path) == b"d" * 32
    assert not (tmp_path / "door.key").exists()     # nothing generated


# ---------------------------------------------------------------------------
# holder detection (the one seam every anchor gate goes through)
# ---------------------------------------------------------------------------

def test_holds_anchor_file_beats_role(tmp_path):
    cfg = types.SimpleNamespace(data_dir=tmp_path, role="node",
                                ca_key_file=None)
    assert cli._holds_anchor(cfg) is False
    _af().save(tmp_path)
    assert cli._holds_anchor(cfg) is True           # possession IS authority


def test_holds_anchor_legacy_config_still_counts(tmp_path):
    cfg = types.SimpleNamespace(data_dir=tmp_path, role="anchor",
                                ca_key_file=tmp_path / "ca.key")
    assert cli._holds_anchor(cfg) is True


def test_holds_anchor_corrupt_file_is_fatal_not_false(tmp_path):
    anchorfile.anchor_path(tmp_path).write_text("garbage")
    cfg = types.SimpleNamespace(data_dir=tmp_path, role="node",
                                ca_key_file=None)
    with pytest.raises(SystemExit, match="corrupt"):
        cli._holds_anchor(cfg)


# ---------------------------------------------------------------------------
# gw anchor init / export / adopt / drop
# ---------------------------------------------------------------------------

def _cfg_file(tmp_path, role, ca_key=None, trusted=()):
    trusted_line = f'trusted_pubs = {list(trusted)!r}\n' if trusted else ""
    anchor_sec = (f'[anchor]\nca_key_file = "{ca_key}"\n' if ca_key else "")
    p = tmp_path / "gw.toml"
    p.write_text(f'''[node]
hostname = "h1"
data_dir = "{tmp_path}"
role = "{role}"
[network]
seeds = []
root_url = ""
mesh_domain = "test.internal"
[ca]
{trusted_line}{anchor_sec}''')
    return p


def test_init_folds_legacy_anchor_into_file(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(cli, "_require_root", lambda *a, **k: None)
    ca_keys = CAKeys.generate()
    ca_keys.save(tmp_path / "ca.key")
    cfg = _cfg_file(tmp_path, "anchor", ca_key=tmp_path / "ca.key")
    assert cli.cmd_anchor(types.SimpleNamespace(
        config=str(cfg), action="init", path=None)) == 0
    af = anchorfile.load(tmp_path)
    assert af.ca_keys().ca_pub_hex == ca_keys.ca_pub_hex
    assert af.mesh_domain == "test.internal"
    # idempotent
    assert cli.cmd_anchor(types.SimpleNamespace(
        config=str(cfg), action="init", path=None)) == 0
    assert "already present" in capsys.readouterr().out


def test_adopt_installs_grants_roles_and_export_matches(tmp_path, monkeypatch,
                                                        capsys):
    """The full transfer: holder exports, node adopts — file installed, mesh
    checked, anchor roles minted as a replicated setcaps statement."""
    monkeypatch.setattr(cli, "_require_root", lambda *a, **k: None)
    monkeypatch.setattr(cli, "_service_restart", lambda *a, **k: True)
    ca_keys = CAKeys.generate()

    # holder side: init from legacy, then export
    holder = tmp_path / "holder"
    holder.mkdir()
    ca_keys.save(holder / "ca.key")
    hcfg = _cfg_file(holder, "anchor", ca_key=holder / "ca.key")
    # (writes gw.toml into holder/, but _cfg_file uses tmp_path for data_dir)
    hcfg.write_text(hcfg.read_text().replace(f'data_dir = "{tmp_path}"',
                                             f'data_dir = "{holder}"'))
    cli.cmd_anchor(types.SimpleNamespace(config=str(hcfg), action="init",
                                         path=None))
    out = tmp_path / "transfer.gwa"
    assert cli.cmd_anchor(types.SimpleNamespace(
        config=str(hcfg), action="export", path=str(out))) == 0

    # adopting node: enrolled member of the same mesh, trusting the CA
    node_dir = tmp_path / "node"
    node_dir.mkdir()
    nk = NodeKeys.load_or_generate(node_dir)
    enroll_record(ca_keys, node_dir, nk, "gp2", caps=["role:node"])
    ncfg = _cfg_file(node_dir, "node", trusted=[ca_keys.ca_pub_hex])
    ncfg.write_text(ncfg.read_text().replace(f'data_dir = "{tmp_path}"',
                                             f'data_dir = "{node_dir}"'))
    assert cli.cmd_anchor(types.SimpleNamespace(
        config=str(ncfg), action="adopt", path=str(out))) == 0

    af = anchorfile.load(node_dir)
    assert af.ca_keys().ca_pub_hex == ca_keys.ca_pub_hex
    # The replicated role grant landed:
    stmts = StatementLog.load(node_dir / "statements.json",
                              [ca_keys.ca_pub_bytes])
    caps, _ts = stmts.caps_override(nk.id_pub_hex)
    assert "role:*" in caps and "role:anchor" in caps and "role:node" in caps

    # …and drop sheds them and deletes the file.
    assert cli.cmd_anchor(types.SimpleNamespace(
        config=str(ncfg), action="drop", path=None)) == 0
    assert anchorfile.load(node_dir) is None
    stmts = StatementLog.load(node_dir / "statements.json",
                              [ca_keys.ca_pub_bytes])
    caps, _ts = stmts.caps_override(nk.id_pub_hex)
    assert "role:*" not in caps and "role:anchor" not in caps
    assert "role:node" in caps


def test_adopt_refuses_cross_mesh_and_untrusted(tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "_require_root", lambda *a, **k: None)
    other = anchorfile.AnchorFile.build("other.internal", CAKeys.generate(),
                                        b"d" * 32)
    src = tmp_path / "foreign.gwa"
    src.write_bytes(other.to_bytes())
    cfg = _cfg_file(tmp_path, "node")
    with pytest.raises(SystemExit, match="cross-mesh"):
        cli.cmd_anchor(types.SimpleNamespace(config=str(cfg), action="adopt",
                                             path=str(src)))
    # right mesh, wrong (untrusted) CA
    stranger = anchorfile.AnchorFile.build("test.internal", CAKeys.generate(),
                                           b"d" * 32)
    src.write_bytes(stranger.to_bytes())
    cfg = _cfg_file(tmp_path, "node", trusted=[CAKeys.generate().ca_pub_hex])
    with pytest.raises(SystemExit, match="not in this node's trusted_pubs"):
        cli.cmd_anchor(types.SimpleNamespace(config=str(cfg), action="adopt",
                                             path=str(src)))
