"""
Name-keyed multi-mesh memberships: every mesh on a host — including the first —
derives its artifacts from the mesh's own name (given at `gw create <name>`,
carried in every join token as <name>.internal). Nothing is unsuffixed and
nothing is numbered.
"""
from pathlib import Path

from greasewood import cli, status
from greasewood.keys import CAKeys


def _write_cfg(path: Path, data_dir: Path, ca_hex: str, iface="gw-x",
               port=51900, domain="x.internal"):
    path.write_text(f"""[node]
hostname = "n1"
data_dir = "{data_dir}"
role = "node"
[network]
interface = "{iface}"
listen_port = {port}
mesh_domain = "{domain}"
seeds = []
[ca]
trusted_pubs = ["{ca_hex}"]
""")


def test_membership_key_and_paths():
    assert cli.membership_key("prod-fleet.internal") == "prod-fleet"
    assert cli.membership_key("corp.example.internal") == "corp-example"  # sanitized
    mp = cli._membership_paths("prod-fleet")
    assert mp["config"] == Path("/etc/greasewood_prod-fleet.toml")
    assert mp["data_dir"] == Path("/var/lib/greasewood_prod-fleet")
    assert mp["interface"] == "gw-prod-fleet"           # 13 chars, fits
    assert mp["unit"] == "greasewood@prod-fleet"
    # 15-char kernel limit: gw- + first 12 chars only.
    long = cli._membership_paths("engineering-platform")
    assert long["interface"] == "gw-engineering"
    assert len(long["interface"]) <= 15


def test_memberships_discovery(tmp_path):
    assert cli._memberships(etc=tmp_path) == []
    ca = CAKeys.generate()
    _write_cfg(tmp_path / "greasewood_alpha.toml", tmp_path / "da", ca.ca_pub_hex)
    _write_cfg(tmp_path / "greasewood_beta-2.toml", tmp_path / "db", ca.ca_pub_hex)
    (tmp_path / "greasewood.toml").write_text("legacy")          # not a membership
    (tmp_path / "greasewood_UPPER.toml").write_text("junk")      # invalid key
    assert [k for k, _ in cli._memberships(etc=tmp_path)] == ["alpha", "beta-2"]


def test_membership_for_ca_routes_and_reroot(tmp_path):
    ca_a, ca_b, new = CAKeys.generate(), CAKeys.generate(), CAKeys.generate()
    _write_cfg(tmp_path / "greasewood_alpha.toml", tmp_path / "da", ca_a.ca_pub_hex)
    # beta trusts old+new (mid re-root): both route to beta, no ghost membership.
    (tmp_path / "greasewood_beta.toml").write_text(f"""[node]
hostname = "n1"
data_dir = "{tmp_path}/db"
role = "node"
[network]
seeds = []
[ca]
trusted_pubs = ["{ca_b.ca_pub_hex}", "{new.ca_pub_hex}"]
""")
    assert cli._membership_for_ca(ca_a.ca_pub_hex, etc=tmp_path) == "alpha"
    assert cli._membership_for_ca(ca_b.ca_pub_hex, etc=tmp_path) == "beta"
    assert cli._membership_for_ca(new.ca_pub_hex, etc=tmp_path) == "beta"
    assert cli._membership_for_ca(CAKeys.generate().ca_pub_hex, etc=tmp_path) is None


def test_free_listen_port_skips_used(tmp_path):
    ca = CAKeys.generate()
    assert cli._free_listen_port(etc=tmp_path) == 51900
    _write_cfg(tmp_path / "greasewood_a.toml", tmp_path / "da", ca.ca_pub_hex,
               port=51900)
    _write_cfg(tmp_path / "greasewood_b.toml", tmp_path / "db", ca.ca_pub_hex,
               port=51910)
    assert cli._free_listen_port(etc=tmp_path) == 51920


def test_iface_truncation_collision_detected(tmp_path):
    """Two long names sharing a 12-char prefix truncate to the same interface —
    detected so join/create can refuse loudly instead of silently renaming."""
    ca = CAKeys.generate()
    _write_cfg(tmp_path / "greasewood_engineering-platform.toml", tmp_path / "da",
               ca.ca_pub_hex, iface="gw-engineering")
    iface = cli._membership_paths("engineering-payroll")["interface"]
    assert iface == "gw-engineering"                     # same truncation
    clash = cli._iface_collision(
        iface, tmp_path / "greasewood_engineering-payroll.toml", etc=tmp_path)
    assert clash == tmp_path / "greasewood_engineering-platform.toml"
    # Its own config never counts as a clash.
    assert cli._iface_collision(
        "gw-engineering", tmp_path / "greasewood_engineering-platform.toml",
        etc=tmp_path) is None


def test_discover_config_single_multi_none(tmp_path):
    import pytest
    ca = CAKeys.generate()
    with pytest.raises(SystemExit) as e:
        cli._discover_config(etc=tmp_path)
    assert "no greasewood mesh is configured" in str(e.value)

    _write_cfg(tmp_path / "greasewood_solo.toml", tmp_path / "d", ca.ca_pub_hex)
    assert cli._discover_config(etc=tmp_path) == tmp_path / "greasewood_solo.toml"

    _write_cfg(tmp_path / "greasewood_duo.toml", tmp_path / "d2", ca.ca_pub_hex)
    with pytest.raises(SystemExit) as e:
        cli._discover_config(etc=tmp_path)
    assert "say which one" in str(e.value)
    assert "greasewood_solo.toml" in str(e.value)


def test_shared_prefix_warns_distinct_does_not(tmp_path, caplog):
    """Two memberships on one overlay /64: functional (all routing is /128) but
    prefix-scoped firewall rules / human reading break — warn at join."""
    import logging
    ca_a, ca_b = CAKeys.generate(), CAKeys.generate()
    _write_cfg(tmp_path / "greasewood_alpha.toml", tmp_path / "da", ca_a.ca_pub_hex)
    (tmp_path / "greasewood_alpha.toml").write_text(
        (tmp_path / "greasewood_alpha.toml").read_text().replace(
            "[network]", '[network]\noverlay_prefix = "fd8d:e5c1:db1a:7::"'))
    cfg2 = tmp_path / "greasewood_beta.toml"
    _write_cfg(cfg2, tmp_path / "db", ca_b.ca_pub_hex, iface="gw-beta",
               port=51910, domain="beta.internal")
    cfg2.write_text(cfg2.read_text().replace(
        "[network]", '[network]\noverlay_prefix = "fdde:cafc:ffe:e::"'))

    with caplog.at_level(logging.WARNING, logger="greasewood"):
        assert cli._warn_shared_overlay_prefix(
            cfg2, "fd8d:e5c1:db1a:0007::", etc=tmp_path) is True
        assert any("SAME overlay /64" in r.message for r in caplog.records)
        caplog.clear()
        assert cli._warn_shared_overlay_prefix(
            cfg2, "fdde:cafc:ffe:e::", etc=tmp_path) is False
        assert not caplog.records


def test_token_carries_mesh_domain_roundtrip():
    from greasewood.door import encode_token, decode_token
    tok = encode_token(b"\x01" * 32, b"\x02" * 32, "203.0.113.9", b"\x03" * 32,
                       51901, mesh_domain="prod-fleet.internal")
    *_, domain = decode_token(tok)
    assert domain == "prod-fleet.internal"


def test_create_requires_valid_mesh_name(monkeypatch):
    import types
    import pytest
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)
    ns = types.SimpleNamespace(name="Bad_Name!")
    with pytest.raises(SystemExit) as e:
        cli.cmd_create(ns)
    assert "must be a DNS label" in str(e.value)


def test_join_derives_paths_with_no_flags(tmp_path, monkeypatch):
    """Regression: -c/--data-dir default to None (derived from the token's mesh
    name); cmd_join must survive its entry path — Path(None) once crashed every
    flag-less join before the door dance. Runs join up to the door bring-up
    (stubbed to a sentinel), proving derivation happened."""
    import types
    import pytest
    from greasewood.door import encode_token, generate_seed

    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)
    mp = {"config": tmp_path / "greasewood_zzz.toml",
          "data_dir": tmp_path / "greasewood_zzz",
          "interface": "gw-zzz", "unit": "greasewood@zzz"}
    monkeypatch.setattr(cli, "_membership_paths", lambda key, **kw: mp)
    monkeypatch.setattr(cli, "_memberships", lambda etc=None: [])
    monkeypatch.setattr(cli, "_membership_for_ca", lambda ca, etc=None: None)

    class Sentinel(RuntimeError):
        pass

    def boom(*a, **k):
        raise Sentinel("reached the door bring-up")
    monkeypatch.setattr("greasewood.wg.ensure_node_door_interface", boom)

    token = encode_token(b"\x01" * 32, b"\x02" * 32, "203.0.113.9",
                         generate_seed(), 51901, mesh_domain="zzz.internal")
    ns = types.SimpleNamespace(token=token, config=None, data_dir=None,
                               listen_port=None, interface=None, hostname="n1",
                               inbound=None, endpoint="[fd00::1]:51900",
                               hosts_sync=None)
    with pytest.raises(Sentinel):
        cli.cmd_join(ns)
    # Derivation happened: keys were generated into the derived data dir.
    assert (tmp_path / "greasewood_zzz" / "id_pub.hex").exists()


def test_migrate_membership_moves_everything(tmp_path, monkeypatch):
    """rename-mesh's engine: config renamed + rewritten (domain/interface/
    data_dir), data dir moved, grace marker dropped, old config gone."""
    import json
    etc = tmp_path / "etc"; var = tmp_path / "var"
    etc.mkdir(); var.mkdir()
    old_data = var / "greasewood_alpha"; old_data.mkdir()
    (old_data / "id_pub.hex").write_text("aa")
    ca = CAKeys.generate()
    cfg = etc / "greasewood_alpha.toml"
    _write_cfg(cfg, old_data, ca.ca_pub_hex, iface="gw-alpha",
               domain="alpha.internal")
    monkeypatch.setattr("greasewood.wg.interface_exists", lambda i: False)
    monkeypatch.setattr("shutil.which", lambda n: None)       # no systemctl

    new_cfg = cli._migrate_membership(cfg, "beta", etc=etc, var=var)
    assert new_cfg == etc / "greasewood_beta.toml"
    assert not cfg.exists()
    text = new_cfg.read_text()
    assert 'mesh_domain = "beta.internal"' in text
    assert 'interface = "gw-beta"' in text
    assert f'data_dir = "{var / "greasewood_beta"}"' in text
    assert (var / "greasewood_beta" / "id_pub.hex").read_text() == "aa"
    assert not old_data.exists()
    marker = json.loads((var / "greasewood_beta" / "rename_grace.json").read_text())
    assert marker["old_domain"] == "alpha.internal"
    assert "until" in marker


def test_migrate_membership_refuses_collisions(tmp_path, monkeypatch):
    etc = tmp_path / "etc"; var = tmp_path / "var"
    etc.mkdir(); var.mkdir()
    ca = CAKeys.generate()
    (var / "greasewood_alpha").mkdir()
    cfg = etc / "greasewood_alpha.toml"
    _write_cfg(cfg, var / "greasewood_alpha", ca.ca_pub_hex,
               iface="gw-alpha", domain="alpha.internal")
    _write_cfg(etc / "greasewood_beta.toml", var / "gb", ca.ca_pub_hex,
               iface="gw-beta", domain="beta.internal")
    import pytest
    with pytest.raises(SystemExit) as e:
        cli._migrate_membership(cfg, "beta", etc=etc, var=var)
    assert "already exists" in str(e.value)
    assert cfg.exists()                                      # nothing moved


def test_sync_warns_on_mesh_rename(tmp_path, caplog):
    """A member whose anchor advertises a different domain gets the exact
    migration command, once."""
    import logging
    from greasewood.directory import Directory
    from greasewood import sync as syncmod
    loop = syncmod.SyncLoop(Directory(), lambda: [], tmp_path / "d.json",
                            expected_domain="alpha.internal")
    with caplog.at_level(logging.WARNING, logger="greasewood.sync"):
        loop._note_mesh_domain("beta.internal")
        loop._note_mesh_domain("beta.internal")              # warned once
        loop._note_mesh_domain("alpha.internal")             # match: silent
    warns = [r for r in caplog.records if "renamed this mesh" in r.message]
    assert len(warns) == 1
    assert "gw rename-mesh beta" in warns[0].message


def test_reconcile_rename_grace_dual_then_retire(tmp_path, monkeypatch):
    """During grace the OLD domain's names are synced too; past the deadline
    the old block and marker retire."""
    import datetime as dt
    import json
    from greasewood.reconcile import ReconcileLoop
    from greasewood.directory import Directory

    calls = []
    class FakeHosts:
        @staticmethod
        def sync(records, domain, path=None):
            calls.append(("sync", domain))
        @staticmethod
        def remove_block(domain, path=None):
            calls.append(("remove", domain))
    loop = ReconcileLoop(iface="gw-x", directory=Directory(),
                         local_id_pub=b"\x01" * 32, local_caps=[],
                         get_ca_pubs=lambda: [], get_revoked=set,
                         hosts_domain="beta.internal", data_dir=tmp_path)
    future = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=1)).isoformat()
    (tmp_path / "rename_grace.json").write_text(json.dumps(
        {"old_domain": "alpha.internal", "until": future}))
    loop._rename_grace([], FakeHosts)
    assert ("sync", "alpha.internal") in calls               # dual during grace

    calls.clear()
    past = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=1)).isoformat()
    (tmp_path / "rename_grace.json").write_text(json.dumps(
        {"old_domain": "alpha.internal", "until": past}))
    loop._rename_grace([], FakeHosts)
    assert ("remove", "alpha.internal") in calls             # retired
    assert not (tmp_path / "rename_grace.json").exists()


def test_join_refuses_same_name_different_mesh(tmp_path, monkeypatch):
    """A NEW mesh (unknown CA) whose name collides with an existing membership
    derives the SAME config path — the refusal must still fire (the earlier
    exclude-by-path logic masked exactly this). Refusal is pre-door: no keys
    written, token not consumed."""
    import types
    import pytest
    from greasewood.door import encode_token, generate_seed

    etc_dir = tmp_path / "etc"; etc_dir.mkdir()
    ca_existing = CAKeys.generate()
    # Existing membership 'prod' with domain prod.internal, CA = ca_existing.
    _write_cfg(etc_dir / "greasewood_prod.toml", tmp_path / "dp", ca_existing.ca_pub_hex,
               iface="gw-prod", domain="prod.internal")
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)
    # Redirect the two leaf helpers to the tmp /etc and data root, matching
    # their real signatures; _membership_for_ca / _iface_collision / _free_
    # listen_port all route through _memberships, so they follow automatically.
    _orig_memberships = cli._memberships
    _orig_paths = cli._membership_paths
    monkeypatch.setattr(cli, "_memberships",
                        lambda etc=None: _orig_memberships(etc=etc_dir))
    monkeypatch.setattr(cli, "_membership_paths",
                        lambda key, etc=None, var=None:
                            _orig_paths(key, etc=etc_dir, var=tmp_path))

    # A DIFFERENT anchor (fresh CA) for a mesh ALSO named 'prod'.
    other_ca = CAKeys.generate()
    token = encode_token(b"\x01" * 32, other_ca.ca_pub_bytes, "203.0.113.9",
                         generate_seed(), 51901, mesh_domain="prod.internal")
    ns = types.SimpleNamespace(token=token, config=None, data_dir=None,
                               listen_port=None, interface=None, hostname="n1",
                               inbound=None, endpoint="[fd00::1]:51900",
                               hosts_sync=None)
    with pytest.raises(SystemExit) as e:
        cli.cmd_join(ns)
    msg = str(e.value)
    assert "cannot bridge two meshes with the same domain" in msg
    assert "NOT consumed" in msg
    # No state written for the refused join.
    assert not (tmp_path / "greasewood_prod" / "id_priv.pem").exists()


def test_free_port_avoids_live_interface_orphan(monkeypatch, tmp_path):
    """A purged mesh can leave a WG interface still bound to its port with no
    config — _free_listen_port must skip it, not hand it to a new mesh that
    would then crash at interface-up (the bastion incident)."""
    from greasewood import wg as wgmod
    monkeypatch.setattr(cli, "_memberships", lambda etc=None: [])   # no configs
    # But a leftover interface holds 51900.
    monkeypatch.setattr(wgmod, "wg_interface_ports", lambda: {"gw-old": 51900})
    assert cli._free_listen_port(etc=tmp_path) == 51910


def test_ensure_interface_port_in_use_is_actionable(monkeypatch):
    """An EADDRINUSE at `ip link set up` (another wg iface on our port) raises
    PortInUse with the culprit + fix — not a raw CalledProcessError."""
    import subprocess
    from greasewood import wg as wgmod

    def fake_run(*args, check=True):
        cmd = list(args)
        if cmd[:3] == ["ip", "link", "set"] and cmd[-1] == "up":
            return subprocess.CompletedProcess(
                cmd, 2, "", "RTNETLINK answers: Address already in use")
        return subprocess.CompletedProcess(cmd, 0, "", "")
    monkeypatch.setattr(wgmod, "_run", fake_run)
    monkeypatch.setattr(wgmod, "_wg_iface_on_port",
                        lambda port, exclude="": "gw-old")

    import pytest
    with pytest.raises(wgmod.PortInUse) as e:
        wgmod.ensure_interface("gw-pm", "fd8d::1", 51900, __import__("pathlib").Path("/x"))
    msg = str(e.value)
    assert "UDP port 51900 is already used by WireGuard interface 'gw-old'" in msg
    assert "ip link del gw-old" in msg and "--listen-port" in msg


def test_sync_persists_pending_rename(tmp_path):
    """A detected rename is written to pending_rename.json (survives restarts,
    surfaces in status) and cleared when the anchor domain matches again."""
    import json
    from greasewood.directory import Directory
    from greasewood import sync as syncmod
    loop = syncmod.SyncLoop(Directory(), lambda: [], tmp_path / "directory.json",
                            expected_domain="old.internal")
    loop._note_mesh_domain("new.internal")
    p = tmp_path / "pending_rename.json"
    assert p.exists()
    d = json.loads(p.read_text())
    assert d == {"new_domain": "new.internal", "old_domain": "old.internal"}
    # Anchor back in sync (e.g. after this member migrated) → marker cleared.
    loop._note_mesh_domain("old.internal")
    assert not p.exists()


def test_status_surfaces_pending_rename(tmp_path):
    import json
    import types
    from greasewood import cli
    from greasewood.keys import CAKeys, NodeKeys
    from greasewood.directory import Directory
    from greasewood.wire import Credential, NodeRecord
    import datetime as dt
    _UTC = dt.timezone.utc
    keys = NodeKeys.load_or_generate(tmp_path)
    ca = CAKeys.generate()
    (tmp_path / "gw.toml").write_text(f"""[node]
hostname = "n1"
data_dir = "{tmp_path}"
role = "node"
[network]
seeds = []
mesh_domain = "old.internal"
[ca]
trusted_pubs = ["{ca.ca_pub_hex}"]
""")
    (tmp_path / "pending_rename.json").write_text(json.dumps(
        {"new_domain": "prod-fleet.internal", "old_domain": "old.internal"}))
    from greasewood.config import load_config
    cfg = load_config(tmp_path / "gw.toml")
    lines = status._self_health_lines(cfg, Directory(), keys.id_pub_hex)
    joined = "\n".join(lines)
    assert "the anchor renamed this mesh" in joined
    assert "sudo gw rename-mesh prod-fleet" in joined
