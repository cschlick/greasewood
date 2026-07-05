"""
Name-keyed multi-mesh memberships: every mesh on a host — including the first —
derives its artifacts from the mesh's own name (given at `gw create <name>`,
carried in every join token as <name>.internal). Nothing is unsuffixed and
nothing is numbered.
"""
from pathlib import Path

from greasewood import cli
from greasewood.keys import CAKeys


def _write_cfg(path: Path, data_dir: Path, ca_hex: str, iface="gw_x",
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
    assert cli._membership_key("prod-fleet.internal") == "prod-fleet"
    assert cli._membership_key("corp.example.internal") == "corp-example"  # sanitized
    mp = cli._membership_paths("prod-fleet")
    assert mp["config"] == Path("/etc/greasewood_prod-fleet.toml")
    assert mp["data_dir"] == Path("/var/lib/greasewood_prod-fleet")
    assert mp["interface"] == "gw_prod-fleet"           # 13 chars, fits
    assert mp["unit"] == "greasewood@prod-fleet"
    # 15-char kernel limit: gw_ + first 12 chars only.
    long = cli._membership_paths("engineering-platform")
    assert long["interface"] == "gw_engineering"
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
               ca.ca_pub_hex, iface="gw_engineering")
    iface = cli._membership_paths("engineering-payroll")["interface"]
    assert iface == "gw_engineering"                     # same truncation
    clash = cli._iface_collision(
        iface, tmp_path / "greasewood_engineering-payroll.toml", etc=tmp_path)
    assert clash == tmp_path / "greasewood_engineering-platform.toml"
    # Its own config never counts as a clash.
    assert cli._iface_collision(
        "gw_engineering", tmp_path / "greasewood_engineering-platform.toml",
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
    _write_cfg(cfg2, tmp_path / "db", ca_b.ca_pub_hex, iface="gw_beta",
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
          "interface": "gw_zzz", "unit": "greasewood@zzz"}
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
