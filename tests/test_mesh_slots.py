"""
Multi-mesh membership slots: `gw join <token>` with everything at defaults
routes by the token's CA — refresh the membership that already trusts it, or
auto-provision the next numbered slot (greasewoodN.toml, /var/lib/greasewoodN,
gw-meshN, 51900+10*(N-1), gwN.internal) for a genuinely new mesh.
"""
from pathlib import Path

from greasewood import cli
from greasewood.keys import CAKeys


def _write_cfg(path: Path, data_dir: Path, ca_hex: str, iface="gw-mesh",
               port=51900, domain="gw.internal"):
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


def test_slot_paths_formula():
    one = cli._slot_paths(1)
    assert one["config"] == Path("/etc/greasewood.toml")
    assert one["data_dir"] == Path("/var/lib/greasewood")
    assert one["interface"] == "gw-mesh" and one["listen_port"] == 51900
    assert one["mesh_domain"] == "gw.internal"

    three = cli._slot_paths(3)
    assert three["config"] == Path("/etc/greasewood3.toml")
    assert three["data_dir"] == Path("/var/lib/greasewood3")
    assert three["interface"] == "gw-mesh3" and three["listen_port"] == 51920
    assert three["mesh_domain"] == "gw3.internal"


def test_mesh_slots_discovery_and_next_free(tmp_path):
    assert cli._mesh_slots(etc=tmp_path) == []
    assert cli._next_free_slot(etc=tmp_path) == 2   # slot 1 is never allocated here

    ca = CAKeys.generate()
    _write_cfg(tmp_path / "greasewood.toml", tmp_path / "d1", ca.ca_pub_hex)
    _write_cfg(tmp_path / "greasewood2.toml", tmp_path / "d2", ca.ca_pub_hex)
    _write_cfg(tmp_path / "greasewood4.toml", tmp_path / "d4", ca.ca_pub_hex)
    (tmp_path / "greasewood-backup.toml").write_text("junk")   # not a slot
    slots = cli._mesh_slots(etc=tmp_path)
    assert [n for n, _ in slots] == [1, 2, 4]
    assert cli._next_free_slot(etc=tmp_path) == 3              # first gap


def test_slot_for_ca_routes_by_trusted_pubs(tmp_path):
    ca_a, ca_b = CAKeys.generate(), CAKeys.generate()
    _write_cfg(tmp_path / "greasewood.toml", tmp_path / "d1", ca_a.ca_pub_hex)
    _write_cfg(tmp_path / "greasewood2.toml", tmp_path / "d2", ca_b.ca_pub_hex)

    assert cli._slot_for_ca(ca_a.ca_pub_hex, etc=tmp_path) == 1
    assert cli._slot_for_ca(ca_b.ca_pub_hex, etc=tmp_path) == 2
    assert cli._slot_for_ca(CAKeys.generate().ca_pub_hex, etc=tmp_path) is None


def test_slot_for_ca_matches_any_trusted_pub_for_reroot(tmp_path):
    """During a re-root, trusted_pubs holds old+new CA — a token signed by the
    NEW CA must still route to the same membership, not spawn a new slot."""
    old, new = CAKeys.generate(), CAKeys.generate()
    (tmp_path / "greasewood.toml").write_text(f"""[node]
hostname = "n1"
data_dir = "{tmp_path}/d1"
role = "node"
[network]
seeds = []
[ca]
trusted_pubs = ["{old.ca_pub_hex}", "{new.ca_pub_hex}"]
""")
    assert cli._slot_for_ca(new.ca_pub_hex, etc=tmp_path) == 1
    assert cli._slot_for_ca(old.ca_pub_hex, etc=tmp_path) == 1


def test_unparseable_slot_config_is_skipped(tmp_path):
    ca = CAKeys.generate()
    (tmp_path / "greasewood.toml").write_text("not toml at all [[[")
    _write_cfg(tmp_path / "greasewood2.toml", tmp_path / "d2", ca.ca_pub_hex)
    assert cli._slot_for_ca(ca.ca_pub_hex, etc=tmp_path) == 2
