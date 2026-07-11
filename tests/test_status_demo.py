"""
`gw status` output demonstration + regression, on a full (12-node) directory.

Builds a varied directory cache and runs the real `cmd_status`: mixed roles
(the default `mesh` pool, `prod`/`dev`/`web`, a multi-role *bridge*, the
reach-all `*`), and varied credential states (`23h` / `<1h!` / `EXPIRED`) in the
split roster — LEFT is the mesh (fleet-wide), RIGHT is 'this node' (the `peer?`
policy answer without root; live links + traffic with sudo). It prints the full
table, so `pytest -s` shows what a dozen nodes looks like; without `-s` it's a
plain regression on the output shape.
"""
import datetime as dt
import types

from greasewood import cli
from greasewood.config import load_config
from greasewood.directory import Directory
from greasewood.keys import CAKeys, NodeKeys, derive_addr
from greasewood.wire import Credential, NodeRecord

_UTC = dt.timezone.utc


def _cred(ca, node, hostname, segs, *, hours=24, secs=None):
    now = dt.datetime.now(_UTC).replace(microsecond=0)
    exp = now + (dt.timedelta(seconds=secs) if secs is not None
                 else dt.timedelta(hours=hours))
    return Credential(
        id_pub=node.id_pub_bytes, wg_pub=node.wg_pub_bytes,
        addr=derive_addr(node.id_pub_bytes), hostname=hostname,
        caps=["role:" + s for s in segs], iat=now, exp=exp,
    ).sign(ca.ca_priv)


def _rec(node, cred, endpoints=()):
    return NodeRecord(id_pub=node.id_pub_bytes, seq=1, endpoints=list(endpoints),
                      cred=cred).sign(node.id_priv)


def test_nodes_full_directory(tmp_path, capsys):
    ca = CAKeys.generate()
    me = NodeKeys.load_or_generate(tmp_path)                 # this node = api1
    (tmp_path / "gw.toml").write_text(f"""[node]
hostname = "api1"
data_dir = "{tmp_path}"
role = "node"
caps = ["role:prod"]
[network]
interface = "gw-mesh"
seeds = []
[ca]
trusted_pubs = ["{ca.ca_pub_hex}"]
""")
    cfg = load_config(tmp_path / "gw.toml")

    directory = Directory()
    directory.put(_rec(me, _cred(ca, me, "api1", ["prod"])))          # ← self
    fleet = [
        ("anchor",       ["*"],           {}),                          # reach-all
        ("monitor",   ["*"],           {}),                          # shared services
        ("db1",       ["prod"],        {}),
        ("db2",       ["prod"],        {"secs": 22 * 60}),           # expiring
        ("web1",      ["prod", "web"], {}),                          # bridge (2 segments)
        ("web2",      ["web"],         {}),
        ("cache1",    ["mesh"],        {}),                          # default pool
        ("bastion",   ["mesh"],        {}),
        ("ci-runner", ["dev"],         {}),
        ("build1",    ["dev"],         {}),
        ("legacy",    ["prod"],        {"secs": -120}),              # EXPIRED
    ]
    for name, segs, kw in fleet:
        k = NodeKeys.generate()
        directory.put(_rec(k, _cred(ca, k, name, segs, **kw)))
    directory.save(cfg.dir_cache_path)

    print("\n$ gw status")
    cli.cmd_watch(types.SimpleNamespace(config=str(tmp_path / "gw.toml")))
    out = capsys.readouterr().out
    print(out)   # visible under `pytest -s`

    assert "role     : node" in out and "hostname : api1" in out     # self header
    assert "logs     : journalctl -eu greasewood@gw" in out           # how to read the daemon log
    assert "audit    : " in out and "audit.log" in out                # the ip/wg/nft command trail
    assert "│ self" in out                                            # self marked in the 'this node' column
    assert "name" in out and "roles" in out                       # left (mesh) columns
    assert "this node" in out and "peer?" in out                     # the split; non-root right side
    assert "run 'sudo gw watch'" in out                             # hint to see live links
    # Default view is the LIVE mesh only: 12 records, 'legacy' expired → hidden.
    assert "11 live · 1 expired hidden (gw watch --all to show)" in out
    assert "prod,web" in out                                          # multi-role bridge
    assert "*" in out                                                 # reach-all role
    assert "<1h!" in out and "legacy" not in out                      # db2 shown (live), legacy hidden
    assert "EXPIRED" not in out                                       # no expired cell in the default view

    # --all reveals the expired node (with its EXPIRED exp cell) and drops the count line.
    cli.cmd_watch(types.SimpleNamespace(config=str(tmp_path / "gw.toml"), all=True))
    out_all = capsys.readouterr().out
    assert "legacy" in out_all and "EXPIRED" in out_all
    assert "12 record(s) in local directory cache" in out_all


def test_nodes_by_role(tmp_path, capsys):
    ca = CAKeys.generate()
    me = NodeKeys.load_or_generate(tmp_path)
    (tmp_path / "gw.toml").write_text(f"""[node]
hostname = "api1"
data_dir = "{tmp_path}"
role = "node"
caps = ["role:prod"]
[network]
interface = "gw-mesh"
seeds = []
[ca]
trusted_pubs = ["{ca.ca_pub_hex}"]
""")
    cfg = load_config(tmp_path / "gw.toml")
    directory = Directory()
    directory.put(_rec(me, _cred(ca, me, "api1", ["prod"])))
    for name, segs in [
        ("anchor", ["*"]), ("monitor", ["*"]),          # reach-all
        ("db1", ["prod"]), ("web1", ["prod", "web"]),  # web1 is in two segments
        ("web2", ["web"]), ("ci-runner", ["dev"]), ("build1", ["dev"]),
    ]:
        k = NodeKeys.generate()
        directory.put(_rec(k, _cred(ca, k, name, segs)))
    directory.save(cfg.dir_cache_path)

    import types as _types
    cli.cmd_watch(_types.SimpleNamespace(config=str(tmp_path / "gw.toml"),
                                         by_role=True))
    out = capsys.readouterr().out
    print(out)   # visible under `pytest -s`

    for s in ("dev", "prod", "web"):                 # one table per named role
        assert f"role: {s}" in out
    assert "segment: *" not in out                   # * isn't a group, it's ubiquitous
    assert out.count("anchor.gw.internal") >= 3         # reach-all appears under every segment
    assert out.count("web1.gw.internal") >= 2        # a 2-segment node under both
    assert "8 record(s) in local directory cache" in out
