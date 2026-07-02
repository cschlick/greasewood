"""
`gw nodes` output demonstration + regression, on a full (12-node) directory.

Builds a varied directory cache and runs the real `cmd_nodes`: mixed segments
(the default `mesh` pool, `prod`/`dev`/`web`, a multi-segment *bridge*, the
reach-all `*`), the `← self` marker, and `ok`/`expiring`/`EXPIRED` states. It
prints the full table, so `pytest -s tests/test_nodes_demo.py` shows what a dozen
nodes looks like; without `-s` it's a plain regression on the output shape.
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
        caps=["segment:" + s for s in segs], iat=now, exp=exp,
    ).sign(ca.ca_priv)


def _rec(node, cred):
    return NodeRecord(id_pub=node.id_pub_bytes, seq=1, endpoints=[],
                      inbound="yes", cred=cred).sign(node.id_priv)


def test_nodes_full_directory(tmp_path, capsys):
    ca = CAKeys.generate()
    me = NodeKeys.load_or_generate(tmp_path)                 # this node = api1
    (tmp_path / "gw.toml").write_text(f"""[node]
hostname = "api1"
data_dir = "{tmp_path}"
role = "node"
caps = ["segment:prod"]
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
        ("hub",       ["*"],           {}),                          # reach-all
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

    print("\n$ gw nodes")
    cli.cmd_nodes(types.SimpleNamespace(config=str(tmp_path / "gw.toml")))
    out = capsys.readouterr().out
    print(out)   # visible under `pytest -s`

    assert "role     : node" in out and "hostname : api1" in out     # self header
    assert "← self" in out                                            # self row marked
    assert "name" in out and "segments" in out                       # column header
    assert "12 record(s) in local directory cache" in out            # self + 11
    assert "prod,web" in out                                          # multi-segment bridge
    assert "*" in out                                                 # reach-all segment
    assert "expiring" in out and "EXPIRED" in out                     # varied states
