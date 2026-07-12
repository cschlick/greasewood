"""
`gw watch --json`: a stable, versioned machine snapshot so monitors/jq never
scrape the human view. Validates the schema shape + the derived fields (roles,
expiry, the policy peering verdict from this node) on a small directory.
"""
import datetime as dt
import json
import types

import pytest

from greasewood import status
from greasewood.config import load_config
from greasewood.directory import Directory
from greasewood.keys import CAKeys, NodeKeys, derive_addr
from greasewood.wire import Credential, NodeRecord

_UTC = dt.timezone.utc


def _cred(ca, node, hostname, roles, *, secs=24 * 3600):
    now = dt.datetime.now(_UTC).replace(microsecond=0)
    return Credential(
        id_pub=node.id_pub_bytes, wg_pub=node.wg_pub_bytes,
        addr=derive_addr(node.id_pub_bytes), hostname=hostname,
        caps=["role:" + r for r in roles], iat=now,
        exp=now + dt.timedelta(seconds=secs),
    ).sign(ca.ca_priv)


def _rec(node, cred, endpoints=()):
    return NodeRecord(id_pub=node.id_pub_bytes, seq=1, endpoints=list(endpoints),
                      cred=cred).sign(node.id_priv)


def _setup(tmp_path):
    ca = CAKeys.generate()
    me = NodeKeys.load_or_generate(tmp_path)                    # this node = web1
    (tmp_path / "gw.toml").write_text(f"""[node]
hostname = "web1"
data_dir = "{tmp_path}"
role = "node"
caps = ["role:web"]
[network]
interface = "gw-mesh"
mesh_domain = "gw.internal"
seeds = []
[ca]
trusted_pubs = ["{ca.ca_pub_hex}"]
""")
    cfg = load_config(tmp_path / "gw.toml")

    directory = Directory()
    directory.put(_rec(me, _cred(ca, me, "web1", ["web"]),
                       endpoints=["[203.0.113.7]:51900"]))       # self
    api = NodeKeys.generate()
    directory.put(_rec(api, _cred(ca, api, "api1", ["api"])))
    dead = NodeKeys.generate()
    directory.put(_rec(dead, _cred(ca, dead, "old1", ["web"], secs=-120)))  # expired
    directory.save(cfg.dir_cache_path)
    return cfg


def _run_json(cfg):
    """Invoke cmd_watch in --json mode and parse its stdout."""
    import io
    import contextlib
    args = types.SimpleNamespace(config=str(cfg.dir_cache_path.parent / "gw.toml"),
                                 json=True, snapshot=True)
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = status.cmd_watch(args)
    assert rc == 0
    return json.loads(buf.getvalue())


def test_schema_and_top_level(tmp_path):
    doc = _run_json(_setup(tmp_path))
    assert doc["schema"] == "gw.watch/v1"
    assert doc["generated_at"].endswith("Z")
    assert doc["self"]["hostname"] == "web1"
    assert doc["self"]["roles"] == ["web"]
    assert doc["self"]["is_anchor"] is False
    assert doc["mesh"]["domain"] == "gw.internal"
    assert doc["mesh"]["interface"] == "gw-mesh"
    assert doc["counts"] == {"total": 3, "live": 2, "expired": 1}


def test_node_entries_and_expiry(tmp_path):
    doc = _run_json(_setup(tmp_path))
    by_name = {n["hostname"]: n for n in doc["nodes"]}
    assert set(by_name) == {"web1", "api1", "old1"}

    assert by_name["web1"]["is_self"] is True
    assert by_name["web1"]["roles"] == ["web"]
    assert by_name["web1"]["endpoints"] == ["[203.0.113.7]:51900"]
    assert by_name["web1"]["expired"] is False
    assert by_name["web1"]["ttl_remaining_s"] > 0

    assert by_name["old1"]["expired"] is True
    assert by_name["old1"]["ttl_remaining_s"] < 0

    # every entry carries the required keys and is JSON-clean
    for n in doc["nodes"]:
        assert {"id", "hostname", "addr", "roles", "caps", "endpoints", "iat",
                "exp", "expired", "ttl_remaining_s", "is_self", "peer_expected",
                "reachable"} <= set(n)


def test_peer_expected_tracks_policy(tmp_path):
    """With no policy the mesh is flat → every peer is expected. Under a signed
    `web -> api` table, this web node expects api but not the expired web peer."""
    cfg = _setup(tmp_path)

    # no policy yet → flat: api1 (and old1) are peer_expected from web1
    doc = _run_json(cfg)
    by = {n["hostname"]: n for n in doc["nodes"]}
    assert by["api1"]["peer_expected"] is True

    # write a web->api policy.json and re-read (snapshot reads grants directly;
    # the signature isn't checked on this local read path).
    from greasewood import policy as polmod
    from greasewood.wire import GrantTable
    grants = [{"from": ["web"], "to": ["api"], "ports": ["tcp/8000"]}]
    tbl = GrantTable(seq=2, grants=grants)
    (cfg.data_dir / polmod.POLICY_BASENAME).write_text(json.dumps(tbl.to_dict()))

    doc = _run_json(cfg)
    by = {n["hostname"]: n for n in doc["nodes"]}
    assert doc["policy"] == {"seq": 2, "grants": 1}
    assert by["api1"]["peer_expected"] is True          # web -> api
    assert by["old1"]["peer_expected"] is False         # web -> web not granted


def test_static_roster_is_rendered_from_the_snapshot(tmp_path, monkeypatch):
    """The dogfood: `gw watch --snapshot` (text) renders its roster from the SAME
    _watch_snapshot_dict that `--json` emits — so a per-node column can't exist
    that the JSON contract doesn't carry. Spy that the builder is on the path."""
    import io, contextlib, types
    cfg = _setup(tmp_path)
    calls = []
    orig = status._watch_snapshot_dict
    monkeypatch.setattr(status, "_watch_snapshot_dict",
                        lambda *a, **k: (calls.append(1), orig(*a, **k))[1])
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = status.cmd_watch(types.SimpleNamespace(
            config=str(cfg.dir_cache_path.parent / "gw.toml")))
    out = buf.getvalue()
    assert rc == 0
    assert calls, "static roster must be built from _watch_snapshot_dict (the --json model)"
    assert "web1" in out and "api1" in out          # the model's nodes reached the text view


def test_text_peer_column_tracks_json_peer_expected(tmp_path):
    """Couple the two views on real data: under a web->api policy, the JSON marks
    api1 peer_expected=True and old1 (web) False from this web node — and the text
    roster's peer? column shows 'yes' / 'no' to match."""
    import io, contextlib, types, json as _json
    from greasewood import policy as polmod
    from greasewood.wire import GrantTable
    cfg = _setup(tmp_path)
    (cfg.data_dir / polmod.POLICY_BASENAME).write_text(_json.dumps(GrantTable(
        seq=2, grants=[{"from": ["web"], "to": ["api"], "ports": ["tcp/8000"]}]).to_dict()))

    by = {n["hostname"]: n for n in _run_json(cfg)["nodes"]}
    assert by["api1"]["peer_expected"] is True and by["old1"]["peer_expected"] is False

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        status.cmd_watch(types.SimpleNamespace(
            config=str(cfg.dir_cache_path.parent / "gw.toml"), all=True))
    rows = {ln.split(".")[0]: ln for ln in buf.getvalue().splitlines()
            if ln.startswith(("api1.", "old1."))}
    assert rows["api1"].rstrip().endswith("yes")     # peer? column ← peer_expected True
    assert rows["old1"].rstrip().endswith("no")      # peer? column ← peer_expected False
