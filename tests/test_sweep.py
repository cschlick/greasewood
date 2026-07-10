"""
StaleSweep — the anchor's periodic GC tick: it drops abandoned nodes from the
CA (authorization) and prunes them from the served directory (visibility), then
persists the directory so peers converge.
"""
import datetime as dt

from greasewood.ca import CA
from greasewood.directory import Directory, DROP_GRACE
from greasewood.keys import CAKeys, NodeKeys, derive_addr
from greasewood.sweep import StaleSweep
from greasewood.wire import Credential, NodeRecord

_UTC = dt.timezone.utc


def _rec(ca_keys, k, name, exp):
    iat = exp - dt.timedelta(hours=24)
    cred = Credential(id_pub=k.id_pub_bytes, wg_pub=k.wg_pub_bytes,
                      addr=derive_addr(k.id_pub_bytes), hostname=name,
                      caps=["role:mesh"], iat=iat, exp=exp).sign(ca_keys.ca_priv)
    return NodeRecord(id_pub=k.id_pub_bytes, seq=1, endpoints=[],
                      cred=cred).sign(k.id_priv)


def test_sweep_tick_drops_from_ca_and_directory(tmp_path):
    ca_keys = CAKeys.generate()
    ca = CA(ca_keys, tmp_path, credential_ttl=dt.timedelta(hours=1))
    now = dt.datetime.now(_UTC).replace(microsecond=0)

    # A live node (issued now) and an abandoned one whose registry exp is far
    # in the past — issue both, then backdate the abandoned one's registry exp.
    live = NodeKeys.generate()
    dead = NodeKeys.generate()
    ca.issue(live.id_pub_bytes, live.wg_pub_bytes, "live", ["mesh"])
    dead_cred_exp = now - (DROP_GRACE + dt.timedelta(days=2))
    ca.issue(dead.id_pub_bytes, dead.wg_pub_bytes, "dead", ["mesh"])
    import json
    p = tmp_path / "nodes" / f"{dead.id_pub_bytes.hex()}.json"
    rec = json.loads(p.read_text())
    rec["exp"] = dead_cred_exp.isoformat()
    p.write_text(json.dumps(rec))

    directory = Directory()
    directory.put(_rec(ca_keys, live, "live", now + dt.timedelta(hours=12)))
    directory.put(_rec(ca_keys, dead, "dead", dead_cred_exp))     # past-grace record
    cache = tmp_path / "directory.json"

    StaleSweep(ca, directory, drop_grace=DROP_GRACE, cache_path=cache)._tick()

    # CA forgot the abandoned node; kept the live one.
    assert ca.node_info(dead.id_pub_bytes) is None
    assert ca.node_info(live.id_pub_bytes) is not None
    # Directory pruned it and persisted the result.
    assert {r.cred.hostname for r in directory.all()} == {"live"}
    assert cache.exists()
    reloaded = Directory.load(cache)
    assert {r.cred.hostname for r in reloaded.all()} == {"live"}


def test_sweep_tick_noop_when_nothing_stale(tmp_path):
    ca_keys = CAKeys.generate()
    ca = CA(ca_keys, tmp_path, credential_ttl=dt.timedelta(hours=1))
    k = NodeKeys.generate()
    ca.issue(k.id_pub_bytes, k.wg_pub_bytes, "n", ["mesh"])
    directory = Directory()
    now = dt.datetime.now(_UTC).replace(microsecond=0)
    directory.put(_rec(ca_keys, k, "n", now + dt.timedelta(hours=12)))
    cache = tmp_path / "directory.json"
    StaleSweep(ca, directory, drop_grace=DROP_GRACE, cache_path=cache)._tick()
    assert cache.exists() is False                           # nothing changed → no write
    assert ca.node_info(k.id_pub_bytes) is not None
