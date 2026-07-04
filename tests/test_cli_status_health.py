"""
The self/health block at the top of `gw status` — local facts about THIS node
(version, own credential, inbound posture, trust anchors, and directory-sync
freshness for a node). All local: no root, no network.
"""
import datetime as dt
import types

from greasewood import cli, sync
from greasewood.directory import Directory
from greasewood.keys import CAKeys, NodeKeys
from greasewood.wire import Credential, NodeRecord

_UTC = dt.timezone.utc


def _node(tmp_path, *, role="node", inbound="yes", trusted=None, cred_ttl_h=18,
          with_self=True):
    keys = NodeKeys.load_or_generate(tmp_path)
    ca = trusted or CAKeys.generate()
    (tmp_path / "gw.toml").write_text(f"""[node]
hostname = "db01"
data_dir = "{tmp_path}"
role = "{role}"
inbound = "{inbound}"
[network]
seeds = []
root_url = "http://[fd8d:e5c1:db1a:7::1]:51902"
mesh_domain = "gw.internal"
[ca]
trusted_pubs = ["{ca.ca_pub_hex}"]
""")
    if with_self:
        now = dt.datetime.now(_UTC).replace(microsecond=0)
        cred = Credential(id_pub=keys.id_pub_bytes, wg_pub=keys.wg_pub_bytes,
                          addr=keys.addr, hostname="db01", caps=["segment:prod"],
                          iat=now, exp=now + dt.timedelta(hours=cred_ttl_h)).sign(ca.ca_priv)
        d = Directory()
        d.put(NodeRecord(id_pub=keys.id_pub_bytes, seq=1, endpoints=[],
                         inbound=inbound, cred=cred).sign(keys.id_priv))
        d.save(tmp_path / "directory.json")
    return types.SimpleNamespace(config=str(tmp_path / "gw.toml"), by_segment=False)


def test_health_block_shows_self_facts(tmp_path, capsys):
    args = _node(tmp_path)
    sync.stamp_sync_path(tmp_path).write_text(
        dt.datetime.now(_UTC).replace(microsecond=0).isoformat())
    cli.cmd_status(args)
    out = capsys.readouterr().out
    assert "version  :" in out
    assert "cred     : expires" in out and "in 17h" in out     # 18h ttl, ~17h left
    assert "inbound  : yes" in out
    assert "trust    : 1 trusted CA · hub http://[fd8d" in out
    assert "sync     : directory synced 0s ago" in out


def test_expired_credential_is_flagged(tmp_path, capsys):
    args = _node(tmp_path, cred_ttl_h=-1)                       # already expired
    cli.cmd_status(args)
    assert "cred     : ⚠ EXPIRED" in capsys.readouterr().out


def test_never_synced_and_stale(tmp_path, capsys):
    args = _node(tmp_path)                                      # no sync stamp
    cli.cmd_status(args)
    assert "sync     : never" in capsys.readouterr().out

    old = dt.datetime.now(_UTC) - dt.timedelta(minutes=6)
    sync.stamp_sync_path(tmp_path).write_text(old.replace(microsecond=0).isoformat())
    cli.cmd_status(args)
    out = capsys.readouterr().out
    assert "sync     : ⚠" in out and "hub unreachable?" in out


def test_outbound_only_posture(tmp_path, capsys):
    args = _node(tmp_path, inbound="no")
    cli.cmd_status(args)
    assert "inbound  : no (outbound-only)" in capsys.readouterr().out


def test_hub_has_no_sync_line(tmp_path, capsys):
    # The hub is the source of truth — nothing to be 'stale' against.
    args = _node(tmp_path, role="hub")
    cli.cmd_status(args)
    out = capsys.readouterr().out
    assert "version  :" in out                                 # block still shows
    assert "sync     :" not in out


def test_sync_stamp_written_on_successful_pull(tmp_path, monkeypatch):
    # A successful pull records the timestamp read_last_sync surfaces.
    from greasewood import sync as syncmod
    assert syncmod.read_last_sync(tmp_path) is None
    loop = syncmod.SyncLoop(directory=Directory(),
                            get_seeds=lambda: ["http://seed"],
                            cache_path=tmp_path / "directory.json")
    monkeypatch.setattr(syncmod, "pull_directory", lambda url, timeout=10.0: ([], None, None))
    loop._pull_once()
    assert syncmod.read_last_sync(tmp_path) is not None


def test_syncloop_lifecycle_methods_exist(tmp_path):
    # Guard against the class body being broken by a mis-indented insert: the
    # daemon calls start()/stop(), which no unit test exercised before — so a
    # missing method sailed past 329 tests and only integration caught it.
    import time
    from greasewood import sync as syncmod
    loop = syncmod.SyncLoop(directory=Directory(), get_seeds=lambda: [],
                            cache_path=tmp_path / "directory.json")
    assert callable(loop.run) and callable(loop.start) and callable(loop.stop)
    t = loop.start()
    try:
        assert t.is_alive()
    finally:
        loop.stop()
        t.join(timeout=2)
