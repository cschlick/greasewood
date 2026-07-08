"""
The self/health block at the top of `gw status` — local facts about THIS node
(version, own credential, inbound posture, trust anchors, and directory-sync
freshness for a node). All local: no root, no network.
"""
import datetime as dt
import types

from greasewood import cli, sync, status
from greasewood.directory import Directory
from greasewood.keys import CAKeys, NodeKeys
from greasewood.wire import Credential, NodeRecord

_UTC = dt.timezone.utc


def _node(tmp_path, *, role="node", endpoints=None, trusted=None, cred_ttl_h=18,
          with_self=True):
    keys = NodeKeys.load_or_generate(tmp_path)
    ca = trusted or CAKeys.generate()
    eps = f"\nendpoints = {endpoints}" if endpoints else ""
    (tmp_path / "gw.toml").write_text(f"""[node]
hostname = "db01"
data_dir = "{tmp_path}"
role = "{role}"{eps}
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
        d.put(NodeRecord(id_pub=keys.id_pub_bytes, seq=1,
                         endpoints=list(endpoints or []), cred=cred).sign(keys.id_priv))
        d.save(tmp_path / "directory.json")
    return types.SimpleNamespace(config=str(tmp_path / "gw.toml"), by_segment=False)


def test_health_block_shows_self_facts(tmp_path, capsys):
    args = _node(tmp_path, endpoints=["[2001:db8::1]:51900"])
    sync.stamp_sync_path(tmp_path).write_text(
        dt.datetime.now(_UTC).replace(microsecond=0).isoformat())
    cli.cmd_watch(args)
    out = capsys.readouterr().out
    assert "version  :" in out
    assert "cred     : expires" in out and "in 17h" in out     # 18h ttl, ~17h left
    assert "reach    : advertises an endpoint" in out
    assert "trust    : 1 trusted CA · anchor http://[fd8d" in out
    assert "synced   : directory synced 0s ago" in out


def test_expired_credential_is_flagged(tmp_path, capsys):
    args = _node(tmp_path, cred_ttl_h=-1)                       # already expired
    cli.cmd_watch(args)
    assert "cred     : ⚠ EXPIRED" in capsys.readouterr().out


def test_never_synced_and_stale(tmp_path, capsys):
    args = _node(tmp_path)                                      # no sync stamp
    cli.cmd_watch(args)
    assert "synced   : never" in capsys.readouterr().out

    old = dt.datetime.now(_UTC) - dt.timedelta(minutes=6)
    sync.stamp_sync_path(tmp_path).write_text(old.replace(microsecond=0).isoformat())
    cli.cmd_watch(args)
    out = capsys.readouterr().out
    assert "synced   : ⚠" in out and "anchor unreachable?" in out


def test_outbound_only_posture(tmp_path, capsys):
    # A node that advertises no endpoint is naturally outbound-only.
    args = _node(tmp_path, endpoints=None)
    cli.cmd_watch(args)
    assert "reach    : no endpoint (outbound-only" in capsys.readouterr().out


def test_anchor_has_no_sync_line(tmp_path, capsys):
    # The anchor is the source of truth — nothing to be 'stale' against.
    args = _node(tmp_path, role="anchor")
    cli.cmd_watch(args)
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
    monkeypatch.setattr(syncmod, "pull_directory", lambda url, timeout=10.0: ([], None, None, None, None))
    loop._pull_once()
    assert syncmod.read_last_sync(tmp_path) is not None


def test_split_roster_live_links(tmp_path, monkeypatch, capsys):
    """With root + live WireGuard state, the roster's right side shows THIS
    node's data links: linked peers with traffic, a non-peer (the policy
    grants no tunnel), and a peer with no handshake."""
    import base64
    import os
    import time
    from greasewood import wg
    keys = NodeKeys.load_or_generate(tmp_path)
    ca = CAKeys.generate()
    (tmp_path / "gw.toml").write_text(f"""[node]
hostname = "me"
data_dir = "{tmp_path}"
role = "node"
caps = ["role:prod"]
[network]
interface = "gw-mesh"
seeds = []
[ca]
trusted_pubs = ["{ca.ca_pub_hex}"]
""")
    now = dt.datetime.now(_UTC).replace(microsecond=0)

    def rec(k, name, segs):
        cred = Credential(id_pub=k.id_pub_bytes, wg_pub=k.wg_pub_bytes, addr=k.addr,
                          hostname=name, caps=[f"role:{s}" for s in segs],
                          iat=now, exp=now + dt.timedelta(hours=18)).sign(ca.ca_priv)
        return NodeRecord(id_pub=k.id_pub_bytes, seq=1, endpoints=[], inbound="yes",
                          cred=cred).sign(k.id_priv)

    linked, other, silent = NodeKeys.generate(), NodeKeys.generate(), NodeKeys.generate()
    d = Directory()
    d.put(rec(keys, "me", ["prod"]))
    d.put(rec(linked, "db01", ["prod"]))          # granted prod↔prod → peer, linked
    d.put(rec(other, "laptop", ["dev"]))          # no grant covers dev → not a peer
    d.put(rec(silent, "old", ["prod"]))           # peer but no handshake
    d.save(tmp_path / "directory.json")
    # A policy that grants only prod↔prod — what makes laptop a non-peer under
    # the derived topology (with no policy, everyone would peer).
    import json as _json
    (tmp_path / "policy.json").write_text(_json.dumps({
        "seq": 1, "ca_sig": "",
        "grants": [{"from": ["prod"], "to": ["prod"], "ports": ["*"]}]}))

    nowe = int(time.time())
    live = {
        base64.b64encode(linked.wg_pub_bytes).decode():
            wg.LivePeer(wg_pub_b64="x", endpoint="", allowed_ips="",
                        latest_handshake=nowe - 12, rx_bytes=4_200_000, tx_bytes=1_100_000),
        base64.b64encode(silent.wg_pub_bytes).decode():
            wg.LivePeer(wg_pub_b64="x", endpoint="", allowed_ips="",
                        latest_handshake=0, rx_bytes=0, tx_bytes=0),
    }
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr("greasewood.wg.get_peers", lambda iface: live)

    cli.cmd_watch(types.SimpleNamespace(config=str(tmp_path / "gw.toml"), by_segment=False))
    out = capsys.readouterr().out
    assert "link" in out and "traffic" in out             # live headers, not 'peer?'
    assert "● up, 12s ago" in out and "↓4.0M ↑1.0M" in out  # linked peer + traffic
    assert "— not a peer" in out                          # laptop, different segment
    assert "○ no handshake" in out                        # old, peer but silent
    assert "(self)" in out                                # self row


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


def test_roster_live_mode_columns(tmp_path):
    """Live roster: right side is link · per-second rate · latency; the latency
    cell shows the async value (or '…' until a peer's ping returns)."""
    import base64
    import time
    import types
    from greasewood import cli, wg
    keys = NodeKeys.generate()
    ca = CAKeys.generate()
    linked, pending = NodeKeys.generate(), NodeKeys.generate()
    now = dt.datetime.now(_UTC).replace(microsecond=0)

    def rec(k, name):
        cred = Credential(id_pub=k.id_pub_bytes, wg_pub=k.wg_pub_bytes, addr=k.addr,
                          hostname=name, caps=["segment:mesh"], iat=now,
                          exp=now + dt.timedelta(hours=18)).sign(ca.ca_priv)
        return NodeRecord(id_pub=k.id_pub_bytes, seq=1, endpoints=[], inbound="yes",
                          cred=cred).sign(k.id_priv)
    records = [rec(keys, "me"), rec(linked, "db01"), rec(pending, "web1")]
    cfg = types.SimpleNamespace(caps=["segment:mesh"], mesh_domain="gw.internal")
    nowe = int(time.time())
    live = {
        base64.b64encode(linked.wg_pub_bytes).decode():
            wg.LivePeer(wg_pub_b64="x", endpoint="", allowed_ips="",
                        latest_handshake=nowe - 5, rx_bytes=0, tx_bytes=0),
        base64.b64encode(pending.wg_pub_bytes).decode():
            wg.LivePeer(wg_pub_b64="y", endpoint="", allowed_ips="",
                        latest_handshake=nowe - 4, rx_bytes=0, tx_bytes=0),
    }
    latency = {linked.addr: "12ms", keys.addr: "0ms"}     # web1's ping not back yet
    rates = {linked.addr: "↓1.2M/s ↑300K/s"}
    lines = status._roster_lines(records, cfg, dt.datetime.now(_UTC),
                              keys.id_pub_hex, live, True,
                              latency=latency, rates=rates)
    joined = "\n".join(lines)
    assert "link" in joined and "rate" in joined and "latency" in joined
    # the self row carries a latency too (ping to own addr) so broken/no-latency
    # rows stand out
    self_row = next(ln for ln in lines if "(self)" in ln)
    assert "0ms" in self_row
    assert "12ms" in joined and "↓1.2M/s ↑300K/s" in joined
    assert "…" in joined                                  # pending ping placeholder


def test_ping_rtt_parses_and_times_out(monkeypatch):
    import subprocess
    from greasewood import cli

    def ok(*a, **k):
        return subprocess.CompletedProcess(a[0], 0, "64 bytes ... time=13.4 ms\n", "")
    monkeypatch.setattr(subprocess, "run", ok)
    assert status._ping_rtt("fd8d::1") == "13ms"

    def down(*a, **k):
        return subprocess.CompletedProcess(a[0], 1, "", "")
    monkeypatch.setattr(subprocess, "run", down)
    assert status._ping_rtt("fd8d::2") == "—"


def test_latency_prober_updates_results(monkeypatch):
    import time
    from greasewood import cli
    monkeypatch.setattr(status, "_ping_rtt", lambda a: "7ms")
    p = status._LatencyProber()
    p.set_targets(["fd8d::1", "fd8d::2"])
    p.start()
    for _ in range(20):
        if p.results.get("fd8d::1") and p.results.get("fd8d::2"):
            break
        time.sleep(0.05)
    p.stop()
    assert p.results["fd8d::1"] == "7ms" and p.results["fd8d::2"] == "7ms"


def test_watch_live_requires_root_and_tty(monkeypatch):
    import pytest
    import types
    from greasewood import cli
    monkeypatch.setattr("sys.stdout.isatty", lambda: True)
    monkeypatch.setattr(cli.os, "geteuid", lambda: 1000)
    with pytest.raises(SystemExit) as e:
        status._watch_live(types.SimpleNamespace(), "abc", "fd8d::1")
    assert "needs root" in str(e.value)
