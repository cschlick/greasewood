"""
`gw diagnose` output demonstration + regression.

Degraded states are hard to reproduce on a live mesh, so this builds a directory
cache of crafted peer records plus a stubbed live-WireGuard state and runs the
real `cmd_diagnose`, asserting every classification it can emit:

    LINKED · installed/no-handshake · verified-but-not-installed ·
    REJECTED (untrusted CA / expired / revoked) · policy-denied ·
    both-outbound-only · the reachability advisory (confirmed / outbound-only)

It also prints the full output, so `pytest -s tests/test_diagnose_scenarios.py`
shows exactly what an operator would see — a way to eyeball diagnose without
having to break a real system.
"""
import datetime as dt
import json
import os
import time
import types

from greasewood import cli, wg
from greasewood.directory import Directory
from greasewood.keys import CAKeys, NodeKeys, derive_addr
from greasewood.wire import Credential, NodeRecord

_UTC = dt.timezone.utc


def _cred(node, ca, hostname, caps=("segment:mesh",), ttl=3600):
    now = dt.datetime.now(_UTC).replace(microsecond=0)
    return Credential(
        id_pub=node.id_pub_bytes, wg_pub=node.wg_pub_bytes,
        addr=derive_addr(node.id_pub_bytes), hostname=hostname, caps=list(caps),
        iat=now, exp=now + dt.timedelta(seconds=ttl),
    ).sign(ca.ca_priv)


def _rec(node, cred, endpoints=(), inbound="yes"):
    return NodeRecord(id_pub=node.id_pub_bytes, seq=1, endpoints=list(endpoints),
                      inbound=inbound, cred=cred).sign(node.id_priv)


def _live(node, endpoint="", handshake_ago=None):
    hs = 0 if handshake_ago is None else int(time.time()) - handshake_ago
    return wg.LivePeer(wg_pub_b64=node.wg_pub_b64, endpoint=endpoint,
                       allowed_ips=derive_addr(node.id_pub_bytes) + "/128",
                       latest_handshake=hs, rx_bytes=1, tx_bytes=1)


def _diagnose(tmp_path, monkeypatch, *, title, inbound, trusted, records,
              live_peers, revoked=()):
    """Set up a fake node + directory cache, stub live wg + root, run diagnose.
    Everything printed between the banner and the next banner is the real,
    verbatim `sudo gw diagnose` output for that node."""
    NodeKeys.load_or_generate(tmp_path)                        # our own identity
    (tmp_path / "gw.toml").write_text(f"""[node]
hostname = "self"
data_dir = "{tmp_path}"
role = "node"
inbound = "{inbound}"
caps = ["segment:mesh"]
[network]
interface = "gw-mesh"
seeds = []
root_url = "http://[fd8d:e5c1:db1a:7::1]:51902"
[ca]
trusted_pubs = ["{trusted.ca_pub_hex}"]
""")
    if revoked:
        (tmp_path / "revoked.json").write_text(json.dumps({"revoked": list(revoked)}))

    from greasewood.config import load_config
    cfg = load_config(tmp_path / "gw.toml")
    directory = Directory()
    for r in records:
        directory.put(r)
    directory.save(cfg.dir_cache_path)

    monkeypatch.setattr(os, "geteuid", lambda: 0)             # pretend root
    monkeypatch.setattr("greasewood.wg.get_peers", lambda iface: live_peers)

    print("\n" + "━" * 78)
    print(f"┃ {title}")
    print(f"┃ $ sudo gw diagnose")
    print("━" * 78 + "\n(everything below, to the next banner, is verbatim `gw diagnose` output)\n")
    cli.cmd_diagnose(types.SimpleNamespace(config=str(tmp_path / "gw.toml"),
                                           hostname=None))
    print("\n" + "─" * 78)


def test_diagnose_mixed_fleet(tmp_path, monkeypatch, capsys):
    trusted, evil = CAKeys.generate(), CAKeys.generate()
    db, laptop, web, cache = (NodeKeys.generate() for _ in range(4))
    oldhub, stale, banned, prod1 = (NodeKeys.generate() for _ in range(4))

    records = [
        _rec(db,     _cred(db, trusted, "db"),         endpoints=["203.0.113.7:51900"]),   # v4 underlay
        _rec(laptop, _cred(laptop, trusted, "laptop"), inbound="no"),                        # outbound-only
        _rec(web,    _cred(web, trusted, "web"),        endpoints=["[2001:db8::9]:51900"]),
        _rec(cache,  _cred(cache, trusted, "cache"),    endpoints=["198.51.100.4:51900"]),
        _rec(oldhub, _cred(oldhub, evil, "oldhub"),     endpoints=["203.0.113.9:51900"]),    # untrusted CA
        _rec(stale,  _cred(stale, trusted, "stale", ttl=-600), endpoints=["203.0.113.2:51900"]),  # expired
        _rec(banned, _cred(banned, trusted, "banned"),  endpoints=["203.0.113.3:51900"]),    # revoked
        _rec(prod1,  _cred(prod1, trusted, "prod1", caps=("segment:prod",)),
             endpoints=["203.0.113.5:51900"]),                                                # other segment
    ]
    live_peers = {
        db.wg_pub_b64:     _live(db, "203.0.113.7:51900", handshake_ago=12),        # LINKED (v4)
        laptop.wg_pub_b64: _live(laptop, "198.51.100.50:40012", handshake_ago=30),  # LINKED, dialed in
        web.wg_pub_b64:    _live(web, "[2001:db8::9]:51900"),                        # installed, no handshake
        # cache absent → "verified but NOT installed"
    }
    _diagnose(tmp_path, monkeypatch,
              title="node 'self' — inbound hub, mixed fleet of 8 peers",
              inbound="yes", trusted=trusted,
              records=records, live_peers=live_peers,
              revoked=[banned.id_pub_bytes.hex()])

    out = capsys.readouterr().out
    print(out)   # visible under `pytest -s`

    assert "db" in out and "LINKED" in out
    assert "v4=203.0.113.7" in out and "v6=2001:db8::9" in out         # per-node underlay
    assert "dialing [2001:db8::9]:51900 but no handshake" in out       # firewall hint
    assert "verified but NOT installed" in out                         # cache
    assert "not from a trusted CA" in out                             # oldhub
    assert "credential EXPIRED" in out                               # stale
    assert "node is REVOKED" in out                                  # banned
    assert "policy denies link" in out                              # prod1
    assert "2 linked, 2 configured/no-handshake, 3 rejected, 1 policy-denied" in out
    assert "inbound=yes CONFIRMED" in out                           # laptop dialed in


def test_diagnose_outbound_only(tmp_path, monkeypatch, capsys):
    trusted = CAKeys.generate()
    peer = NodeKeys.generate()
    records = [_rec(peer, _cred(peer, trusted, "peer"), inbound="no")]  # both outbound-only
    live_peers = {peer.wg_pub_b64: _live(peer)}
    _diagnose(tmp_path, monkeypatch,
              title="node 'self' — outbound-only (inbound=no)",
              inbound="no", trusted=trusted,
              records=records, live_peers=live_peers)

    out = capsys.readouterr().out
    print(out)   # visible under `pytest -s`

    assert "both sides are outbound-only" in out
    assert "reachability: inbound=no (outbound-only)" in out
