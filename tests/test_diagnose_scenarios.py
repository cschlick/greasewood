"""
`gw diagnose` pairwise output demonstration + regression.

Builds a directory cache of crafted records plus a stubbed live-WireGuard state
and runs the real `cmd_diagnose`, asserting the pairwise model:

    the comparison table (per-node underlay families, credential, firewall) ·
    firewall INFERRED open from an observed handshake · a LINKED verdict ·
    no-handshake block localization (host-open → suspect upstream router/NAT) ·
    no-dialable-direction (both outbound-only).

`pytest -s tests/test_diagnose_scenarios.py` prints the verbatim output — a way
to eyeball diagnose without breaking a real system.
"""
import datetime as dt
import os
import time
import types

from greasewood import cli, status, wg
from greasewood.directory import Directory
from greasewood.keys import CAKeys, NodeKeys, derive_addr
from greasewood.wire import Credential, NodeRecord

_UTC = dt.timezone.utc
CA = CAKeys.generate()


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


def _run(tmp_path, monkeypatch, *, title, nodes, records, live_peers,
         inbound="yes", endpoints=(), self_fw="OPEN"):
    NodeKeys.load_or_generate(tmp_path)
    eps = f"\nendpoints = {list(endpoints)}" if endpoints else ""
    (tmp_path / "gw.toml").write_text(f"""[node]
hostname = "self"
data_dir = "{tmp_path}"
role = "node"
inbound = "{inbound}"
caps = ["segment:mesh"]{eps}
[network]
interface = "gw-mesh"
seeds = []
root_url = ""
[ca]
trusted_pubs = ["{CA.ca_pub_hex}"]
""")
    from greasewood.config import load_config
    cfg = load_config(tmp_path / "gw.toml")
    directory = Directory()
    for r in records:
        directory.put(r)
    directory.save(cfg.dir_cache_path)

    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr("greasewood.wg.get_peers", lambda iface: live_peers)
    monkeypatch.setattr(status, "_self_firewall_port", lambda port: self_fw)

    print("\n" + "━" * 78)
    print(f"┃ {title}\n┃ $ sudo gw diagnose {' '.join(nodes)}")
    print("━" * 78)
    cli.cmd_diagnose(types.SimpleNamespace(config=str(tmp_path / "gw.toml"),
                                           nodes=list(nodes)))


def test_diagnose_linked_pair_infers_firewall(tmp_path, monkeypatch, capsys):
    """A live handshake to db proves its inbound path — db's firewall cell reads
    'OPEN (inferred)' and the verdict is LINKED."""
    db = NodeKeys.generate()
    _run(tmp_path, monkeypatch, title="self ↔ db (linked, v4 underlay)",
         nodes=["db"],
         records=[_rec(db, _cred(db, CA, "db"), endpoints=["203.0.113.7:51900"])],
         live_peers={db.wg_pub_b64: _live(db, "203.0.113.7:51900", handshake_ago=8)})
    out = capsys.readouterr().out
    print(out)
    assert "underlay v4" in out and "203.0.113.7" in out
    assert "OPEN (inferred: handshake)" in out       # db's firewall inferred
    assert "● LINKED" in out


def test_diagnose_no_handshake_localizes_to_upstream(tmp_path, monkeypatch, capsys):
    """self is inbound with an endpoint and its host firewall is OPEN, but the
    peer has no handshake → point at an upstream router/NAT, not this host."""
    gamma = NodeKeys.generate()
    _run(tmp_path, monkeypatch, title="self ↔ gamma (no handshake)",
         nodes=["gamma"], inbound="yes", endpoints=["[2001:db8::1]:51900"],
         records=[_rec(gamma, _cred(gamma, CA, "gamma"),
                       endpoints=["203.0.113.9:51900"])],
         live_peers={}, self_fw="OPEN")
    out = capsys.readouterr().out
    print(out)
    assert "no handshake" in out
    assert "UPSTREAM router/NAT" in out              # the flagship deduction
    assert "isn't answering" in out                  # directional dial hint


def test_diagnose_self_firewall_closed(tmp_path, monkeypatch, capsys):
    """If this host's own firewall blocks the port, say THAT (not upstream)."""
    gamma = NodeKeys.generate()
    _run(tmp_path, monkeypatch, title="self ↔ gamma (our fw closed)",
         nodes=["gamma"], inbound="yes", endpoints=["[2001:db8::1]:51900"],
         records=[_rec(gamma, _cred(gamma, CA, "gamma"),
                       endpoints=["203.0.113.9:51900"])],
         live_peers={}, self_fw="CLOSED — blocked!")
    out = capsys.readouterr().out
    print(out)
    assert "OPEN it" in out and "UPSTREAM" not in out


def test_diagnose_outbound_only_no_direction(tmp_path, monkeypatch, capsys):
    """Both sides outbound-only → no dialable direction, link can't form."""
    peer = NodeKeys.generate()
    _run(tmp_path, monkeypatch, title="self(outbound-only) ↔ peer(outbound-only)",
         nodes=["peer"], inbound="no",
         records=[_rec(peer, _cred(peer, CA, "peer"), inbound="no")],
         live_peers={})
    out = capsys.readouterr().out
    print(out)
    assert "no dialable direction" in out
    assert "outbound-only" in out
