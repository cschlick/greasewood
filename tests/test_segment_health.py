"""
Segment connectivity in `gw watch --by-segment`: connected components + down
edges, computed from nodes' self-reported `reachable` sets (synced records, no
root). This is the "find the firewall partition" view.
"""
import datetime as dt
import types

from greasewood import cli, status
from greasewood.keys import CAKeys, NodeKeys, derive_addr
from greasewood.wire import Credential, NodeRecord

_UTC = dt.timezone.utc
CA = CAKeys.generate()


def _rec(name, endpoints, reachable=()):
    k = NodeKeys.generate()
    now = dt.datetime.now(_UTC).replace(microsecond=0)
    cred = Credential(id_pub=k.id_pub_bytes, wg_pub=k.wg_pub_bytes,
                      addr=derive_addr(k.id_pub_bytes), hostname=name,
                      caps=["role:db"], iat=now,
                      exp=now + dt.timedelta(hours=1)).sign(CA.ca_priv)
    return NodeRecord(id_pub=k.id_pub_bytes, seq=1, endpoints=list(endpoints),
                      cred=cred, reachable=list(reachable)).sign(k.id_priv)


def _mesh(*recs):
    """Set each record's reachable to all OTHER given records (fully connected)."""
    addrs = [r.cred.addr for r in recs]
    for r in recs:
        r.reachable[:] = sorted(a for a in addrs if a != r.cred.addr)
    return list(recs)


def test_fully_connected(capsys):
    a, b, c = _mesh(_rec("db01", ["1:51900"]), _rec("db02", ["2:51900"]),
                    _rec("db03", ["3:51900"]))
    status._print_segment_health([a, b, c], types.SimpleNamespace(mesh_domain="m.internal"))
    assert "✓ fully connected" in capsys.readouterr().out


def test_partition_and_isolated(capsys):
    a, b, c = _mesh(_rec("db01", ["1:51900"]), _rec("db02", ["2:51900"]),
                    _rec("db03", ["3:51900"]))
    d = _rec("web1", ["4:51900"])                      # nobody reaches d, d reaches nobody
    status._print_segment_health([a, b, c, d], types.SimpleNamespace(mesh_domain="m.internal"))
    out = capsys.readouterr().out
    assert "PARTITIONED — 2 islands" in out
    assert "web1.m.internal }   ← isolated" in out
    assert "3 expected links down" in out


def test_one_sided_report_counts_as_up(capsys):
    """An edge is up if EITHER end reports it (robust to one-sided staleness)."""
    a = _rec("db01", ["1:51900"])
    b = _rec("db02", ["2:51900"])
    a.reachable[:] = [b.cred.addr]                     # only a reports the edge
    b.reachable[:] = []                                # b hasn't (stale)
    status._print_segment_health([a, b], types.SimpleNamespace(mesh_domain="m.internal"))
    assert "✓ fully connected" in capsys.readouterr().out


def test_directional_hint_when_one_advertises(capsys):
    a = _rec("db01", ["203.0.113.1:51900"])           # dialable
    b = _rec("db02", [])                               # outbound-only → must dial a
    status._print_segment_health([a, b], types.SimpleNamespace(mesh_domain="m.internal"))
    out = capsys.readouterr().out
    assert "db02.m.internal can't reach db01.m.internal at 203.0.113.1:51900" in out


def test_two_outbound_only_not_flagged(capsys):
    """Two nodes that both advertise nothing CAN'T link — that's by design, not a
    fault, so it's not reported as a down edge."""
    a = _rec("db01", [])
    b = _rec("db02", [])
    status._print_segment_health([a, b], types.SimpleNamespace(mesh_domain="m.internal"))
    out = capsys.readouterr().out
    assert "down" not in out                           # no expected edge → not degraded
