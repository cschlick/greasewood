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


# ---------------------------------------------------------------------------
# gw watch: the enforcement (greasewood nftables table) summary block
# ---------------------------------------------------------------------------

def test_enforcement_lines_open_default(monkeypatch):
    import types
    from greasewood import status
    monkeypatch.setattr(status.os, "geteuid", lambda: 1000)   # non-root: skip nft read
    cfg = types.SimpleNamespace(enforce_ports=True, mesh_domain="pm.internal",
                                caps=["role:api"])
    out = "\n".join(status._enforcement_lines(cfg, None))
    assert "port enforcement on" in out and "greasewood_pm" in out
    assert "mesh open" in out and "* → * : *" in out


def test_enforcement_lines_tightened_shows_inbound_scopes(monkeypatch):
    import types
    from greasewood import status
    monkeypatch.setattr(status.os, "geteuid", lambda: 1000)
    cfg = types.SimpleNamespace(enforce_ports=True, mesh_domain="pm.internal",
                                caps=["role:api"])
    grants = [{"from": ["web", "worker"], "to": ["api"], "ports": ["tcp/8000"]},
              {"from": ["web"], "to": ["db"], "ports": ["tcp/5432"]}]
    out = "\n".join(status._enforcement_lines(cfg, grants))
    assert "tcp/8000 ← web,worker" in out           # this node's inbound grant
    assert "5432" not in out                         # the db grant isn't inbound here


def test_enforcement_lines_tightened_no_inbound_is_default_deny(monkeypatch):
    import types
    from greasewood import status
    monkeypatch.setattr(status.os, "geteuid", lambda: 1000)
    cfg = types.SimpleNamespace(enforce_ports=True, mesh_domain="pm.internal",
                                caps=["role:worker"])   # no grant targets worker
    grants = [{"from": ["web"], "to": ["api"], "ports": ["tcp/8000"]}]
    out = "\n".join(status._enforcement_lines(cfg, grants))
    assert "default-deny" in out


def test_enforcement_lines_off(monkeypatch):
    import types
    from greasewood import status
    cfg = types.SimpleNamespace(enforce_ports=False, mesh_domain="pm.internal",
                                caps=["role:api"])
    out = "\n".join(status._enforcement_lines(cfg, None))
    assert "OFF" in out and "advisory" in out


def test_enforcement_lines_warns_when_table_missing_as_root(monkeypatch):
    import types
    from greasewood import status, wg
    monkeypatch.setattr(status.os, "geteuid", lambda: 0)         # root → reads nft
    monkeypatch.setattr(wg, "nft_table_exists", lambda t: False) # simulate flush window
    cfg = types.SimpleNamespace(enforce_ports=True, mesh_domain="pm.internal",
                                caps=["role:api"])
    out = "\n".join(status._enforcement_lines(cfg, None))
    assert "not in kernel yet" in out


# ---------------------------------------------------------------------------
# gw watch live view — scroll math + viewport windowing (the TUI groundwork)
# ---------------------------------------------------------------------------

def test_scroll_clamp_bounds():
    from greasewood import status as s
    assert s._scroll_clamp(-5, 100, 10) == 0        # never before start
    assert s._scroll_clamp(999, 100, 10) == 90      # never past end (total - view)
    assert s._scroll_clamp(50, 100, 10) == 50
    assert s._scroll_clamp(5, 3, 10) == 0           # content fits → pinned at top


def test_scroll_key_actions():
    from greasewood import status as s
    assert s._scroll_key("down", 0, 100, 10) == 1
    assert s._scroll_key("up", 0, 100, 10) == 0     # clamps at 0
    assert s._scroll_key("pgdown", 0, 100, 10) == 10
    assert s._scroll_key("pgup", 20, 100, 10) == 10
    assert s._scroll_key("bottom", 0, 100, 10) == 90
    assert s._scroll_key("top", 50, 100, 10) == 0


def test_key_action_map_covers_keys_and_arrows():
    from greasewood import status as s
    assert s._KEY_ACTIONS[b"j"] == "down" and s._KEY_ACTIONS[b"\x1b[B"] == "down"
    assert s._KEY_ACTIONS[b"k"] == "up" and s._KEY_ACTIONS[b"\x1b[A"] == "up"
    assert s._KEY_ACTIONS[b" "] == "pgdown" and s._KEY_ACTIONS[b"\x1b[6~"] == "pgdown"
    assert s._KEY_ACTIONS[b"q"] == "quit" and s._KEY_ACTIONS[b"\x03"] == "quit"


def _mk_app(top, rows):
    from greasewood import status as s
    app = s._WatchApp.__new__(s._WatchApp)
    app._top, app._rows, app._off, app._up = top, rows, 0, len(rows)
    return app


def test_compose_windows_rows_and_pins_footer():
    app = _mk_app(["h1", "h2"], [f"peer{i}" for i in range(50)])
    frame = app._compose(cols=80, term_h=10)          # view_h = 10-2-1 = 7
    assert len(frame) == 10                            # exactly fills the height
    assert frame[:2] == ["h1", "h2"]                   # pinned header
    assert frame[2:9] == [f"peer{i}" for i in range(7)]
    assert "peers 1–7 of 50" in frame[-1]              # footer scroll indicator


def test_compose_clamps_offset_and_shows_tail():
    app = _mk_app(["h1", "h2"], [f"peer{i}" for i in range(50)])
    app._off = 999
    frame = app._compose(80, 10)
    assert app._off == 43                              # clamped to total - view_h
    assert frame[2:9] == [f"peer{i}" for i in range(43, 50)]
    assert "peers 44–50 of 50" in frame[-1]


def test_compose_all_fit_no_scroll_indicator():
    app = _mk_app(["h1", "h2"], [f"peer{i}" for i in range(3)])
    frame = app._compose(80, 24)
    assert "all 3" in frame[-1]                        # fits → 'all N', not a range
    assert len(frame) == 24                            # still fills the screen (padded)
