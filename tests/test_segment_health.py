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
# gw watch: the greasewood nftables table, shown verbatim (command + output)
# ---------------------------------------------------------------------------

def _cfg(enforce=True):
    import types
    return types.SimpleNamespace(enforce_ports=enforce, mesh_domain="pm.internal",
                                 caps=["role:api"])


def test_nft_table_lines_shows_command_then_raw_output(monkeypatch):
    import subprocess, types
    from greasewood import status
    raw = ("table inet greasewood_pm {\n"
           "\tchain meshfilter {\n"
           "\t\tiifname \"gw-pm\" accept\n"
           "\t}\n}")
    monkeypatch.setattr(status.subprocess, "run",
                        lambda *a, **k: subprocess.CompletedProcess(a, 0, raw, ""))
    lines = status._nft_table_lines(_cfg())
    assert lines[0] == "$ sudo nft list table inet greasewood_pm"   # literal command
    assert lines[1:] == raw.splitlines()                            # verbatim output


def test_nft_table_lines_off(monkeypatch):
    from greasewood import status
    out = "\n".join(status._nft_table_lines(_cfg(enforce=False)))
    assert out.startswith("$ sudo nft list table inet greasewood_pm")
    assert "enforcement off" in out


def test_nft_table_lines_needs_root(monkeypatch):
    import subprocess
    from greasewood import status
    monkeypatch.setattr(status.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(status.subprocess, "run",
                        lambda *a, **k: subprocess.CompletedProcess(a, 1, "", "denied"))
    out = "\n".join(status._nft_table_lines(_cfg()))
    assert "run as root" in out


def test_nft_table_lines_missing_table_as_root(monkeypatch):
    import subprocess
    from greasewood import status
    monkeypatch.setattr(status.os, "geteuid", lambda: 0)
    monkeypatch.setattr(status.subprocess, "run",
                        lambda *a, **k: subprocess.CompletedProcess(
                            a, 1, "", "Error: No such file or directory"))
    out = "\n".join(status._nft_table_lines(_cfg()))
    assert "no such table" in out.lower()


def test_nft_table_lines_nft_absent(monkeypatch):
    from greasewood import status
    def boom(*a, **k):
        raise FileNotFoundError()
    monkeypatch.setattr(status.subprocess, "run", boom)
    out = "\n".join(status._nft_table_lines(_cfg()))
    assert "nft not installed" in out


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
    assert s._KEY_ACTIONS[b"f"] == "toggle_nft"


def _mk_app(header, rows, nft=("$ sudo nft list table inet greasewood_pm",
                               "table inet greasewood_pm {", "}")):
    from greasewood import status as s
    app = s._WatchApp.__new__(s._WatchApp)
    app._header = list(header)
    app._nft_lines = list(nft)
    app._chrome = []
    app._rows, app._off, app._up = rows, 0, len(rows)
    app._show_nft = True
    return app


def test_compose_windows_rows_and_pins_footer():
    app = _mk_app(["h1"], [f"peer{i}" for i in range(50)])
    term_h = 24
    frame = app._compose(cols=80, term_h=term_h)
    top = app._top_lines()
    view_h = term_h - len(top) - 1
    assert len(frame) == term_h                         # exactly fills the height
    assert frame[:len(top)] == top                      # pinned top
    assert frame[len(top):len(top) + view_h] == [f"peer{i}" for i in range(view_h)]
    assert f"of 50" in frame[-1]                        # footer scroll indicator


def test_compose_clamps_offset_and_shows_tail():
    app = _mk_app(["h1"], [f"peer{i}" for i in range(50)])
    app._off = 999
    term_h = 24
    frame = app._compose(80, term_h)
    top = app._top_lines()
    view_h = term_h - len(top) - 1
    assert app._off == 50 - view_h                      # clamped to total - view_h
    assert frame[len(top):len(top) + view_h] == [f"peer{i}" for i in range(50 - view_h, 50)]


def test_compose_all_fit_no_scroll_indicator():
    app = _mk_app(["h1"], [f"peer{i}" for i in range(3)])
    frame = app._compose(80, 24)
    assert "all 3" in frame[-1]                         # fits → 'all N', not a range
    assert len(frame) == 24                             # still fills the screen (padded)


def test_toggle_nft_collapses_the_top_block():
    app = _mk_app(["h1"], [f"peer{i}" for i in range(5)])
    expanded = app._top_lines()
    app._show_nft = False
    collapsed = app._top_lines()
    assert len(collapsed) < len(expanded)              # collapsing shrinks the pinned top
    assert any("f to expand" in ln for ln in collapsed)    # still shows how to restore
    assert any("nft list table" in ln for ln in collapsed) # keeps the command line
