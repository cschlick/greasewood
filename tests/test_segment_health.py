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
    # nft's real error is multi-line (message + command echo + a ^^^ caret) —
    # it must collapse to ONE line so it can't bleed into the roster layout.
    multiline = ("Error: No such file or directory\n"
                 "list table inet greasewood_pm\n                ^^^^^^^^^^^^^")
    monkeypatch.setattr(status.subprocess, "run",
                        lambda *a, **k: subprocess.CompletedProcess(a, 1, "", multiline))
    lines = status._nft_table_lines(_cfg())
    assert len(lines) == 2                       # command line + ONE note
    assert "not present" in lines[1] and "^" not in lines[1]


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
                               "table inet greasewood_pm {", "}"),
            fw=("main firewall : udp/51900 + gw-* overlay allowed ✓",
                "  $ sudo nft list ruleset | grep -E '51900|gw-'",
                "    udp dport 51900 accept")):
    from greasewood import status as s
    app = s._WatchApp.__new__(s._WatchApp)
    app._header = list(header)
    app._fw_lines = list(fw)
    app._nft_lines = list(nft)
    app._chrome = []
    app._rows, app._off, app._up = rows, 0, len(rows)
    app._show_nft = True
    app._hidden = 0
    app._show_total = False
    return app


def test_compose_windows_rows_and_pins_footer():
    app = _mk_app(["h1"], [f"peer{i}" for i in range(50)])
    term_h = 24
    frame = app._compose(cols=80, term_h=term_h)
    top = app._top_lines()
    view_h = term_h - len(top) - 1
    assert len(frame) == term_h                         # exactly fills the height
    assert frame[:len(top)] == top                      # pinned top
    body = frame[len(top):len(top) + view_h]
    assert all(body[i].startswith(f"peer{i}") for i in range(view_h))   # rows, in order
    assert all(ln[-1] in ("░", "█") for ln in body)     # scrollbar rail on every row
    assert body[0][-1] == "█"                            # thumb at the top (off=0)
    assert f"of 50" in frame[-1]                        # footer scroll indicator


def test_compose_clamps_offset_and_shows_tail():
    app = _mk_app(["h1"], [f"peer{i}" for i in range(50)])
    app._off = 999
    term_h = 24
    frame = app._compose(80, term_h)
    top = app._top_lines()
    view_h = term_h - len(top) - 1
    assert app._off == 50 - view_h                      # clamped to total - view_h
    body = frame[len(top):len(top) + view_h]
    assert all(body[i].startswith(f"peer{50 - view_h + i}") for i in range(view_h))
    assert body[-1][-1] == "█"                           # thumb at the bottom (scrolled to end)


def test_compose_all_fit_no_scroll_indicator():
    app = _mk_app(["h1"], [f"peer{i}" for i in range(3)])
    frame = app._compose(80, 24)
    assert "all 3" in frame[-1]                         # fits → 'all N', not a range
    assert len(frame) == 24                             # still fills the screen (padded)
    top = app._top_lines()
    body = frame[len(top):len(top) + 3]                 # the 3 peer rows
    assert all("░" not in ln and "█" not in ln for ln in body)   # no scrollbar when it fits


def test_toggle_nft_collapses_the_top_block():
    app = _mk_app(["h1"], [f"peer{i}" for i in range(5)])
    expanded = app._top_lines()
    app._show_nft = False
    collapsed = app._top_lines()
    assert len(collapsed) < len(expanded)              # collapsing shrinks the pinned top
    assert any("(f to expand" in ln for ln in collapsed)   # still shows how to expand
    assert any("own table" in ln for ln in collapsed)      # gw-table state, one clause
    # the whole firewall area is ONE line collapsed — that's the point
    assert len(expanded) - len(collapsed) >= len(app._nft_lines)
    assert any("main firewall" in ln for ln in collapsed)  # verdict stays verbatim


def test_frame_clears_before_content_and_expands_tabs():
    """Regression: nft output is tab-indented; the redraw must clear each line
    BEFORE writing (a tab skips columns without erasing them) and expand tabs so
    stale content in the indent can't show through."""
    from greasewood.status import _WatchApp
    f = _WatchApp._frame(["header", "\tchain x {", "\t\tdrop"], cols=80)
    assert f.startswith("\x1b[H") and f.endswith("\x1b[J")
    assert "\t" not in f                          # tabs expanded (no cursor-skip)
    line = f.split("\r\n")[1]
    assert line.startswith("\x1b[K")              # cleared BEFORE the content
    assert "chain x {" in line


# ---------------------------------------------------------------------------
# gw watch: reconcile (daemon-liveness) heartbeat freshness
# ---------------------------------------------------------------------------

def test_reconcile_freshness_states(tmp_path):
    import datetime as _dt
    from greasewood import status, reconcile
    cfg = types.SimpleNamespace(role="anchor", data_dir=tmp_path,
                                mesh_domain="pm.internal")
    # no heartbeat yet → "never" (daemon not running / never reconciled)
    assert "never reconciled" in status._reconcile_freshness(cfg)
    # fresh heartbeat → healthy
    reconcile.stamp_reconcile_path(tmp_path).write_text(
        _dt.datetime.now(_UTC).replace(microsecond=0).isoformat())
    assert status._reconcile_freshness(cfg).startswith("reconciled ")
    # stale heartbeat → warning (daemon stalled/stopped)
    reconcile.stamp_reconcile_path(tmp_path).write_text(
        (_dt.datetime.now(_UTC) - _dt.timedelta(minutes=5)).replace(
            microsecond=0).isoformat())
    out = status._reconcile_freshness(cfg)
    assert "⚠" in out and "stalled or stopped" in out


def test_reconcile_freshness_surfaces_startup_fatal_reason(tmp_path):
    # A daemon that died at startup left a breadcrumb; watch shows WHY it's down
    # (the visible end of the restart-loop fix), not just "never reconciled".
    from greasewood import status, reconcile
    cfg = types.SimpleNamespace(role="node", data_dir=tmp_path,
                                mesh_domain="pm.internal")
    reconcile.write_daemon_fatal(tmp_path, "wireguard port 51900 already in use")
    out = status._reconcile_freshness(cfg)
    assert "daemon FAILED to start" in out and "51900 already in use" in out


def test_reconcile_freshness_prefers_liveness_over_stale_breadcrumb(tmp_path):
    # If the daemon is reconciling NOW, a leftover breadcrumb must not shadow the
    # healthy signal (a start clears it, but be robust to a race).
    import datetime as _dt
    from greasewood import status, reconcile
    cfg = types.SimpleNamespace(role="node", data_dir=tmp_path,
                                mesh_domain="pm.internal")
    reconcile.write_daemon_fatal(tmp_path, "stale reason")
    reconcile.stamp_reconcile_path(tmp_path).write_text(
        _dt.datetime.now(_UTC).replace(microsecond=0).isoformat())
    assert status._reconcile_freshness(cfg).startswith("reconciled ")


def test_reconcile_freshness_shown_for_anchor_in_header(tmp_path, monkeypatch):
    # the anchor has no sync line (it's the source), so the reconcile heartbeat
    # is its only freshness signal — it must appear in the watch header.
    import datetime as _dt
    from greasewood import status, reconcile
    reconcile.stamp_reconcile_path(tmp_path).write_text(
        _dt.datetime.now(_UTC).replace(microsecond=0).isoformat())
    # isolate the header's freshness assembly from the (cfg-heavy) sub-blocks
    monkeypatch.setattr(status, "_self_health_lines", lambda *a: [])
    monkeypatch.setattr(status, "_door_status_lines", lambda *a: [])
    cfg = types.SimpleNamespace(role="anchor", data_dir=tmp_path,
                                mesh_domain="pm.internal", hostname="anchor")
    lines = status._watch_header(cfg, None, "abc", "fd8d::1")
    assert not any(ln.startswith("synced") for ln in lines)   # anchor doesn't sync
    assert any(ln.startswith("daemon   : reconciled") for ln in lines)


def test_reconcile_heartbeat_round_trips(tmp_path):
    from greasewood import reconcile
    assert reconcile.read_last_reconcile(tmp_path) is None
    reconcile.stamp_reconcile_path(tmp_path).write_text("2026-07-08T00:00:00+00:00")
    assert reconcile.read_last_reconcile(tmp_path) == "2026-07-08T00:00:00+00:00"


def test_diagnose_find_accepts_mesh_names(monkeypatch):
    """The roster prints full mesh names (bastion.pm.internal); diagnose must
    accept them, not just the bare hostname."""
    import types as _t
    from greasewood import status
    me = _rec("me", ["203.0.113.2:51900"])
    bastion = _rec("bastion", ["203.0.113.1:51900"])
    directory = _t.SimpleNamespace(all=lambda: [me, bastion])
    cfg = _t.SimpleNamespace(mesh_domain="pm.internal", hostname="me",
                             role="node", root_url="")
    args = _t.SimpleNamespace(nodes=["bastion.pm.internal"])
    # reach into the picker: full-name lookup must resolve, not sys.exit
    picks = status._resolve_diag_columns(args, cfg, directory, me.id_pub, me)
    assert any(lbl == "bastion" for lbl, r, _ in picks if r is not None)


def test_live_and_hidden_filters_expired():
    """gw watch shows only the live mesh: expired records are split out (hidden)
    unless --all, and the count is reported for the footer."""
    import datetime as dt
    from greasewood import status
    now = dt.datetime.now(dt.timezone.utc)
    live = _rec("live", ["1:51900"])                 # exp = now + 1h (see _rec)
    expired = _rec("gone", ["2:51900"])
    expired.cred.exp = now - dt.timedelta(minutes=1)  # force expiry

    shown, hidden = status._live_and_hidden([live, expired], now, show_all=False)
    assert [r.cred.hostname for r in shown] == ["live"] and hidden == 1

    shown_all, hidden_all = status._live_and_hidden([live, expired], now, show_all=True)
    assert len(shown_all) == 2 and hidden_all == 0    # --all shows everything


def test_roster_live_rate_vs_cumulative_total():
    """The live view's middle column is per-second rate by default, or cumulative
    traffic with show_total (the `t` toggle / --total) — steady, not jittering."""
    import types as _t
    from greasewood import status
    now = dt.datetime.now(_UTC)
    r = _rec("db01", ["1:51900"])
    wg_key = status._wg_key(r)
    lp = _t.SimpleNamespace(latest_handshake=int(now.timestamp()) - 5,
                            rx_bytes=4_200_000, tx_bytes=1_050_000,
                            allowed_ips=r.cred.addr + "/128", keepalive=25)
    cfg = _t.SimpleNamespace(mesh_domain="pm.internal", caps=["role:db"], hostname="self")
    rates = {r.cred.addr: "↓46B/s ↑46B/s"}
    common = dict(records=[r], cfg=cfg, now=now, own_id="deadbeef",
                  live_peers={wg_key: lp}, is_root=True,
                  latency={r.cred.addr: "38ms"}, rates=rates)

    rate_view = "\n".join(status._roster_lines(**common, show_total=False))
    assert "rate" in rate_view and "46B/s" in rate_view          # header + rate value

    total_view = "\n".join(status._roster_lines(**common, show_total=True))
    assert "traffic" in total_view                                # header flips
    assert "↓4.0M ↑1.0M" in total_view and "B/s" not in total_view  # cumulative, no rate


def test_scrollbar_column_geometry():
    from greasewood import status as s
    # 100 rows, 10 on screen → thumb ~1 row; tracks the offset top→bottom.
    top = s._scrollbar_column(0, 100, 10)
    assert len(top) == 10 and top[0] == "█" and top.count("█") >= 1 and top[-1] == "░"
    mid = s._scrollbar_column(45, 100, 10)
    assert mid[0] == "░" and mid[-1] == "░" and "█" in mid          # thumb in the middle
    bot = s._scrollbar_column(90, 100, 10)                          # clamped-to-end offset
    assert bot[-1] == "█" and bot[0] == "░"
    # bigger thumb when more of the content is visible (20 of 40 → half the bar)
    assert s._scrollbar_column(0, 40, 20).count("█") == 10
    # everything fits → blank rail, no thumb
    assert s._scrollbar_column(0, 5, 10) == [" "] * 10


def test_firewall_summary_rows():
    from greasewood.status import _firewall_summary_lines as fsl
    fw = ["main firewall : ⚠ udp/51910, gw-* overlay BLOCKED by default-drop "
          "— daemon likely UNREACHABLE inbound", "  $ nft ...", "    (no rule)"]
    nft_ok = ["$ sudo nft list table inet greasewood_pm",
              "table inet greasewood_pm {",
              '        iifname "gw-pm" tcp dport 22 accept',
              '        iifname "gw-pm" drop', "}"]
    rows = fsl(fw, nft_ok, "f")
    # three rows: verbatim verdict / own-table state / how to expand
    assert rows[0] == fw[0]
    assert rows[1].startswith("own table") and "✓" in rows[1] and "(2 rules)" in rows[1]
    assert rows[2] == "(f to expand — raw nft rules)"
    # the two labels' colons align (that's what makes the rows scannable)
    assert rows[0].index(":") == rows[1].index(":")
    # missing table is loud
    nft_missing = [nft_ok[0], "  (table not present — the daemon isn't running "
                   "yet, or hasn't applied enforcement; ...)"]
    assert any("MISSING" in r for r in fsl(fw, nft_missing, "f"))
    # enforcement off with no host check still yields labeled rows
    nft_off = [nft_ok[0], "  (port enforcement off — enforce_ports=false; no table)"]
    rows_off = fsl([], nft_off, "--firewall")
    assert rows_off[0].startswith("own table") and "port enforcement off" in rows_off[0]
    assert rows_off[1] == "(--firewall to expand — raw nft rules)"
    # nothing to say → no rows (nft absent entirely)
    assert fsl([], [], "f") == []
    assert fsl([], [nft_ok[0], "  (nft not installed)"], "f") == []


# ---------------------------------------------------------------------------
# gw watch live view — color (paint is zero-width, opt-out honored)
# ---------------------------------------------------------------------------

_ANSI = __import__("re").compile(r"\x1b\[[0-9;]*m")


def test_paint_never_changes_content():
    # The invariant that makes painting safe AFTER layout: strip the escapes
    # and you must get the input back, for every kind of line we render.
    from greasewood.status import _paint
    lines = [
        "main firewall : ⚠ udp/51910, gw-* overlay BLOCKED by default-drop "
        "— daemon likely UNREACHABLE inbound · own table MISSING (daemon "
        "running?) · (f for detail)",
        "main firewall : udp/51900 + gw-* overlay allowed ✓ · own table ✓ "
        "(5 rules) · (--firewall for detail)",
        "db01.pm.internal  fd8d::1  db  23h  │ ● up, 3m ago  ↓1.2K/s ↑340B/s  12ms",
        "web1.pm.internal  fd8d::2  web  <1h!  │ ○ no handshake",
        "self.pm.internal  fd8d::3  api  EXPIRED  │ (self)   0ms",
        "  $ sudo nft list ruleset | grep -E '51900|gw-'",
        "-----------------+------------------------------",
        "12:00:00Z · 3 links up · all 5 · ↑↓/PgUp/PgDn/g/G scroll · f firewall "
        "· t total · q quit",
        "synced   : never synced (is the daemon running / reaching the anchor?)",
        "plain line with no tokens at all",
    ]
    for ln in lines:
        assert _ANSI.sub("", _paint(ln)) == ln


def test_paint_latency_heat():
    from greasewood.status import _paint
    assert "\x1b[32m12ms\x1b[0m" in _paint("x 12ms")       # fast: green
    assert _paint("x 80ms") == "x 80ms"                    # mid: untouched
    assert "\x1b[33m400ms\x1b[0m" in _paint("x 400ms")     # slow: yellow


def test_frame_paints_only_after_truncation():
    from greasewood import status as s
    # the ✓ sits beyond the 10-col clip → no escape may survive for it
    out = s._WatchApp._frame(["0123456789 ✓"], 10, color=True)
    assert "✓" not in out and "\x1b[32m" not in out
    # default stays plain (snapshot/tests contract)
    assert "\x1b[32m" not in s._WatchApp._frame(["a ✓"], 80)
    # and colored mode paints within the clip
    assert "\x1b[32m✓\x1b[0m" in s._WatchApp._frame(["a ✓"], 80, color=True)


def test_color_enabled_honors_opt_outs(monkeypatch):
    from greasewood.status import _color_enabled
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setenv("TERM", "xterm-256color")
    assert _color_enabled()
    monkeypatch.setenv("NO_COLOR", "1")
    assert not _color_enabled()
    monkeypatch.delenv("NO_COLOR")
    monkeypatch.setenv("TERM", "dumb")
    assert not _color_enabled()
