"""
greasewood.narrate — translate the ip/wg command trail into human prose.
Covers the parser, the per-command translator, the per-operation intro, the
grouping/rendering, and the summary.
"""
from greasewood import narrate as N


def test_parse_line_extracts_fields():
    line = ('ts=2026-07-02T22:12:03Z cmd rc=0 t=14ms '
            'ctx="enroll: +peer db01 [fd8d::a1] from fd52::9" '
            'argv="wg set gw-mesh peer ABC= allowed-ips fd8d::a1/128"')
    e = N.parse_line(line)
    assert e.ts == "2026-07-02T22:12:03Z" and e.rc == 0 and e.t_ms == 14
    assert e.ctx.startswith("enroll: +peer db01")
    assert e.argv[:3] == ["wg", "set", "gw-mesh"]
    assert not e.failed


def test_parse_line_marks_failure_via_stderr():
    line = ('ts=2026-07-02T23:02:10Z cmd rc=1 t=2ms ctx="reconcile: -peer db01 [x]" '
            'argv="ip -6 route del fd8d::a1/128 dev gw-mesh" '
            'stderr="No such process"')
    e = N.parse_line(line)
    assert e.failed and e.stderr == "No such process"


def test_parse_line_ignores_non_command_lines():
    assert N.parse_line("22:10:01 INFO greasewood: starting — role=anchor") is None
    assert N.parse_line("") is None


def test_describe_wg_peer_setup():
    d = N.describe(["wg", "set", "gw-mesh", "peer", "ABCDEFGHIJKLMNOP=",
                    "allowed-ips", "fd8d::a1/128", "persistent-keepalive", "25",
                    "endpoint", "[203.0.113.7]:51900"])
    assert "tunnel" in d and "ABCDEFGHIJ…" in d          # key shortened
    assert "fd8d::a1" in d and "203.0.113.7" in d
    assert "keepalive every 25s" in d


def test_describe_wg_peer_remove_and_no_endpoint():
    assert "Remove WireGuard peer" in N.describe(
        ["wg", "set", "gw-mesh", "peer", "ABC=", "remove"])
    d = N.describe(["wg", "set", "gw-mesh", "peer", "ABC=", "allowed-ips", "fd8d::b/128",
                    "persistent-keepalive", "25"])
    assert "wait for it to dial us" in d                 # no endpoint advertised


def test_describe_ip_commands():
    assert "Create the WireGuard interface gw-mesh" in N.describe(
        ["ip", "link", "add", "gw-mesh", "type", "wireguard"])
    assert "Route traffic for fd8d::a1 over gw-mesh" in N.describe(
        ["ip", "-6", "route", "replace", "fd8d::a1/128", "dev", "gw-mesh"])
    assert "Remove the kernel route to fd8d::a1" in N.describe(
        ["ip", "-6", "route", "del", "fd8d::a1/128", "dev", "gw-mesh"])
    assert "Blackhole everything in routing table 51820" in N.describe(
        ["ip", "-6", "route", "add", "blackhole", "default", "table", "51820"])
    assert "Policy-route packets from" in N.describe(
        ["ip", "-6", "rule", "add", "from", "fd8d::2", "lookup", "51820",
         "priority", "100"])


def test_describe_operation_intros():
    assert "added a peer" in N.describe_operation("reconcile: +peer db01 [x] seg=prod")
    assert "removed a peer" in N.describe_operation("reconcile: -peer db01 [x] seg=prod")
    assert "endpoint changed" in N.describe_operation(
        "reconcile: ~peer db01 [x] seg=prod (endpoint)")
    assert "enrolled through the door" in N.describe_operation("enroll: +peer db01 [x] from y")
    assert N.describe_operation("") is None


def test_grouping_and_render_smoke():
    lines = [
        'ts=2026-07-02T22:12:03Z cmd rc=0 t=14ms ctx="enroll: +peer db01 [fd8d::a1] from fd52::9" argv="wg set gw-mesh peer ABC= allowed-ips fd8d::a1/128 endpoint [203.0.113.7]:51900"',
        'ts=2026-07-02T22:12:03Z cmd rc=0 t=3ms ctx="enroll: +peer db01 [fd8d::a1] from fd52::9" argv="ip -6 route replace fd8d::a1/128 dev gw-mesh"',
    ]
    entries = [N.parse_line(x) for x in lines]
    out = "\n".join(N.narrate(entries, color=False))
    assert "A new node enrolled through the door" in out   # one op header
    assert out.count("●") == 1                             # both commands, one group
    assert "✓" in out and "(14ms)" in out


def test_summarize_counts_operations_not_commands():
    lines = [
        'ts=2026-07-02T23:02:10Z cmd rc=1 t=2ms ctx="reconcile: -peer db01 [x]" argv="ip -6 route del fd8d::a1/128 dev gw-mesh" stderr="No such process"',
        'ts=2026-07-02T23:02:10Z cmd rc=0 t=2ms ctx="reconcile: -peer db01 [x]" argv="wg set gw-mesh peer ABC= remove"',
    ]
    entries = [N.parse_line(x) for x in lines]
    s = N.summarize(entries)
    assert "1 removed" in s                # one operation, not two commands
    assert "1 command(s) failed" in s      # but failures counted per command


def test_cmd_narrate_since_filter_works(tmp_path, capsys):
    """Regression: `gw narrate --since 30m` crashed with NameError —
    _parse_duration was only imported inside cmd_create."""
    import types
    from greasewood import cli
    log = tmp_path / "audit.log"
    log.write_text(
        'ts=2020-01-01T00:00:00Z cmd rc=0 t=1ms ctx="old: +peer x" '
        'argv="wg set gw-mesh peer OLD= allowed-ips fd8d::1/128"\n'
        'ts=2099-01-01T00:00:00Z cmd rc=0 t=1ms ctx="new: +peer y" '
        'argv="wg set gw-mesh peer NEW= allowed-ips fd8d::2/128"\n')
    args = types.SimpleNamespace(config="/nonexistent", source=str(log),
                                 since="30m", peer=None, grep=None,
                                 failures=False, raw=False, stats=False,
                                 no_color=True)
    assert cli.cmd_narrate(args) == 0
    out = capsys.readouterr().out
    assert "NEW" in out or "fd8d::2" in out    # recent entry survives the filter
    assert "OLD" not in out                    # 2020 entry filtered out


def test_describe_ip_bare_line_does_not_crash():
    """Regression: a bare/truncated `ip` argv IndexError'd on toks[-1]."""
    assert N._describe_ip(["ip"]) == "ip "
    assert N._describe_ip(["ip", "-6"]).startswith("ip")
    assert N._describe_ip(["ip", "link"]).startswith("ip")


def test_cycle_period_detects_repeats():
    import types
    def E(argv): return types.SimpleNamespace(argv=argv, t_ms=1, failed=False)
    A, B = ["wg", "set", "x"], ["ip", "link", "up"]
    assert N._cycle_period([E(A), E(B), E(A), E(B), E(A), E(B)]) == 2   # ABAB… → 2
    assert N._cycle_period([E(A), E(A), E(A)]) == 1                     # AAA → 1
    assert N._cycle_period([E(A), E(B), E(A)]) == 0                     # not a clean cycle
    assert N._cycle_period([E(A), E(B)]) == 0                           # <2 reps → no collapse


def test_render_collapses_crashloop_cycle():
    # a crash-loop: the same Configure/Bring-up pair recorded N times under one
    # context should render as the 2-command cycle ×N, not 2N lines.
    lines = []
    for _ in range(50):
        lines += [
            'ts=2026-07-08T09:38:30Z cmd rc=0 t=1ms ctx="startup: ensure interface gw-pm [fd8d::1]" argv="wg set gw-pm private-key /k listen-port 51900"',
            'ts=2026-07-08T09:38:30Z cmd rc=0 t=1ms ctx="startup: ensure interface gw-pm [fd8d::1]" argv="ip link set gw-pm up"',
        ]
    entries = [N.parse_line(x) for x in lines]
    out = "\n".join(N.narrate(entries, color=False))
    assert out.count("✓") == 2                     # collapsed to the 2 cycle commands
    assert "×50" in out
    assert "2-command cycle ×50" in out
    assert "100 commands" in out                   # footer still reports the true total


def test_render_does_not_collapse_when_a_command_failed():
    # a failure inside the run must stay visible — no cycle collapse.
    lines = [
        'ts=2026-07-08T09:38:30Z cmd rc=0 t=1ms ctx="startup: ensure interface gw-pm [x]" argv="wg set gw-pm private-key /k listen-port 51900"',
        'ts=2026-07-08T09:38:30Z cmd rc=1 t=1ms ctx="startup: ensure interface gw-pm [x]" argv="ip link set gw-pm up" stderr="boom"',
        'ts=2026-07-08T09:38:30Z cmd rc=0 t=1ms ctx="startup: ensure interface gw-pm [x]" argv="wg set gw-pm private-key /k listen-port 51900"',
        'ts=2026-07-08T09:38:30Z cmd rc=0 t=1ms ctx="startup: ensure interface gw-pm [x]" argv="ip link set gw-pm up"',
    ]
    entries = [N.parse_line(x) for x in lines]
    out = "\n".join(N.narrate(entries, color=False))
    assert "×" not in out                           # no collapse
    assert "✗" in out and "boom" in out             # the failure is shown


# ── domain-event lines (event=topology / event=policy) ───────────────────────

def test_parse_line_parses_event():
    e = N.parse_line("ts=2026-07-02T22:12:08Z event=topology added=2 removed=1 peers=7")
    assert isinstance(e, N.EventEntry)
    assert e.ts == "2026-07-02T22:12:08Z" and e.kind == "topology"
    assert e.fields == {"added": "2", "removed": "1", "peers": "7"}
    assert not e.failed                      # events are never failures


def test_command_line_never_parsed_as_event():
    # a command whose ctx text mentions 'event' is still a command, not an event
    line = ('ts=2026-07-02T22:12:03Z cmd rc=0 t=1ms ctx="reconcile: note" '
            'argv="ip -6 route replace fd8d::a1/128 dev gw-mesh"')
    assert isinstance(N.parse_line(line), N.Entry)


def test_describe_event_topology_and_policy():
    topo = N.EventEntry("t", "topology", {"added": "2", "removed": "1", "peers": "7"})
    assert N.describe_event(topo) == \
        "Topology settled — 2 peers added, 1 removed (7 peers now up)."
    one = N.EventEntry("t", "topology", {"added": "1", "removed": "0", "peers": "1"})
    assert N.describe_event(one).startswith("Topology settled — 1 peer added (1 peer now up)")
    pol = N.EventEntry("t", "policy", {"prev": "4", "seq": "5", "grants": "3"})
    assert N.describe_event(pol).startswith("Policy adopted — v4 → v5 (3 grants)")
    first = N.EventEntry("t", "policy", {"prev": "none", "seq": "1", "grants": "1"})
    assert "the first policy → v1 (1 grant)" in N.describe_event(first)


def test_narrate_renders_event_markers_interleaved():
    lines = [
        "ts=2026-07-02T22:12:01Z event=policy prev=4 seq=5 grants=3",
        ('ts=2026-07-02T22:12:03Z cmd rc=0 t=12ms ctx="reconcile: +peer db01 [fd8d::a1]" '
         'argv="wg set gw-mesh peer ABC= allowed-ips fd8d::a1/128"'),
        "ts=2026-07-02T22:12:08Z event=topology added=2 removed=1 peers=7",
    ]
    entries = [N.parse_line(x) for x in lines]
    out = "\n".join(N.narrate(entries, color=False))
    assert "◆" in out and "●" in out                  # both markers present
    assert "Policy adopted — v4 → v5" in out
    assert "Topology settled — 2 peers added, 1 removed" in out
    # the event marker is standalone (not folded into the command op's ✓ block)
    assert "◆ 2026-07-02 22:12:08Z  Topology settled" in out


def test_summarize_counts_events_separately():
    lines = [
        "ts=2026-07-02T22:12:01Z event=policy prev=4 seq=5 grants=3",
        ('ts=2026-07-02T22:12:03Z cmd rc=0 t=12ms ctx="reconcile: +peer db01 [fd8d::a1]" '
         'argv="wg set gw-mesh peer ABC= allowed-ips fd8d::a1/128"'),
        "ts=2026-07-02T22:12:08Z event=topology added=2 removed=1 peers=7",
    ]
    entries = [N.parse_line(x) for x in lines]
    s = N.summarize(entries)
    assert "1 data-plane commands" in s                # the event lines aren't commands
    assert "Events: 1 policy change(s), 1 topology transition(s)." in s


def test_searchable_matches_event_content():
    ev = N.parse_line("ts=t event=policy prev=4 seq=5 grants=3")
    assert "policy" in N.searchable(ev)
    assert "seq=5" in N.searchable(ev)
