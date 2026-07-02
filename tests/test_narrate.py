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
    assert N.parse_line("22:10:01 INFO greasewood: starting — role=hub") is None
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
