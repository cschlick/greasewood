"""
The macOS port, tested from Linux: platform detection, logical-name → utun
resolution, and the exact commands the macOS backend renders (subprocess is
mocked — the real runtime behavior is verified on a Mac). The Linux paths are
covered by the rest of the suite; these tests pin the Darwin branches.
"""
import subprocess as _subprocess
import types

import pytest

from greasewood import platform as gwplat
from greasewood import wg


@pytest.fixture
def macos(monkeypatch, tmp_path):
    """Flip the platform module to Darwin and sandbox the wireguard run dir.
    Returns the run dir (where name files + UAPI sockets live)."""
    monkeypatch.setattr(gwplat, "IS_MACOS", True)
    monkeypatch.setattr(gwplat, "IS_LINUX", False)
    monkeypatch.setattr(wg, "_WG_RUN_DIR", tmp_path)
    return tmp_path


def _wire(run_dir, logical="gw-pm", dev="utun4"):
    """Create the name file + live socket that make `logical` resolve to `dev`."""
    (run_dir / f"{logical}.name").write_text(f"{dev}\n")
    (run_dir / f"{dev}.sock").touch()
    return dev


# ---------------------------------------------------------------------------
# platform module
# ---------------------------------------------------------------------------

def test_capabilities_on_this_host():
    # platform-correct on whichever OS the suite runs on (Linux CI or a Mac)
    if gwplat.IS_LINUX:
        assert gwplat.port_enforcement_available()
        assert wg.resolve_iface("gw-pm") == "gw-pm"   # identity on Linux
    elif gwplat.IS_MACOS:
        assert not gwplat.port_enforcement_available()   # pf backend not built
    else:
        pytest.skip("unsupported host OS")


def test_macos_has_no_port_enforcement_v1(macos):
    assert not gwplat.port_enforcement_available()


# ---------------------------------------------------------------------------
# logical name → utun resolution
# ---------------------------------------------------------------------------

def test_resolve_reads_namefile_and_checks_socket(macos):
    dev = _wire(macos)
    assert wg.resolve_iface("gw-pm") == dev
    # a dead wireguard-go (socket gone) → unresolved, not a stale utun name
    (macos / f"{dev}.sock").unlink()
    assert wg.resolve_iface("gw-pm") is None
    # no name file at all → None
    assert wg.resolve_iface("gw-other") is None


def test_resolve_passes_utun_names_through(macos):
    assert wg.resolve_iface("utun7") == "utun7"


def test_interface_exists_uses_resolution(macos, monkeypatch):
    calls = []
    def fake_run(*args, check=True, env=None):
        calls.append(list(args))
        return _subprocess.CompletedProcess(args, 0, "", "")
    monkeypatch.setattr(wg, "_run", fake_run)
    assert not wg.interface_exists("gw-pm")        # unresolved → doesn't exist
    dev = _wire(macos)
    assert wg.interface_exists("gw-pm")            # resolved → ifconfig utun4
    assert ["ifconfig", dev] in calls


# ---------------------------------------------------------------------------
# command rendering (what the macOS backend actually runs)
# ---------------------------------------------------------------------------

def test_set_peer_renders_wg_on_utun_and_route_commands(macos, monkeypatch):
    dev = _wire(macos)
    calls = []
    def fake_run(*args, check=True, env=None):
        calls.append(list(args))
        return _subprocess.CompletedProcess(args, 0, "", "")
    monkeypatch.setattr(wg, "_run", fake_run)
    wg.set_peer("gw-pm", "PUB=", "fd8d::9", endpoint="[2001:db8::1]:51900")
    flat = [" ".join(c) for c in calls]
    assert any(f.startswith(f"wg set {dev} peer PUB=") for f in flat)  # utun, not gw-pm
    assert f"route -q -n delete -inet6 fd8d::9/128" in flat            # replace =
    assert f"route -q -n add -inet6 fd8d::9/128 -interface {dev}" in flat  # del + add
    assert not any(f.startswith("ip ") for f in flat)                  # no iproute2


def test_remove_peer_deletes_route(macos, monkeypatch):
    dev = _wire(macos)
    calls = []
    monkeypatch.setattr(wg, "_run", lambda *a, **k: (
        calls.append(list(a)), _subprocess.CompletedProcess(a, 0, "", ""))[1])
    wg.remove_peer("gw-pm", "PUB=", allowed_ip="fd8d::9")
    flat = [" ".join(c) for c in calls]
    assert f"wg set {dev} peer PUB= remove" in flat
    assert "route -q -n delete -inet6 fd8d::9/128" in flat


def test_destroy_removes_socket_and_namefile(macos):
    dev = _wire(macos)
    wg.destroy_interface("gw-pm")
    # removing the UAPI socket is how wireguard-go is told to exit
    assert not (macos / f"{dev}.sock").exists()
    assert not (macos / "gw-pm.name").exists()
    wg.destroy_interface("gw-pm")                  # idempotent


def test_rename_moves_the_namefile_only(macos):
    dev = _wire(macos, "gw-old")
    wg.rename_interface("gw-old", "gw-new")
    assert wg.resolve_iface("gw-new") == dev       # same utun, new logical name
    assert wg.resolve_iface("gw-old") is None


def test_get_peers_returns_none_when_unresolved(macos):
    # interface not up → None (the "dump failed" signal), never a false empty
    assert wg.get_peers("gw-pm") is None


# ---------------------------------------------------------------------------
# door isolation: forwarding-off assertion instead of policy routing
# ---------------------------------------------------------------------------

def test_door_routing_asserts_forwarding_off(macos, monkeypatch, caplog):
    import logging
    outputs = {"cmd": None}
    def fake_run(*args, check=True, env=None):
        outputs["cmd"] = list(args)
        return _subprocess.CompletedProcess(args, 0, outputs["val"], "")
    monkeypatch.setattr(wg, "_run", fake_run)

    outputs["val"] = "0\n"                          # forwarding off → quiet
    with caplog.at_level(logging.INFO, logger="greasewood.wg"):
        wg.setup_door_routing()
    assert outputs["cmd"] == ["sysctl", "-n", "net.inet6.ip6.forwarding"]
    assert not any(r.levelno >= logging.WARNING for r in caplog.records)

    caplog.clear()
    outputs["val"] = "1\n"                          # forwarding ON → loud warning
    with caplog.at_level(logging.WARNING, logger="greasewood.wg"):
        wg.setup_door_routing()
    assert any("forwarding is ENABLED" in r.message for r in caplog.records)


def test_door_routing_teardown_is_noop(macos, monkeypatch):
    calls = []
    monkeypatch.setattr(wg, "_run", lambda *a, **k: (
        calls.append(a), _subprocess.CompletedProcess(a, 0, "", ""))[1])
    wg.teardown_door_routing()
    assert calls == []                              # nothing persisted, nothing to undo


# ---------------------------------------------------------------------------
# endpoint / family detection via ifconfig + route
# ---------------------------------------------------------------------------

_IFCONFIG = """\
lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384
\tinet6 ::1 prefixlen 128
\tinet6 fe80::1%lo0 prefixlen 64 scopeid 0x1
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\tinet 192.168.1.23 netmask 0xffffff00 broadcast 192.168.1.255
\tinet6 fe80::1c5e%en0 prefixlen 64 secured scopeid 0xb
\tinet6 2001:db8:15::7a prefixlen 64 autoconf secured
\tinet6 2001:db8:15::99 prefixlen 64 autoconf temporary
\tinet6 fd00:aaaa::5 prefixlen 64 autoconf secured
"""


def test_detect_public_ipv6_parses_ifconfig(macos, monkeypatch):
    from greasewood import cli
    monkeypatch.setattr(cli.subprocess, "run", lambda *a, **k:
                        _subprocess.CompletedProcess(a, 0, _IFCONFIG, ""))
    # stable GUA preferred over temporary; ULA (fd00) + link-local excluded
    assert cli._detect_public_ipv6() == "2001:db8:15::7a"


def test_detect_public_ipv4_parses_ifconfig(macos, monkeypatch):
    from greasewood import cli
    monkeypatch.setattr(cli.subprocess, "run", lambda *a, **k:
                        _subprocess.CompletedProcess(a, 0, _IFCONFIG, ""))
    assert cli._detect_public_ipv4() is None       # 192.168.* is private → none
    public = _IFCONFIG.replace("192.168.1.23", "93.184.216.34")
    monkeypatch.setattr(cli.subprocess, "run", lambda *a, **k:
                        _subprocess.CompletedProcess(a, 0, public, ""))
    assert cli._detect_public_ipv4() == "93.184.216.34"


def test_local_families_via_route_get(macos, monkeypatch):
    from greasewood import cli
    def fake_run(cmd, **k):
        if "-inet6" in cmd:                        # v6 default route present
            return _subprocess.CompletedProcess(cmd, 0,
                "   route to: default\n  gateway: fe80::1\n", "")
        return _subprocess.CompletedProcess(cmd, 1, "",
                "route: writing to routing socket: not in table")
    monkeypatch.setattr(cli.subprocess, "run", fake_run)
    assert cli._local_families() == {6}


# ---------------------------------------------------------------------------
# ping command selection
# ---------------------------------------------------------------------------

def test_ping_rtt_uses_ping6_on_macos(macos, monkeypatch):
    from greasewood import status
    seen = {}
    def fake_run(cmd, **k):
        seen["cmd"] = cmd
        return _subprocess.CompletedProcess(
            cmd, 0, "16 bytes from fd8d::1: icmp_seq=0 hlim=64 time=1.234 ms", "")
    monkeypatch.setattr(status.subprocess, "run", fake_run)
    assert status._ping_rtt("fd8d::1") == "1ms"
    assert seen["cmd"][0] == "ping6" and "-W" not in seen["cmd"]


def test_nft_table_lines_macos_says_not_available(macos):
    from greasewood import status
    cfg = types.SimpleNamespace(enforce_ports=True, mesh_domain="pm.internal",
                                caps=["role:mesh"])
    out = "\n".join(status._nft_table_lines(cfg))
    assert "not available on macOS" in out
    assert "nft" not in out                       # no misleading nft command line


def test_audit_readonly_knows_macos_probes():
    """The reconcile loop's existence probe on macOS is `ifconfig utunN` — it
    must classify as read-only (DEBUG) or it spams the audit log every 5s
    (seen on the first real Mac). Mutating ifconfig forms stay loud."""
    from greasewood import audit
    assert audit.is_readonly(["ifconfig", "utun7"])            # probe
    assert audit.is_readonly(["ifconfig", "-a"])               # detection sweep
    assert audit.is_readonly(["route", "-n", "get", "default"])
    assert audit.is_readonly(["sysctl", "-n", "net.inet6.ip6.forwarding"])
    assert not audit.is_readonly(["ifconfig", "utun7", "up"])  # mutation
    assert not audit.is_readonly(
        ["ifconfig", "utun7", "inet6", "fd8d::1", "prefixlen", "128", "alias"])
    assert not audit.is_readonly(["route", "-q", "-n", "add", "-inet6", "x"])
    # Linux classification unchanged
    assert audit.is_readonly(["ip", "link", "show", "gw-pm"])
    assert audit.is_readonly(["wg", "show", "gw-pm", "dump"])
    assert not audit.is_readonly(["wg", "set", "gw-pm", "peer", "X"])


def test_macos_adds_lo0_self_route(macos, monkeypatch):
    """On macOS the node's own overlay /128 gets a loopback delivery route
    (Linux does this automatically; macOS needs it explicit for a utun)."""
    calls = []
    monkeypatch.setattr(wg, "_run", lambda *a, **k: (
        calls.append(list(a)), _subprocess.CompletedProcess(a, 0, "", ""))[1])
    wg._macos_self_route("fd8d::42")
    flat = [" ".join(c) for c in calls]
    assert "route -q -n add -inet6 fd8d::42/128 -interface lo0" in flat
    # delete-then-add for idempotency
    assert flat.index("route -q -n delete -inet6 fd8d::42/128") < \
           flat.index("route -q -n add -inet6 fd8d::42/128 -interface lo0")


def test_wedge_heal_rebuilds_dead_interface(macos, monkeypatch):
    """macOS: interface up + peers installed + zero live links for a sustained
    time → rebuild the interface (destroy + recreate) to rebind wireguard-go.
    Backs off; recovers instantly when a link appears."""
    from greasewood import reconcile
    loop = reconcile.ReconcileLoop.__new__(reconcile.ReconcileLoop)
    loop._local_id_pub = b"self"
    loop._iface = "gw-pm"
    loop._wedge_since = None
    loop._heal_backoff = reconcile._WEDGE_HEAL_MIN
    rebuilt = []
    loop._ensure_iface = lambda: rebuilt.append("create")
    monkeypatch.setattr(reconcile.wgmod, "destroy_interface",
                        lambda i: rebuilt.append("destroy"))

    peer = types.SimpleNamespace(id_pub=b"peer")
    trusted = [types.SimpleNamespace(id_pub=b"self"), peer]

    clock = [1000.0]
    monkeypatch.setattr(reconcile.time, "monotonic", lambda: clock[0])

    loop._maybe_heal_wedged(trusted, reachable=[])      # first sighting → arm
    assert rebuilt == []
    clock[0] += 10                                       # not past the threshold
    loop._maybe_heal_wedged(trusted, reachable=[])
    assert rebuilt == []
    clock[0] += reconcile._WEDGE_HEAL_MIN                # now past it → rebuild
    loop._maybe_heal_wedged(trusted, reachable=[])
    assert rebuilt == ["destroy", "create"]
    assert loop._heal_backoff == reconcile._WEDGE_HEAL_MIN * 2   # backed off

    # a live link clears the wedge + resets backoff
    loop._maybe_heal_wedged(trusted, reachable=["fd8d::9"])
    assert loop._wedge_since is None
    assert loop._heal_backoff == reconcile._WEDGE_HEAL_MIN


def test_wedge_heal_noop_without_peers(macos):
    from greasewood import reconcile
    loop = reconcile.ReconcileLoop.__new__(reconcile.ReconcileLoop)
    loop._local_id_pub = b"self"
    loop._ensure_iface = lambda: None
    loop._wedge_since = 1.0
    loop._heal_backoff = 999.0
    # only self in trusted → nothing to reach → not a wedge
    loop._maybe_heal_wedged([types.SimpleNamespace(id_pub=b"self")], reachable=[])
    assert loop._wedge_since is None


def test_wedge_heal_is_macos_only():
    """On Linux the check is inert — kernel WireGuard rebinds on its own, and
    the Linux data plane stays byte-identical."""
    from greasewood import reconcile
    loop = reconcile.ReconcileLoop.__new__(reconcile.ReconcileLoop)
    loop._ensure_iface = lambda: None
    loop._local_id_pub = b"self"
    loop._wedge_since = None
    # gwplat.IS_MACOS is False on this (Linux) host → immediate return, no arming
    loop._maybe_heal_wedged([types.SimpleNamespace(id_pub=b"peer")], reachable=[])
    assert loop._wedge_since is None
