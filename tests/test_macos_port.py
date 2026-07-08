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

def test_linux_capabilities_on_this_host():
    # the suite runs on Linux: enforcement available, resolution is identity
    assert gwplat.IS_LINUX
    assert gwplat.port_enforcement_available()
    assert wg.resolve_iface("gw-pm") == "gw-pm"


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
