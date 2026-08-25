"""
The macOS port, tested from Linux (or anywhere): platform detection,
logical-name → utun resolution, and the exact commands the Darwin backend
renders (subprocess is mocked — real runtime behavior is verified on a Mac).
The Linux paths are covered by the rest of the suite, which the conftest pins
to IS_LINUX; these tests opt in to Darwin explicitly.

Revived from tag macos-port-archive after the Lima-VM approach was abandoned
(tag lima-era-archive).
"""
import subprocess as _subprocess

import pytest

from greasewood import platform as gwplat
from greasewood import wg


@pytest.fixture
def macos(monkeypatch, tmp_path):
    """Flip the platform seam to Darwin and sandbox the wireguard run dir.
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


def _recorder(monkeypatch, stdout=""):
    calls = []
    def fake_run(*args, check=True, env=None, input=None):
        calls.append(list(args))
        return _subprocess.CompletedProcess(args, 0, stdout, "")
    monkeypatch.setattr(wg, "_run", fake_run)
    return calls


# ---------------------------------------------------------------------------
# platform module
# ---------------------------------------------------------------------------

def test_linux_capabilities_under_the_suite_pin():
    # The conftest pins the seam to Linux for the rest of the suite — assert
    # the pinned world is the Linux one.
    assert gwplat.port_enforcement_available()
    assert wg.resolve_iface("gw-pm") == "gw-pm"       # identity on Linux
    assert wg._required_tools() == ("wg", "ip")


def test_macos_capabilities(macos):
    assert not gwplat.port_enforcement_available()    # pf backend not built
    assert wg._required_tools() == ("wg", "wireguard-go")


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
    _recorder(monkeypatch)
    assert not wg.interface_exists("gw-pm")           # unresolved → doesn't exist
    _wire(macos)
    assert wg.interface_exists("gw-pm")


# ---------------------------------------------------------------------------
# command rendering (what the Darwin backend actually runs)
# ---------------------------------------------------------------------------

def test_set_peer_renders_wg_on_utun_and_route_commands(macos, monkeypatch):
    dev = _wire(macos)
    calls = _recorder(monkeypatch)
    wg.set_peer("gw-pm", "PUB=", "fd8d::9", endpoint="[2001:db8::1]:51900")
    flat = [" ".join(c) for c in calls]
    assert any(f.startswith(f"wg set {dev} peer PUB=") for f in flat)  # utun, not gw-pm
    assert "route -q -n delete -inet6 fd8d::9/128" in flat             # replace =
    assert f"route -q -n add -inet6 fd8d::9/128 -interface {dev}" in flat  # del + add
    assert not any(f.startswith("ip ") for f in flat)                  # no iproute2


def test_remove_peer_deletes_route(macos, monkeypatch):
    dev = _wire(macos)
    calls = _recorder(monkeypatch)
    wg.remove_peer("gw-pm", "PUB=", allowed_ips="fd8d::9")
    flat = [" ".join(c) for c in calls]
    assert f"wg set {dev} peer PUB= remove" in flat
    assert "route -q -n delete -inet6 fd8d::9/128" in flat


def test_ensure_interface_spawns_wireguard_go_and_self_routes(macos, monkeypatch,
                                                              tmp_path):
    calls = []
    def fake_run(*args, check=True, env=None, input=None):
        calls.append(list(args))
        if args[0] == "wireguard-go":
            # the daemon writes its claimed utun into WG_TUN_NAME_FILE
            _wire(macos, "gw-pm", "utun9")
        return _subprocess.CompletedProcess(args, 0, "", "")
    monkeypatch.setattr(wg, "_run", fake_run)
    key = tmp_path / "wg.key"
    key.write_text("PRIVKEY=\n")
    wg.ensure_interface("gw-pm", "fd8d::1", 51900, key)
    flat = [" ".join(c) for c in calls]
    assert flat[0] == "wireguard-go utun"
    assert "wg set utun9 private-key /dev/stdin listen-port 51900" in flat
    assert "ifconfig utun9 inet6 fd8d::1 prefixlen 128 alias" in flat
    assert "route -q -n add -inet6 fd8d::1/128 -interface lo0" in flat  # self route
    assert "ifconfig utun9 up" in flat
    assert not any(f.startswith("ip ") for f in flat)


def test_port_in_use_remedy_names_the_socket(macos, monkeypatch, tmp_path):
    _wire(macos, "gw-pm", "utun3")
    def fake_run(*args, check=True, env=None, input=None):
        if args[0] == "wg" and "private-key" in args:
            return _subprocess.CompletedProcess(args, 1, "", "address already in use")
        if list(args[:3]) == ["wg", "show", "interfaces"]:
            return _subprocess.CompletedProcess(args, 0, "utun3 utun8\n", "")
        return _subprocess.CompletedProcess(args, 0, "", "")
    monkeypatch.setattr(wg, "_run", fake_run)
    monkeypatch.setattr(wg, "_wg_iface_on_port", lambda port, exclude="": "utun8")
    key = tmp_path / "wg.key"
    key.write_text("PRIVKEY=\n")
    with pytest.raises(wg.PortInUse) as e:
        wg.ensure_interface("gw-pm", "fd8d::1", 51900, key)
    assert "rm /var/run/wireguard/utun8.sock" in str(e.value)


def test_destroy_removes_socket_and_namefile(macos):
    dev = _wire(macos)
    wg.destroy_interface("gw-pm")
    # removing the UAPI socket is how wireguard-go is told to exit
    assert not (macos / f"{dev}.sock").exists()
    assert not (macos / "gw-pm.name").exists()
    wg.destroy_interface("gw-pm")                     # idempotent


def test_rename_moves_the_namefile_only(macos):
    dev = _wire(macos, "gw-old")
    wg.rename_interface("gw-old", "gw-new")
    assert wg.resolve_iface("gw-new") == dev          # same utun, new logical name
    assert wg.resolve_iface("gw-old") is None


def test_get_peers_returns_none_when_unresolved(macos):
    # interface not up → None (the "dump failed" signal), never a false empty
    assert wg.get_peers("gw-pm") is None


# ---------------------------------------------------------------------------
# door isolation: forwarding-off assertion instead of policy routing
# ---------------------------------------------------------------------------

def test_door_routing_asserts_forwarding_off(macos, monkeypatch, caplog):
    import logging
    state = {"cmd": None, "val": "0\n"}
    def fake_run(*args, check=True, env=None, input=None):
        state["cmd"] = list(args)
        return _subprocess.CompletedProcess(args, 0, state["val"], "")
    monkeypatch.setattr(wg, "_run", fake_run)

    with caplog.at_level(logging.INFO, logger="greasewood.wg"):
        wg.setup_door_routing()                       # forwarding off → quiet
    assert state["cmd"] == ["sysctl", "-n", "net.inet6.ip6.forwarding"]
    assert not any(r.levelno >= logging.WARNING for r in caplog.records)

    caplog.clear()
    state["val"] = "1\n"                              # forwarding ON → loud warning
    with caplog.at_level(logging.WARNING, logger="greasewood.wg"):
        wg.setup_door_routing()
    assert any("forwarding is ENABLED" in r.message for r in caplog.records)


def test_door_routing_teardown_is_noop(macos, monkeypatch):
    calls = _recorder(monkeypatch)
    wg.teardown_door_routing()
    assert calls == []                                # nothing persisted, nothing to undo


def test_door_interfaces_use_primitives_not_iproute2(macos, monkeypatch, tmp_path):
    calls = []
    def fake_run(*args, check=True, env=None, input=None):
        calls.append(list(args))
        if args[0] == "wireguard-go":
            _wire(macos, "gw-door", "utun5")
        return _subprocess.CompletedProcess(args, 0, "", "")
    monkeypatch.setattr(wg, "_run", fake_run)
    key = tmp_path / "door.key"
    key.write_text("DOORKEY=\n")
    wg.ensure_anchor_door_interface(key, "GUESTPUB=", "PSK=")
    flat = [" ".join(c) for c in calls]
    assert not any(f.startswith("ip ") for f in flat)
    assert any(f.startswith("wg set utun5 private-key") for f in flat)
    assert any("-interface utun5" in f for f in flat)  # guest /128 route via utun


# ---------------------------------------------------------------------------
# cli detection via ifconfig + route (Stage 4)
# ---------------------------------------------------------------------------

_IFCONFIG = """\
lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384
\tinet6 ::1 prefixlen 128
\tinet6 fe80::1%lo0 prefixlen 64 scopeid 0x1
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\tinet 192.168.1.23 netmask 0xffffff00 broadcast 192.168.1.255
\tinet 185.199.108.1 netmask 0xffffff00 broadcast 185.199.108.255
\tinet6 fe80::1c5e%en0 prefixlen 64 secured scopeid 0xb
\tinet6 2001:db8:15::7a prefixlen 64 autoconf secured
\tinet6 2001:db8:15::99 prefixlen 64 autoconf temporary
\tinet6 fd00:aaaa::5 prefixlen 64 autoconf secured
"""


def _fake_cmd(monkeypatch, table):
    """Route cli's subprocess.run by argv[0] (+ first args) through `table`."""
    import subprocess as sp
    from greasewood import cli
    def fake_run(argv, **kw):
        for prefix, (rc, out) in table.items():
            if tuple(argv[:len(prefix)]) == prefix:
                return sp.CompletedProcess(argv, rc, out, "")
        return sp.CompletedProcess(argv, 1, "", "not scripted")
    monkeypatch.setattr(cli.subprocess, "run", fake_run)


def test_detect_public_ipv6_parses_ifconfig(macos, monkeypatch):
    from greasewood import cli
    _fake_cmd(monkeypatch, {("ifconfig", "-a"): (0, _IFCONFIG)})
    # stable GUA wins over the temporary one; ULA + link-local excluded
    assert cli._detect_public_ipv6() == "2001:db8:15::7a"


def test_detect_public_ipv4_parses_ifconfig(macos, monkeypatch):
    from greasewood import cli
    _fake_cmd(monkeypatch, {("ifconfig", "-a"): (0, _IFCONFIG)})
    # the RFC1918 inet is skipped; the truly-global one wins (doc ranges
    # like 203.0.113/24 would be rejected by _globally_reachable_v4)
    assert cli._detect_public_ipv4() == "185.199.108.1"


def test_local_families_via_route_get(macos, monkeypatch):
    from greasewood import cli
    _fake_cmd(monkeypatch, {
        ("route", "-n", "get", "-inet6", "default"): (0, "   gateway: fe80::1\n"),
        ("route", "-n", "get", "default"): (1, "route: not in table\n"),
    })
    assert cli._local_families() == {6}


def test_enforce_ports_defaults_off_on_macos(macos, caplog):
    import logging
    from greasewood import cli
    with caplog.at_level(logging.WARNING, logger="greasewood"):
        assert cli._enforce_ports_default() is False
    assert any("pf backend" in r.message for r in caplog.records)


def test_require_supported_accepts_macos(macos):
    gwplat.require_supported()                       # must not exit


def test_firewall_help_macos_says_nothing_to_configure(macos, capsys):
    from greasewood import cli
    cli._print_firewall_help(51900, role="node")
    out = capsys.readouterr().out
    assert "runs no packet filter" in out          # (wraps across lines)
    assert "nftables" not in out.split("pf backend")[0]   # no nft rules offered


# ---------------------------------------------------------------------------
# status probes (Stage 4)
# ---------------------------------------------------------------------------

def test_ping_rtt_uses_ping6_on_macos(macos, monkeypatch):
    import subprocess as sp
    from greasewood import status
    seen = {}
    def fake_run(argv, **kw):
        seen["argv"] = list(argv)
        return sp.CompletedProcess(argv, 0, "time=12.5 ms", "")
    monkeypatch.setattr(status.subprocess, "run", fake_run)
    assert status._ping_rtt("fd8d::1") == "12ms"
    assert seen["argv"][0] == "ping6"


def test_iface_mtu_resolves_utun_and_parses_ifconfig(macos, monkeypatch):
    import subprocess as sp
    from greasewood import status, wg
    _wire(macos, "gw-pm", "utun2")
    def fake_run(argv, **kw):
        assert argv == ["ifconfig", "utun2"]
        return sp.CompletedProcess(argv, 0,
            "utun2: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1420\n", "")
    monkeypatch.setattr(status.subprocess, "run", fake_run)
    assert status._iface_mtu("gw-pm") == 1420
    assert status._iface_mtu("gw-absent") is None     # unresolved → None


def test_mtu_probe_unavailable_on_macos(macos):
    from greasewood import status
    assert status._ping6_df("fd8d::1", 1372) is None  # no DF knob → quiet skip


def test_self_firewall_verdict_macos(macos):
    from greasewood import status
    assert "no packet filter" in status._self_firewall_verdict(51900)
