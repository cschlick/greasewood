"""
gw watch's host-firewall check (_main_firewall_lines) — the replacement for the
removed `gw firewall` subcommand. It reuses firewall.py's reasoning; here we mock
the nft layer to exercise the verdicts. A node needs the mesh UDP port + the
coarse `gw-*` overlay admit; an anchor also needs the door port. When something's
blocked the complaint carries the exact nft rule to fix it.
"""
import subprocess
import types

from greasewood import status, firewall


def _rs(*items):
    return {"nftables": list(items)}


_DROP_INPUT = {"chain": {"hook": "input", "policy": "drop"}}
_ACCEPT_INPUT = {"chain": {"hook": "input", "policy": "accept"}}


def _accept(proto, port):
    return {"rule": {"expr": [
        {"match": {"left": {"payload": {"protocol": proto, "field": "dport"}},
                   "right": port}},
        {"accept": None}]}}


def _admit_iface(pat="gw-*"):
    return {"rule": {"expr": [
        {"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": pat}},
        {"accept": None}]}}


def _cfg(role="node", enforce=True):
    return types.SimpleNamespace(role=role, listen_port=51900, wg_interface="gw-pm",
                                 enforce_ports=enforce, mesh_domain="pm.internal",
                                 control_listen=":51902")


def _nft_present(monkeypatch, ruleset, raw=""):
    monkeypatch.setattr(status.shutil, "which", lambda n: "/usr/sbin/nft")
    monkeypatch.setattr(firewall, "_load_ruleset", lambda: ruleset)
    monkeypatch.setattr(status.subprocess, "run",
                        lambda *a, **k: subprocess.CompletedProcess(a, 0, stdout=raw, stderr=""))


def test_omitted_when_nft_not_installed(monkeypatch):
    monkeypatch.setattr(status.shutil, "which", lambda n: None)
    assert status._main_firewall_lines(_cfg()) == []


def test_node_allowed_needs_mesh_port_plus_overlay_only(monkeypatch):
    _nft_present(monkeypatch, _rs(_DROP_INPUT, _accept("udp", 51900), _admit_iface()),
                 raw="        udp dport 51900 accept\n        iifname \"gw-*\" accept")
    lines = status._main_firewall_lines(_cfg("node"))
    assert "allowed ✓" in lines[0]
    assert "udp/51900" in lines[0] and "gw-*" in lines[0]
    assert "51901" not in lines[0]              # a plain node doesn't need the door port


def test_anchor_checks_door_port_and_gives_fix_rule_when_blocked(monkeypatch):
    # default-drop; mesh port + overlay admitted, but the door port (51901) is not.
    _nft_present(monkeypatch, _rs(_DROP_INPUT, _accept("udp", 51900), _admit_iface()))
    lines = status._main_firewall_lines(_cfg("anchor"))
    assert "⚠" in lines[0] and "BLOCKED" in lines[0] and "UNREACHABLE" in lines[0]
    assert "udp/51901" in lines[0]              # names the blocked door port
    # the loud complaint carries the exact nft rule to add:
    assert any(l.strip() == "udp dport 51901 accept   # enrollment door (WireGuard)"
               for l in lines)


def test_overlay_not_admitted_is_flagged_with_fix(monkeypatch):
    # ports open, but no coarse `iifname gw-* accept` → overlay dropped before our
    # table sees it. Flag it AND print the admit rule to add.
    _nft_present(monkeypatch, _rs(_DROP_INPUT, _accept("udp", 51900)))
    lines = status._main_firewall_lines(_cfg("node"))
    assert "gw-* overlay" in lines[0] and "BLOCKED" in lines[0]
    assert any('iifname "gw-*" accept' in l for l in lines)   # the fix rule


def test_not_default_drop_is_fine(monkeypatch):
    _nft_present(monkeypatch, _rs(_ACCEPT_INPUT))
    line0 = status._main_firewall_lines(_cfg("node"))[0]
    assert "ACCEPT" in line0 and "not blocked ✓" in line0


def test_unreadable_ruleset_points_at_root(monkeypatch):
    monkeypatch.setattr(status.shutil, "which", lambda n: "/usr/sbin/nft")
    monkeypatch.setattr(firewall, "_load_ruleset", lambda: None)
    assert "sudo gw watch" in status._main_firewall_lines(_cfg())[0]


def test_verdict_is_line0_so_collapse_keeps_it_visible(monkeypatch):
    # `f`-collapse keeps only line 0, so the loud BLOCKED verdict must be it.
    _nft_present(monkeypatch, _rs(_DROP_INPUT))   # nothing accepted at all
    assert status._main_firewall_lines(_cfg("node"))[0].startswith("main firewall : ⚠")
