"""
`gw run`'s port-enforcement decision (_make_port_enforcer).

The load-bearing guarantee: an nft-less host must NOT crash-loop. A previous
version sys.exit()'d when enforce_ports=true but nftables was unusable, which
under systemd is an endless restart loop. Now it degrades to unenforced (None)
with a loud error. Paired with create/join writing enforce_ports=false on an
nft-less host, a freshly-set-up node never even reaches the degrade path.
"""
import types

from greasewood import cli
from greasewood import portfilter as pf


def _cfg(enforce_ports=True):
    return types.SimpleNamespace(
        enforce_ports=enforce_ports, wg_interface="gw-pm",
        mesh_domain="pm.internal", caps=["role:mesh"], hostname="pm-node",
        control_listen=":51902",
        data_dir="/nonexistent-gw-test")   # H2 breadcrumb writes here; no-op if unwritable


def _args():
    return types.SimpleNamespace(config="/etc/greasewood_pm.toml")


def test_enforce_on_but_no_nft_degrades_not_exits(monkeypatch):
    # THE regression: enforce requested, nftables missing → return None, no exit.
    monkeypatch.setattr(pf.shutil, "which", lambda n: None)
    enforcer = cli._make_port_enforcer(_cfg(enforce_ports=True), _args(), None)
    assert enforcer is None            # degraded, did not raise SystemExit


def test_enforce_off_returns_none(monkeypatch):
    # Explicitly off: never touches nftables at all.
    called = []
    monkeypatch.setattr(pf, "ensure_available",
                        lambda: called.append(True))
    enforcer = cli._make_port_enforcer(_cfg(enforce_ports=False), _args(), None)
    assert enforcer is None and called == []


def test_no_enforce_ports_flag_overrides_config(monkeypatch):
    # --no-enforce-ports wins over enforce_ports=true for this run.
    monkeypatch.setattr(pf, "ensure_available",
                        lambda: (_ for _ in ()).throw(AssertionError("probed")))
    args = types.SimpleNamespace(config="/x", no_enforce_ports=True)
    assert cli._make_port_enforcer(_cfg(enforce_ports=True), args, None) is None


def test_enforce_on_with_nft_builds_enforcer(monkeypatch):
    # Happy path: nft usable → a real PortFilter scoped to this membership.
    monkeypatch.setattr(pf, "ensure_available", lambda: None)
    enforcer = cli._make_port_enforcer(_cfg(enforce_ports=True), _args(), None)
    assert isinstance(enforcer, pf.PortFilter)
    assert enforcer._table == "greasewood_pm"     # per-membership table
