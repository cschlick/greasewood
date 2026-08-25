"""
The launchd ServiceManager backend, tested from anywhere (launchctl is mocked;
the plist rendering and bootstrap choreography are what's pinned — the real
runtime behavior is verified on a Mac). Revived from tag macos-port-archive,
reshaped onto the ServiceManager interface that postdates it.
"""
import plistlib
import subprocess as _subprocess

import pytest

from greasewood import platform as gwplat
from greasewood import service


@pytest.fixture
def macos(monkeypatch, tmp_path):
    """Darwin platform + sandboxed launchd dirs + no-op chown/sleep."""
    monkeypatch.setattr(gwplat, "IS_MACOS", True)
    monkeypatch.setattr(gwplat, "IS_LINUX", False)
    monkeypatch.setattr(service, "LAUNCHD_DIR", tmp_path / "LaunchDaemons")
    monkeypatch.setattr(service, "LAUNCHD_LOG_DIR", tmp_path / "log")
    monkeypatch.setattr(service.os, "chown", lambda *a, **k: None)
    monkeypatch.setattr(service.shutil, "which",
                        lambda n: "/bin/launchctl" if n == "launchctl" else None)
    return tmp_path


class _Launchctl:
    """Scripted launchctl that models load state: bootout unloads, a successful
    bootstrap loads. Without that modeling, install's bounded unload-wait
    (real time, no-op injected sleep) busy-spins recording calls — the mock
    must 404 the label after bootout exactly as launchd does."""

    def __init__(self, running=True, bootstrap_rc=0):
        self.calls = []
        self.running = running            # state once loaded
        self.bootstrap_rc = bootstrap_rc
        self.loaded = True

    def __call__(self, argv, **kw):
        self.calls.append(list(argv))
        cmd = argv[0]
        if cmd == "bootout":
            self.loaded = False
            return _subprocess.CompletedProcess(argv, 0, "", "")
        if cmd == "bootstrap":
            if self.bootstrap_rc == 0:
                self.loaded = True
            return _subprocess.CompletedProcess(argv, self.bootstrap_rc, "", "")
        if cmd == "print":
            if not self.loaded:
                return _subprocess.CompletedProcess(argv, 113, "", "not found")
            out = "state = running" if self.running else "state = waiting"
            return _subprocess.CompletedProcess(argv, 0, out, "")
        return _subprocess.CompletedProcess(argv, 0, "", "")


def _install(key="home", **launchctl_kw):
    lc = _Launchctl(**launchctl_kw)
    state = service.launchd_install(key, run=lc, sleep=lambda s: None)
    return state, lc


# ---------------------------------------------------------------------------
# plist rendering
# ---------------------------------------------------------------------------

def test_plist_contents(macos):
    d = plistlib.loads(service.render_launchd_plist(
        "home", "/etc/greasewood_home.toml", ["/opt/py", "-m", "greasewood"]))
    assert d["Label"] == "com.greasewood.home"
    assert d["ProgramArguments"] == ["/opt/py", "-m", "greasewood",
                                     "-c", "/etc/greasewood_home.toml", "run"]
    assert d["RunAtLoad"] is True and d["KeepAlive"] is True
    assert "/opt/homebrew/bin" in d["EnvironmentVariables"]["PATH"]
    assert d["StandardOutPath"].endswith("home.log")
    assert d["ThrottleInterval"] == 5


def test_plist_defaults_to_interpreter_module_form(macos, monkeypatch):
    monkeypatch.setattr(service.sys, "executable", "/venv/bin/python")
    d = plistlib.loads(service.render_launchd_plist("home", "/etc/gw.toml"))
    assert d["ProgramArguments"][:3] == ["/venv/bin/python", "-m", "greasewood"]


def test_label_and_config_derivation(macos):
    assert service.launchd_label("home") == "com.greasewood.home"
    assert str(service.launchd_plist_path("home")).endswith(
        "LaunchDaemons/com.greasewood.home.plist")
    assert str(service.launchd_config_path("home")) == "/etc/greasewood_home.toml"


# ---------------------------------------------------------------------------
# install choreography
# ---------------------------------------------------------------------------

def test_install_writes_plist_and_bootstraps(macos):
    state, lc = _install(running=True)
    assert state == "active"
    assert service.launchd_plist_path("home").exists()
    flat = [" ".join(c) for c in lc.calls]
    assert flat[0] == "bootout system/com.greasewood.home"   # re-bootstrap: out first
    assert any(c[0] == "bootstrap" for c in lc.calls)
    assert "kickstart -k system/com.greasewood.home" in flat  # deterministic start


def test_install_reports_failed_when_job_never_runs(macos):
    state, _ = _install(running=False)
    assert state == "failed"


def test_install_manual_when_bootstrap_never_succeeds(macos):
    state, lc = _install(bootstrap_rc=5)
    assert state == "manual"
    assert sum(1 for c in lc.calls if c[0] == "bootstrap") == 4   # the retry loop


def test_install_manual_when_not_macos(monkeypatch):
    # conftest pins Linux; launchd must refuse to pretend
    assert service.launchd_install("home") == "manual"


def test_remove_boots_out_and_unlinks(macos):
    service.LAUNCHD_DIR.mkdir(parents=True)
    service.launchd_plist_path("home").write_bytes(b"x")
    lc = _Launchctl()
    assert service.launchd_remove("home", run=lc)
    assert not service.launchd_plist_path("home").exists()
    assert ["bootout", "system/com.greasewood.home"] in lc.calls
    service.launchd_remove("home", run=_Launchctl())              # idempotent


# ---------------------------------------------------------------------------
# refresh (self-heal) + the ServiceManager face
# ---------------------------------------------------------------------------

def test_refresh_rewrites_stale_interpreter(macos, monkeypatch):
    service.LAUNCHD_DIR.mkdir(parents=True)
    stale = service.render_launchd_plist("home", "/etc/greasewood_home.toml",
                                         ["/old/python", "-m", "greasewood"])
    service.launchd_plist_path("home").write_bytes(stale)
    monkeypatch.setattr(service.sys, "executable", "/new/python")
    assert service.refresh_launchd_plists() is True
    d = plistlib.loads(service.launchd_plist_path("home").read_bytes())
    assert d["ProgramArguments"][0] == "/new/python"
    assert d["ProgramArguments"][-2] == "/etc/greasewood_home.toml"  # cfg kept
    assert service.refresh_launchd_plists() is False                  # steady state


def test_detect_prefers_launchd_on_macos(macos):
    mgr = service.detect()
    assert isinstance(mgr, service.LaunchdManager)
    assert mgr.name == "launchd"


def test_manager_hints_are_launchctl_shaped(macos):
    mgr = service.LaunchdManager(service.LAUNCHD_DIR)
    assert mgr.unit_name("home") == "com.greasewood.home"
    assert "kickstart -k" in mgr.restart_hint("home")
    assert "bootout" in mgr.stop_hint("home")
    assert "tail" in mgr.logs_hint("home") and "home.log" in mgr.logs_hint("home")
    assert mgr.write_template() == "launchd"
    assert mgr.remove_template() is False              # nothing shared exists
    assert not mgr.template_installed()
    service.LAUNCHD_DIR.mkdir(parents=True)
    service.launchd_plist_path("home").write_bytes(b"x")
    assert mgr.template_installed()


def test_linux_detect_unaffected():
    # under the suite's Linux pin, launchd must never win detection
    assert not service.launchd_available()
