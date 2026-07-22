"""
Unit tests for greasewood.service — the ServiceManager backend seam.

cli.py's existing systemd tests exercise the same logic through its thin
delegators; these lock down the module's own interface: SystemdManager writes
the hardened template and reports settle state, unit_name/restart_hint carry the
systemd naming, and detect() picks systemd only when systemd is actually
running (the manual path otherwise). This is the surface a second backend
(OpenRC) plugs into.
"""
import shutil as _shutil
import subprocess as _subprocess

import pytest

from greasewood import service


def _which(mapping):
    return lambda name: mapping.get(name)


def test_systemd_manager_writes_hardened_template(tmp_path, monkeypatch):
    monkeypatch.setattr(_shutil, "which",
                        _which({"systemctl": "/bin/systemctl"}))
    monkeypatch.setattr(service.sys, "executable", "/opt/py/bin/python3")
    calls = []
    monkeypatch.setattr(_subprocess, "run",
                        lambda cmd, *a, **k: calls.append(cmd)
                        or _subprocess.CompletedProcess(cmd, 0))
    mgr = service.SystemdManager(unit_dir=tmp_path)
    assert mgr.write_template() == "/bin/systemctl"
    assert ["/bin/systemctl", "daemon-reload"] in calls
    unit = (tmp_path / "greasewood@.service").read_text()
    assert "ExecStart=/opt/py/bin/python3 -m greasewood -c /etc/greasewood_%i.toml run" in unit
    assert "CapabilityBoundingSet=CAP_NET_ADMIN" in unit
    assert "Restart=always" in unit and "WatchdogSec=" in unit


def test_systemd_manager_names_and_hints():
    mgr = service.SystemdManager()
    assert mgr.name == "systemd"
    assert mgr.unit_name("home") == "greasewood@home.service"
    assert mgr.restart_hint("home") == "sudo systemctl restart greasewood@home"


def test_enable_now_manual_without_template(tmp_path, monkeypatch):
    # systemctl present but no installed template → nothing to enable.
    monkeypatch.setattr(_shutil, "which",
                        _which({"systemctl": "/bin/systemctl"}))
    assert service.SystemdManager(unit_dir=tmp_path).enable_now("prod") == "manual"


def test_enable_now_settles(tmp_path, monkeypatch):
    (tmp_path / "greasewood@.service").write_text("template")
    monkeypatch.setattr(_shutil, "which",
                        _which({"systemctl": "/bin/systemctl"}))

    def run(cmd, *a, **k):
        # is-active reports "not yet active" so enable is attempted; enable ok.
        rc = 1 if cmd[:2] == ["/bin/systemctl", "is-active"] else 0
        return _subprocess.CompletedProcess(cmd, rc)
    monkeypatch.setattr(_subprocess, "run", run)
    monkeypatch.setattr(service, "wait_systemd_settled", lambda *a, **k: "active")
    assert service.SystemdManager(unit_dir=tmp_path).enable_now("prod") == "active"


def test_refresh_only_when_installed_and_stale(tmp_path, monkeypatch):
    monkeypatch.setattr(service, "service_exec", lambda: "/usr/local/bin/gw")
    monkeypatch.setattr(service, "systemctl_run",
                        lambda *a, **k: _subprocess.CompletedProcess(a, 0))
    mgr = service.SystemdManager(unit_dir=tmp_path)
    tmpl = tmp_path / "greasewood@.service"
    assert mgr.refresh_template() is False          # none installed → never installs
    assert not tmpl.exists()
    tmpl.write_text("[Service]\nRestart=on-failure\n")
    assert mgr.refresh_template() is True            # stale → rewritten
    assert "Restart=always" in tmpl.read_text()
    assert mgr.refresh_template() is False           # current → untouched


def test_detect_picks_systemd_only_when_running(monkeypatch):
    monkeypatch.setattr(service, "systemd_available", lambda: True)
    mgr = service.detect()
    assert isinstance(mgr, service.SystemdManager)

    monkeypatch.setattr(service, "systemd_available", lambda: False)
    assert service.detect() is None                  # → the manual `gw run` path


def test_detect_honors_unit_dir(monkeypatch, tmp_path):
    monkeypatch.setattr(service, "systemd_available", lambda: True)
    assert service.detect(tmp_path).unit_dir == tmp_path
