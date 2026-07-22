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


def test_openrc_script_is_valid_posix_sh(tmp_path):
    """The rendered init script must be valid POSIX sh. This test runs on every
    CI distro leg, so on the alpine:latest leg it validates against busybox ash
    — the shell the script actually runs under on Alpine — not just bash. Skips
    the openrc-run shebang line, which is not a real sh interpreter."""
    sh = _shutil.which("sh")
    if sh is None:
        pytest.skip("no sh on this host")
    body = "\n".join(
        service.render_openrc_script("/usr/local/bin/gw").splitlines()[1:])
    script = tmp_path / "rc_body.sh"
    script.write_text(body)
    r = _subprocess.run([sh, "-n", str(script)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr


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


# --- OpenRC backend --------------------------------------------------------

def test_render_openrc_splits_command_and_args():
    # interpreter-module launch form → command is the interpreter, args carry -m
    s = service.render_openrc_script("/opt/py/bin/python3 -m greasewood")
    assert 'command="/opt/py/bin/python3"' in s
    assert 'command_args="-m greasewood -c /etc/greasewood_${mesh}.toml run"' in s
    # bare gw → no args prefix
    s2 = service.render_openrc_script("/usr/local/bin/gw")
    assert 'command="/usr/local/bin/gw"' in s2
    assert 'command_args="-c /etc/greasewood_${mesh}.toml run"' in s2
    # supervise-daemon + a bounded respawn (the Restart=always / start-limit analog)
    assert "supervisor=supervise-daemon" in s2
    assert "respawn_max=5" in s2 and "respawn_period=120" in s2


def test_openrc_manager_writes_executable_script(tmp_path, monkeypatch):
    import os as _os
    monkeypatch.setattr(_shutil, "which", _which({"rc-service": "/sbin/rc-service"}))
    monkeypatch.setattr(service.sys, "executable", "/opt/py/bin/python3")
    mgr = service.OpenRCManager(init_dir=tmp_path)
    assert mgr.write_template() == "/sbin/rc-service"
    script = tmp_path / "greasewood"
    assert script.exists() and (_os.stat(script).st_mode & 0o111)   # executable
    assert "openrc-run" in script.read_text()


def test_openrc_manager_names_and_hints():
    mgr = service.OpenRCManager()
    assert mgr.name == "openrc"
    assert mgr.unit_name("home") == "greasewood.home"
    assert mgr.restart_hint("home") == "sudo rc-service greasewood.home restart"


def test_enable_openrc_manual_without_base_script(tmp_path, monkeypatch):
    monkeypatch.setattr(_shutil, "which", _which({"rc-service": "/sbin/rc-service"}))
    assert service.OpenRCManager(init_dir=tmp_path).enable_now("prod") == "manual"


def test_enable_openrc_links_enables_and_starts(tmp_path, monkeypatch):
    (tmp_path / "greasewood").write_text("#!/sbin/openrc-run\n")
    monkeypatch.setattr(_shutil, "which", _which({"rc-service": "/sbin/rc-service"}))
    calls = []

    def run(cmd, *a, **k):
        calls.append(cmd)
        # status reports "not started" (rc=3) so we proceed to enable+start
        rc = 3 if cmd[:1] == ["rc-service"] and cmd[2:] == ["status"] else 0
        return _subprocess.CompletedProcess(cmd, rc)
    monkeypatch.setattr(service, "rc_run", run)
    monkeypatch.setattr(service, "wait_openrc_started", lambda *a, **k: "active")
    assert service.OpenRCManager(init_dir=tmp_path).enable_now("prod") == "active"
    assert (tmp_path / "greasewood.prod").is_symlink()
    assert ["rc-update", "add", "greasewood.prod", "default"] in calls
    assert ["rc-service", "greasewood.prod", "start"] in calls


def test_enable_openrc_short_circuits_when_already_started(tmp_path, monkeypatch):
    (tmp_path / "greasewood").write_text("#!/sbin/openrc-run\n")
    monkeypatch.setattr(_shutil, "which", _which({"rc-service": "/sbin/rc-service"}))
    # status rc=0 → already running; never touches rc-update / start
    monkeypatch.setattr(service, "rc_run",
                        lambda cmd, *a, **k: _subprocess.CompletedProcess(cmd, 0))
    assert service.OpenRCManager(init_dir=tmp_path).enable_now("prod") == "active"
    assert not (tmp_path / "greasewood.prod").exists()


def test_openrc_refresh_only_when_installed_and_stale(tmp_path, monkeypatch):
    monkeypatch.setattr(service, "service_exec", lambda: "/usr/local/bin/gw")
    mgr = service.OpenRCManager(init_dir=tmp_path)
    script = tmp_path / "greasewood"
    assert mgr.refresh_template() is False           # none installed → never installs
    assert not script.exists()
    script.write_text("#!/sbin/openrc-run\n# stale\n")
    assert mgr.refresh_template() is True             # differs → rewritten
    assert "supervise-daemon" in script.read_text()
    assert mgr.refresh_template() is False            # current → untouched


def test_systemd_disable_and_remove_template(tmp_path, monkeypatch):
    (tmp_path / "greasewood@.service").write_text("template")
    monkeypatch.setattr(_shutil, "which", _which({"systemctl": "/bin/systemctl"}))
    calls = []
    # is-active rc=0 (was running) so disable_now reports True
    monkeypatch.setattr(service, "systemctl_run",
                        lambda cmd, *a, **k: calls.append(cmd)
                        or _subprocess.CompletedProcess(cmd, 0))
    mgr = service.SystemdManager(unit_dir=tmp_path)
    assert mgr.template_installed() is True
    assert mgr.disable_now("prod") is True
    assert ["/bin/systemctl", "disable", "--now", "greasewood@prod.service"] in calls
    assert mgr.remove_template() is True
    assert not (tmp_path / "greasewood@.service").exists()
    assert mgr.remove_template() is False            # already gone → nothing to do


def test_openrc_disable_stops_deboots_and_unlinks(tmp_path, monkeypatch):
    (tmp_path / "greasewood").write_text("#!/sbin/openrc-run\n")
    (tmp_path / "greasewood.prod").symlink_to("greasewood")
    monkeypatch.setattr(_shutil, "which", _which({"rc-service": "/sbin/rc-service"}))
    calls = []
    monkeypatch.setattr(service, "rc_run",
                        lambda cmd, *a, **k: calls.append(cmd)
                        or _subprocess.CompletedProcess(cmd, 0))
    mgr = service.OpenRCManager(init_dir=tmp_path)
    assert mgr.disable_now("prod") is True           # status rc=0 → was running
    assert ["rc-service", "greasewood.prod", "stop"] in calls
    assert ["rc-update", "del", "greasewood.prod"] in calls
    assert not (tmp_path / "greasewood.prod").exists()   # instance symlink removed


def test_openrc_remove_and_template_installed(tmp_path):
    mgr = service.OpenRCManager(init_dir=tmp_path)
    assert mgr.template_installed() is False
    (tmp_path / "greasewood").write_text("#!/sbin/openrc-run\n")
    assert mgr.template_installed() is True
    assert mgr.template_name() == str(tmp_path / "greasewood")
    assert mgr.remove_template() is True
    assert not (tmp_path / "greasewood").exists()


def test_detect_falls_back_to_openrc(monkeypatch):
    monkeypatch.setattr(service, "systemd_available", lambda: False)
    monkeypatch.setattr(service, "openrc_available", lambda: True)
    assert isinstance(service.detect(), service.OpenRCManager)

    monkeypatch.setattr(service, "openrc_available", lambda: False)
    assert service.detect() is None                  # neither → manual path
