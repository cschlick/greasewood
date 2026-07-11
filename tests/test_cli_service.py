"""
Systemd service plumbing. There is no install-service / uninstall-service
command anymore — create/join install the greasewood@ template and enable this
mesh's instance by default (--no-service opts out), and purge removes it. These
tests cover the shared helpers: _write_service_template, _membership_service's
settle-check, and _print_daemon_guidance's default-vs-no-service branches. The
unit dir is redirected via _UNIT_DIR and systemctl/which are stubbed, so nothing
real is touched.
"""
import shutil as _shutil
import subprocess as _subprocess

import pytest

from greasewood import cli


@pytest.fixture
def units(tmp_path, monkeypatch):
    d = tmp_path / "units"
    d.mkdir()
    monkeypatch.setattr(cli, "_UNIT_DIR", d)
    return d


def _which(mapping):
    return lambda name: mapping.get(name)


def _record_run(calls):
    def run(cmd, *a, **k):
        calls.append(cmd)
        return _subprocess.CompletedProcess(cmd, 0)
    return run


def test_write_service_template_is_the_hardened_template(units, monkeypatch):
    monkeypatch.setattr(_shutil, "which",
                        _which({"systemctl": "/bin/systemctl", "gw": "/bin/gw"}))
    # The daemon launches as `<abs-interpreter> -m greasewood`, NOT the `gw`
    # wrapper path — that's what survives a moved/regenerated console script.
    monkeypatch.setattr(cli.sys, "executable", "/opt/py/bin/python3")
    calls = []
    monkeypatch.setattr(_subprocess, "run", _record_run(calls))
    systemctl = cli._write_service_template()
    assert systemctl == "/bin/systemctl"
    assert ["/bin/systemctl", "daemon-reload"] in calls        # reloaded
    unit = (units / "greasewood@.service").read_text()
    assert "ExecStart=/opt/py/bin/python3 -m greasewood -c /etc/greasewood_%i.toml run" in unit
    assert "ConditionPathExists=/etc/greasewood_%i.toml" in unit
    # The hardening block a daemon RCE shouldn't escape.
    for directive in ("NoNewPrivileges=yes",
                      "CapabilityBoundingSet=CAP_NET_ADMIN",
                      "ProtectHome=yes", "PrivateTmp=yes",
                      "RestrictAddressFamilies=AF_INET AF_INET6 AF_NETLINK AF_UNIX"):
        assert directive in unit
    active = [ln.strip() for ln in unit.splitlines()
              if ln.strip() and not ln.lstrip().startswith("#")]
    assert "ProtectSystem=yes" in active                       # not strict/full
    assert not any(d.startswith("ProtectKernelModules") for d in active)


def test_service_exec_prefers_interpreter_module_form(monkeypatch):
    """Stable launch: the concrete interpreter + `-m greasewood`, not `gw`."""
    monkeypatch.setattr(cli.sys, "executable", "/venv/bin/python3")
    assert cli._service_exec() == "/venv/bin/python3 -m greasewood"


def test_service_exec_falls_back_to_gw_when_no_interpreter(monkeypatch):
    """Frozen/embedded interpreter (sys.executable unset) → the gw path."""
    monkeypatch.setattr(cli.sys, "executable", "")
    monkeypatch.setattr(_shutil, "which", _which({"gw": "/usr/local/bin/gw"}))
    assert cli._service_exec() == "/usr/local/bin/gw"


def test_write_service_template_no_systemctl(units, monkeypatch):
    monkeypatch.setattr(_shutil, "which", _which({}))          # no systemctl
    assert cli._write_service_template() is None
    assert (units / "greasewood@.service").exists()            # still written


def test_membership_service_settle_checks(units, monkeypatch):
    """_membership_service enables the instance then verifies it reached AND
    held 'active' — a Type=simple daemon that crashes a second later still
    'starts', so returning 'installed' unconditionally would lie."""
    (units / "greasewood@.service").write_text("template")
    monkeypatch.setattr(_shutil, "which", _which({"systemctl": "/bin/systemctl"}))
    calls = []

    def run(cmd, *a, **k):
        calls.append(cmd)
        rc = 1 if cmd[:2] == ["/bin/systemctl", "is-active"] else 0  # not yet active
        return _subprocess.CompletedProcess(cmd, rc)
    monkeypatch.setattr(_subprocess, "run", run)
    monkeypatch.setattr(cli, "_wait_service_settled", lambda *a, **k: "active")
    assert cli._membership_service("prod") == "active"
    assert ["/bin/systemctl", "enable", "--now", "greasewood@prod.service"] in calls

    monkeypatch.setattr(cli, "_wait_service_settled", lambda *a, **k: "failed")
    assert cli._membership_service("prod") == "failed"


def test_membership_service_manual_without_template(units, monkeypatch):
    monkeypatch.setattr(_shutil, "which", _which({"systemctl": "/bin/systemctl"}))
    assert cli._membership_service("prod") == "manual"         # no template → nothing to do


def test_guidance_default_installs_and_reports(units, monkeypatch, capsys):
    monkeypatch.setattr(cli, "_systemd_available", lambda: True)   # hermetic vs the host
    monkeypatch.setattr(cli, "_write_service_template", lambda *a: "/bin/systemctl")
    monkeypatch.setattr(cli, "_membership_service", lambda key: "active")
    cli._print_daemon_guidance("prod", "/etc/greasewood_prod.toml")
    out = capsys.readouterr().out
    assert "greasewood@prod is running" in out and "starts at boot" in out


def test_guidance_reports_crash(units, monkeypatch, capsys):
    monkeypatch.setattr(cli, "_systemd_available", lambda: True)   # hermetic vs the host
    monkeypatch.setattr(cli, "_write_service_template", lambda *a: "/bin/systemctl")
    monkeypatch.setattr(cli, "_membership_service", lambda key: "failed")
    cli._print_daemon_guidance("prod", "/etc/greasewood_prod.toml")
    out = capsys.readouterr().out
    assert "likely crashing" in out and "journalctl -u greasewood@prod" in out


def test_guidance_no_service_skips_systemd(units, monkeypatch, capsys):
    calls = []
    monkeypatch.setattr(cli, "_write_service_template",
                        lambda *a: calls.append("wrote"))
    cli._print_daemon_guidance("prod", "/etc/greasewood_prod.toml", no_service=True)
    out = capsys.readouterr().out
    assert "sudo gw -c /etc/greasewood_prod.toml run" in out
    assert not calls                                           # template NOT written


def test_permission_error_as_root_names_the_ownership_fix(monkeypatch):
    """EACCES while ALREADY root (sandboxed unit + non-root-owned key) must not
    say 'try sudo' — it must name the chown fix."""
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)

    def boom(args):
        raise PermissionError(13, "Permission denied", "/var/lib/greasewood/ca.key")
    monkeypatch.setattr(cli, "cmd_watch", boom)
    with pytest.raises(SystemExit) as e:
        cli.main(["-c", "/tmp/x.toml", "watch"])
    msg = str(e.value)
    assert "AS ROOT" in msg and "CAP_DAC_OVERRIDE" in msg
    assert "chown root:root /var/lib/greasewood/ca.key" in msg
