"""
Unit tests for `gw install-service` / `gw uninstall-service` (the pip-only,
no-Ansible service story). The unit dir is redirected to a tmp path via the
_UNIT_DIR constant, and systemctl/shutil.which are stubbed, so nothing under
/etc/systemd/system or the real systemctl is touched.
"""
import shutil as _shutil
import subprocess as _subprocess
import types

import pytest

from greasewood import cli


@pytest.fixture
def as_root(monkeypatch):
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)


def _which(mapping):
    return lambda name: mapping.get(name)


def _record_run(calls):
    def run(cmd, *a, **k):
        calls.append(cmd)
        return _subprocess.CompletedProcess(cmd, 0)
    return run


def test_install_requires_root(monkeypatch):
    monkeypatch.setattr(cli.os, "geteuid", lambda: 1000)
    with pytest.raises(SystemExit):
        cli.cmd_install_service(types.SimpleNamespace(exec=None, no_enable=False))


def test_install_writes_template_when_no_systemctl(tmp_path, monkeypatch, as_root):
    monkeypatch.setattr(cli, "_UNIT_DIR", tmp_path)
    monkeypatch.setattr(_shutil, "which", _which({}))  # no gw, no systemctl
    rc = cli.cmd_install_service(
        types.SimpleNamespace(exec="/usr/local/bin/gw", no_enable=False))
    assert rc == 0
    body = (tmp_path / "greasewood@.service").read_text()
    assert "ExecStart=/usr/local/bin/gw -c /etc/greasewood_%i.toml run" in body


def test_installed_unit_is_sandboxed(tmp_path, monkeypatch, as_root):
    """The installed service must carry the hardening block: a daemon RCE
    shouldn't own the box. Checks the directives that are safe for a root
    CAP_NET_ADMIN daemon that shells to ip/wg/nft and writes /etc/hosts."""
    monkeypatch.setattr(cli, "_UNIT_DIR", tmp_path)
    monkeypatch.setattr(_shutil, "which", _which({}))
    cli.cmd_install_service(
        types.SimpleNamespace(exec="/usr/local/bin/gw", no_enable=False))
    unit = (tmp_path / "greasewood@.service").read_text()
    for directive in [
        "NoNewPrivileges=yes",
        "CapabilityBoundingSet=CAP_NET_ADMIN",
        "ProtectHome=yes",
        "PrivateTmp=yes",
        "RestrictAddressFamilies=AF_INET AF_INET6 AF_NETLINK AF_UNIX",
    ]:
        assert directive in unit, f"missing hardening directive: {directive}"
    # strict would break the daemon's own /etc/hosts write (temp+lock siblings
    # in /etc); ProtectSystem must be the compatible 'yes', not 'strict'/'full'.
    # Check active directive lines only (the rationale comment mentions strict).
    directives = [ln.strip() for ln in unit.splitlines()
                  if ln.strip() and not ln.lstrip().startswith("#")]
    assert "ProtectSystem=yes" in directives
    assert "ProtectSystem=strict" not in directives
    assert "ProtectSystem=full" not in directives
    # Blocking module autoload can break `ip link add type wireguard`.
    assert not any(d.startswith("ProtectKernelModules") for d in directives)


def test_install_enables_existing_memberships(tmp_path, monkeypatch, as_root, capsys):
    monkeypatch.setattr(cli, "_UNIT_DIR", tmp_path)
    monkeypatch.setattr(_shutil, "which",
                        _which({"systemctl": "/bin/systemctl", "gw": "/bin/gw"}))
    calls = []
    monkeypatch.setattr(_subprocess, "run", _record_run(calls))
    monkeypatch.setattr(cli, "_memberships",
                        lambda etc=None: [("prod", tmp_path / "greasewood_prod.toml")])
    monkeypatch.setattr(cli, "_wait_service_settled", lambda *a, **k: "active")
    rc = cli.cmd_install_service(types.SimpleNamespace(exec=None, no_enable=False))
    assert rc == 0
    assert ["/bin/systemctl", "daemon-reload"] in calls
    assert ["/bin/systemctl", "enable", "--now", "greasewood@prod.service"] in calls
    assert "greasewood@prod: up and running" in capsys.readouterr().out


def test_install_with_no_memberships_says_so(tmp_path, monkeypatch, as_root, capsys):
    monkeypatch.setattr(cli, "_UNIT_DIR", tmp_path)
    monkeypatch.setattr(_shutil, "which",
                        _which({"systemctl": "/bin/systemctl", "gw": "/bin/gw"}))
    monkeypatch.setattr(_subprocess, "run", _record_run([]))
    monkeypatch.setattr(cli, "_memberships", lambda etc=None: [])
    cli.cmd_install_service(types.SimpleNamespace(exec=None, no_enable=False))
    assert "No mesh configured yet" in capsys.readouterr().out


def test_install_flags_crashing_membership(tmp_path, monkeypatch, as_root, capsys):
    """`systemctl start` looks successful even when the daemon crashes a second
    later — install must verify each membership comes up AND stays up."""
    monkeypatch.setattr(cli, "_UNIT_DIR", tmp_path)
    monkeypatch.setattr(_shutil, "which",
                        _which({"systemctl": "/bin/systemctl", "gw": "/bin/gw"}))
    monkeypatch.setattr(_subprocess, "run", _record_run([]))
    monkeypatch.setattr(cli, "_memberships",
                        lambda etc=None: [("prod", tmp_path / "greasewood_prod.toml")])
    monkeypatch.setattr(cli, "_wait_service_settled", lambda *a, **k: "failed")
    cli.cmd_install_service(types.SimpleNamespace(exec=None, no_enable=False))
    out = capsys.readouterr().out
    assert "likely crashing at startup" in out
    assert "journalctl -u greasewood@prod -n 20" in out


def test_permission_error_as_root_names_the_ownership_fix(monkeypatch):
    """EACCES while ALREADY root (sandboxed unit + non-root-owned key) must not
    say 'try sudo' — it must name the chown fix."""
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)

    def boom(args):
        raise PermissionError(13, "Permission denied", "/var/lib/greasewood/ca.key")
    monkeypatch.setattr(cli, "cmd_status", boom)
    with pytest.raises(SystemExit) as e:
        cli.main(["-c", "/tmp/x.toml", "status"])
    msg = str(e.value)
    assert "AS ROOT" in msg and "CAP_DAC_OVERRIDE" in msg
    assert "chown root:root /var/lib/greasewood/ca.key" in msg


def test_install_no_enable_skips_enable(tmp_path, monkeypatch, as_root):
    monkeypatch.setattr(cli, "_UNIT_DIR", tmp_path)
    monkeypatch.setattr(_shutil, "which", _which({"systemctl": "/bin/systemctl"}))
    calls = []
    monkeypatch.setattr(_subprocess, "run", _record_run(calls))
    cli.cmd_install_service(types.SimpleNamespace(exec="/bin/gw", no_enable=True))
    assert ["/bin/systemctl", "daemon-reload"] in calls
    assert not any("enable" in c for c in calls)


def test_uninstall_requires_root(monkeypatch):
    monkeypatch.setattr(cli.os, "geteuid", lambda: 1000)
    with pytest.raises(SystemExit):
        cli.cmd_uninstall_service(types.SimpleNamespace())


def test_uninstall_removes_template_instances_and_legacy(tmp_path, monkeypatch, as_root):
    monkeypatch.setattr(cli, "_UNIT_DIR", tmp_path)
    (tmp_path / "greasewood@.service").write_text("t")
    (tmp_path / "greasewood.service").write_text("x")   # legacy
    (tmp_path / "greasewood.path").write_text("y")      # legacy
    monkeypatch.setattr(_shutil, "which", _which({"systemctl": "/bin/systemctl"}))
    monkeypatch.setattr(cli, "_memberships",
                        lambda etc=None: [("prod", tmp_path / "greasewood_prod.toml")])
    calls = []
    monkeypatch.setattr(_subprocess, "run", _record_run(calls))
    rc = cli.cmd_uninstall_service(types.SimpleNamespace())
    assert rc == 0
    assert ["/bin/systemctl", "disable", "--now", "greasewood@prod.service"] in calls
    assert not (tmp_path / "greasewood@.service").exists()
    assert not (tmp_path / "greasewood.service").exists()
    assert not (tmp_path / "greasewood.path").exists()
