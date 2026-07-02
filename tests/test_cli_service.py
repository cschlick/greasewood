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


def test_install_writes_units_when_no_systemctl(tmp_path, monkeypatch, as_root):
    monkeypatch.setattr(cli, "_UNIT_DIR", tmp_path)
    monkeypatch.setattr(_shutil, "which", _which({}))  # no gw, no systemctl
    rc = cli.cmd_install_service(
        types.SimpleNamespace(exec="/usr/local/bin/gw", no_enable=False))
    assert rc == 0
    assert "ExecStart=/usr/local/bin/gw run" in (tmp_path / "greasewood.service").read_text()
    assert "PathExists=/etc/greasewood.toml" in (tmp_path / "greasewood.path").read_text()


def test_installed_unit_is_sandboxed(tmp_path, monkeypatch, as_root):
    """The installed service must carry the hardening block: a daemon RCE
    shouldn't own the box. Checks the directives that are safe for a root
    CAP_NET_ADMIN daemon that shells to ip/wg/nft and writes /etc/hosts."""
    monkeypatch.setattr(cli, "_UNIT_DIR", tmp_path)
    monkeypatch.setattr(_shutil, "which", _which({}))
    cli.cmd_install_service(
        types.SimpleNamespace(exec="/usr/local/bin/gw", no_enable=False))
    unit = (tmp_path / "greasewood.service").read_text()
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


def test_install_enables_with_systemctl(tmp_path, monkeypatch, as_root):
    monkeypatch.setattr(cli, "_UNIT_DIR", tmp_path)
    monkeypatch.setattr(_shutil, "which",
                        _which({"systemctl": "/bin/systemctl", "gw": "/bin/gw"}))
    calls = []
    monkeypatch.setattr(_subprocess, "run", _record_run(calls))
    rc = cli.cmd_install_service(types.SimpleNamespace(exec=None, no_enable=False))
    assert rc == 0
    assert ["/bin/systemctl", "daemon-reload"] in calls
    assert ["/bin/systemctl", "enable", "--now", "greasewood.path"] in calls
    assert ["/bin/systemctl", "enable", "greasewood.service"] in calls


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


def test_uninstall_removes_units(tmp_path, monkeypatch, as_root):
    monkeypatch.setattr(cli, "_UNIT_DIR", tmp_path)
    (tmp_path / "greasewood.service").write_text("x")
    (tmp_path / "greasewood.path").write_text("y")
    monkeypatch.setattr(_shutil, "which", _which({"systemctl": "/bin/systemctl"}))
    calls = []
    monkeypatch.setattr(_subprocess, "run", _record_run(calls))
    rc = cli.cmd_uninstall_service(types.SimpleNamespace())
    assert rc == 0
    assert not (tmp_path / "greasewood.service").exists()
    assert not (tmp_path / "greasewood.path").exists()
    assert ["/bin/systemctl", "disable", "--now",
            "greasewood.path", "greasewood.service"] in calls
