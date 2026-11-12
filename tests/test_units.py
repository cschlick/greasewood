"""
Unit tests for the systemd template unit / install-service plumbing.

No systemd needed: these check the embedded unit text is well-formed and stays
in sync with the canonical file in systemd/. One TEMPLATE serves every mesh
membership as greasewood@<name>; there is no unsuffixed unit and no path unit
(create/join enable their instance directly).
"""
from pathlib import Path

from greasewood.cli import _SERVICE_UNIT

_REPO = Path(__file__).parent.parent
_EXEC = "/usr/local/bin/gw"
# The canonical sandbox pass-through: what _sandbox_rw_line() renders on the
# documented fleet layout (pipx at /opt/pipx, apps linked in /usr/local/bin).
_RW = "ReadWritePaths=-/opt/pipx -/usr/local/bin\n"


def test_service_template_directives():
    body = _SERVICE_UNIT.format(exec=_EXEC, rw_paths=_RW)
    assert "ExecStart=/usr/local/bin/gw -c /etc/greasewood_%i.toml run" in body
    # Only start once this membership is configured; recover from failure.
    assert "ConditionPathExists=/etc/greasewood_%i.toml" in body
    assert "Restart=always" in body        # a stray kill must not strand the node
    assert "WatchdogSec=" in body          # alive must mean reconciling
    assert "NotifyAccess=main" in body
    assert "WantedBy=multi-user.target" in body
    assert "Description=greasewood mesh daemon (%i)" in body


def test_repo_template_matches_embedded():
    """The committed systemd/ file must match what `gw install-service` writes,
    so manual install and pip install agree."""
    svc = (_REPO / "systemd" / "greasewood@.service").read_text()
    assert svc.strip() == _SERVICE_UNIT.format(exec=_EXEC, rw_paths=_RW).strip()


def test_sandbox_rw_line_renders_the_pipx_paths(monkeypatch):
    """A pipx-managed install gets its home + bin dir passed through the unit
    sandbox ('-' = ignore if missing); any other install gets no line at all —
    the sandbox stays as tight as before."""
    from greasewood import service
    monkeypatch.setattr(service, "_pipx_install_env",
                        lambda: (Path("/opt/pipx"), Path("/usr/local/bin")))
    assert service._sandbox_rw_line() == _RW
    monkeypatch.setattr(service, "_pipx_install_env", lambda: None)
    assert service._sandbox_rw_line() == ""


def test_write_unit_renders_sandbox_passthrough(tmp_path, monkeypatch):
    """The written unit carries the pass-through exactly when the install is
    pipx-managed — the regression that made upgrade-all fail fleet-wide: the
    daemon's own `pipx uninstall` hit the read-only /usr/local/bin."""
    import subprocess
    from greasewood import service
    monkeypatch.setattr(service, "_pipx_install_env",
                        lambda: (Path("/opt/pipx"), Path("/usr/local/bin")))
    service.write_systemd_unit(
        tmp_path, _EXEC,
        run=lambda *a, **k: subprocess.CompletedProcess(a, 0, "", ""))
    assert _RW.strip() in (tmp_path / "greasewood@.service").read_text()


def test_watchdog_ping_sends_datagram(tmp_path, monkeypatch):
    import socket
    from greasewood.loop import sd_watchdog_ping
    sock_path = str(tmp_path / "notify.sock")
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    srv.bind(sock_path)
    srv.settimeout(2)
    monkeypatch.setenv("NOTIFY_SOCKET", sock_path)
    sd_watchdog_ping()
    assert srv.recv(64) == b"WATCHDOG=1"
    srv.close()


def test_watchdog_ping_noop_outside_systemd(monkeypatch):
    from greasewood.loop import sd_watchdog_ping
    monkeypatch.delenv("NOTIFY_SOCKET", raising=False)
    sd_watchdog_ping()                          # must not raise
    monkeypatch.setenv("NOTIFY_SOCKET", "/nonexistent/notify.sock")
    sd_watchdog_ping()                          # dead socket: swallowed, not fatal


def test_refresh_service_template(tmp_path, monkeypatch):
    from greasewood import cli
    monkeypatch.setattr(cli, "_UNIT_DIR", tmp_path)
    monkeypatch.setattr(cli, "_service_exec", lambda: "/usr/local/bin/gw")
    monkeypatch.setattr(cli, "_systemctl_run",
                        lambda *a, **k: __import__("subprocess").CompletedProcess(a, 0, "", ""))
    tmpl = tmp_path / "greasewood@.service"
    # no template installed (bare `gw run` host) → never installs one
    assert cli._refresh_service_template() is False
    assert not tmpl.exists()
    # stale template (an old version's) → refreshed in place
    tmpl.write_text("[Service]\nRestart=on-failure\n")
    assert cli._refresh_service_template() is True
    assert "Restart=always" in tmpl.read_text()
    # current template → untouched, no reload
    assert cli._refresh_service_template() is False
