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


def test_service_template_directives():
    body = _SERVICE_UNIT.format(exec=_EXEC)
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
    assert svc.strip() == _SERVICE_UNIT.format(exec=_EXEC).strip()


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
