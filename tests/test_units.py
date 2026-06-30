"""
Unit tests for the systemd units / install-service plumbing (§ service mode).

No systemd needed: these check the embedded unit text is well-formed and stays
in sync with the canonical files in systemd/ (and with the Ansible templates).
"""
from pathlib import Path

from greasewood.cli import _SERVICE_UNIT, _PATH_UNIT

_REPO = Path(__file__).parent.parent
_EXEC = "/usr/local/bin/gw"


def test_service_unit_directives():
    body = _SERVICE_UNIT.format(exec=_EXEC)
    assert "ExecStart=/usr/local/bin/gw run" in body
    # Only start once configured, and recover from transient failure.
    assert "ConditionPathExists=/etc/greasewood.toml" in body
    assert "Restart=on-failure" in body
    assert "WantedBy=multi-user.target" in body


def test_path_unit_directives():
    assert "PathExists=/etc/greasewood.toml" in _PATH_UNIT
    assert "Unit=greasewood.service" in _PATH_UNIT
    assert "WantedBy=paths.target" in _PATH_UNIT


def test_repo_units_match_embedded():
    """The committed systemd/ files must match what `gw install-service` writes,
    so manual install and pip install agree."""
    svc = (_REPO / "systemd" / "greasewood.service").read_text()
    pth = (_REPO / "systemd" / "greasewood.path").read_text()
    assert svc.strip() == _SERVICE_UNIT.format(exec=_EXEC).strip()
    assert pth.strip() == _PATH_UNIT.strip()
