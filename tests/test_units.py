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
    assert "Restart=on-failure" in body
    assert "WantedBy=multi-user.target" in body
    assert "Description=greasewood mesh daemon (%i)" in body


def test_repo_template_matches_embedded():
    """The committed systemd/ file must match what `gw install-service` writes,
    so manual install and pip install agree."""
    svc = (_REPO / "systemd" / "greasewood@.service").read_text()
    assert svc.strip() == _SERVICE_UNIT.format(exec=_EXEC).strip()
