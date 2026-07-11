"""
_daemon_fatal — the visible replacement for a bare sys.exit in the daemon.

Under the systemd unit's Restart=on-failure a bare exit is a near-invisible 5s
restart loop. _daemon_fatal instead logs CRITICAL, drops a breadcrumb that
`gw watch` surfaces as the death reason, then exits — and the unit's StartLimit
bounds the loop into a visible `failed` state.
"""
import types

import pytest

from greasewood import cli, reconcile


def test_daemon_fatal_writes_breadcrumb_then_exits(tmp_path):
    cfg = types.SimpleNamespace(data_dir=tmp_path)
    with pytest.raises(SystemExit) as e:
        cli._daemon_fatal(cfg, "wireguard port 51900 already in use")
    assert "51900" in str(e.value)                      # exits with the message
    crumb = reconcile.read_daemon_fatal(tmp_path)        # and records the reason
    assert crumb and crumb["reason"] == "wireguard port 51900 already in use"


def test_daemon_fatal_still_exits_if_breadcrumb_unwritable(tmp_path, monkeypatch):
    # A failure to write the breadcrumb must never mask the real cause: still exit.
    monkeypatch.setattr(reconcile, "write_daemon_fatal",
                        lambda *a, **k: (_ for _ in ()).throw(OSError("ro fs")))
    cfg = types.SimpleNamespace(data_dir=tmp_path)
    with pytest.raises(SystemExit):
        cli._daemon_fatal(cfg, "control plane can't bind")


def test_service_unit_bounds_the_restart_loop():
    # The embedded unit must carry a StartLimit — otherwise RestartSec=5 loops
    # forever within systemd's default 10s window.
    assert "StartLimitBurst=" in cli._SERVICE_UNIT
    assert "StartLimitIntervalSec=" in cli._SERVICE_UNIT
