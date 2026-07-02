"""
greasewood.audit — the data-plane command trail. Every ip/wg command must be
recorded (always, not behind -v), with context, exit code, timing, and — on
failure — stderr, in a greppable logfmt line, to a durable rotating file.
"""
import logging
import stat
import subprocess
import types

from greasewood import audit


def test_record_command_success_line(caplog):
    with caplog.at_level(logging.INFO, logger="greasewood.audit"):
        audit.record_command(["wg", "set", "gw-mesh", "peer", "ABC="], 0, 7, "", "")
    msg = caplog.records[-1].message
    assert "cmd rc=0 t=7ms" in msg
    assert 'argv="wg set gw-mesh peer ABC="' in msg
    assert caplog.records[-1].levelno == logging.INFO


def test_record_command_failure_is_error_with_stderr(caplog):
    with caplog.at_level(logging.INFO, logger="greasewood.audit"):
        audit.record_command(["wg", "set", "x", "peer", "y"], 1, 3, "",
                             "no such device", failed=True)
    rec = caplog.records[-1]
    assert rec.levelno == logging.ERROR
    assert "rc=1" in rec.message and 'stderr="no such device"' in rec.message


def test_tolerated_nonzero_is_info_not_error(caplog):
    # A check=False cleanup (route already gone) has rc!=0 but isn't a failure.
    with caplog.at_level(logging.INFO, logger="greasewood.audit"):
        audit.record_command(["ip", "-6", "route", "del", "x"], 2, 1, failed=False)
    assert caplog.records[-1].levelno == logging.INFO


def test_readonly_commands_are_debug(caplog):
    # State queries run every reconcile cycle — they must not fill the trail.
    with caplog.at_level(logging.DEBUG, logger="greasewood.audit"):
        audit.record_command(["wg", "show", "gw-mesh", "dump"], 0, 1)
        audit.record_command(["ip", "-6", "addr", "show", "dev", "gw-mesh"], 0, 1)
    assert all(r.levelno == logging.DEBUG for r in caplog.records[-2:])
    assert audit.is_readonly(["wg", "show", "gw-mesh", "dump"])
    assert not audit.is_readonly(["wg", "set", "gw-mesh", "peer", "x"])


def test_context_tags_commands_and_resets(caplog):
    with caplog.at_level(logging.INFO, logger="greasewood.audit"):
        assert audit.current_context() == ""
        with audit.context("reconcile: +peer db01"):
            assert audit.current_context() == "reconcile: +peer db01"
            audit.record_command(["wg", "set", "gw-mesh", "peer", "x"], 0, 1)
        assert audit.current_context() == ""      # reset after the block
        audit.record_command(["ip", "link"], 0, 1)
    inside, outside = caplog.records[-2].message, caplog.records[-1].message
    assert 'ctx="reconcile: +peer db01"' in inside
    assert "ctx=-" in outside


def test_wg_run_emits_an_audit_record(monkeypatch, caplog):
    from greasewood import wg
    monkeypatch.setattr(wg.subprocess, "run",
                        lambda *a, **k: subprocess.CompletedProcess(a[0], 0, "out", ""))
    with caplog.at_level(logging.INFO, logger="greasewood.audit"):
        wg._run("ip", "-6", "route", "replace", "fd8d::a1/128", "dev", "gw-mesh")
    assert any('argv="ip -6 route replace fd8d::a1/128 dev gw-mesh"' in r.message for r in caplog.records)


def test_wg_run_records_failures_too(monkeypatch, caplog):
    from greasewood import wg

    def boom(*a, **k):
        raise subprocess.CalledProcessError(1, a[0], "", "boom")
    monkeypatch.setattr(wg.subprocess, "run", boom)
    with caplog.at_level(logging.INFO, logger="greasewood.audit"):
        try:
            wg._run("wg", "set", "x", "peer", "y", "remove")
        except subprocess.CalledProcessError:
            pass
    rec = [r for r in caplog.records if "cmd rc=1" in r.message][-1]
    assert 'argv="wg set x peer y remove"' in rec.message


def test_attach_file_writes_rotating_0600(tmp_path):
    p = tmp_path / "sub" / "audit.log"
    h = audit.attach_file(p, max_mb=1, keep=3)
    try:
        assert h is not None
        audit.record_command(["ip", "link", "set", "gw-mesh", "up"], 0, 1)
        for hh in audit.log.handlers:
            hh.flush()
        text = p.read_text()
        assert "ts=" in text and 'argv="ip link set gw-mesh up"' in text
        assert stat.S_IMODE(p.stat().st_mode) == 0o600   # holds topology/IPs
        # Attaching the same path again is idempotent (no duplicate handler).
        assert audit.attach_file(p) is h
    finally:
        audit.log.removeHandler(h)


def test_logfmt_quoting():
    # bare tokens unquoted; anything with spaces/=/quotes gets quoted+escaped
    assert audit._q("simple") == "simple"
    assert audit._q("has space") == '"has space"'
    assert audit._q('a"b') == '"a\\"b"'
    assert audit._q("") == '""'
