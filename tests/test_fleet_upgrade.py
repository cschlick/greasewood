"""
Fleet upgrade announcements (`gw upgrade-all` → auto_upgrade nodes).

One CA-signed `upgrade` statement pins a release version + its tarball's
sha256 and rides the ordinary statement gossip. The node side (UpgradeManager)
is opt-in, verifies the hash before touching anything, fetches before it
uninstalls, and backs off after a failure. The signal can only ever name a
specific published artifact — that property is what most of these tests pin.
"""
import datetime as dt
import hashlib
import subprocess
import types

import pytest

from greasewood import upgrade as up
from greasewood.keys import CAKeys, NodeKeys
from greasewood.statements import StatementLog, statements_path
from greasewood.wire import AnchorStatement

_UTC = dt.timezone.utc


def _now():
    return dt.datetime.now(_UTC).replace(microsecond=0)


def _hint(ca, version="9.9.9", sha="ab" * 32, ts=None):
    return AnchorStatement(kind="upgrade", id_pub=ca.ca_pub_bytes,
                           ts=ts or _now(),
                           upgrade={"version": version, "sha256": sha},
                           ).sign(ca.ca_priv)


# ---------------------------------------------------------------------------
# wire: the upgrade statement kind
# ---------------------------------------------------------------------------

def test_upgrade_statement_round_trips_signed():
    ca = CAKeys.generate()
    s = _hint(ca, "0.8.0", "cd" * 32)
    back = AnchorStatement.from_dict(s.to_dict())
    back.verify([ca.ca_pub_bytes])
    assert back.upgrade == {"version": "0.8.0", "sha256": "cd" * 32}


def test_pre_upgrade_statements_keep_their_signed_body():
    # The payload field is added to the signed body ONLY when present, so a
    # statement signed before the field existed still verifies byte-for-byte.
    ca, node = CAKeys.generate(), NodeKeys.generate()
    s = AnchorStatement(kind="revoke", id_pub=node.id_pub_bytes,
                        ts=_now()).sign(ca.ca_priv)
    d = s.to_dict()
    assert "upgrade" not in d                     # absent, not {}
    AnchorStatement.from_dict(d).verify([ca.ca_pub_bytes])


def test_payload_is_signed_tamper_is_detected():
    ca = CAKeys.generate()
    d = _hint(ca, "0.8.0").to_dict()
    d["upgrade"]["version"] = "0.9.0"             # attacker retargets the pin
    with pytest.raises(ValueError):
        AnchorStatement.from_dict(d).verify([ca.ca_pub_bytes])


def test_upgrade_kind_requires_version_and_sha():
    ca = CAKeys.generate()
    d = _hint(ca).to_dict()
    del d["upgrade"]["sha256"]
    with pytest.raises(ValueError, match="version . sha256"):
        AnchorStatement.from_dict(d)
    d2 = _hint(ca).to_dict()
    d2["upgrade"] = {"version": 42, "sha256": "x"}   # non-str payload
    with pytest.raises(ValueError):
        AnchorStatement.from_dict(d2)


# ---------------------------------------------------------------------------
# StatementLog: newest announcement wins, across CAs too
# ---------------------------------------------------------------------------

def test_upgrade_hint_latest_ts_wins_across_cas():
    ca1, ca2 = CAKeys.generate(), CAKeys.generate()
    pubs = [ca1.ca_pub_bytes, ca2.ca_pub_bytes]
    log = StatementLog()
    t = _now()
    log.merge([_hint(ca1, "0.8.0", ts=t)], pubs)
    log.merge([_hint(ca2, "0.8.1", ts=t + dt.timedelta(seconds=5))], pubs)
    hint = log.upgrade_hint()
    assert hint.upgrade["version"] == "0.8.1"
    # persistence round-trip keeps it
    assert log.prune() == 0                       # never pruned by the rules


def test_upgrade_hint_survives_save_load(tmp_path):
    ca = CAKeys.generate()
    log = StatementLog()
    log.merge([_hint(ca, "0.8.0")], [ca.ca_pub_bytes])
    log.save(statements_path(tmp_path))
    back = StatementLog.load(statements_path(tmp_path), [ca.ca_pub_bytes])
    assert back.upgrade_hint().upgrade["version"] == "0.8.0"


# ---------------------------------------------------------------------------
# version comparison
# ---------------------------------------------------------------------------

def test_version_compare_is_numeric_and_suffix_tolerant():
    assert up.is_newer("0.10.0", "0.9.9")         # numeric, not lexical
    assert up.is_newer("0.8.0", "0.7.3+dirty")
    assert not up.is_newer("0.7.0", "0.7.0")
    assert not up.is_newer("0.6.9", "0.7.0")


# ---------------------------------------------------------------------------
# UpgradeManager: the opt-in gate and the acting path
# ---------------------------------------------------------------------------

def _cfg(tmp_path, auto=False):
    return types.SimpleNamespace(auto_upgrade=auto, data_dir=tmp_path,
                                 ca_pubs_hex=[])


def _mgr(tmp_path, auto=False, version="0.7.0", env=("h", "b"),
         restart=None):
    calls = {"restart": []}
    mgr = up.UpgradeManager(
        _cfg(tmp_path, auto), "pm",
        get_version=lambda: version,
        pipx_env=lambda: env,
        restart=restart or (lambda key: calls["restart"].append(key) or True))
    return mgr, calls


def test_not_newer_is_a_silent_noop(tmp_path):
    ca = CAKeys.generate()
    mgr, _ = _mgr(tmp_path, auto=True, version="0.8.0")
    mgr.offer(_hint(ca, "0.8.0"))
    assert mgr._timer is None


def test_auto_off_logs_once_and_never_schedules(tmp_path, caplog):
    import logging
    ca = CAKeys.generate()
    mgr, _ = _mgr(tmp_path, auto=False)
    h = _hint(ca, "0.8.0")
    with caplog.at_level(logging.INFO, logger="greasewood.upgrade"):
        mgr.offer(h)
        mgr.offer(h)                               # the same level, next pull
    assert mgr._timer is None
    notes = [r for r in caplog.records if "auto_upgrade is off" in r.message]
    assert len(notes) == 1                         # once per announcement


def test_non_pipx_install_is_note_only(tmp_path, caplog):
    import logging
    ca = CAKeys.generate()
    mgr, _ = _mgr(tmp_path, auto=True, env=None)
    with caplog.at_level(logging.INFO, logger="greasewood.upgrade"):
        mgr.offer(_hint(ca, "0.8.0"))
    assert mgr._timer is None
    assert any("isn't pipx-managed" in r.message for r in caplog.records)


def test_macos_is_note_only(tmp_path, caplog, monkeypatch):
    import logging
    from greasewood import platform as gwplat
    monkeypatch.setattr(gwplat, "IS_MACOS", True)
    ca = CAKeys.generate()
    mgr, _ = _mgr(tmp_path, auto=True)
    with caplog.at_level(logging.INFO, logger="greasewood.upgrade"):
        mgr.offer(_hint(ca, "0.8.0"))
    assert mgr._timer is None
    assert any("brew upgrade" in r.message for r in caplog.records)


def test_auto_on_schedules_exactly_one_jittered_attempt(tmp_path):
    ca = CAKeys.generate()
    mgr, _ = _mgr(tmp_path, auto=True)
    h = _hint(ca, "0.8.0")
    try:
        mgr.offer(h)
        t1 = mgr._timer
        assert t1 is not None
        mgr.offer(h)                               # re-offered while pending
        assert mgr._timer is t1                    # no second attempt
    finally:
        if mgr._timer is not None:
            mgr._timer.cancel()


def test_upgrade_verifies_hash_fetches_before_uninstall(tmp_path, monkeypatch):
    """The happy path, and its ordering: download + hash-check happen before
    any pipx step, the steps run uninstall-then-install-from-local-file, and
    the daemon restart is requested at the end."""
    payload = b"the release tarball"
    sha = hashlib.sha256(payload).hexdigest()

    def fake_fetch(version, dest_dir, timeout=0):
        p = dest_dir / f"greasewood-{version}.tar.gz"
        p.write_bytes(payload)
        return p

    ran = []
    monkeypatch.setattr(up, "fetch_release", fake_fetch)
    monkeypatch.setattr(up.subprocess, "run",
                        lambda step, **k: ran.append(list(step)) or
                        subprocess.CompletedProcess(step, 0, "", ""))
    mgr, calls = _mgr(tmp_path, auto=True)
    mgr._upgrade("0.8.0", sha)
    assert ran[0][:3] == ["pipx", "uninstall", "greasewood"]
    assert ran[1][:2] == ["pipx", "install"]
    assert ran[1][2].endswith("greasewood-0.8.0.tar.gz")   # LOCAL verified file
    assert calls["restart"] == ["pm"]
    # workdir cleaned after success
    assert not list(tmp_path.glob("gw-autoupgrade-*"))


def test_hash_mismatch_refuses_before_touching_anything(tmp_path, monkeypatch):
    def fake_fetch(version, dest_dir, timeout=0):
        p = dest_dir / "t.tar.gz"
        p.write_bytes(b"not what was announced")
        return p

    ran = []
    monkeypatch.setattr(up, "fetch_release", fake_fetch)
    monkeypatch.setattr(up.subprocess, "run",
                        lambda step, **k: ran.append(step))
    mgr, calls = _mgr(tmp_path, auto=True)
    with pytest.raises(RuntimeError, match="hash mismatch"):
        mgr._upgrade("0.8.0", "00" * 32)
    assert ran == []                               # nothing was uninstalled
    assert calls["restart"] == []
    assert not list(tmp_path.glob("gw-autoupgrade-*"))


def test_failed_attempt_backs_off_then_retries(tmp_path, monkeypatch):
    ca = CAKeys.generate()
    mgr, _ = _mgr(tmp_path, auto=True)
    h = _hint(ca, "0.8.0")
    monkeypatch.setattr(mgr, "_upgrade",
                        lambda *a: (_ for _ in ()).throw(RuntimeError("boom")))
    mgr._attempt(h.ts, "0.8.0", "00" * 32)         # the timer's body, directly
    assert mgr._failed_ts == h.ts
    mgr.offer(h)
    assert mgr._timer is None                      # backed off, not hammering
    mgr._retry_at = 0.0                            # backoff window elapsed
    try:
        mgr.offer(h)
        assert mgr._timer is not None              # retried
    finally:
        if mgr._timer is not None:
            mgr._timer.cancel()


def test_manual_upgrade_racing_wins_quietly(tmp_path, monkeypatch):
    # By the time the jittered attempt fires, a hand-run `gw upgrade` already
    # installed the version — the attempt must no-op, not reinstall.
    seen = []
    monkeypatch.setattr(up, "fetch_release",
                        lambda *a, **k: seen.append("fetch"))
    mgr, _ = _mgr(tmp_path, auto=True, version="0.8.0")
    mgr._upgrade("0.8.0", "00" * 32)
    assert seen == []


# ---------------------------------------------------------------------------
# sync: the hint is offered each successful pull, and can't break sync
# ---------------------------------------------------------------------------

def test_sync_offers_newest_hint_and_survives_handler_errors(tmp_path):
    from greasewood.sync import SyncLoop
    from greasewood.directory import Directory
    ca = CAKeys.generate()
    log = StatementLog()
    log.merge([_hint(ca, "0.8.0")], [ca.ca_pub_bytes])
    got = []

    def handler(stmt):
        got.append(stmt.upgrade["version"])
        raise RuntimeError("handler bug")          # must not kill the pull

    loop = SyncLoop(Directory(), lambda: [], tmp_path / "dir.json",
                    statements=log,
                    get_ca_pubs=lambda: [ca.ca_pub_bytes],
                    on_upgrade_hint=handler)
    loop._offer_upgrade_hint()
    assert got == ["0.8.0"]


# ---------------------------------------------------------------------------
# gw upgrade-all: the announcing side
# ---------------------------------------------------------------------------

def _fake_ca():
    calls = {}

    class _CA:
        def announce_upgrade(self, version, sha256):
            calls.update(version=version, sha256=sha256)
            return types.SimpleNamespace(ts=_now())
    return _CA(), calls


def test_upgrade_all_hashes_the_release_artifact(tmp_path, monkeypatch, capsys):
    import io
    from greasewood import cli
    payload = b"release bytes"
    ca, calls = _fake_ca()
    cfg = types.SimpleNamespace(audit_log=None, data_dir=tmp_path)
    monkeypatch.setattr(cli, "_load_anchor_ca", lambda a, c: (cfg, ca))
    import urllib.request
    monkeypatch.setattr(urllib.request, "urlopen",
                        lambda url, timeout=0: io.BytesIO(payload))
    args = types.SimpleNamespace(config="x", version="0.8.0", sha256=None)
    assert cli.cmd_upgrade_all(args) == 0
    assert calls == {"version": "0.8.0",
                     "sha256": hashlib.sha256(payload).hexdigest()}
    out = capsys.readouterr().out
    assert "announced: greasewood v0.8.0" in out
    assert "auto_upgrade = true" in out


def test_upgrade_all_refuses_to_announce_a_dev_build(monkeypatch):
    from greasewood import cli
    ca, _ = _fake_ca()
    cfg = types.SimpleNamespace(audit_log=None)
    monkeypatch.setattr(cli, "_load_anchor_ca", lambda a, c: (cfg, ca))
    monkeypatch.setattr(cli, "_version", lambda: "0.0.0+unknown")
    args = types.SimpleNamespace(config="x", version=None, sha256=None)
    with pytest.raises(SystemExit, match="dev build"):
        cli.cmd_upgrade_all(args)


def test_upgrade_all_accepts_a_supplied_sha(monkeypatch, capsys):
    from greasewood import cli
    ca, calls = _fake_ca()
    cfg = types.SimpleNamespace(audit_log=None)
    monkeypatch.setattr(cli, "_load_anchor_ca", lambda a, c: (cfg, ca))
    args = types.SimpleNamespace(config="x", version="0.8.0", sha256="AB" * 32)
    assert cli.cmd_upgrade_all(args) == 0
    assert calls["sha256"] == "ab" * 32            # normalized, no download


# ---------------------------------------------------------------------------
# config + watch surface
# ---------------------------------------------------------------------------

def test_auto_upgrade_config_defaults_off_and_round_trips(tmp_path):
    from greasewood.config import load_config, render_config
    p = tmp_path / "gw.toml"
    p.write_text(render_config(hostname="n1", role="node", listen_port=51900,
                               endpoints=[], caps=[], data_dir=tmp_path,
                               seeds=[], root_url="", hosts_sync=True,
                               mesh_domain="pm.internal", interface="gw-pm",
                               overlay_prefix="fd8d:e5c1:db1a:7::",
                               trusted_pubs=[]))
    assert load_config(p).auto_upgrade is False
    p.write_text(p.read_text() + "\n[network]\nauto_upgrade = true\n"
                 if "[network]" not in p.read_text() else
                 p.read_text().replace("[network]",
                                       "[network]\nauto_upgrade = true"))
    assert load_config(p).auto_upgrade is True


def test_watch_header_shows_the_announcement(tmp_path, monkeypatch):
    from greasewood import status
    ca = CAKeys.generate()
    log = StatementLog()
    log.merge([_hint(ca, "0.8.0")], [ca.ca_pub_bytes])
    log.save(statements_path(tmp_path))
    cfg = types.SimpleNamespace(data_dir=tmp_path,
                                ca_pubs_hex=[ca.ca_pub_bytes.hex()],
                                auto_upgrade=False)
    monkeypatch.setattr(status, "_version", lambda: "0.7.0")
    lines = status._upgrade_hint_lines(cfg)
    assert lines and "v0.8.0 announced" in lines[0]
    assert "sudo gw upgrade" in lines[0]           # the off-path instruction
    # at (or past) the version → quiet
    monkeypatch.setattr(status, "_version", lambda: "0.8.0")
    assert status._upgrade_hint_lines(cfg) == []
