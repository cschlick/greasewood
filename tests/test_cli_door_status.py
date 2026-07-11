"""
`gw status` shows the enrollment door's state (anchor only):
  - open  → time-to-close, granted caps, failed attempts + IPs, attempts left;
  - closed → how long ago + why, and the last window's failed attempts.
Driven by a fabricated door_status.json (the daemon writes it; here we stand it
in) plus the humanize helpers.
"""
import datetime as dt
import types

from greasewood import cli, door
from greasewood.keys import NodeKeys

_UTC = dt.timezone.utc


def _anchor(tmp_path, role="anchor"):
    NodeKeys.load_or_generate(tmp_path)
    (tmp_path / "gw.toml").write_text(f"""[node]
hostname = "anchor"
data_dir = "{tmp_path}"
role = "{role}"
[network]
seeds = []
[ca]
trusted_pubs = []
""")
    return types.SimpleNamespace(config=str(tmp_path / "gw.toml"), by_segment=False)


def _iso(delta_s):
    return (dt.datetime.now(_UTC) + dt.timedelta(seconds=delta_s)) \
        .replace(microsecond=0).isoformat()


def test_open_door_shows_countdown_attempts_and_caps(tmp_path, capsys):
    args = _anchor(tmp_path)
    door.mark_door_opened(tmp_path, _iso(600), caps=["segment:mesh", "tls"],
                          max_attempts=3)
    door.mark_door_attempt(tmp_path, "fd52::9", "hostname already in use")
    cli.cmd_watch(args)
    out = capsys.readouterr().out
    assert "door     : OPEN" in out
    assert "closes in 10m" in out
    assert "grants: segment:mesh, tls" in out
    assert "1 failed attempt: fd52::9 (hostname already in use)" in out
    assert "2 attempts remaining" in out


def test_closed_door_shows_time_ago_and_reason(tmp_path, capsys):
    args = _anchor(tmp_path)
    door.mark_door_opened(tmp_path, _iso(-1))
    door.mark_door_attempt(tmp_path, "fd52::9", "revoked")
    door.mark_door_enrolled(tmp_path, "fd52::a", "db01")
    door.mark_door_closed(tmp_path, "enrolled")
    cli.cmd_watch(args)
    out = capsys.readouterr().out
    assert "door     : closed — last closed" in out
    assert "enrolled db01 from fd52::a" in out
    assert "last window: 1 failed attempt: fd52::9 (revoked)" in out


def test_never_opened(tmp_path, capsys):
    cli.cmd_watch(_anchor(tmp_path))
    assert "door     : closed (never opened)" in capsys.readouterr().out


def test_expired_reason_phrase(tmp_path, capsys):
    args = _anchor(tmp_path)
    door.mark_door_opened(tmp_path, _iso(-1))
    door.mark_door_closed(tmp_path, "expired")
    cli.cmd_watch(args)
    assert "window expired with no enrollment" in capsys.readouterr().out


def test_non_anchor_has_no_door_block(tmp_path, capsys):
    # A node isn't an anchor; even if a stray status file existed, don't show it.
    args = _anchor(tmp_path, role="node")
    door.mark_door_opened(tmp_path, _iso(600))
    cli.cmd_watch(args)
    # No anchor door block on a node. (Match the block's label, not a bare
    # "door" — the audit-log path can contain it, e.g. a pytest tmp dir named
    # after this test.)
    assert "door     :" not in capsys.readouterr().out
