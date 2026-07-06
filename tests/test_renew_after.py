"""
Unit tests for the fleet-wide "renew asap" mechanism (gw renew-all):

  - the anchor writes a renew_after hint and refuses on a non-anchor;
  - sync parses the hint (both wire shapes);
  - RenewalLoop.maybe_renew_after acts only when our credential predates the
    hint, dedups, and draws its delay from a window that scales with mesh size
    (so the anchor's renewals/sec stays ~constant as the fleet grows).
"""
import datetime as dt
import types

import pytest

from greasewood import cli
from greasewood.directory import Directory
from greasewood.keys import CAKeys, NodeKeys
from greasewood.renewal import RenewalLoop
from greasewood.sync import _parse_renew_after
from greasewood.wire import Credential

_UTC = dt.timezone.utc


def _cred(node, ca, *, iat=None):
    now = iat or dt.datetime.now(_UTC).replace(microsecond=0)
    return Credential(
        id_pub=node.id_pub_bytes, wg_pub=node.wg_pub_bytes, addr=node.addr,
        hostname="n1", caps=["segment:mesh"], iat=now,
        exp=now + dt.timedelta(hours=24),
    ).sign(ca.ca_priv)


def _loop(tmp_path, *, n_nodes, cred):
    node = NodeKeys.generate()
    loop = RenewalLoop(
        node_keys=node, directory=Directory(), get_anchor_url=lambda: "",
        current_cred=cred, hostname="n1", endpoints=[],
        cache_path=tmp_path / "d.json",
    )
    loop._directory = types.SimpleNamespace(size=lambda: n_nodes)   # fake mesh size
    return loop


class _FakeTimer:
    """Capture the scheduled delay without spawning a real timer thread."""
    last = None

    def __init__(self, delay, fn):
        _FakeTimer.last = {"delay": delay, "fn": fn}
        self.daemon = False

    def start(self):
        pass


def _patch(monkeypatch):
    captured = {}
    monkeypatch.setattr("greasewood.renewal.random.uniform",
                        lambda lo, hi: captured.update(lo=lo, hi=hi) or 0.0)
    monkeypatch.setattr("greasewood.renewal.threading.Timer", _FakeTimer)
    _FakeTimer.last = None
    return captured


# --- parsing ---------------------------------------------------------------

def test_parse_renew_after():
    assert _parse_renew_after(None) is None
    assert _parse_renew_after("") is None
    assert _parse_renew_after("not-a-date") is None
    ts = _parse_renew_after("2026-07-01T00:00:00")
    assert ts is not None and ts.tzinfo is not None            # naive → UTC-stamped


# --- window scales with mesh size -----------------------------------------

def test_window_scales_with_mesh_size(tmp_path, monkeypatch):
    node = NodeKeys.generate()
    ca = CAKeys.generate()
    future = dt.datetime.now(_UTC) + dt.timedelta(hours=1)     # our cred predates it

    for n in (1, 10, 100):
        cap = _patch(monkeypatch)
        loop = _loop(tmp_path, n_nodes=n, cred=_cred(node, ca))
        loop.maybe_renew_after(future)
        # delay ~ U(0, N * spread): the window's upper bound is proportional to N,
        # so expected renewals/sec at the anchor is N/(N*spread) = 1/spread, constant.
        assert cap["lo"] == 0.0
        assert cap["hi"] == n * loop._renew_spread
        assert _FakeTimer.last is not None                    # a renewal was scheduled


# --- acts only when older; dedups -----------------------------------------

def test_noop_when_cred_postdates_hint(tmp_path, monkeypatch):
    node = NodeKeys.generate()
    ca = CAKeys.generate()
    _patch(monkeypatch)
    loop = _loop(tmp_path, n_nodes=10, cred=_cred(node, ca))
    past = dt.datetime.now(_UTC) - dt.timedelta(hours=1)       # cred is newer than hint
    loop.maybe_renew_after(past)
    assert _FakeTimer.last is None                            # nothing scheduled


def test_dedups_same_hint(tmp_path, monkeypatch):
    node = NodeKeys.generate()
    ca = CAKeys.generate()
    _patch(monkeypatch)
    loop = _loop(tmp_path, n_nodes=10, cred=_cred(node, ca))
    future = dt.datetime.now(_UTC) + dt.timedelta(hours=1)
    loop.maybe_renew_after(future)
    first = _FakeTimer.last
    _FakeTimer.last = None
    loop.maybe_renew_after(future)                            # same hint again
    assert _FakeTimer.last is None                            # not re-scheduled
    assert first is not None


# --- the anchor command -------------------------------------------------------

def _anchor_cfg(tmp_path, role="anchor"):
    (tmp_path / "gw.toml").write_text(f"""[node]
hostname = "anchor"
data_dir = "{tmp_path}"
role = "{role}"
[network]
interface = "gw-mesh"
seeds = []
[ca]
trusted_pubs = []
[anchor]
ca_key_file = "{tmp_path}/ca.key"
""")
    return tmp_path / "gw.toml"


def test_renew_all_writes_hint(tmp_path, monkeypatch):
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)   # gated command
    cfg = _anchor_cfg(tmp_path)
    rc = cli.cmd_renew_all(types.SimpleNamespace(config=str(cfg)))
    assert rc == 0
    written = (tmp_path / "renew_after").read_text().strip()
    dt.datetime.fromisoformat(written)                        # parseable ISO timestamp


def test_renew_all_refuses_non_anchor(tmp_path):
    cfg = _anchor_cfg(tmp_path, role="node")
    with pytest.raises(SystemExit):
        cli.cmd_renew_all(types.SimpleNamespace(config=str(cfg)))
    assert not (tmp_path / "renew_after").exists()
