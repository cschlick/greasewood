"""
Unit tests for config parsing — there was no test_config.py; config.py was only
exercised indirectly through the integration daemon. Covers duration parsing,
the required-hostname guard, and malformed-overlay-prefix handling.
"""
import datetime as dt

import pytest

from greasewood.config import _parse_duration, load_config


def test_parse_duration_units():
    assert _parse_duration("24h") == dt.timedelta(hours=24)
    assert _parse_duration("7d") == dt.timedelta(days=7)
    assert _parse_duration("30m") == dt.timedelta(minutes=30)


def test_parse_duration_bad_suffix_raises():
    with pytest.raises(ValueError):
        _parse_duration("5x")


def test_parse_duration_non_integer_raises():
    # e.g. a typo'd duration in [hub]; must surface as ValueError, not crash oddly
    with pytest.raises(ValueError):
        _parse_duration("abch")


def _write(tmp_path, body):
    p = tmp_path / "gw.toml"
    p.write_text(body)
    return p


def test_missing_hostname_exits(tmp_path):
    p = _write(tmp_path, '[node]\nrole = "node"\n')
    with pytest.raises(SystemExit):
        load_config(p)


def test_minimal_config_defaults(tmp_path):
    p = _write(tmp_path, '[node]\nhostname = "n1"\n')
    cfg = load_config(p)
    assert cfg.hostname == "n1"
    assert cfg.role == "node"
    assert cfg.inbound == "yes"                # default
    assert cfg.wg_interface == "gw-mesh"       # default
    assert cfg.hosts_sync is True              # /etc/hosts sync on by default
    assert cfg.mesh_domain == "gw.internal"    # namespaced under reserved TLD
    # The default caps must place the node in the default segment — a bare
    # "mesh" tag is NOT a segment, and default_policy would peer it with nobody.
    assert cfg.caps == ["segment:mesh"]


def test_new_node_defaults_fallback(tmp_path):
    # No [hub] defaults set → ship defaults: mesh segment, tls on.
    p = _write(tmp_path, '[node]\nhostname = "n1"\n')
    cfg = load_config(p)
    assert cfg.default_segments == ["mesh"]
    assert cfg.default_caps == ["tls"]


def test_new_node_defaults_explicit(tmp_path):
    # The hub operator can change what new nodes get (e.g. tls off, rename the
    # default segment) — read fresh at each invite.
    p = _write(tmp_path,
               '[node]\nhostname = "hub"\nrole = "hub"\n'
               '[hub]\ndefault_segments = ["core"]\ndefault_caps = []\n')
    cfg = load_config(p)
    assert cfg.default_segments == ["core"]
    assert cfg.default_caps == []


def test_malformed_overlay_prefix_is_swallowed(tmp_path):
    # A hand-edited bad prefix must not crash load_config; the parse failure is
    # swallowed (the process keeps the default /64) and the raw value is stored.
    p = _write(tmp_path,
               '[node]\nhostname = "n1"\n[network]\noverlay_prefix = "not-an-ip"\n')
    cfg = load_config(p)  # must not raise
    assert cfg.overlay_prefix == "not-an-ip"
