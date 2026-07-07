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
    # e.g. a typo'd duration in [anchor]; must surface as ValueError, not crash oddly
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
    assert cfg.wg_interface == "gw-mesh"       # default
    assert cfg.hosts_sync is True              # /etc/hosts sync on by default
    assert cfg.mesh_domain == "gw.internal"    # namespaced under reserved TLD
    # The default caps must place the node in the default segment — a bare
    # "mesh" tag is NOT a segment, and default_policy would peer it with nobody.
    assert cfg.caps == ["role:mesh"]
    assert cfg.aliases == []                    # no published service names by default


def test_aliases_parsed(tmp_path):
    p = _write(tmp_path,
               '[node]\nhostname = "db01"\n[network]\naliases = ["pg", "metrics"]\n')
    cfg = load_config(p)
    assert cfg.aliases == ["pg", "metrics"]


def test_new_node_defaults_fallback(tmp_path):
    # No [anchor] defaults set → ship defaults: mesh segment, tls on.
    p = _write(tmp_path, '[node]\nhostname = "n1"\n')
    cfg = load_config(p)
    assert cfg.default_roles == ["mesh"]
    assert cfg.default_caps == ["tls"]


def test_new_node_defaults_explicit(tmp_path):
    # The anchor operator can change what new nodes get (e.g. tls off, rename the
    # default segment) — read fresh at each invite.
    p = _write(tmp_path,
               '[node]\nhostname = "anchor"\nrole = "anchor"\n'
               '[anchor]\ndefault_roles = ["core"]\ndefault_caps = []\n')
    cfg = load_config(p)
    assert cfg.default_roles == ["core"]
    assert cfg.default_caps == []


def test_bad_overlay_prefix_fails_loudly(tmp_path):
    """Regression: a malformed overlay_prefix was silently swallowed, quietly
    addressing the node under the DEFAULT /64 instead of the fleet's."""
    import pytest
    from greasewood.config import load_config
    p = tmp_path / "gw.toml"
    p.write_text('''[node]
hostname = "n1"
data_dir = "/tmp/x"
[network]
overlay_prefix = "not-a-prefix"
seeds = []
[ca]
trusted_pubs = []
''')
    with pytest.raises(SystemExit) as e:
        load_config(p)
    assert "bad overlay_prefix" in str(e.value) and "not-a-prefix" in str(e.value)


def test_zero_or_negative_credential_ttl_rejected():
    """A non-positive credential_ttl would have the anchor issue already-expired
    credentials — reject it (and give a clean config: message, not a traceback)."""
    import pytest
    from greasewood.config import _parse_duration
    for bad in ("0h", "-5h", "0d"):
        with pytest.raises(ValueError, match="must be positive"):
            _parse_duration(bad)


def test_bad_duration_exits_cleanly(tmp_path):
    """A typo'd duration exits with a `config:` message, like overlay_prefix —
    not a raw ValueError traceback at startup."""
    import pytest
    from greasewood.config import load_config
    p = tmp_path / "gw.toml"
    p.write_text('[node]\nhostname="n1"\nrole="anchor"\n[network]\nseeds=[]\n'
                 '[ca]\ntrusted_pubs=[]\n[anchor]\ncredential_ttl="2x"\n')
    with pytest.raises(SystemExit) as e:
        load_config(p)
    assert "credential_ttl" in str(e.value) and "2x" in str(e.value)
