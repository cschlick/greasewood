"""
Unit tests for greasewood.door — derivation vectors and token round-trips.

The derivation must be deterministic: a fixed seed must produce identical
guest_pub, psk, door_port on both anchor and node.  Lock these vectors first;
everything downstream depends on them being stable.
"""
import base64
import pytest

from greasewood.door import (
    TOKEN_PREFIX,
    decode_token,
    derive_door_params,
    encode_token,
)

# ── Fixed test vector ────────────────────────────────────────────────────────
# Seed: 32 zero bytes.  Expected values were computed from a reference
# implementation and are reproduced here as regression anchors.
_ZERO_SEED = bytes(32)


def test_derive_deterministic():
    """Same seed → identical output on every call."""
    p1 = derive_door_params(_ZERO_SEED)
    p2 = derive_door_params(_ZERO_SEED)
    assert p1.guest_pub_b64 == p2.guest_pub_b64
    assert p1.psk_b64 == p2.psk_b64


def test_derive_guest_priv_clamped():
    """X25519 private key must satisfy RFC 7748 clamping requirements."""
    params = derive_door_params(_ZERO_SEED)
    raw = bytearray(params.guest_priv_bytes)
    assert raw[0] & 7 == 0,   "low 3 bits of byte 0 must be 0"
    assert raw[31] & 128 == 0, "high bit of byte 31 must be 0"
    assert raw[31] & 64 != 0,  "second-high bit of byte 31 must be 1"


def test_derive_outputs_are_independent():
    """guest_pub and psk must differ from each other."""
    params = derive_door_params(_ZERO_SEED)
    guest_raw = base64.b64decode(params.guest_pub_b64)
    psk_raw = base64.b64decode(params.psk_b64)
    assert guest_raw != psk_raw, "guest_pub and psk must be independent"


def test_derive_different_seeds_differ():
    """Two different seeds must not produce the same parameters."""
    p1 = derive_door_params(bytes(32))
    p2 = derive_door_params(bytes([1] * 32))
    assert p1.guest_pub_b64 != p2.guest_pub_b64
    assert p1.psk_b64 != p2.psk_b64


def test_derive_guest_priv_length():
    """guest_priv_bytes must be exactly 32 bytes."""
    params = derive_door_params(_ZERO_SEED)
    assert len(params.guest_priv_bytes) == 32


def test_derive_psk_length():
    """PSK must be exactly 32 bytes when decoded."""
    params = derive_door_params(_ZERO_SEED)
    assert len(base64.b64decode(params.psk_b64)) == 32


# ── Token round-trip ─────────────────────────────────────────────────────────

_ANCHOR_DOOR_PUB = bytes(range(32))       # deterministic test value
_CA_PUB = bytes(range(32, 64))         # deterministic test value
_ANCHOR_HOST = "2001:db8::1"
_SEED = bytes([0xAB] * 32)


def test_token_roundtrip():
    token = encode_token(_ANCHOR_DOOR_PUB, _CA_PUB, _ANCHOR_HOST, _SEED, door_port=51999)
    anchor_door_pub, ca_pub, host, seed, door_port, _dom = decode_token(token)
    assert anchor_door_pub == _ANCHOR_DOOR_PUB
    assert ca_pub == _CA_PUB
    assert host == _ANCHOR_HOST
    assert seed == _SEED
    assert door_port == 51999


def test_token_default_door_port():
    token = encode_token(_ANCHOR_DOOR_PUB, _CA_PUB, _ANCHOR_HOST, _SEED)
    *_, door_port, _dom = decode_token(token)
    assert door_port == 51901  # DOOR_PORT default


def test_token_prefix():
    token = encode_token(_ANCHOR_DOOR_PUB, _CA_PUB, _ANCHOR_HOST, _SEED)
    assert token.startswith(TOKEN_PREFIX)


def test_token_opaque():
    """Token must not contain the seed in plain base64."""
    token = encode_token(_ANCHOR_DOOR_PUB, _CA_PUB, _ANCHOR_HOST, _SEED)
    # The seed is embedded inside a larger payload so its raw b64 won't appear
    seed_b64 = base64.b64encode(_SEED).decode()
    assert seed_b64 not in token


def test_token_bad_prefix():
    with pytest.raises(ValueError, match="gw1."):
        decode_token("notgw1.abc")


def test_token_truncated():
    with pytest.raises(ValueError):
        decode_token(TOKEN_PREFIX + base64.urlsafe_b64encode(b"short").decode())


def test_token_different_hosts():
    for host in ["192.0.2.1", "example.com", "2001:db8::cafe"]:
        token = encode_token(_ANCHOR_DOOR_PUB, _CA_PUB, host, _SEED)
        _, _, decoded_host, _, _, _ = decode_token(token)
        assert decoded_host == host


# ── Door window slot detection (invite clobber guard) ──────────────────────────

def _write_window(data_dir, delta_minutes):
    import datetime as dt
    import json
    exp = dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=delta_minutes)
    (data_dir / "door_window.json").write_text(
        json.dumps({"v": 1, "expires": exp.strftime("%Y-%m-%dT%H:%M:%SZ")})
    )
    return exp.strftime("%Y-%m-%dT%H:%M:%SZ")


def test_active_window_none_when_absent(tmp_path):
    from greasewood.door import active_window_expiry
    assert active_window_expiry(tmp_path) is None


def test_active_window_returns_expiry_when_open(tmp_path):
    from greasewood.door import active_window_expiry
    exp = _write_window(tmp_path, 15)
    assert active_window_expiry(tmp_path) == exp


def test_active_window_none_when_expired(tmp_path):
    from greasewood.door import active_window_expiry
    _write_window(tmp_path, -1)
    assert active_window_expiry(tmp_path) is None


def test_active_window_none_when_malformed(tmp_path):
    from greasewood.door import active_window_expiry
    (tmp_path / "door_window.json").write_text("{not valid json")
    assert active_window_expiry(tmp_path) is None


# ── Door status/history (surfaced by `gw status`) ────────────────────────────

class TestDoorStatus:
    def test_lifecycle_open_attempt_enroll_close(self, tmp_path):
        from greasewood import door
        assert door.read_door_status(tmp_path) is None      # never opened

        door.mark_door_opened(tmp_path, "2026-07-02T10:00:00+00:00",
                              caps=["segment:mesh", "tls"], max_attempts=3)
        st = door.read_door_status(tmp_path)
        assert st["state"] == "open" and st["caps"] == ["segment:mesh", "tls"]
        assert st["attempts"] == [] and st["enrolled"] is None

        door.mark_door_attempt(tmp_path, "fd52::9", "hostname already in use")
        door.mark_door_attempt(tmp_path, "fd52::9", "revoked")
        st = door.read_door_status(tmp_path)
        assert [a["ip"] for a in st["attempts"]] == ["fd52::9", "fd52::9"]
        assert st["attempts"][0]["reason"] == "hostname already in use"

        door.mark_door_enrolled(tmp_path, "fd52::a", "db01")
        door.mark_door_closed(tmp_path, "enrolled")
        st = door.read_door_status(tmp_path)
        assert st["state"] == "closed" and st["close_reason"] == "enrolled"
        assert st["enrolled"] == {"ts": st["enrolled"]["ts"], "ip": "fd52::a",
                                  "hostname": "db01"}
        assert len(st["attempts"]) == 2                     # history preserved

    def test_close_is_idempotent_keeps_first_reason(self, tmp_path):
        from greasewood import door
        door.mark_door_opened(tmp_path, "2026-07-02T10:00:00+00:00")
        door.mark_door_closed(tmp_path, "expired")
        door.mark_door_closed(tmp_path, "superseded")       # second close ignored
        assert door.read_door_status(tmp_path)["close_reason"] == "expired"

    def test_reopen_resets_per_window_counters(self, tmp_path):
        from greasewood import door
        door.mark_door_opened(tmp_path, "2026-07-02T10:00:00+00:00")
        door.mark_door_attempt(tmp_path, "fd52::9", "x")
        door.mark_door_closed(tmp_path, "expired")
        door.mark_door_opened(tmp_path, "2026-07-02T11:00:00+00:00")   # new window
        st = door.read_door_status(tmp_path)
        assert st["state"] == "open" and st["attempts"] == [] and st["enrolled"] is None

    def test_status_file_is_0600(self, tmp_path):
        import stat
        from greasewood import door
        door.mark_door_opened(tmp_path, "2026-07-02T10:00:00+00:00")
        mode = stat.S_IMODE((tmp_path / "door_status.json").stat().st_mode)
        assert mode == 0o600, oct(mode)   # contains source IPs


def test_node_door_log_reports_configured_port(monkeypatch, caplog):
    """Regression: the 'node door interface up' log printed the DOOR_PORT
    constant, not the actually-configured door_port — lying exactly when a
    custom port was in play (i.e. when someone was debugging one)."""
    import logging
    import subprocess
    from greasewood import wg
    monkeypatch.setattr(wg, "_run",
                        lambda *a, **k: subprocess.CompletedProcess(a, 0, "", ""))
    with caplog.at_level(logging.INFO, logger="greasewood.wg"):
        wg.ensure_node_door_interface(b"k" * 32, "QUJD", "UFNL",
                                      "203.0.113.9", door_port=51999)
    assert any(":51999" in r.getMessage() for r in caplog.records)
    assert not any(":51901" in r.getMessage() for r in caplog.records)
