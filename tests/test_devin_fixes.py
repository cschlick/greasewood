"""
Fixes for the applicable findings from the Devin (macos-branch) security review,
verified against current main:
  GW-IFACE-001  - reject an unsafe --interface (nft-injection / path-traversal surface)
  GW-REPLAY-001 - the replay guard has a hard memory cap (nonce-flood DoS)
  GW-CRYPTO-001 - wire from_dict length-checks public keys (clean 400, not 500)
"""
import base64

import pytest


# ---- GW-IFACE-001: interface-name validation ------------------------------

def test_reject_bad_interface_accepts_valid_names():
    from greasewood import cli
    for ok in ("gw-mesh", "gw-prod-fleet1", "mesh0", "eth0", "gw_door", "a"):
        cli._reject_bad_interface(ok)          # must not raise


@pytest.mark.parametrize("bad", [
    'gw-x"accept',        # quote — would break/inject the nft ruleset text
    "gw-\naccept",        # newline
    "gw-x;drop",          # semicolon
    "gw-x}chain{",        # braces
    "gw/../x",            # path traversal chars
    "gw x",               # space
    "a" * 16,             # 16 > kernel IFNAMSIZ-1 (15)
    "",                   # empty
])
def test_reject_bad_interface_refuses_unsafe(bad):
    from greasewood import cli
    with pytest.raises(SystemExit, match="valid Linux interface name"):
        cli._reject_bad_interface(bad)


# ---- GW-REPLAY-001: replay guard hard cap ---------------------------------

def test_replay_guard_bounds_memory_under_a_nonce_flood():
    from greasewood.server import _ReplayGuard
    g = _ReplayGuard(window=600.0)             # everything stays live in-window
    accepted = 0
    for i in range(_ReplayGuard._HARD * 2):
        if g.check_and_add(f"nonce-{i}"):
            accepted += 1
    # It stopped accepting new nonces once saturated, and never grew past the cap.
    assert accepted <= _ReplayGuard._HARD
    assert len(g._seen) <= _ReplayGuard._HARD
    # A truly full guard refuses even a brand-new nonce (fail closed under flood).
    assert g.check_and_add("a-fresh-one") is False


def test_replay_guard_still_detects_a_plain_replay():
    from greasewood.server import _ReplayGuard
    g = _ReplayGuard(window=600.0)
    assert g.check_and_add("n1") is True        # fresh
    assert g.check_and_add("n1") is False       # replay


# ---- GW-CRYPTO-001: from_dict rejects wrong-length keys -------------------

def _short_key_b64():
    return base64.b64encode(b"\x00" * 16).decode()   # 16 bytes, not 32


def test_credential_from_dict_rejects_short_id_pub():
    from greasewood.wire import Credential
    d = {"id_pub": _short_key_b64(), "wg_pub": base64.b64encode(b"\x00" * 32).decode(),
         "addr": "fd8d::1", "hostname": "n1", "caps": [], "iat": "2026-01-01T00:00:00Z",
         "exp": "2026-01-02T00:00:00Z", "ca_sig": base64.b64encode(b"\x00" * 64).decode()}
    with pytest.raises(ValueError, match="id_pub must be a 32-byte key"):
        Credential.from_dict(d)


def test_renewrequest_from_dict_rejects_short_wg_pub():
    from greasewood.wire import RenewRequest
    d = {"id_pub": base64.b64encode(b"\x00" * 32).decode(), "wg_pub": _short_key_b64(),
         "nonce": "x", "ts": "2026-01-01T00:00:00Z",
         "sig": base64.b64encode(b"\x00" * 64).decode()}
    with pytest.raises(ValueError, match="wg_pub must be a 32-byte key"):
        RenewRequest.from_dict(d)
