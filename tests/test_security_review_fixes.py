"""
Regression tests for the fixes to the 2026-07-13 security review:
  H1  - door enrollment requires proof-of-possession of id_priv (enroll.py / wire.py)
  L10 - TLS cert placement resists a symlink race (certs.py)
(L6 - the standing-door window is written 0600-atomically - is asserted in
 test_standing_door.py's file-mode check via keys.atomic_write.)
"""
import base64
import os
import types
from pathlib import Path

import pytest

from greasewood.enroll import EnrollServer, EnrollContext
from greasewood.keys import NodeKeys
from greasewood.wire import enroll_pop_body


# ---- H1: proof-of-possession at door enrollment ---------------------------

class _CA:
    def node_info(self, id_pub):
        return None


def _srv():
    ctx = EnrollContext(ca=_CA(), directory=types.SimpleNamespace(get=lambda *a: None),
                        node_keys=NodeKeys.generate(), wg_iface="gw-mesh")
    return EnrollServer(ctx, lambda: None)


def _signed_req(joiner, hostname="n1", wg_pub=None, roles=()):
    wgb = joiner.wg_pub_bytes if wg_pub is None else wg_pub
    sig = joiner.id_priv.sign(enroll_pop_body(joiner.id_pub_bytes, wgb, hostname or ""))
    return {
        "v": 1,
        "id_pub": joiner.id_pub_bytes.hex(),
        "wg_pub": base64.b64encode(wgb).decode(),
        "hostname": hostname,
        "roles": list(roles),
        "id_sig": base64.b64encode(sig).decode(),
    }


def test_valid_proof_of_possession_accepted():
    j = NodeKeys.generate()
    idp, wgp, host, _ = _srv()._validate_request(_signed_req(j, "web1"))
    assert idp == j.id_pub_bytes and wgp == j.wg_pub_bytes and host == "web1"


def test_missing_id_sig_rejected():
    j = NodeKeys.generate()
    req = _signed_req(j)
    del req["id_sig"]
    with pytest.raises(ValueError, match="proof-of-possession"):
        _srv()._validate_request(req)


def test_H1_attacker_cannot_enroll_under_victims_id_pub():
    """The core H1 fix: an adversary presents the victim's (public) id_pub bound
    to its OWN wg_pub, signing with its own id_priv. Without the victim's id_priv
    the signature can't verify against victim id_pub -> refused."""
    victim, attacker = NodeKeys.generate(), NodeKeys.generate()
    req = {
        "v": 1,
        "id_pub": victim.id_pub_bytes.hex(),                 # victim's public id
        "wg_pub": base64.b64encode(attacker.wg_pub_bytes).decode(),  # attacker's wg key
        "hostname": "victimname",
        "roles": [],
        "id_sig": base64.b64encode(attacker.id_priv.sign(    # signed by ATTACKER
            enroll_pop_body(victim.id_pub_bytes, attacker.wg_pub_bytes, "victimname"))).decode(),
    }
    with pytest.raises(ValueError, match="did not prove possession"):
        _srv()._validate_request(req)


def test_captured_signature_cannot_be_reused_with_a_different_wg_pub():
    """The PoP binds wg_pub, so a valid signature can't be replayed to re-point
    the identity at a different WireGuard key."""
    j = NodeKeys.generate()
    req = _signed_req(j, "n1")                                # sig covers j.wg_pub
    req["wg_pub"] = base64.b64encode(NodeKeys.generate().wg_pub_bytes).decode()
    with pytest.raises(ValueError, match="did not prove possession"):
        _srv()._validate_request(req)


def test_garbage_signature_fails_closed():
    j = NodeKeys.generate()
    req = _signed_req(j)
    req["id_sig"] = "@@@ not base64 @@@"
    with pytest.raises(ValueError):
        _srv()._validate_request(req)


def test_pop_body_is_deterministic_and_binds_all_three_fields():
    a, b = b"\x01" * 32, b"\x02" * 32
    base = enroll_pop_body(a, b, "h")
    assert base == enroll_pop_body(a, b, "h")            # deterministic
    assert base != enroll_pop_body(a, b"\x03" * 32, "h")  # wg_pub bound
    assert base != enroll_pop_body(b, b, "h")             # id_pub bound
    assert base != enroll_pop_body(a, b, "h2")            # hostname bound


# ---- L10: cert placement resists a symlink pre-plant ----------------------

def test_place_cert_files_ignores_a_preplanted_symlink_temp(tmp_path):
    """A non-root writer of the target dir pre-plants the OLD predictable temp
    name as a symlink to a sensitive file. With mkstemp (random name) + fd-based
    chmod/chown, placement never opens or follows it: the target is untouched
    and the cert lands correctly."""
    from greasewood import certs
    victim = tmp_path / "root_owned_secret"
    victim.write_text("DO NOT TRUNCATE OR CHOWN ME")
    dest = tmp_path / "server.crt"
    # the attack that WORKED against the old fixed-name temp:
    (tmp_path / "server.crt.gwtmp").symlink_to(victim)

    certs.place_cert_files(
        [{"role": "cert", "path": str(dest), "mode": "0644"}],
        "KEY", "CERTPEM", "CAPEM")

    assert victim.read_text() == "DO NOT TRUNCATE OR CHOWN ME"   # untouched
    assert not victim.is_symlink() and dest.read_text().strip() != ""
    assert oct(dest.stat().st_mode)[-3:] == "644"
