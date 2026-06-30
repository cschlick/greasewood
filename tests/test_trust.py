"""
Unit tests for greasewood.trust — CA succession trust resolution (§11).

These lock down the load-bearing security property: who a node accepts
credential signatures from as hub/CA status migrates A -> B -> C -> ...
"""
import datetime as dt

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from greasewood.wire import CAStatement
from greasewood.trust import CABundle, resolve_trust, active_hub_endpoint

_UTC = dt.timezone.utc


def _ca():
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return priv, pub


def _stmt(kind, by_priv, by_pub, subject_pub, *, endpoint="", iat=None, exp=None):
    now = dt.datetime.now(_UTC).replace(microsecond=0)
    iat = iat or now
    exp = exp or (now + dt.timedelta(days=3650))
    return CAStatement(
        kind=kind, by_pub=by_pub, subject_pub=subject_pub,
        hub_endpoint=endpoint, iat=iat, exp=exp,
    ).sign(by_priv)


def _bundle(*statements):
    b = CABundle()
    b.merge(list(statements))
    return b


# --- CAStatement round-trip + signing ---

def test_statement_sign_verify_roundtrip():
    a_priv, a_pub = _ca()
    _, b_pub = _ca()
    s = _stmt("endorse", a_priv, a_pub, b_pub, endpoint="http://[fd8d::1]:7946")
    s.verify_sig()  # no raise
    s2 = CAStatement.from_dict(s.to_dict())
    s2.verify_sig()
    assert s2.subject_pub == b_pub and s2.hub_endpoint == "http://[fd8d::1]:7946"


def test_statement_tamper_detected():
    a_priv, a_pub = _ca()
    _, b_pub = _ca()
    _, rogue = _ca()
    s = _stmt("endorse", a_priv, a_pub, b_pub)
    s.subject_pub = rogue  # tamper after signing
    with pytest.raises(ValueError):
        s.verify_sig()


def test_statement_unknown_kind_rejected():
    a_priv, a_pub = _ca()
    _, b_pub = _ca()
    s = _stmt("endorse", a_priv, a_pub, b_pub)
    s.kind = "frobnicate"
    with pytest.raises(ValueError):
        s.verify_sig()


# --- resolution: the core succession property ---

def test_root_only_trusts_itself():
    _, a_pub = _ca()
    assert resolve_trust({a_pub}, CABundle()) == {a_pub}


def test_single_endorsement_adds_successor():
    a_priv, a_pub = _ca()
    _, b_pub = _ca()
    b = _bundle(_stmt("endorse", a_priv, a_pub, b_pub))
    assert resolve_trust({a_pub}, b) == {a_pub, b_pub}


def test_transitive_chain_A_B_C():
    a_priv, a_pub = _ca()
    b_priv, b_pub = _ca()
    c_priv, c_pub = _ca()
    b = _bundle(
        _stmt("endorse", a_priv, a_pub, b_pub),
        _stmt("endorse", b_priv, b_pub, c_pub),
    )
    # A node rooted only at A still trusts C through the chain.
    assert resolve_trust({a_pub}, b) == {a_pub, b_pub, c_pub}


def test_retire_predecessor_keeps_successor():
    a_priv, a_pub = _ca()
    b_priv, b_pub = _ca()
    base = dt.datetime.now(_UTC).replace(microsecond=0) - dt.timedelta(hours=1)
    b = _bundle(
        _stmt("endorse", a_priv, a_pub, b_pub, iat=base),
        # B retires A *after* A endorsed B
        _stmt("retire", b_priv, b_pub, a_pub, iat=base + dt.timedelta(seconds=1)),
    )
    # A is gone, B survives via A's durable (pre-retirement) endorsement.
    assert resolve_trust({a_pub}, b) == {b_pub}


def test_indefinite_succession_all_take_a_turn():
    """A -> B -> C -> D, each retiring its predecessor; only the last is active,
    but a node rooted at A keeps up the whole way."""
    cas = [_ca() for _ in range(4)]  # (priv, pub) for A,B,C,D
    pubs = [p for _, p in cas]
    base = dt.datetime.now(_UTC).replace(microsecond=0) - dt.timedelta(hours=1)
    stmts = []
    for i in range(3):  # A->B, B->C, C->D
        t = base + dt.timedelta(seconds=i * 10)
        stmts.append(_stmt("endorse", cas[i][0], pubs[i], pubs[i + 1], iat=t))
        # successor retires predecessor right after taking over
        stmts.append(_stmt("retire", cas[i + 1][0], pubs[i + 1], pubs[i],
                           iat=t + dt.timedelta(seconds=1)))
    b = _bundle(*stmts)
    # Node rooted at the original A ends up trusting only the final hub D.
    assert resolve_trust({pubs[0]}, b) == {pubs[3]}


def test_retired_ca_cannot_endorse_new():
    """A leaked, retired CA key can't inject a fresh successor."""
    a_priv, a_pub = _ca()
    b_priv, b_pub = _ca()
    _, rogue_pub = _ca()
    base = dt.datetime.now(_UTC).replace(microsecond=0) - dt.timedelta(hours=1)
    b = _bundle(
        _stmt("endorse", a_priv, a_pub, b_pub, iat=base),
        _stmt("retire", b_priv, b_pub, a_pub, iat=base + dt.timedelta(seconds=1)),
        # A, already retired, tries to endorse a rogue CA later
        _stmt("endorse", a_priv, a_pub, rogue_pub, iat=base + dt.timedelta(seconds=2)),
    )
    trusted = resolve_trust({a_pub}, b)
    assert rogue_pub not in trusted
    assert trusted == {b_pub}


def test_untrusted_endorser_ignored():
    """An endorsement by a CA nobody trusts does nothing."""
    a_priv, a_pub = _ca()
    stranger_priv, stranger_pub = _ca()
    _, x_pub = _ca()
    b = _bundle(_stmt("endorse", stranger_priv, stranger_pub, x_pub))
    assert resolve_trust({a_pub}, b) == {a_pub}


def test_expired_endorsement_ignored():
    a_priv, a_pub = _ca()
    _, b_pub = _ca()
    past = dt.datetime.now(_UTC).replace(microsecond=0) - dt.timedelta(days=10)
    b = _bundle(_stmt("endorse", a_priv, a_pub, b_pub,
                      iat=past, exp=past + dt.timedelta(days=1)))
    assert resolve_trust({a_pub}, b) == {a_pub}


def test_cycle_is_safe():
    a_priv, a_pub = _ca()
    b_priv, b_pub = _ca()
    b = _bundle(
        _stmt("endorse", a_priv, a_pub, b_pub),
        _stmt("endorse", b_priv, b_pub, a_pub),  # B endorses A back
    )
    assert resolve_trust({a_pub}, b) == {a_pub, b_pub}


# --- hub endpoint advertisement ---

def test_active_hub_endpoint_follows_latest_endorsement():
    a_priv, a_pub = _ca()
    b_priv, b_pub = _ca()
    _, c_pub = _ca()
    base = dt.datetime.now(_UTC).replace(microsecond=0) - dt.timedelta(hours=1)
    b = _bundle(
        _stmt("endorse", a_priv, a_pub, b_pub, endpoint="http://[fd8d::b]:7946",
              iat=base),
        _stmt("endorse", b_priv, b_pub, c_pub, endpoint="http://[fd8d::c]:7946",
              iat=base + dt.timedelta(seconds=10)),
    )
    assert active_hub_endpoint({a_pub}, b) == "http://[fd8d::c]:7946"


def test_active_hub_endpoint_none_without_endorsements():
    _, a_pub = _ca()
    assert active_hub_endpoint({a_pub}, CABundle()) is None


# --- bundle merge / persistence ---

def test_bundle_merge_dedupes_and_drops_invalid():
    a_priv, a_pub = _ca()
    _, b_pub = _ca()
    s = _stmt("endorse", a_priv, a_pub, b_pub)
    bundle = CABundle()
    assert bundle.merge([s]) == 1
    assert bundle.merge([s]) == 0  # duplicate
    bad = _stmt("endorse", a_priv, a_pub, b_pub)
    bad.sig = b"\x00" * 64  # corrupt signature
    assert bundle.merge([bad]) == 0
    assert len(bundle.statements) == 1


def test_bundle_save_load_roundtrip(tmp_path):
    a_priv, a_pub = _ca()
    _, b_pub = _ca()
    bundle = _bundle(_stmt("endorse", a_priv, a_pub, b_pub))
    p = tmp_path / "ca_bundle.json"
    bundle.save(p)
    loaded = CABundle.load(p)
    assert len(loaded.statements) == 1
    assert resolve_trust({a_pub}, loaded) == {a_pub, b_pub}


# --- retired CA cannot make new statements (symmetric guard, security) ---

def test_retired_ca_cannot_retire_live_hub():
    """A leaked, already-retired CA key must not be able to retire (un-trust)
    the current hub fleet-wide. This is the symmetric twin of the endorsement
    guard and a documented security property of §11 succession."""
    a_priv, a_pub = _ca()
    b_priv, b_pub = _ca()
    now = dt.datetime.now(_UTC).replace(microsecond=0)
    day = dt.timedelta(days=1)

    endorse_b = _stmt("endorse", a_priv, a_pub, b_pub, endpoint="http://b",
                      iat=now - 2 * day)
    retire_a = _stmt("retire", a_priv, a_pub, a_pub, iat=now - day)  # A self-retires
    # Attack: A's leaked key signs a *new* retirement of the live hub B.
    attack = _stmt("retire", a_priv, a_pub, b_pub, iat=now)

    active = resolve_trust({a_pub}, _bundle(endorse_b, retire_a, attack), now)
    assert b_pub in active, "leaked retired key must not be able to retire the live hub"
    assert a_pub not in active, "A's own retirement still stands"


def test_live_hub_can_retire_predecessor():
    """The legitimate path must still work: the successor (un-retired) retires
    its predecessor, who drops out while the successor stays trusted."""
    a_priv, a_pub = _ca()
    b_priv, b_pub = _ca()
    now = dt.datetime.now(_UTC).replace(microsecond=0)
    day = dt.timedelta(days=1)

    endorse_b = _stmt("endorse", a_priv, a_pub, b_pub, iat=now - 2 * day)
    retire_a_by_b = _stmt("retire", b_priv, b_pub, a_pub, iat=now)

    active = resolve_trust({a_pub}, _bundle(endorse_b, retire_a_by_b), now)
    assert a_pub not in active and b_pub in active


def test_chain_survives_predecessor_retirement():
    """A -> B -> C, then A retires. A node rooted at A must still trust C."""
    a_priv, a_pub = _ca()
    b_priv, b_pub = _ca()
    _, c_pub = _ca()
    now = dt.datetime.now(_UTC).replace(microsecond=0)
    day = dt.timedelta(days=1)

    endorse_b = _stmt("endorse", a_priv, a_pub, b_pub, iat=now - 2 * day)
    endorse_c = _stmt("endorse", b_priv, b_pub, c_pub, iat=now - day)
    retire_a = _stmt("retire", a_priv, a_pub, a_pub, iat=now)

    active = resolve_trust({a_pub}, _bundle(endorse_b, endorse_c, retire_a), now)
    assert c_pub in active and b_pub in active and a_pub not in active
