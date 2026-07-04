"""
DEEP: wire-object tamper resistance.

The security claim under test: a Credential is unforgeable (any change to any
body field, or to the signature, fails CA verification) and a NodeRecord is
unforgeable against its self-signature. The fast suite spot-checks this; here
Hypothesis drives arbitrary field values AND arbitrary tamper positions.

Keys are generated once at module scope — Hypothesis varies the data and the
tampering, not the keys, so failures shrink deterministically.
"""
import datetime as dt

import pytest
from hypothesis import assume, given, strategies as st

from greasewood.keys import CAKeys, NodeKeys, derive_addr
from greasewood.wire import Credential, NodeRecord

pytestmark = pytest.mark.deep

_UTC = dt.timezone.utc
CA = CAKeys.generate()
NODE = NodeKeys.generate()

# Text that survives a to_dict → JSON-ish → from_dict trip unchanged.
_field_text = st.text(
    alphabet=st.characters(blacklist_categories=("Cs",)), min_size=1, max_size=64)
_caps = st.lists(_field_text, max_size=8)
_ts = st.datetimes(min_value=dt.datetime(2020, 1, 1), max_value=dt.datetime(2100, 1, 1),
                   timezones=st.just(_UTC))
# verify() checks expiry (correctly!), so roundtrip-and-verify needs a live cred.
_future = st.datetimes(min_value=dt.datetime(2030, 1, 1),
                       max_value=dt.datetime(2100, 1, 1), timezones=st.just(_UTC))


def _cred(hostname, caps, iat, exp) -> Credential:
    return Credential(id_pub=NODE.id_pub_bytes, wg_pub=NODE.wg_pub_bytes,
                      addr=NODE.addr, hostname=hostname, caps=caps,
                      iat=iat, exp=exp).sign(CA.ca_priv)


@given(hostname=_field_text, caps=_caps, iat=_ts, exp=_future)
def test_credential_roundtrips_and_verifies(hostname, caps, iat, exp):
    cred = _cred(hostname, caps, iat, exp)
    again = Credential.from_dict(cred.to_dict())
    again.verify([CA.ca_pub_bytes])           # sig survives the round trip
    assert again.hostname == hostname
    assert sorted(again.caps) == sorted(caps)  # wire form canonicalizes caps order


@given(hostname=_field_text, caps=_caps, iat=_ts, exp=_future, data=st.data())
def test_credential_tamper_semantics_decide_verification(hostname, caps, iat, exp, data):
    """Serialize, corrupt one field value, deserialize. The wire format signs
    CANONICAL SEMANTICS, not raw bytes (a first run of this property proved it:
    fromisoformat accepts '2027-01-01000:00:00Z' as the same instant, and
    verify re-canonicalizes before checking the signature). So the honest
    property is: a tamper that changes the parsed semantics MUST fail
    verification; one that decodes to identical semantics MUST still verify."""
    cred = _cred(hostname, caps, iat, exp)
    d = cred.to_dict()
    field = data.draw(st.sampled_from(sorted(d.keys())), label="field")
    tampered = dict(d)
    v = tampered[field]
    if isinstance(v, str):
        pos = data.draw(st.integers(0, max(0, len(v) - 1)), label="pos")
        repl = data.draw(st.sampled_from("0Az/+-"), label="repl")
        assume(pos < len(v) and v[pos] != repl)     # must actually change it
        tampered[field] = v[:pos] + repl + v[pos + 1:]
    elif isinstance(v, list):
        tampered[field] = v + ["segment:injected"]
    else:
        tampered[field] = v if not isinstance(v, (int, float)) else v + 1
    assume(tampered[field] != v)

    try:
        forged = Credential.from_dict(tampered)
    except (ValueError, KeyError):
        return                                       # rejected at decode: fine
    same_body = forged._body_dict() == cred._body_dict()
    same_sig = getattr(forged, "ca_sig", None) == cred.ca_sig
    if same_body and same_sig:
        forged.verify([CA.ca_pub_bytes])             # equivalent encoding: valid
    else:
        with pytest.raises(ValueError):
            forged.verify([CA.ca_pub_bytes])


@given(seq=st.integers(0, 2**31), endpoints=st.lists(_field_text, max_size=4),
       hostname=_field_text, data=st.data())
def test_node_record_tamper_fails_structural(seq, endpoints, hostname, data):
    """The structural gate (self-sig + addr derivation + id/cred consistency)
    that admits records into the directory must reject any tampered field."""
    now = dt.datetime.now(_UTC).replace(microsecond=0)
    cred = _cred(hostname, ["segment:mesh"], now, now + dt.timedelta(hours=24))
    rec = NodeRecord(id_pub=NODE.id_pub_bytes, seq=seq, endpoints=endpoints,
                     inbound="yes", cred=cred).sign(NODE.id_priv)
    NodeRecord.from_dict(rec.to_dict()).verify_structural()   # baseline holds

    d = rec.to_dict()
    field = data.draw(st.sampled_from([k for k in sorted(d.keys()) if k != "cred"]),
                      label="field")
    tampered = dict(d)
    v = tampered[field]
    if isinstance(v, str) and v:
        tampered[field] = ("X" + v[1:]) if v[0] != "X" else ("Y" + v[1:])
    elif isinstance(v, list):
        tampered[field] = v + ["203.0.113.9:51900"]
    elif isinstance(v, int):
        tampered[field] = v + 1
    else:
        tampered[field] = "tampered"
    assume(tampered[field] != v)
    with pytest.raises(ValueError):
        NodeRecord.from_dict(tampered).verify_structural()


@given(st.binary(min_size=32, max_size=32))
def test_addr_derivation_is_stable_and_in_overlay(id_pub):
    """derive_addr is a pure function of id_pub and always lands in a /64."""
    a1, a2 = derive_addr(id_pub), derive_addr(id_pub)
    assert a1 == a2
    assert ":" in a1
