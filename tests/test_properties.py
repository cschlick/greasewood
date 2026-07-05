"""
Property-based tests (hypothesis) for the protocol's core invariants.

The example-based suites pin known-good/known-bad cases; these pin the
*shape* of the guarantees over arbitrary input:

- wire objects survive a to_dict/from_dict roundtrip unchanged
- decode_token never raises anything but ValueError, on any input
- encode_token/decode_token roundtrip exactly
- hosts.sanitize is idempotent and always yields a valid DNS label
- Directory.merge is order-independent and idempotent (the conflict-free
  merge claim, actually tested rather than asserted in a docstring)
"""
import datetime as dt
import string

from hypothesis import given, settings, strategies as st

from greasewood import door, hosts
from greasewood.directory import Directory
from greasewood.keys import CAKeys, NodeKeys
from greasewood.wire import CertRequest, Credential, NodeRecord, RenewRequest

_UTC = dt.timezone.utc

# --- strategies -------------------------------------------------------------

bytes32 = st.binary(min_size=32, max_size=32)
sig64 = st.binary(min_size=64, max_size=64)

# Second-precision aware UTC datetimes, the only form _ts emits.
timestamps = st.datetimes(
    min_value=dt.datetime(2000, 1, 1), max_value=dt.datetime(2100, 1, 1),
).map(lambda t: t.replace(microsecond=0, tzinfo=_UTC))

# caps are signed sorted, so roundtrip equality needs sorted unique input.
cap_token = st.text(alphabet=string.ascii_lowercase + string.digits + ":-*",
                    min_size=1, max_size=20)
caps_lists = st.lists(cap_token, max_size=5, unique=True).map(sorted)

short_text = st.text(max_size=40)


def credentials():
    return st.builds(
        Credential,
        id_pub=bytes32, wg_pub=bytes32,
        addr=short_text, hostname=short_text, caps=caps_lists,
        iat=timestamps, exp=timestamps, ca_sig=sig64,
    )


# --- wire roundtrips ---------------------------------------------------------

@settings(deadline=None)
@given(credentials())
def test_credential_roundtrip(cred):
    assert Credential.from_dict(cred.to_dict()) == cred


@settings(deadline=None)
@given(st.builds(
    NodeRecord,
    id_pub=bytes32, seq=st.integers(min_value=0, max_value=2**53),
    endpoints=st.lists(short_text, max_size=4), inbound=short_text,
    cred=credentials(), sig=sig64,
))
def test_node_record_roundtrip(rec):
    assert NodeRecord.from_dict(rec.to_dict()) == rec


@settings(deadline=None)
@given(st.builds(
    RenewRequest,
    id_pub=bytes32, wg_pub=bytes32, nonce=short_text, ts=timestamps,
    hostname=short_text, sig=sig64,
))
def test_renew_request_roundtrip(req):
    assert RenewRequest.from_dict(req.to_dict()) == req


@settings(deadline=None)
@given(st.builds(
    CertRequest,
    id_pub=bytes32, leaf_pub=bytes32, cn=short_text,
    dns=st.lists(short_text, max_size=4), ips=st.lists(short_text, max_size=4),
    nonce=short_text, ts=timestamps, sig=sig64,
))
def test_cert_request_roundtrip(req):
    assert CertRequest.from_dict(req.to_dict()) == req


# --- join token --------------------------------------------------------------

@settings(deadline=None)
@given(st.text(max_size=200))
def test_decode_token_never_raises_non_valueerror(text):
    """Garbage in → ValueError (or a parse), never any other exception. The
    token is the one input a brand-new node takes from the outside world."""
    try:
        door.decode_token(text)
    except ValueError:
        pass  # includes binascii.Error and UnicodeDecodeError subclasses


@settings(deadline=None)
@given(
    anchor_pub=bytes32, ca_pub=bytes32, seed=bytes32,
    host=st.text(max_size=60).filter(lambda h: len(h.encode()) <= 255),
    port=st.integers(min_value=0, max_value=65535),
)
def test_token_roundtrip(anchor_pub, ca_pub, seed, host, port):
    tok = door.encode_token(anchor_pub, ca_pub, host, seed, door_port=port)
    got_anchor, got_ca, got_host, got_seed, got_port, _dom = door.decode_token(tok)
    assert (got_anchor, got_ca, got_host, got_seed, got_port) == \
        (anchor_pub, ca_pub, host, seed, port)


# --- hostname sanitization ----------------------------------------------------

@settings(deadline=None)
@given(st.text(max_size=200))
def test_sanitize_idempotent_and_valid_label(name):
    import re
    s = hosts.sanitize(name)
    assert hosts.sanitize(s) == s                       # idempotent
    assert 1 <= len(s) <= 63                            # DNS label bounds
    assert re.fullmatch(r"[a-z0-9]([a-z0-9-]*[a-z0-9])?|[a-z0-9]", s), s


# --- directory merge (the CRDT claim) -----------------------------------------

_CA = CAKeys.generate()
_NODES = [NodeKeys.generate() for _ in range(3)]
_RECORD_CACHE: dict = {}


def _record(node_idx: int, seq: int) -> NodeRecord:
    key = (node_idx, seq)
    if key not in _RECORD_CACHE:
        node = _NODES[node_idx]
        now = dt.datetime.now(_UTC).replace(microsecond=0)
        cred = Credential(
            id_pub=node.id_pub_bytes, wg_pub=node.wg_pub_bytes,
            addr=node.addr, hostname=f"n{node_idx}", caps=["segment:mesh"],
            iat=now, exp=now + dt.timedelta(hours=1),
        ).sign(_CA.ca_priv)
        _RECORD_CACHE[key] = NodeRecord(
            id_pub=node.id_pub_bytes, seq=seq, endpoints=[], inbound="yes",
            cred=cred,
        ).sign(node.id_priv)
    return _RECORD_CACHE[key]


record_refs = st.tuples(st.integers(min_value=0, max_value=2),
                        st.integers(min_value=1, max_value=20))


def _state(directory: Directory) -> dict:
    return {r.id_pub.hex(): r.seq for r in directory.all()}


@settings(deadline=None)
@given(refs=st.lists(record_refs, max_size=20), data=st.data())
def test_merge_is_order_independent(refs, data):
    """Highest-seq-wins must converge to the same state whatever order (or
    batching) records arrive in — that's what makes anchor pulls conflict-free."""
    records = [_record(i, s) for i, s in refs]
    shuffled = data.draw(st.permutations(records))

    d1, d2 = Directory(), Directory()
    d1.merge(records)
    for r in shuffled:                # one-at-a-time, different order
        d2.merge([r])
    assert _state(d1) == _state(d2)


@settings(deadline=None)
@given(refs=st.lists(record_refs, max_size=20))
def test_merge_is_idempotent(refs):
    records = [_record(i, s) for i, s in refs]
    d = Directory()
    d.merge(records)
    before = _state(d)
    accepted_again = d.merge(records)  # replaying everything changes nothing
    assert _state(d) == before
    assert accepted_again == 0
