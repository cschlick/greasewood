"""
gw explain — the capstone of "the mesh that explains itself": one command
merges the audit trail, the replicated membership decisions, the credential
history, and peer endpoint testimony into a chronological story plus a
current-state verdict. These tests feed the engine synthetic evidence and
check the story it tells — including a replay of the bb incident, which
took a human two hours the first time.
"""
import datetime as dt
import types

from greasewood import explain as X
from greasewood import narrate as N
from greasewood.attest import AttestLog
from greasewood.directory import Directory
from greasewood.keys import CAKeys, NodeKeys, derive_addr
from greasewood.statements import StatementLog
from greasewood.wire import (AnchorStatement, Credential, EndpointAttestation,
                             NodeRecord)

_UTC = dt.timezone.utc
NOW = dt.datetime(2026, 9, 22, 12, 0, tzinfo=_UTC)


def _rec(ca, k, name, iat=None, endpoints=(), caps=("role:node",), seq=1):
    iat = iat or (NOW - dt.timedelta(hours=2))
    cred = Credential(id_pub=k.id_pub_bytes, wg_pub=k.wg_pub_bytes,
                      addr=derive_addr(k.id_pub_bytes), hostname=name,
                      caps=list(caps), iat=iat,
                      exp=iat + dt.timedelta(hours=24)).sign(ca.ca_priv)
    return NodeRecord(id_pub=k.id_pub_bytes, seq=seq, endpoints=list(endpoints),
                      cred=cred).sign(k.id_priv)


def _audit(*lines):
    return [e for e in (N.parse_line(l) for l in lines) if e is not None]


def _ts(hours_ago):
    return (NOW - dt.timedelta(hours=hours_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _story(subjects, **kw):
    kw.setdefault("now", NOW)
    kw.setdefault("since", NOW - dt.timedelta(hours=24))
    return X.build_story(subjects, **kw)


# ---------------------------------------------------------------------------
# subject resolution
# ---------------------------------------------------------------------------

def test_resolve_by_name_id_prefix_and_departed_name():
    ca, k = CAKeys.generate(), NodeKeys.generate()
    d = Directory()
    d.put(_rec(ca, k, "bb"))
    assert X.resolve_subject("bb", d).id_hex == k.id_pub_hex
    assert X.resolve_subject("BB.home.internal", d).id_hex == k.id_pub_hex
    assert X.resolve_subject(k.id_pub_hex[:12], d).id_hex == k.id_pub_hex

    # departed: record gone, but the tombstone remembers the name
    gone = NodeKeys.generate()
    stmts = StatementLog()
    stmts.add(AnchorStatement(kind="tombstone", id_pub=gone.id_pub_bytes,
                              ts=NOW, hostname="old-nas").sign(ca.ca_priv))
    s = X.resolve_subject("old-nas", Directory(), stmts)
    assert s.id_hex == gone.id_pub_hex


# ---------------------------------------------------------------------------
# the timeline
# ---------------------------------------------------------------------------

def test_story_merges_audit_statements_and_credential_history():
    ca, k = CAKeys.generate(), NodeKeys.generate()
    d = Directory()
    rec = _rec(ca, k, "bb", iat=NOW - dt.timedelta(hours=3))
    d.put(rec)
    subj = X.resolve_subject("bb", d)
    entries = _audit(
        f'ts={_ts(6)} event=enroll node=bb id={k.id_pub_hex[:16]} '
        f'addr={rec.cred.addr} peer_ip=198.51.100.7 reenroll=False',
        f'ts={_ts(5)} cmd rc=0 t=9ms ctx="reconcile: +peer bb [{rec.cred.addr}]" '
        f'argv="wg set gw-home peer AAAA allowed-ips {rec.cred.addr}/128"',
    )
    stmts = StatementLog()
    stmts.add(AnchorStatement(kind="setcaps", id_pub=k.id_pub_bytes,
                              ts=NOW - dt.timedelta(hours=1),
                              caps=["role:node", "role:rdp_srv"],
                              hostname="bb").sign(ca.ca_priv))
    out = _story([subj], audit_entries=entries, directory=d, statements=stmts)
    lines = out.splitlines()
    # chronological: enroll → +peer → renewal → roles
    order = [i for i, l in enumerate(lines)
             if any(w in l for w in ("enroll", "added a peer", "credential issued",
                                     "changed its roles"))]
    assert order == sorted(order) and len(order) == 4
    assert "rdp_srv" in out
    assert "now:" in out


def test_story_filters_to_the_subject_and_the_window():
    ca, k, other = CAKeys.generate(), NodeKeys.generate(), NodeKeys.generate()
    d = Directory()
    d.put(_rec(ca, k, "bb", iat=NOW - dt.timedelta(days=3)))   # old renewal
    d.put(_rec(ca, other, "nas"))
    subj = X.resolve_subject("bb", d)
    entries = _audit(
        f'ts={_ts(2)} cmd rc=0 t=1ms ctx="reconcile: +peer nas [fd8d::9]" '
        'argv="wg set gw-home peer BBBB allowed-ips fd8d::9/128"',      # not bb
        f'ts={_ts(60)} cmd rc=0 t=1ms ctx="reconcile: +peer bb [fd8d::1]" '
        'argv="wg set gw-home peer AAAA allowed-ips fd8d::1/128"',      # too old
    )
    out = _story([subj], audit_entries=entries, directory=d)
    assert "nas [" not in out                    # other node's ops excluded
    assert "no recorded events here" in out      # window empty → says so honestly


def test_failed_operation_is_flagged():
    ca, k = CAKeys.generate(), NodeKeys.generate()
    d = Directory()
    rec = _rec(ca, k, "bb")
    d.put(rec)
    entries = _audit(
        f'ts={_ts(1)} cmd rc=1 t=4ms ctx="reconcile: +peer bb [{rec.cred.addr}]" '
        f'argv="wg set gw-home peer AAAA" stderr="Unable to modify interface"',
    )
    out = _story([X.resolve_subject("bb", d)], audit_entries=entries, directory=d)
    assert "FAILED" in out and "gw narrate" in out


# ---------------------------------------------------------------------------
# the verdict
# ---------------------------------------------------------------------------

def test_now_block_shows_confirmations_and_pair_policy():
    ca = CAKeys.generate()
    a, b, witness = NodeKeys.generate(), NodeKeys.generate(), NodeKeys.generate()
    d = Directory()
    d.put(_rec(ca, a, "melvin", caps=["role:admin"],
               endpoints=["[2001:db8::a]:51900"]))
    d.put(_rec(ca, b, "bb", caps=["role:node"]))
    d.put(_rec(ca, witness, "nas"))
    attns = AttestLog()
    attns.merge([EndpointAttestation(
        attester=witness.id_pub_bytes, subject=a.id_pub_bytes,
        endpoint="[2001:db8::a]:51900",
        ts=NOW - dt.timedelta(minutes=2)).sign(witness.id_priv)],
        lambda h: True, now=NOW)
    grants = [{"from": ["admin"], "to": ["node"], "ports": ["tcp/22"]}]
    out = _story([X.resolve_subject("melvin", d), X.resolve_subject("bb", d)],
                 directory=d, attestations=attns, grants=grants)
    assert "endpoint confirmed by nas" in out
    assert "policy allows this tunnel" in out

    denied = _story([X.resolve_subject("melvin", d), X.resolve_subject("bb", d)],
                    directory=d,
                    grants=[{"from": ["web"], "to": ["db"], "ports": ["tcp/1"]}])
    assert "DENIES this tunnel" in denied


def test_departed_node_verdict():
    ca, gone = CAKeys.generate(), NodeKeys.generate()
    stmts = StatementLog()
    stmts.add(AnchorStatement(kind="tombstone", id_pub=gone.id_pub_bytes,
                              ts=NOW - dt.timedelta(hours=2),
                              hostname="bb").sign(ca.ca_priv))
    out = _story([X.resolve_subject("bb", Directory(), stmts)],
                 directory=Directory(), statements=stmts)
    assert "membership ended" in out             # the timeline line
    assert "departed (tombstoned)" in out        # the verdict line


# ---------------------------------------------------------------------------
# the incident replay: the mirage that took a human two hours
# ---------------------------------------------------------------------------

def test_the_bb_incident_reads_as_one_story():
    """Advertised endpoint no peer confirms + peers reaching it elsewhere:
    explain's verdict states in one line what the VPN-/128 investigation had
    to reconstruct from wg dumps, ip addr on two machines, and a hunch."""
    ca = CAKeys.generate()
    router, p1, p2 = NodeKeys.generate(), NodeKeys.generate(), NodeKeys.generate()
    d = Directory()
    d.put(_rec(ca, router, "router", caps=["role:*"],
               endpoints=["[2a07:b944::2:2]:51900"]))       # the mirage
    d.put(_rec(ca, p1, "nas"))
    d.put(_rec(ca, p2, "panda"))
    attns = AttestLog()
    attns.merge([
        EndpointAttestation(attester=p1.id_pub_bytes, subject=router.id_pub_bytes,
                            endpoint="[2601:643:8800:36f0::1]:51900",
                            ts=NOW - dt.timedelta(minutes=1)).sign(p1.id_priv),
        EndpointAttestation(attester=p2.id_pub_bytes, subject=router.id_pub_bytes,
                            endpoint="[2601:643:8800:36f0::1]:51900",
                            ts=NOW - dt.timedelta(minutes=3)).sign(p2.id_priv),
    ], lambda h: True, now=NOW)
    out = _story([X.resolve_subject("router", d)], directory=d,
                 attestations=attns)
    assert "UNCONFIRMED" in out
    assert "[2601:643:8800:36f0::1]:51900" in out           # the real address
