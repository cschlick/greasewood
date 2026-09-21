"""
The authorization lifecycle without a registry: the node's replicated record
IS what renewal re-issues from, so its presence/absence/tombstoning decides
everything the old nodes/<id>.json drop used to. Once the record ages out (or
a tombstone ends the membership), renew() refuses — a return requires a full
re-enrollment through the door, exactly the old drop semantics with the
mechanism moved into the replicated layer.
"""
import datetime as dt
import secrets

import pytest

from greasewood.ca import CA, UnknownNodeError
from greasewood.directory import Directory
from greasewood.keys import CAKeys, NodeKeys, derive_addr
from greasewood.statements import StatementLog
from greasewood.wire import AnchorStatement, Credential, NodeRecord, RenewRequest

_UTC = dt.timezone.utc


def _now():
    return dt.datetime.now(_UTC).replace(microsecond=0)


def _rec(ca_keys, k, name, iat, ttl_h=24, caps=("mesh",), seq=1):
    cred = Credential(id_pub=k.id_pub_bytes, wg_pub=k.wg_pub_bytes,
                      addr=derive_addr(k.id_pub_bytes), hostname=name,
                      caps=list(caps), iat=iat,
                      exp=iat + dt.timedelta(hours=ttl_h)).sign(ca_keys.ca_priv)
    return NodeRecord(id_pub=k.id_pub_bytes, seq=seq, endpoints=[],
                      cred=cred).sign(k.id_priv)


def _req(k, hostname=""):
    return RenewRequest(id_pub=k.id_pub_bytes, wg_pub=k.wg_pub_bytes,
                        nonce=secrets.token_hex(16), ts=_now(),
                        hostname=hostname).sign(k.id_priv)


def _ca(tmp_path, directory=None, statements=None):
    return CA(CAKeys.generate(), tmp_path, directory=directory or Directory(),
              statements=statements or StatementLog())


def test_renewal_reissues_from_the_replicated_record(tmp_path):
    """The record carries everything renewal needs — hostname AND caps — so
    any holder that has synced it can serve the renewal, with no state that
    ever needs handing over."""
    ca_keys = CAKeys.generate()
    k = NodeKeys.generate()
    d = Directory()
    d.put(_rec(ca_keys, k, "db01", _now() - dt.timedelta(hours=20),
               caps=["segment:prod", "tls"]))
    ca = CA(ca_keys, tmp_path, directory=d, statements=StatementLog())
    cred = ca.renew(_req(k))
    assert cred.hostname == "db01"
    assert set(cred.caps) == {"segment:prod", "tls"}


def test_expired_record_still_renews_within_grace(tmp_path):
    """Expiry is liveness, not death: a node asleep past its TTL recertifies
    from its (expired) record as long as the record hasn't aged out."""
    ca_keys = CAKeys.generate()
    k = NodeKeys.generate()
    d = Directory()
    d.put(_rec(ca_keys, k, "sleeper", _now() - dt.timedelta(days=3)))   # expired 2d ago
    ca = CA(ca_keys, tmp_path, directory=d, statements=StatementLog())
    assert ca.renew(_req(k)).hostname == "sleeper"


def test_no_record_means_reenroll(tmp_path):
    """The drop consequence: no record (aged out and pruned, or never there)
    → typed refusal; the node must come back through the door."""
    ca = _ca(tmp_path)
    with pytest.raises(UnknownNodeError):
        ca.renew(_req(NodeKeys.generate()))


def test_tombstoned_membership_cannot_renew_but_reenrollment_can(tmp_path):
    """A tombstone (leave/sweep decided at ANY holder) ends the membership its
    ts covers: renewal from the old record refuses. The same identity's fresh
    enrollment — credential issued after the tombstone — renews fine."""
    ca_keys = CAKeys.generate()
    k = NodeKeys.generate()
    d, stmts = Directory(), StatementLog()
    d.put(_rec(ca_keys, k, "bb", _now() - dt.timedelta(hours=2)))
    stmts.merge([AnchorStatement(kind="tombstone", id_pub=k.id_pub_bytes,
                                 ts=_now() - dt.timedelta(hours=1),
                                 hostname="bb").sign(ca_keys.ca_priv)],
                [ca_keys.ca_pub_bytes])
    ca = CA(ca_keys, tmp_path, directory=d, statements=stmts)
    with pytest.raises(UnknownNodeError):
        ca.renew(_req(k))
    # …and its hostname is free for anyone (that is what the tombstone frees).
    assert ca.hostname_owner("bb") is None

    # bb re-enrolls: a fresh record postdating the tombstone.
    d.put(_rec(ca_keys, k, "bb", _now(), seq=2))
    assert ca.renew(_req(k)).hostname == "bb"


def test_untrusted_record_is_not_a_renewal_source(tmp_path):
    """A record whose credential no trusted CA signed must never feed
    issuance: structural merge admits it into the directory (CA-independent by
    design), but renewal verifies against the trusted set — otherwise a
    forged-cred record could launder arbitrary caps into a real credential."""
    ca_keys, evil = CAKeys.generate(), CAKeys.generate()
    k = NodeKeys.generate()
    d = Directory()
    d.put(_rec(evil, k, "root", _now(), caps=["role:*"]))   # evil-signed cred
    ca = CA(ca_keys, tmp_path, directory=d, statements=StatementLog())
    with pytest.raises(UnknownNodeError):
        ca.renew(_req(k))


def test_reroot_overlap_renews_from_old_cas_record(tmp_path):
    """The re-root path with no special code: during the overlap the new
    holder trusts old+new CA pubs, so the outgoing CA's record is a valid
    renewal source and the node crosses over on its next renewal."""
    old_ca, new_ca = CAKeys.generate(), CAKeys.generate()
    k = NodeKeys.generate()
    d = Directory()
    d.put(_rec(old_ca, k, "veteran", _now() - dt.timedelta(hours=20)))
    ca = CA(new_ca, tmp_path, directory=d, statements=StatementLog(),
            get_ca_pubs=lambda: [old_ca.ca_pub_bytes, new_ca.ca_pub_bytes])
    cred = ca.renew(_req(k))
    cred.verify([new_ca.ca_pub_bytes])          # now signed by the NEW root
    assert cred.hostname == "veteran"
