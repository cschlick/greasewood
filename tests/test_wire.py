"""Tests for Credential, NodeRecord, and request signing/verification (milestone 1)."""
import datetime as dt
from dataclasses import replace

import pytest

from greasewood.keys import CAKeys, NodeKeys, derive_addr
from greasewood.wire import CertRequest, Credential, NodeRecord, RenewRequest

_UTC = dt.timezone.utc


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def make_cred(
    node: NodeKeys,
    ca: CAKeys,
    caps: list[str] | None = None,
    ttl_seconds: int = 3600,
    hostname: str = "test-node",
) -> Credential:
    now = dt.datetime.now(_UTC).replace(microsecond=0)
    cred = Credential(
        id_pub=node.id_pub_bytes,
        wg_pub=node.wg_pub_bytes,
        addr=node.addr,
        hostname=hostname,
        caps=caps or ["mesh"],
        iat=now,
        exp=now + dt.timedelta(seconds=ttl_seconds),
    )
    return cred.sign(ca.ca_priv)


def make_record(
    node: NodeKeys,
    cred: Credential,
    seq: int = 1,
    endpoints: list[str] | None = None,
    inbound: str = "yes",
) -> NodeRecord:
    r = NodeRecord(
        id_pub=node.id_pub_bytes,
        seq=seq,
        endpoints=endpoints or ["[2001:db8::1]:51820"],
        inbound=inbound,
        cred=cred,
    )
    return r.sign(node.id_priv)


# ---------------------------------------------------------------------------
# Credential
# ---------------------------------------------------------------------------

class TestCredential:
    def test_sign_and_verify(self):
        ca = CAKeys.generate()
        node = NodeKeys.generate()
        cred = make_cred(node, ca)
        cred.verify([ca.ca_pub_bytes])  # must not raise

    def test_wrong_ca_rejected(self):
        ca = CAKeys.generate()
        other = CAKeys.generate()
        node = NodeKeys.generate()
        cred = make_cred(node, ca)
        with pytest.raises(ValueError, match="no trusted CA"):
            cred.verify([other.ca_pub_bytes])

    def test_expired_credential_rejected(self):
        ca = CAKeys.generate()
        node = NodeKeys.generate()
        cred = make_cred(node, ca, ttl_seconds=-1)
        with pytest.raises(ValueError, match="expired"):
            cred.verify([ca.ca_pub_bytes])

    def test_multi_ca_set_passes_with_signing_ca(self):
        ca1 = CAKeys.generate()
        ca2 = CAKeys.generate()
        node = NodeKeys.generate()
        cred = make_cred(node, ca2)
        # Verify with set containing ca1 and ca2 — only ca2 signed it, but that's enough
        cred.verify([ca1.ca_pub_bytes, ca2.ca_pub_bytes])

    def test_tampered_body_rejected(self):
        ca = CAKeys.generate()
        node = NodeKeys.generate()
        cred = make_cred(node, ca)
        # Tamper with caps after signing
        bad = replace(cred, caps=["admin"])
        with pytest.raises(ValueError, match="no trusted CA"):
            bad.verify([ca.ca_pub_bytes])

    def test_json_roundtrip_preserves_verification(self):
        ca = CAKeys.generate()
        node = NodeKeys.generate()
        cred = make_cred(node, ca)
        restored = Credential.from_dict(cred.to_dict())
        restored.verify([ca.ca_pub_bytes])

    def test_caps_order_does_not_affect_signature(self):
        ca = CAKeys.generate()
        node = NodeKeys.generate()
        now = dt.datetime.now(_UTC).replace(microsecond=0)
        cred1 = Credential(
            id_pub=node.id_pub_bytes, wg_pub=node.wg_pub_bytes,
            addr=node.addr, hostname="n", caps=["mesh", "db-client"],
            iat=now, exp=now + dt.timedelta(hours=1),
        ).sign(ca.ca_priv)
        # Restore with reversed cap order in JSON, then verify
        d = cred1.to_dict()
        d["caps"] = list(reversed(d["caps"]))
        restored = Credential.from_dict(d)
        # caps are sorted before signing so order in the object doesn't matter
        restored.verify([ca.ca_pub_bytes])


# ---------------------------------------------------------------------------
# NodeRecord
# ---------------------------------------------------------------------------

class TestNodeRecord:
    def test_full_verify_passes(self):
        ca = CAKeys.generate()
        node = NodeKeys.generate()
        cred = make_cred(node, ca)
        record = make_record(node, cred)
        record.verify([ca.ca_pub_bytes], revoked=set())

    def test_tampered_hostname_rejected(self):
        # hostname now lives in the CA-signed credential (level-b). Changing it
        # alters the record body → the node's self-signature no longer matches,
        # so a forged hostname can't enter the directory.
        ca = CAKeys.generate()
        node = NodeKeys.generate()
        cred = make_cred(node, ca, hostname="db")
        record = make_record(node, cred)
        assert record.hostname == "db"  # property reads it from the credential
        # Changing the hostname in the credential breaks the CA signature — the
        # CA vouched for "db", not "evil-node".
        bad = replace(record, cred=replace(record.cred, hostname="evil-node"))
        with pytest.raises(ValueError, match="no trusted CA"):
            bad.verify([ca.ca_pub_bytes], revoked=set())

    def test_tampered_seq_rejected(self):
        ca = CAKeys.generate()
        node = NodeKeys.generate()
        cred = make_cred(node, ca)
        record = make_record(node, cred, seq=1)
        bad = replace(record, seq=999)
        with pytest.raises(ValueError, match="invalid self-signature"):
            bad.verify([ca.ca_pub_bytes], revoked=set())

    def test_addr_mismatch_rejected(self):
        # Record where id_pub doesn't match cred.id_pub → addr check fails
        ca = CAKeys.generate()
        node_a = NodeKeys.generate()
        node_b = NodeKeys.generate()
        # Credential issued for node_b, but record claims node_a's id_pub
        cred = make_cred(node_b, ca)
        # Build a record manually with node_a's id_pub and sign with node_a's id_priv
        r = NodeRecord(
            id_pub=node_a.id_pub_bytes,
            seq=1,
            endpoints=["[2001:db8::1]:51820"],
            inbound="yes",
            cred=cred,  # cred belongs to node_b
        ).sign(node_a.id_priv)
        # Should fail at step 4 (addr) or the id_pub cross-check
        with pytest.raises(ValueError):
            r.verify([ca.ca_pub_bytes], revoked=set())

    def test_verify_is_prefix_agnostic(self):
        # A cred whose addr uses a DIFFERENT overlay /64 but the correct host
        # bits must still verify: the host portion is the self-certifying part;
        # the prefix is attested by the CA signature. This is what lets one
        # host be a node on two meshes with different prefixes.
        import ipaddress
        from greasewood.keys import derive_addr, parse_overlay_prefix, host_bits
        ca = CAKeys.generate()
        node = NodeKeys.generate()
        other_prefix = parse_overlay_prefix("fdde:cafc:0ffe:e::")
        now = dt.datetime.now(_UTC).replace(microsecond=0)
        cred = Credential(
            id_pub=node.id_pub_bytes, wg_pub=node.wg_pub_bytes,
            addr=derive_addr(node.id_pub_bytes, other_prefix),  # foreign prefix
            hostname="n", caps=["mesh"], iat=now, exp=now + dt.timedelta(hours=1),
        ).sign(ca.ca_priv)
        r = make_record(node, cred)
        r.verify([ca.ca_pub_bytes], revoked=set())   # no raise
        # sanity: the addr really is on the other prefix, correct host bits
        packed = ipaddress.IPv6Address(cred.addr).packed
        assert packed[:8] == other_prefix
        assert packed[8:] == host_bits(node.id_pub_bytes)

    def test_wrong_host_bits_rejected(self):
        # Same prefix but host bits not derived from id_pub → rejected.
        import ipaddress
        from greasewood.keys import OVERLAY_PREFIX_BYTES
        from dataclasses import replace
        ca = CAKeys.generate()
        node = NodeKeys.generate()
        bad_addr = str(ipaddress.IPv6Address(OVERLAY_PREFIX_BYTES + bytes(8)))  # ::0 host
        cred = make_cred(node, ca)
        cred = replace(cred, addr=bad_addr).sign(ca.ca_priv)
        r = make_record(node, cred)
        with pytest.raises(ValueError, match="host portion"):
            r.verify([ca.ca_pub_bytes], revoked=set())

    def test_revoked_node_rejected(self):
        ca = CAKeys.generate()
        node = NodeKeys.generate()
        cred = make_cred(node, ca)
        record = make_record(node, cred)
        revoked = {node.id_pub_bytes.hex()}
        with pytest.raises(ValueError, match="revoked"):
            record.verify([ca.ca_pub_bytes], revoked=revoked)

    def test_expired_credential_rejected_at_record_level(self):
        ca = CAKeys.generate()
        node = NodeKeys.generate()
        cred = make_cred(node, ca, ttl_seconds=-1)
        record = make_record(node, cred)
        with pytest.raises(ValueError, match="expired"):
            record.verify([ca.ca_pub_bytes], revoked=set())

    def test_json_roundtrip_preserves_verification(self):
        ca = CAKeys.generate()
        node = NodeKeys.generate()
        cred = make_cred(node, ca)
        record = make_record(node, cred)
        restored = NodeRecord.from_dict(record.to_dict())
        restored.verify([ca.ca_pub_bytes], revoked=set())

    def test_higher_seq_accepted_in_merge(self):
        from greasewood.directory import Directory
        ca = CAKeys.generate()
        node = NodeKeys.generate()
        cred = make_cred(node, ca)
        r1 = make_record(node, cred, seq=1)
        r2 = make_record(node, cred, seq=2)
        d = Directory()
        d.merge([r1])
        d.merge([r2])
        assert d.get(node.id_pub_hex).seq == 2

    def test_lower_seq_not_accepted_in_merge(self):
        from greasewood.directory import Directory
        ca = CAKeys.generate()
        node = NodeKeys.generate()
        cred = make_cred(node, ca)
        r5 = make_record(node, cred, seq=5)
        r1 = make_record(node, cred, seq=1)
        d = Directory()
        d.merge([r5])
        d.merge([r1])
        assert d.get(node.id_pub_hex).seq == 5


# ---------------------------------------------------------------------------
# RenewRequest
# ---------------------------------------------------------------------------

class TestRenewRequest:
    def test_sign_and_verify(self):
        node = NodeKeys.generate()
        req = RenewRequest(
            id_pub=node.id_pub_bytes,
            wg_pub=node.wg_pub_bytes,
            nonce="abc123",
            ts=dt.datetime.now(_UTC).replace(microsecond=0),
        ).sign(node.id_priv)
        req.verify_self_sig()

    def test_tampered_nonce_rejected(self):
        node = NodeKeys.generate()
        req = RenewRequest(
            id_pub=node.id_pub_bytes,
            wg_pub=node.wg_pub_bytes,
            nonce="abc123",
            ts=dt.datetime.now(_UTC).replace(microsecond=0),
        ).sign(node.id_priv)
        bad = replace(req, nonce="evil")
        with pytest.raises(ValueError):
            bad.verify_self_sig()

    def test_json_roundtrip(self):
        node = NodeKeys.generate()
        req = RenewRequest(
            id_pub=node.id_pub_bytes,
            wg_pub=node.wg_pub_bytes,
            nonce="x",
            ts=dt.datetime.now(_UTC).replace(microsecond=0),
        ).sign(node.id_priv)
        restored = RenewRequest.from_dict(req.to_dict())
        restored.verify_self_sig()


class TestVerifyStructuralErrors:
    """The two verify_structural deny branches that the happy-path and
    host-bits tests don't reach."""

    def test_non_ipv6_cred_addr_rejected(self):
        ca = CAKeys.generate()
        node = NodeKeys.generate()
        now = dt.datetime.now(_UTC).replace(microsecond=0)
        cred = Credential(
            id_pub=node.id_pub_bytes, wg_pub=node.wg_pub_bytes,
            addr="not-an-ip", hostname="n1", caps=["mesh"],
            iat=now, exp=now + dt.timedelta(hours=1),
        ).sign(ca.ca_priv)
        rec = NodeRecord(
            id_pub=node.id_pub_bytes, seq=1, endpoints=[], inbound="yes",
            cred=cred,
        ).sign(node.id_priv)
        with pytest.raises(ValueError, match="not a valid IPv6"):
            rec.verify_structural()

    def test_idpub_credential_mismatch_rejected(self):
        # addr derives from record.id_pub (A), but the credential names a
        # DIFFERENT id_pub (B) — reaches the cross-check the host-bits test shadows.
        ca = CAKeys.generate()
        a = NodeKeys.generate()
        b = NodeKeys.generate()
        now = dt.datetime.now(_UTC).replace(microsecond=0)
        cred = Credential(
            id_pub=b.id_pub_bytes, wg_pub=b.wg_pub_bytes,
            addr=derive_addr(a.id_pub_bytes), hostname="n1", caps=["mesh"],
            iat=now, exp=now + dt.timedelta(hours=1),
        ).sign(ca.ca_priv)
        rec = NodeRecord(
            id_pub=a.id_pub_bytes, seq=1, endpoints=[], inbound="yes",
            cred=cred,
        ).sign(a.id_priv)
        with pytest.raises(ValueError, match="does not match"):
            rec.verify_structural()


# ---------------------------------------------------------------------------
# Timestamp hygiene: naive (timezone-less) timestamps are rejected at parse
# ---------------------------------------------------------------------------

class TestNaiveTimestampRejected:
    """A wire timestamp without a timezone must be refused when the object is
    parsed (ValueError → the server's clean 400 path). Left to parse, a naive
    ts survives until the skew check compares it against an aware clock and
    raises TypeError — an unhandled 500 an attacker can trigger by signing the
    canonical (Z-rendered) body while sending a naive ts string."""

    def test_renew_request_naive_ts(self):
        node = NodeKeys.generate()
        d = RenewRequest(
            id_pub=node.id_pub_bytes, wg_pub=node.wg_pub_bytes, nonce="n",
            ts=dt.datetime.now(_UTC).replace(microsecond=0),
        ).sign(node.id_priv).to_dict()
        d["ts"] = "2026-07-01T12:00:00"          # no Z / offset
        with pytest.raises(ValueError, match="timezone"):
            RenewRequest.from_dict(d)

    def test_cert_request_naive_ts(self):
        node = NodeKeys.generate()
        d = CertRequest(
            id_pub=node.id_pub_bytes, leaf_pub=bytes(32), cn="db",
            dns=[], ips=[], nonce="n",
            ts=dt.datetime.now(_UTC).replace(microsecond=0),
        ).sign(node.id_priv).to_dict()
        d["ts"] = "2026-07-01T12:00:00"
        with pytest.raises(ValueError, match="timezone"):
            CertRequest.from_dict(d)

    def test_credential_naive_exp(self):
        ca = CAKeys.generate()
        node = NodeKeys.generate()
        d = make_cred(node, ca).to_dict()
        d["exp"] = d["exp"].rstrip("Z")          # strip the timezone
        with pytest.raises(ValueError, match="timezone"):
            Credential.from_dict(d)
