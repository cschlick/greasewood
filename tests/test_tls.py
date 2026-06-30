"""
Unit tests for greasewood.tlsca + CertRequest (§12 TLS service certs).

Locks down: the mesh CA issues a valid x509 leaf chained to its self-signed
CA cert, with the requested SANs and correct constraints; and that the
node-side request object signs/verifies under the node identity key.
"""
import datetime as dt
import ipaddress

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import ExtendedKeyUsageOID

from greasewood.keys import CAKeys
from greasewood.ca import CA
from greasewood.tlsca import ensure_ca_cert, issue_tls_cert, ca_cert_path
from greasewood.wire import CertRequest

_UTC = dt.timezone.utc


def _leaf_pub() -> bytes:
    k = Ed25519PrivateKey.generate()
    return k.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )


# --- tlsca: CA cert + leaf issuance ---

def test_ca_cert_is_self_signed_ca(tmp_path):
    ck = CAKeys.generate()
    cert = ensure_ca_cert(ck.ca_priv, ck.ca_pub_hex, tmp_path)
    assert cert.issuer == cert.subject  # self-signed
    bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    assert bc.ca is True and bc.path_length == 0
    # signed by the CA key
    ck.ca_priv.public_key().verify(cert.signature, cert.tbs_certificate_bytes)


def test_ca_cert_is_persisted_and_stable(tmp_path):
    ck = CAKeys.generate()
    c1 = ensure_ca_cert(ck.ca_priv, ck.ca_pub_hex, tmp_path)
    assert ca_cert_path(tmp_path).exists()
    c2 = ensure_ca_cert(ck.ca_priv, ck.ca_pub_hex, tmp_path)
    assert c1.serial_number == c2.serial_number  # not regenerated


def test_leaf_chains_to_ca_with_sans(tmp_path):
    ck = CAKeys.generate()
    ca_cert = ensure_ca_cert(ck.ca_priv, ck.ca_pub_hex, tmp_path)
    leaf_pub = _leaf_pub()
    leaf = issue_tls_cert(
        ck.ca_priv, ca_cert, leaf_pub, "postgres.db",
        dns=["postgres.db", "db.internal"],
        ips=["fd8d:e5c1:db1a:7::1"],
        ttl=dt.timedelta(days=7),
    )
    # chains to the CA: CA key verifies the leaf signature, issuer matches
    assert leaf.issuer == ca_cert.subject
    ck.ca_priv.public_key().verify(leaf.signature, leaf.tbs_certificate_bytes)
    # SANs present
    san = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert "postgres.db" in san.get_values_for_type(x509.DNSName)
    assert "db.internal" in san.get_values_for_type(x509.DNSName)
    assert ipaddress.ip_address("fd8d:e5c1:db1a:7::1") in \
        san.get_values_for_type(x509.IPAddress)
    # leaf, not a CA; EKU is server+client
    bc = leaf.extensions.get_extension_for_class(x509.BasicConstraints).value
    assert bc.ca is False
    eku = leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert ExtendedKeyUsageOID.SERVER_AUTH in eku
    assert ExtendedKeyUsageOID.CLIENT_AUTH in eku
    # the leaf carries exactly the public key we asked for
    leaf_spki = leaf.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    assert leaf_spki == leaf_pub


def test_ca_issue_tls_roundtrip(tmp_path):
    ck = CAKeys.generate()
    ca = CA(ck, tmp_path)
    leaf_pem, ca_pem = ca.issue_tls(
        _leaf_pub(), "svc", dns=["svc.mesh"], ips=[], ttl=dt.timedelta(days=1)
    )
    leaf = x509.load_pem_x509_certificate(leaf_pem.encode())
    ca_cert = x509.load_pem_x509_certificate(ca_pem.encode())
    # leaf verifies under the returned CA cert's key
    ca_cert.public_key().verify(leaf.signature, leaf.tbs_certificate_bytes)
    assert ca.ca_cert_pem() == ca_pem  # stable anchor


# --- CertRequest ---

def test_cert_request_sign_verify_roundtrip():
    idk = Ed25519PrivateKey.generate()
    id_pub = idk.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    req = CertRequest(
        id_pub=id_pub, leaf_pub=_leaf_pub(), cn="svc",
        dns=["svc.mesh"], ips=["fd8d::1"], nonce="abcd",
        ts=dt.datetime.now(_UTC).replace(microsecond=0),
    ).sign(idk)
    req.verify_self_sig()  # no raise
    req2 = CertRequest.from_dict(req.to_dict())
    req2.verify_self_sig()
    assert req2.cn == "svc" and req2.dns == ["svc.mesh"]


def test_cert_request_tamper_detected():
    idk = Ed25519PrivateKey.generate()
    id_pub = idk.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    req = CertRequest(
        id_pub=id_pub, leaf_pub=_leaf_pub(), cn="svc",
        dns=[], ips=[], nonce="abcd",
        ts=dt.datetime.now(_UTC).replace(microsecond=0),
    ).sign(idk)
    req.dns = ["evil.mesh"]  # tamper after signing
    with pytest.raises(ValueError):
        req.verify_self_sig()
