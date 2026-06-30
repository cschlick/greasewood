"""
greasewood.tlsca — x509 TLS certificate issuance under the mesh CA (§12).

The same Ed25519 CA that signs mesh Credentials also signs ordinary x509 TLS
certificates, so an enrolled node can get a server/client cert for an unrelated
service (Postgres, an HTTP API, …) that any peer validates against one trust
root. This is a separate artifact type from the mesh Credential — a real x509
cert with SANs — but it shares the CA key, so there is exactly one trust anchor.

Mirrors internalca.py: Ed25519 throughout, self-signed root with
BasicConstraints CA:TRUE pathlen:0, leaves CA:FALSE with
keyUsage=digitalSignature and EKU serverAuth+clientAuth (every leaf may be
either end of a connection). No CRL/OCSP — revocation is passive (short leaf
TTLs you stop renewing), matching the rest of greasewood.

The leaf private key never reaches the hub: the node generates it locally and
sends only its public key.
"""
from __future__ import annotations

import datetime as dt
import ipaddress
import os
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

_UTC = dt.timezone.utc
_CA_CERT_LIFETIME = dt.timedelta(days=3650)


def ca_cert_path(data_dir: Path) -> Path:
    """The hub's self-signed x509 CA certificate — the TLS trust anchor."""
    return data_dir / "ca.cert.pem"


def _now() -> dt.datetime:
    return dt.datetime.now(_UTC)


def _san(dns: list[str], ips: list[str]) -> x509.SubjectAlternativeName:
    entries: list[x509.GeneralName] = [x509.DNSName(d) for d in dns]
    for ip in ips:
        entries.append(x509.IPAddress(ipaddress.ip_address(ip)))
    return x509.SubjectAlternativeName(entries)


def ensure_ca_cert(
    ca_priv: Ed25519PrivateKey,
    ca_pub_hex: str,
    data_dir: Path,
) -> x509.Certificate:
    """
    Load the hub's self-signed x509 CA certificate, creating and persisting it
    from the existing Ed25519 CA key on first use. The cert wraps the same key
    that signs mesh credentials, so the mesh CA and the TLS CA are one identity.
    """
    path = ca_cert_path(data_dir)
    if path.exists():
        return x509.load_pem_x509_certificate(path.read_bytes())

    # Name the CA after its key so a succession (a different CA key) is a
    # visibly different issuer.
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, f"greasewood-ca-{ca_pub_hex[:16]}"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)  # self-signed
        .public_key(ca_priv.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_now() - dt.timedelta(minutes=5))
        .not_valid_after(_now() + _CA_CERT_LIFETIME)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False, content_commitment=False,
                key_encipherment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=True, crl_sign=True,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_priv.public_key()),
            critical=False,
        )
        .sign(private_key=ca_priv, algorithm=None)  # Ed25519 → algorithm=None
    )
    pem = cert.public_bytes(serialization.Encoding.PEM)
    path.write_bytes(pem)
    os.chmod(path, 0o644)
    return cert


def issue_tls_cert(
    ca_priv: Ed25519PrivateKey,
    ca_cert: x509.Certificate,
    leaf_pub_bytes: bytes,
    cn: str,
    dns: list[str],
    ips: list[str],
    ttl: dt.timedelta,
) -> x509.Certificate:
    """
    Sign an x509 leaf certificate for a node-supplied Ed25519 public key with
    the requested SANs. The leaf's private key stays on the node.
    """
    leaf_pub = Ed25519PublicKey.from_public_bytes(leaf_pub_bytes)
    not_after = _now() + ttl
    return (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
        .issuer_name(ca_cert.subject)
        .public_key(leaf_pub)
        .serial_number(x509.random_serial_number())
        .not_valid_before(_now() - dt.timedelta(minutes=5))
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False,
                key_encipherment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=False, crl_sign=False,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([
                ExtendedKeyUsageOID.SERVER_AUTH,
                ExtendedKeyUsageOID.CLIENT_AUTH,
            ]),
            critical=False,
        )
        .add_extension(_san(dns, ips), critical=False)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(leaf_pub),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_priv.public_key()),
            critical=False,
        )
        .sign(private_key=ca_priv, algorithm=None)
    )


def cert_pem(cert: x509.Certificate) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode()
