"""
greasewood.ca — certificate authority operations (hub only).

The CA signs Credentials only. It never generates or sees any private key
other than ca_priv.

CA.issue() is called by the hub during enrollment (over the transient door, see
greasewood.enroll) and renewal — never directly by an operator, and never over a
network-reachable endpoint.

Revoke list: revoked.json — a set of id_pub hex strings, re-read live by the
  daemon. Revoking refuses the node's renew/publish at the hub immediately and
  frees its hostname; its credential also expires on its own, so other nodes
  evict it within one credential TTL (expiry-based revocation, no CRL).

Node caps: stored in nodes/<id_pub_hex>.json so renewal can re-use them without
  a separate config lookup. Written at issue time; removed on revoke (which is
  what frees the hostname for reuse).
"""
from __future__ import annotations

import datetime as dt
import json
import logging
from pathlib import Path
from typing import Callable

from .keys import CAKeys, derive_addr
from .wire import CAStatement, Credential, RenewRequest

log = logging.getLogger(__name__)
_UTC = dt.timezone.utc

CapPolicy = Callable[[list[str]], list[str]]


def _atomic_write_text(path: Path, text: str) -> None:
    """Write via a temp file + rename so a crash mid-write can't corrupt the
    revoke list or a node-caps file (a corrupt revoked.json would otherwise make
    every issue/renew fail until repaired)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text)
    tmp.replace(path)


class CA:
    def __init__(
        self,
        ca_keys: CAKeys,
        data_dir: Path,
        credential_ttl: dt.timedelta = dt.timedelta(hours=24),
        cap_policy: CapPolicy | None = None,
    ) -> None:
        self._keys = ca_keys
        self._data_dir = data_dir
        self._ttl = credential_ttl
        self._cap_policy: CapPolicy = cap_policy or (lambda caps: caps)
        self._revoke_path = data_dir / "revoked.json"

    # --- credential issuance ---

    def issue(
        self,
        id_pub: bytes,
        wg_pub: bytes,
        hostname: str,
        caps: list[str],
    ) -> Credential:
        """
        Sign a credential for a node (hub-side; called during enrollment/renewal).
        Persists node caps so renewal can re-use them without operator input.
        Raises ValueError if id_pub is revoked or the hostname is already taken
        by a different node (enforced on the sanitized name, so db/DB collide).
        """
        if self.is_revoked(id_pub):
            raise ValueError("id_pub is on the revoke list")

        owner = self._hostname_owner(hostname)
        if owner is not None and owner != id_pub.hex():
            raise ValueError(
                f"hostname {hostname!r} is already in use by another node "
                f"({owner[:16]}…); choose a different hostname"
            )

        caps = self._cap_policy(caps)
        now = dt.datetime.now(_UTC).replace(microsecond=0)
        cred = Credential(
            id_pub=id_pub,
            wg_pub=wg_pub,
            addr=derive_addr(id_pub),
            caps=caps,
            iat=now,
            exp=now + self._ttl,
        )
        signed = cred.sign(self._keys.ca_priv)
        self._save_node_caps(id_pub, hostname, caps)
        log.info("issued credential for %s caps=%s exp=%s", hostname, caps, signed.exp)
        return signed

    # --- renewal (§10.3) ---

    def renew(self, req: RenewRequest) -> Credential:
        """
        Process a renewal request from an already-enrolled node.
        id_priv possession is proven by the self-signature on the request.
        Raises ValueError on any failure.
        """
        req.verify_self_sig()

        skew = abs((dt.datetime.now(_UTC) - req.ts).total_seconds())
        if skew > 300:
            raise ValueError(f"timestamp skew too large ({skew:.0f}s); check NTP")

        if self.is_revoked(req.id_pub):
            raise ValueError("id_pub is on the revoke list")

        node_info = self._load_node_info(req.id_pub)
        if node_info is None:
            raise ValueError("unknown node — issue a credential first")

        hostname, caps = node_info
        log.info("renewing %s", hostname)
        return self.issue(req.id_pub, req.wg_pub, hostname, caps)

    # --- x509 TLS certificate issuance (§12) ---

    def issue_tls(
        self,
        leaf_pub: bytes,
        cn: str,
        dns: list[str],
        ips: list[str],
        ttl: dt.timedelta,
    ) -> tuple[str, str]:
        """
        Issue an x509 TLS leaf cert (signed by the mesh CA) for a node-supplied
        public key. Returns (leaf_cert_pem, ca_cert_pem). The CA key here is the
        same one that signs mesh credentials — one trust root.
        """
        from . import tlsca
        ca_cert = tlsca.ensure_ca_cert(
            self._keys.ca_priv, self._keys.ca_pub_hex, self._data_dir
        )
        leaf = tlsca.issue_tls_cert(
            self._keys.ca_priv, ca_cert, leaf_pub, cn, dns, ips, ttl
        )
        log.info("issued TLS cert cn=%s dns=%s ips=%s exp=%s",
                 cn, dns, ips, leaf.not_valid_after_utc)
        return tlsca.cert_pem(leaf), tlsca.cert_pem(ca_cert)

    def ca_cert_pem(self) -> str:
        """The hub's self-signed x509 CA certificate (the TLS trust anchor)."""
        from . import tlsca
        cert = tlsca.ensure_ca_cert(
            self._keys.ca_priv, self._keys.ca_pub_hex, self._data_dir
        )
        return tlsca.cert_pem(cert)

    def node_info(self, id_pub: bytes) -> tuple[str, list[str]] | None:
        """(hostname, caps) for an enrolled node, or None if unknown."""
        return self._load_node_info(id_pub)

    # --- CA succession (§11) ---

    def endorse(
        self,
        subject_pub: bytes,
        hub_endpoint: str,
        ttl: dt.timedelta,
    ) -> CAStatement:
        """
        Sign an endorsement: this CA vouches for subject_pub as a (successor)
        CA and advertises its hub control-plane endpoint. Long-lived by design
        — the chain must stay intact for nodes still rooted at this CA.
        """
        now = dt.datetime.now(_UTC).replace(microsecond=0)
        stmt = CAStatement(
            kind="endorse",
            by_pub=self._keys.ca_pub_bytes,
            subject_pub=subject_pub,
            hub_endpoint=hub_endpoint,
            iat=now,
            exp=now + ttl,
        ).sign(self._keys.ca_priv)
        log.info("endorsed CA %s (endpoint=%s) until %s",
                 subject_pub.hex()[:16], hub_endpoint, stmt.exp)
        return stmt

    def retire(
        self,
        subject_pub: bytes,
        ttl: dt.timedelta,
        grace: dt.timedelta = dt.timedelta(0),
    ) -> CAStatement:
        """
        Sign a retirement: subject_pub will no longer be an accepted signer.

        The retirement takes effect after `grace` (it is dated now + grace), not
        immediately. This is essential: a retirement removes trust in the old CA
        and therefore in every still-old-signed node. If it took effect at once,
        the new hub would drop those nodes as peers before they could learn of
        the retirement and renew under the new CA — they'd be cut off mid-
        migration. The grace (≈ one credential TTL) lets the statement propagate
        and every node re-credential under the successor first, then it
        activates. This is the "one-TTL overlap" of §11.
        """
        now = dt.datetime.now(_UTC).replace(microsecond=0)
        effective = now + grace
        stmt = CAStatement(
            kind="retire",
            by_pub=self._keys.ca_pub_bytes,
            subject_pub=subject_pub,
            hub_endpoint="",
            iat=effective,
            exp=effective + ttl,
        ).sign(self._keys.ca_priv)
        log.info("retired CA %s effective %s until %s",
                 subject_pub.hex()[:16], effective, stmt.exp)
        return stmt

    # --- revoke list ---

    def is_revoked(self, id_pub: bytes) -> bool:
        return id_pub.hex() in self._load_revoked()

    def add_revoke(self, id_pub: bytes) -> bool:
        """Revoke an identity and release its hostname. Returns True if the
        node's caps record existed and was removed (i.e. a hostname was freed)."""
        revoked = self._load_revoked()
        revoked.add(id_pub.hex())
        self._save_revoked(revoked)
        freed = self.forget_node(id_pub)
        log.info("revoked %s%s", id_pub.hex()[:16],
                 " (hostname freed)" if freed else "")
        return freed

    def forget_node(self, id_pub: bytes) -> bool:
        """Remove the node's caps record (nodes/<id>.json). This is what holds
        the hostname for uniqueness, so deleting it frees the name for reuse by
        a different identity. Returns True if a record was actually removed.
        Safe alongside revocation: a revoked id can't renew anyway, and without
        a caps record renewal would refuse it regardless."""
        p = self._node_path(id_pub)
        try:
            p.unlink()
            return True
        except FileNotFoundError:
            return False

    def load_revoked_set(self) -> set[str]:
        return self._load_revoked()

    def _load_revoked(self) -> set[str]:
        if not self._revoke_path.exists():
            return set()
        return set(json.loads(self._revoke_path.read_text()).get("revoked", []))

    def _save_revoked(self, revoked: set[str]) -> None:
        _atomic_write_text(
            self._revoke_path, json.dumps({"revoked": sorted(revoked)}, indent=2)
        )

    # --- node info (for renewal) ---

    def _node_path(self, id_pub: bytes) -> Path:
        return self._data_dir / "nodes" / f"{id_pub.hex()}.json"

    def _save_node_caps(self, id_pub: bytes, hostname: str, caps: list[str]) -> None:
        p = self._node_path(id_pub)
        p.parent.mkdir(parents=True, exist_ok=True)
        _atomic_write_text(p, json.dumps({"hostname": hostname, "caps": caps}, indent=2))

    def _load_node_info(self, id_pub: bytes) -> tuple[str, list[str]] | None:
        p = self._node_path(id_pub)
        if not p.exists():
            return None
        d = json.loads(p.read_text())
        return d.get("hostname", ""), d.get("caps", [])

    def _hostname_owner(self, hostname: str) -> str | None:
        """id_pub hex of the node already using this (sanitized) hostname among
        the credentials this CA has issued, or None. Note: this tracks the
        names the CA *issued*; a decommissioned node keeps its name until its
        nodes/<id>.json is removed."""
        from .hosts import sanitize
        want = sanitize(hostname)
        nodes_dir = self._data_dir / "nodes"
        if not nodes_dir.exists():
            return None
        for p in nodes_dir.glob("*.json"):
            try:
                info = json.loads(p.read_text())
            except (OSError, ValueError):
                continue
            if sanitize(info.get("hostname", "")) == want:
                return p.stem  # filename is the id_pub hex
        return None
