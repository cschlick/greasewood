"""
greasewood.ca — certificate authority operations (anchor only).

The CA signs Credentials only. It never generates or sees any private key
other than ca_priv.

CA.issue() is called by the anchor during enrollment (over the transient door, see
greasewood.enroll) and renewal — never directly by an operator, and never over a
network-reachable endpoint.

Revoke list: revoked.json — a set of id_pub hex strings, re-read live by the
  daemon. Revoking refuses the node's renew/publish at the anchor immediately and
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
import os
import threading
from pathlib import Path
from typing import Callable

from .keys import CAKeys, derive_addr
from .wire import Credential, RenewRequest

log = logging.getLogger(__name__)


class UnknownNodeError(ValueError):
    """The id_pub has no registry entry (nodes/<id>.json). A distinct type
    because the control plane's re-root fallback fires ONLY on this condition
    (server._reroot_reissue) — gating a security-relevant path on an exception
    *type* instead of its message text."""

_UTC = dt.timezone.utc

CapPolicy = Callable[[list[str]], list[str]]


def _atomic_write_text(path: Path, text: str) -> None:
    """Write via a UNIQUE temp file + rename so a crash mid-write can't corrupt
    the revoke list or a node-caps file, and concurrent writers (multiple
    threads now that the control plane is threaded, or a `gw revoke`/`set-caps`
    process racing the daemon) can't collide on a shared temp path — the rename
    is atomic and last-writer-wins, never a truncated/mixed file or a
    FileNotFoundError from one writer moving another's temp."""
    import tempfile
    path.parent.mkdir(parents=True, exist_ok=True)
    # mkstemp in the SAME dir → same filesystem, so os.replace is a real atomic
    # rename (not a cross-device copy).
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=path.name + ".", suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(text)
        os.replace(tmp, path)
    except BaseException:
        # Clean up our own temp on any failure; never leave litter behind.
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise


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
        # Serializes the registry's check-then-act / read-modify-write regions
        # (issue/renew/set-caps/revoke). The control plane is a
        # ThreadingHTTPServer, so these run concurrently; without this a hostname
        # uniqueness check could interleave (two nodes claim one name) and two
        # writers could race. Reentrant because renew()->issue() and
        # add_revoke()->forget_node() nest. Cross-PROCESS races (a `gw revoke`
        # CLI vs the daemon) are handled by the unique-temp atomic write, not
        # this lock.
        self._lock = threading.RLock()

    # --- credential issuance ---

    def issue(
        self,
        id_pub: bytes,
        wg_pub: bytes,
        hostname: str,
        caps: list[str],
    ) -> Credential:
        """
        Sign a credential for a node (anchor-side; called during enrollment/renewal).
        Persists node caps so renewal can re-use them without operator input.
        Raises ValueError if id_pub is revoked or the hostname is already taken
        by a different node (enforced on the sanitized name, so db/DB collide).
        """
        # The revoke check, the hostname-uniqueness check, and the registry
        # write are one atomic critical section: otherwise two concurrent
        # issues for the same name both see it free and both persist it.
        with self._lock:
            if self.is_revoked(id_pub):
                raise ValueError("id_pub is on the revoke list")

            owner = self.hostname_owner(hostname)
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
                hostname=hostname,
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

        # Load-decide-issue as one critical section so a rename can't race
        # another node claiming the same target name (issue() re-checks
        # uniqueness under the same reentrant lock).
        with self._lock:
            if self.is_revoked(req.id_pub):
                raise ValueError("id_pub is on the revoke list")

            node_info = self.node_info(req.id_pub)
            if node_info is None:
                raise UnknownNodeError("unknown node — issue a credential first")

            hostname, caps = node_info
            if req.hostname and req.hostname != hostname:
                # Rename (gw rename): issue() enforces uniqueness on the new name
                # and rewrites nodes/<id>.json, which frees the old name for
                # reuse. But an anchor-pinned node (enrolled via `gw invite
                # --hostname`) may not rename itself — the name is the anchor's.
                if "hostname-pinned" in caps:
                    raise ValueError(
                        "hostname is anchor-pinned for this node; rename disabled "
                        "(re-invite with a new --hostname to change it)"
                    )
                log.info("renaming %s -> %s", hostname, req.hostname)
                hostname = req.hostname
            else:
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
        # ensure_ca_cert is check-then-create; serialize it so concurrent first
        # issuances don't each build (and race-write) a different CA cert.
        with self._lock:
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
        """The anchor's self-signed x509 CA certificate (the TLS trust anchor)."""
        from . import tlsca
        with self._lock:
            cert = tlsca.ensure_ca_cert(
                self._keys.ca_priv, self._keys.ca_pub_hex, self._data_dir
            )
        return tlsca.cert_pem(cert)

    def node_info(self, id_pub: bytes) -> tuple[str, list[str]] | None:
        """(hostname, caps) for an enrolled node, or None if unknown."""
        p = self._node_path(id_pub)
        if not p.exists():
            return None
        d = json.loads(p.read_text())
        return d.get("hostname", ""), d.get("caps", [])

    def set_caps(self, id_pub: bytes, caps: list[str]) -> None:
        """Rewrite a known node's caps in the registry. Takes effect at the
        node's NEXT renewal — `renew` re-issues from the registry, so the node
        picks up the change with no re-join. Raises ValueError if unknown."""
        with self._lock:
            info = self.node_info(id_pub)
            if info is None:
                raise UnknownNodeError("unknown node — enroll it first")
            hostname, _ = info
            self._save_node_caps(id_pub, hostname, caps)

    # --- revoke list ---

    def is_revoked(self, id_pub: bytes) -> bool:
        return id_pub.hex() in self.load_revoked_set()

    def add_revoke(self, id_pub: bytes) -> bool:
        """Revoke an identity and release its hostname. Returns True if the
        node's caps record existed and was removed (i.e. a hostname was freed)."""
        with self._lock:
            revoked = self.load_revoked_set()
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

    def hostname_owner(self, hostname: str) -> str | None:
        """id_pub hex of the node already using this (sanitized) hostname among
        the credentials this CA has issued, or None. `gw invite --hostname`
        uses it to verify a pinned name is free before issuing the token. Note:
        this tracks the names the CA *issued*; a decommissioned node keeps its
        name until its nodes/<id>.json is removed."""
        from .hosts import sanitize
        want = sanitize(hostname)
        nodes_dir = self._data_dir / "nodes"
        # List explicitly, not via glob/exists: Path.exists() reads a denied
        # stat as False and glob can swallow an unreadable dir — both would
        # turn "you can't read the registry" into "no such node". Only a
        # genuinely-missing dir means an empty registry.
        try:
            entries = sorted(n for n in os.listdir(nodes_dir) if n.endswith(".json"))
        except FileNotFoundError:
            return None
        for p in (nodes_dir / n for n in entries):
            try:
                info = json.loads(p.read_text())
            except PermissionError:
                # Can't read the registry ≠ node not found. Swallowing this made
                # a non-root `gw set-segments` report "no node named X" for a
                # node that exists; propagate so the CLI's handler tells the
                # truth ("permission denied — try sudo").
                raise
            except (OSError, ValueError):
                continue    # corrupt or concurrently-removed entry: skip it
            if sanitize(info.get("hostname", "")) == want:
                return p.stem  # filename is the id_pub hex
        return None
