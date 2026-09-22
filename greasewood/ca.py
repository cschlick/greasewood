"""
greasewood.ca — certificate authority operations (anchor-file holders).

The CA signs Credentials only. It never generates or sees any private key
other than ca_priv.

There is NO private registry. The credential itself is the registry entry —
hostname, caps, and expiry all ride in it, CA-signed, replicated to every
node inside its NodeRecord — and the three mutations a credential can't
express (revoke, forget, re-cap) are CA-signed AnchorStatements replicated
the same way (greasewood.statements). That is what makes anchor duties
location-independent: ANY holder of the anchor file serves issuance from the
same eventually-consistent view every node already has, several holders at
once, with no state to hand over.

What replaced the old nodes/<id>.json registry:
  hostname uniqueness  → scan of live directory records (+ this process's
                         just-issued credentials, below)
  renewal's (hostname, caps) lookup → the node's own directory record,
                         cred verified against the TRUSTED CA SET (so a
                         re-root overlap re-issues from the outgoing CA's
                         records with no special path)
  caps changes         → setcaps statements, applied at next renewal
  forgetting a node    → tombstone statements (leave / sweep / revoke)
  the revoke list      → revoke statements, merged with legacy revoked.json

The one gap the directory can't cover: a credential issued moments ago whose
NodeRecord hasn't landed yet (the joiner publishes it seconds later over the
door's second leg). `_recent` — an in-process overlay of just-issued
credentials — bridges it, so two concurrent enrolls at THIS holder can't both
claim one hostname. Two enrolls racing at DIFFERENT holders is the
active/active design's accepted race: both succeed, the collision is visible
in every view (two records, one name), and the fix is re-running one join.
"""
from __future__ import annotations

import datetime as dt
import json
import logging
import threading
from pathlib import Path
from typing import Callable

from .keys import CAKeys, atomic_write, derive_addr
from .wire import AnchorStatement, Credential, RenewRequest

log = logging.getLogger(__name__)


class UnknownNodeError(ValueError):
    """No live, trusted record (or just-issued credential) exists for this
    id — nothing to renew from. The node must (re-)enroll through the door."""

_UTC = dt.timezone.utc

CapPolicy = Callable[[list[str]], list[str]]


class CA:
    def __init__(
        self,
        ca_keys: CAKeys,
        data_dir: Path,
        credential_ttl: dt.timedelta = dt.timedelta(hours=24),
        cap_policy: CapPolicy | None = None,
        key_file: "Path | None" = None,
        directory=None,
        statements=None,
        get_ca_pubs: "Callable[[], list[bytes]] | None" = None,
        dir_cache_path: "Path | None" = None,
    ) -> None:
        self._keys = ca_keys
        self._data_dir = data_dir
        self._ttl = credential_ttl
        self._cap_policy: CapPolicy = cap_policy or (lambda caps: caps)
        self._revoke_path = data_dir / "revoked.json"
        # The replicated substrate. The daemon injects its LIVE directory and
        # statement log; a one-shot CLI process (gw revoke, gw invite's
        # hostname check) loads both from the same on-disk caches the daemon
        # maintains — one view, two access paths.
        self._get_ca_pubs = get_ca_pubs or (lambda: [ca_keys.ca_pub_bytes])
        if directory is None:
            from .directory import Directory
            directory = Directory.load(
                dir_cache_path or (data_dir / "directory.json"))
        self._directory = directory
        self._dir_cache_path = dir_cache_path or (data_dir / "directory.json")
        if statements is None:
            from .statements import StatementLog, statements_path
            statements = StatementLog.load(statements_path(data_dir),
                                           self._get_ca_pubs())
        self._statements = statements
        # Just-issued credentials whose records haven't landed yet:
        # id_pub_hex → {hostname, caps, iat, exp}. In-process only — the
        # window is the seconds between issue and the joiner's door-leg
        # publish, not something worth a persistence story.
        self._recent: dict[str, dict] = {}
        # Stale-key guard (long-running daemon only — one-shot CLI uses skip it
        # by not passing key_file): snapshot the key FILE's bytes at load so
        # issue() can detect the file changing underneath a running daemon
        # (e.g. `gw create --force` re-rooting while the old daemon is up).
        # Without this the daemon keeps signing with the old in-memory key
        # while every new invite embeds the new disk key, and every join fails
        # with an unexplained bad signature (seen in the field). Raw-bytes
        # comparison, not a key parse: it needs no passphrase, and ANY change
        # to the key file means the operator did something a restart resolves.
        self._key_file = Path(key_file) if key_file is not None else None
        self._key_snapshot = self._key_file.read_bytes() if self._key_file else None
        # Serializes check-then-act regions (issue/renew/set-caps/revoke) —
        # the control plane is a ThreadingHTTPServer, so these run
        # concurrently; without this a hostname uniqueness check could
        # interleave (two nodes claim one name). Reentrant because
        # renew()->issue() and add_revoke()->forget_node() nest. Cross-PROCESS
        # races (a `gw revoke` CLI vs the daemon) converge through the
        # statement log's merge, not this lock.
        self._lock = threading.RLock()

    # --- credential issuance ---

    def _refuse_if_key_stale(self) -> None:
        """Refuse to sign if the CA key file changed since this CA was loaded
        (no-op when no key_file was given). Raises ValueError, which the
        enroll/renew paths already report cleanly to the far side — so the
        JOINER sees the real cause instead of a bare signature failure."""
        if self._key_file is None:
            return
        try:
            current = self._key_file.read_bytes()
        except OSError as e:
            log.error("CA key file %s unreadable at issue time: %s", self._key_file, e)
            raise ValueError(f"anchor's CA key file is unreadable ({e}) — "
                             f"refusing to sign; check {self._key_file} on the anchor")
        if current != self._key_snapshot:
            log.error("CA key file %s CHANGED since this daemon loaded it "
                      "(a re-create/re-root while the daemon was running?) — "
                      "refusing to sign with the stale in-memory key. Restart "
                      "the daemon, then mint fresh invites.", self._key_file)
            from . import service
            _mgr = service.detect()
            _restart = (_mgr.restart_hint("<mesh>") if _mgr
                        else "sudo systemctl restart greasewood@<mesh>")
            raise ValueError(
                "anchor's CA key changed on disk after its daemon started (a "
                f"re-create?) — on the anchor: restart the daemon ({_restart}) "
                "and mint a fresh invite")

    def issue(
        self,
        id_pub: bytes,
        wg_pub: bytes,
        hostname: str,
        caps: list[str],
    ) -> Credential:
        """
        Sign a credential for a node (holder-side; called during
        enrollment/renewal). Raises ValueError if id_pub is revoked or the
        hostname is already claimed by a different live node (enforced on the
        sanitized name, so db/DB collide).
        """
        # The revoke check, the hostname-uniqueness check, and the recent-
        # issue note are one atomic critical section: otherwise two concurrent
        # issues for the same name both see it free and both sign.
        with self._lock:
            self._refuse_if_key_stale()
            if self.is_revoked(id_pub):
                raise ValueError("id_pub is on the revoke list")

            owner = self.hostname_owner(hostname)
            if owner is not None and owner != id_pub.hex():
                raise ValueError(
                    f"hostname {hostname!r} is already in use by another node "
                    f"({owner[:16]}…). If that node isn't in `gw watch --all` on "
                    f"the anchor, it's a stale/decommissioned entry still holding "
                    f"the name — `sudo gw revoke {hostname}` on the anchor frees "
                    f"it. Otherwise choose a different hostname."
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
            self._gc_recent(now)
            self._recent[id_pub.hex()] = {
                "hostname": hostname, "caps": list(caps), "iat": now,
                "exp": signed.exp,
            }
        log.info("issued credential for %s caps=%s exp=%s", hostname, caps, signed.exp)
        return signed

    def _gc_recent(self, now: "dt.datetime | None" = None) -> None:
        """Drop overlay entries the directory has caught up with (a record at
        or past the issue's iat landed) or whose credential expired. Called
        under the lock."""
        now = now or dt.datetime.now(_UTC)
        for hex_id in list(self._recent):
            entry = self._recent[hex_id]
            rec = self._directory.get(hex_id)
            caught_up = rec is not None and rec.cred.iat >= entry["iat"]
            if caught_up or now >= entry["exp"]:
                del self._recent[hex_id]

    def discard_recent(self, id_pub: bytes) -> bool:
        """Roll back a just-issued credential that never took effect (a failed
        enrollment's peer-install). Frees the hostname the overlay was
        holding. Nothing was replicated yet, so — unlike forget_node — no
        tombstone is minted; there is nothing anywhere else to kill."""
        with self._lock:
            return self._recent.pop(id_pub.hex(), None) is not None

    # --- renewal (§10.3) ---

    def renew(self, req: RenewRequest) -> Credential:
        """
        Process a renewal request from an enrolled node. id_priv possession is
        proven by the self-signature on the request. The (hostname, caps) to
        re-issue come from the node's live directory record — cred verified
        against the TRUSTED CA SET, not just this CA's key, so during a
        re-root overlap the new CA recertifies the outgoing CA's nodes from
        their records with no special path. Raises ValueError on any failure;
        UnknownNodeError when no live trusted record exists (the node must
        re-enroll through the door).
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
                raise UnknownNodeError(
                    "unknown node — no live record to renew from; re-enroll "
                    "through the door (gw invite / gw join)")

            hostname, caps = node_info
            if req.hostname and req.hostname != hostname:
                # Rename (gw rename): issue() enforces uniqueness on the new name.
                # But an anchor-pinned node (enrolled via `gw invite --hostname`)
                # may not rename itself — the name is the anchor's.
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

    # --- the replicated registry view ---

    def _live_record(self, id_pub_hex: str):
        """The node's directory record, IF its credential is signed by a
        trusted CA (expired is fine — expiry means "recertify me", and this is
        the recertification path) and no tombstone ended that membership.
        Returns the NodeRecord or None."""
        rec = self._directory.get(id_pub_hex)
        if rec is None:
            return None
        try:
            rec.cred.verify(self._get_ca_pubs(), allow_expired=True)
        except ValueError:
            return None
        if self._statements.is_dead(id_pub_hex, rec.cred.iat):
            return None
        return rec

    def node_info(self, id_pub: bytes) -> tuple[str, list[str]] | None:
        """(hostname, caps) for an enrolled node, or None if unknown. Caps
        honor the newest setcaps statement when it postdates the credential —
        the operator's pending change, applied at the next renewal. (A setcaps
        raced by a renewal at a holder that hadn't synced it yet can be lost
        for one cycle — re-apply; the ~20s statement gossip makes the window
        small. Accepted active/active race.)"""
        hex_id = id_pub.hex()
        if hex_id in self.load_revoked_set():
            return None
        with self._lock:
            self._gc_recent()
            entry = self._recent.get(hex_id)
            if entry is not None:
                return entry["hostname"], self._caps_for(
                    hex_id, entry["caps"], entry["iat"])
        rec = self._live_record(hex_id)
        if rec is None:
            return None
        return rec.cred.hostname, self._caps_for(
            hex_id, list(rec.cred.caps), rec.cred.iat)

    def _caps_for(self, hex_id: str, cred_caps: list[str],
                  cred_iat: dt.datetime) -> list[str]:
        # The newest decision wins: a setcaps at or after the credential's
        # issuance is the operator's latest wish (>= not >, so a set-caps in
        # the same second as an issue isn't lost to timestamp granularity);
        # a credential issued after it — a re-enrollment, whose caps the
        # anchor chose fresh at the door — supersedes it.
        override = self._statements.caps_override(hex_id)
        if override is not None and override[1] >= cred_iat:
            return override[0]
        return cred_caps

    def set_caps(self, id_pub: bytes, caps: list[str]) -> None:
        """Change a node's caps: mint a replicated setcaps statement. Takes
        effect at the node's NEXT renewal — served by whichever holder gets
        it, since the statement reaches them all. Raises if unknown."""
        with self._lock:
            info = self.node_info(id_pub)
            if info is None:
                raise UnknownNodeError("unknown node — enroll it first")
            self._mint("setcaps", id_pub, caps=caps, hostname=info[0])

    # --- revoke list ---

    def is_revoked(self, id_pub: bytes) -> bool:
        return id_pub.hex() in self.load_revoked_set()

    def add_revoke(self, id_pub: bytes) -> bool:
        """Revoke an identity and release its hostname. Returns True if a
        live claim (record or just-issued credential) existed and was ended.
        Dual-written: a replicated revoke statement (reaches every holder and
        node) AND the legacy revoked.json (so this holder's /revoked and any
        pre-statement holder stay correct)."""
        with self._lock:
            revoked = self._load_legacy_revoked()
            revoked.add(id_pub.hex())
            self._save_revoked(revoked)
            info = self.node_info(id_pub)
            self._mint("revoke", id_pub,
                       hostname=info[0] if info else "")
            freed = self.forget_node(id_pub)
        log.info("revoked %s%s", id_pub.hex()[:16],
                 " (hostname freed)" if freed else "")
        return freed

    def forget_node(self, id_pub: bytes) -> bool:
        """End this id's membership: mint a tombstone (kills its records
        everywhere, freeing the hostname for reuse) and drop it from the local
        view now. A later re-enrollment mints a fresh credential the
        tombstone doesn't touch. Returns True if a live claim existed."""
        hex_id = id_pub.hex()
        with self._lock:
            had_recent = self._recent.pop(hex_id, None) is not None
            rec = self._directory.get(hex_id)
            self._mint("tombstone", id_pub,
                       hostname=rec.hostname if rec is not None else "")
            dropped = self._directory.remove(hex_id)
            if dropped:
                try:
                    self._directory.save(self._dir_cache_path)
                except OSError as e:
                    log.warning("could not persist directory after forget: %s", e)
        return had_recent or dropped

    def announce_upgrade(self, version: str, sha256: str) -> AnchorStatement:
        """Mint the fleet upgrade announcement (gw upgrade-all): a CA-signed
        statement pinning a release version AND the sha256 of its published
        tarball, so the signal can only ever name that specific artifact.
        Subject id is this CA's own pub (one slot; latest announcement wins).
        Rides the ordinary statement gossip; nodes act only when opted in
        (auto_upgrade) and verify the hash before installing."""
        return self._mint("upgrade", self._keys.ca_pub_bytes,
                          upgrade={"version": version, "sha256": sha256})

    def _mint(self, kind: str, id_pub: bytes, caps: "list[str] | None" = None,
              hostname: str = "", upgrade: "dict | None" = None) -> AnchorStatement:
        """Sign one AnchorStatement, add it to the log, persist the log."""
        from .statements import statements_path
        stmt = AnchorStatement(
            kind=kind, id_pub=id_pub,
            ts=dt.datetime.now(_UTC).replace(microsecond=0),
            caps=list(caps or []), hostname=hostname,
            upgrade=dict(upgrade or {}),
        ).sign(self._keys.ca_priv)
        self._statements.add(stmt)
        try:
            self._statements.save(statements_path(self._data_dir))
        except OSError as e:
            log.warning("could not persist statements: %s", e)
        return stmt

    def _load_legacy_revoked(self) -> set[str]:
        if not self._revoke_path.exists():
            return set()
        return set(json.loads(self._revoke_path.read_text()).get("revoked", []))

    def load_revoked_set(self) -> set[str]:
        """The full revoke set: legacy revoked.json ∪ replicated revoke
        statements — so a revocation minted at ANY holder counts here."""
        return self._load_legacy_revoked() | self._statements.revoked_ids()

    def _save_revoked(self, revoked: set[str]) -> None:
        atomic_write(
            self._revoke_path, json.dumps({"revoked": sorted(revoked)}, indent=2)
        )

    def hostname_owner(self, hostname: str) -> str | None:
        """id_pub hex of the live node claiming this (sanitized) hostname, or
        None. A claim is a trusted, un-tombstoned directory record — or a
        just-issued credential still in this process's overlay. Departed,
        revoked, and aged-out nodes hold nothing: their claims ended with
        their records, which is exactly what frees a name for reuse."""
        from .hosts import sanitize
        want = sanitize(hostname)
        revoked = self.load_revoked_set()
        with self._lock:
            self._gc_recent()
            for hex_id, entry in self._recent.items():
                if hex_id in revoked:
                    continue
                if sanitize(entry["hostname"]) == want:
                    return hex_id
        for rec in self._directory.all():
            hex_id = rec.id_pub.hex()
            if hex_id in revoked:
                continue
            if sanitize(rec.cred.hostname) != want:
                continue
            if self._live_record(hex_id) is not None:
                return hex_id
        return None
