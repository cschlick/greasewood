"""
greasewood.attest — endpoint attestations: reachability as verified fact.

Every advertised endpoint is a self-asserted claim produced by heuristics,
and the field kept proving how wrong a claim can look right: a VM-internal
ULA, a VPN's shared /128 — both advertised confidently, both unreachable,
both discovered only as incidents. Meanwhile the mesh generates ground truth
continuously: every fresh WireGuard handshake proves that the endpoint the
kernel is using for that peer WORKS.

This module publishes that ground truth. Each node's AttestLoop reads its own
kernel state every couple of minutes and, for every peer with a fresh
handshake, signs an EndpointAttestation ("my tunnel to S rides E") and POSTs
the batch to a holder (/attest). Holders keep the newest testimony per
(attester, subject) in an AttestLog — verified, membership-gated, freshness-
bounded — and serve it in /directory, where every node's sync (and every
other holder's) picks it up. `gw watch` then shows reachability as evidence:
"confirmed by N peer(s)", or the mirage warning — advertised one address,
confirmed at another.

Attestations are testimony about reachability ONLY. They never feed
issuance, policy, or peering decisions, so the worst a lying member can do
is distort a diagnostic display; the self-signature stops impersonation and
the freshness window ages testimony out on its own.
"""
from __future__ import annotations

import datetime as dt
import json
import logging
import threading
import urllib.error
import urllib.request
from pathlib import Path

from .keys import atomic_write
from .loop import Loop
from .wire import EndpointAttestation

log = logging.getLogger(__name__)

_UTC = dt.timezone.utc

ATTEST_BASENAME = "attestations.json"

# A handshake this recent proves the endpoint works NOW (WireGuard
# re-handshakes at least every ~2 minutes on an active tunnel).
FRESH_HANDSHAKE = 180.0

# Testimony older than this is dropped everywhere — reachability is a live
# fact, and stale confirmations are exactly the false comfort this exists to
# kill. Comfortably above the emission interval so healthy links never flap.
MAX_AGE = dt.timedelta(minutes=30)

# How often each node re-reads its kernel state and re-testifies.
_EMIT_INTERVAL = 120.0


def attest_path(data_dir) -> Path:
    return Path(data_dir) / ATTEST_BASENAME


class AttestLog:
    """Thread-safe store of the newest attestation per (attester, subject)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._by_pair: dict[tuple[str, str], EndpointAttestation] = {}

    def merge(self, attestations, known_attester,
              now: "dt.datetime | None" = None) -> int:
        """Merge incoming testimony. Each entry must carry a valid
        self-signature AND come from a known mesh member (`known_attester`:
        id_pub_hex → bool — a live record exists; holders pass a directory
        lookup) — so junk from a never-enrolled key can't pad the log. Stale
        entries (past MAX_AGE, or older than what we hold) are ignored.
        Returns the number accepted. `now` is injectable for callers
        replaying evidence on their own clock (tests, gw explain)."""
        now = now or dt.datetime.now(_UTC)
        accepted = 0
        with self._lock:
            for a in attestations:
                try:
                    a.verify_self_sig()
                except ValueError as e:
                    log.debug("attest merge: dropping (%s)", e)
                    continue
                if now - a.ts > MAX_AGE or a.ts - now > dt.timedelta(minutes=5):
                    continue                     # stale, or a clock from the future
                if not known_attester(a.attester.hex()):
                    log.debug("attest merge: unknown attester %s",
                              a.attester.hex()[:16])
                    continue
                key = (a.attester.hex(), a.subject.hex())
                existing = self._by_pair.get(key)
                if existing is None or a.ts > existing.ts:
                    self._by_pair[key] = a
                    accepted += 1
        return accepted

    def prune(self, now: "dt.datetime | None" = None) -> int:
        now = now or dt.datetime.now(_UTC)
        with self._lock:
            stale = [k for k, a in self._by_pair.items() if now - a.ts > MAX_AGE]
            for k in stale:
                del self._by_pair[k]
        return len(stale)

    def all(self) -> "list[EndpointAttestation]":
        with self._lock:
            return list(self._by_pair.values())

    def confirmations_for(self, subject_hex: str,
                          now: "dt.datetime | None" = None) -> "dict[str, list[str]]":
        """endpoint → [attester id_pub_hex, ...] of FRESH testimony about one
        node — the display shape: who confirms which address. `now` lets a
        caller with its own clock (gw explain's story time) judge freshness
        consistently."""
        now = now or dt.datetime.now(_UTC)
        out: dict[str, list[str]] = {}
        with self._lock:
            for (att, sub), a in self._by_pair.items():
                if sub != subject_hex or now - a.ts > MAX_AGE:
                    continue
                out.setdefault(a.endpoint, []).append(att)
        return out

    def size(self) -> int:
        with self._lock:
            return len(self._by_pair)

    # --- persistence (Directory/StatementLog discipline) ---

    def save(self, path: Path) -> None:
        with self._lock:
            data = [a.to_dict() for a in self._by_pair.values()]
            atomic_write(path, json.dumps(data, indent=2), mode=0o644)

    @classmethod
    def load(cls, path: Path, known_attester) -> "AttestLog":
        logf = cls()
        try:
            raw = json.loads(path.read_text())
        except FileNotFoundError:
            return logf
        except Exception as e:
            log.warning("attestation cache unreadable, starting empty: %s", e)
            return logf
        parsed = []
        for d in raw if isinstance(raw, list) else []:
            try:
                parsed.append(EndpointAttestation.from_dict(d))
            except Exception as e:
                log.warning("skipping one corrupt cached attestation: %s", e)
        logf.merge(parsed, known_attester)
        return logf


def parse_attestations(raw_list) -> list:
    """Parse a wire list, per-entry tolerant (verification happens at merge)."""
    out = []
    for d in raw_list if isinstance(raw_list, list) else []:
        try:
            out.append(EndpointAttestation.from_dict(d))
        except Exception as e:
            log.debug("skipping one unparseable attestation: %s", e)
    return out


def build_attestations(node_keys, directory, iface: str,
                       now: "dt.datetime | None" = None) -> list:
    """This node's current testimony: one signed attestation per peer whose
    tunnel has a FRESH handshake and a known endpoint, mapped back to the
    peer's identity through its directory record (wg_pub → id_pub). Pure
    kernel truth — nothing is attested that isn't presently carrying a
    handshake."""
    from . import wg as wgmod
    now = now or dt.datetime.now(_UTC)
    peers = wgmod.get_peers(iface)
    if not peers:
        return []
    import base64
    by_wg_pub = {}
    for rec in directory.all():
        by_wg_pub[base64.b64encode(rec.cred.wg_pub).decode()] = rec
    out = []
    for wg_pub_b64, live in peers.items():
        if not live.endpoint or not live.latest_handshake:
            continue
        if now.timestamp() - live.latest_handshake > FRESH_HANDSHAKE:
            continue
        rec = by_wg_pub.get(wg_pub_b64)
        if rec is None or rec.id_pub == node_keys.id_pub_bytes:
            continue
        out.append(EndpointAttestation(
            attester=node_keys.id_pub_bytes,
            subject=rec.id_pub,
            endpoint=live.endpoint,
            ts=now.replace(microsecond=0),
        ).sign(node_keys.id_priv))
    return out


def push_attestations(holder_url: str, attestations, timeout: float = 10.0) -> None:
    """POST a batch to one holder's /attest. Raises RuntimeError on failure
    (the caller rotates holders). A holder too old to know the endpoint is a
    silent no-op by design — mixed fleets just lack the testimony."""
    body = json.dumps({"attestations": [a.to_dict() for a in attestations]}).encode()
    req = urllib.request.Request(
        f"{holder_url.rstrip('/')}/attest", data=body,
        headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            resp.read()
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return                      # pre-attestation holder: fine, no-op
        raise RuntimeError(f"attest push to {holder_url} failed: HTTP {e.code}")
    except (urllib.error.URLError, OSError) as e:
        raise RuntimeError(f"attest push to {holder_url} failed: {e}") from e


class AttestLoop(Loop):
    """Every couple of minutes: read the kernel, sign the testimony, hand it
    to the first live holder. Failures are quiet-debug — attestation is a
    diagnostic layer and must never make noise the data plane doesn't."""

    def __init__(self, node_keys, directory, iface: str, get_holder_urls,
                 interval: float = _EMIT_INTERVAL) -> None:
        super().__init__(interval, "attest")
        self._keys = node_keys
        self._directory = directory
        self._iface = iface
        self._get_holder_urls = get_holder_urls

    def _tick(self) -> None:
        try:
            batch = build_attestations(self._keys, self._directory, self._iface)
        except Exception as e:  # noqa: BLE001 — kernel read hiccups are non-events
            log.debug("attest: could not read peer state: %s", e)
            return
        if not batch:
            return
        for url in self._get_holder_urls():
            try:
                push_attestations(url, batch)
                log.debug("attested %d live endpoint(s) via %s", len(batch), url)
                return
            except RuntimeError as e:
                log.debug("%s", e)
