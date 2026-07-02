"""
greasewood.server — HTTP control plane (hub role).

Endpoints:
  GET  /directory   → {"records": [NodeRecord, ...], "renew_after": <iso ts|null>}
  POST /publish     → accept a self-signed, CA-credentialed NodeRecord
  POST /renew       → RenewRequest → Credential  (hub only)
  GET  /health      → {"status": "ok"}

There is no /enroll endpoint here. Enrollment happens out of band — over the
transient WireGuard "door" (`gw invite` / `gw join`, see greasewood.enroll), or
by manually copying a credential from `gw issue`. This server is intended to
run on the overlay address so all traffic goes through the WireGuard tunnel.

/publish is the exception that may be called before a node is fully in the
mesh: a newly installed node POSTs its own signed record so the hub can
configure a WireGuard peer for it. It is safe to expose because it requires
a fully valid, CA-signed NodeRecord — a bad actor cannot forge one without
ca_priv, and the worst they can do with a valid record is cause a failed
connection, not an intercepted one.
"""
from __future__ import annotations

import concurrent.futures
import json
import logging
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path
    from .ca import CA
    from .directory import Directory

log = logging.getLogger(__name__)

# Largest control-plane request body we will read. Records/requests are a few KB;
# this just stops an in-mesh peer from forcing an unbounded allocation.
_MAX_BODY = 256 * 1024


class _ReplayGuard:
    """
    Thread-safe single-use nonce set with time eviction. The signature on a
    request proves authenticity; this makes each accepted request single-use,
    so a captured /renew or /cert cannot be replayed within the skew window.
    Entries are kept for `window` seconds (> the 300s skew bound), after which
    the stale-timestamp check would reject a replay anyway.
    """

    def __init__(self, window: float = 600.0) -> None:
        self._window = window
        self._seen: dict[str, float] = {}  # nonce -> expiry epoch
        self._lock = threading.Lock()

    def check_and_add(self, nonce: str) -> bool:
        """True if the nonce is fresh (and records it); False if it is a replay."""
        now = time.time()
        with self._lock:
            if len(self._seen) > 4096:  # bound memory; evict expired in bulk
                self._seen = {n: e for n, e in self._seen.items() if e > now}
            exp = self._seen.get(nonce)
            if exp is not None and exp > now:
                return False
            self._seen[nonce] = now + self._window
            return True


class _Handler(BaseHTTPRequestHandler):
    directory: "Directory"
    ca: "CA | None" = None
    get_ca_pubs: "callable" = staticmethod(list)
    get_revoked: "callable" = staticmethod(set)
    cache_path: "Path | None" = None
    tls_cert_ttl: "dt.timedelta | None" = None
    mesh_domain: str = "gw.internal"
    # Fleet-wide renew hint (see gw renew-all): a callable returning an ISO
    # timestamp string (or None). Served in /directory so cooperating nodes whose
    # credential predates it renew. Read fresh per request (no restart needed).
    get_renew_after: "callable" = staticmethod(lambda: None)
    replay: "_ReplayGuard" = _ReplayGuard()

    def log_message(self, fmt, *args) -> None:
        log.debug("http %s %s", self.command, self.path)

    def _send_json(self, data, status: int = 200) -> None:
        body = json.dumps(data, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self) -> dict:
        length = int(self.headers.get("Content-Length", 0))
        if length > _MAX_BODY:
            raise ValueError(f"request body too large ({length} bytes)")
        body = json.loads(self.rfile.read(length))
        # Every endpoint expects a JSON object. Enforce it here so a bare null,
        # list, or scalar is a clean 400 in do_POST — not a TypeError deep in a
        # from_dict (d["id_pub"] on a non-dict) that escapes as a 500.
        if not isinstance(body, dict):
            raise ValueError("request body must be a JSON object")
        return body

    @staticmethod
    def _now_iso() -> str:
        """The hub's UTC time, stamped into /directory and /health so nodes can
        detect clock skew (sync loop warning, gw diagnose) instead of
        mis-reading it as credential failures."""
        import datetime as dt
        return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()

    def do_GET(self) -> None:
        if self.path == "/directory":
            self._send_json({
                "records": [r.to_dict() for r in self.directory.all()],
                "renew_after": self.get_renew_after(),
                "now": self._now_iso(),
            })
        elif self.path == "/ca-cert":
            if self.ca is None:
                self.send_error(404)
            else:
                self._send_json({"ca_cert": self.ca.ca_cert_pem()})
        elif self.path == "/health":
            self._send_json({"status": "ok", "now": self._now_iso()})
        else:
            self.send_error(404)

    def do_POST(self) -> None:
        try:
            body = self._read_json()
        except Exception:
            self.send_error(400, "bad JSON")
            return

        if self.path == "/publish":
            self._handle_publish(body)
        elif self.path == "/renew":
            if self.ca is None:
                self.send_error(403, "not a hub")
            else:
                self._handle_renew(body)
        elif self.path == "/cert":
            if self.ca is None:
                self.send_error(403, "not a hub")
            else:
                self._handle_cert(body)
        else:
            self.send_error(404)

    def _handle_publish(self, body: dict) -> None:
        from .wire import NodeRecord
        try:
            record = NodeRecord.from_dict(body)
            record.verify(self.get_ca_pubs(), self.get_revoked())
            accepted = self.directory.merge([record])
            # Persist so the record survives a daemon restart and shows up in
            # `gw nodes` (which reads the on-disk cache, not live memory).
            if accepted and self.cache_path is not None:
                try:
                    self.directory.save(self.cache_path)
                except Exception as e:
                    log.warning("failed to persist directory after publish: %s", e)
            log.debug("published record from %s seq=%d", record.hostname, record.seq)
            self._send_json({"status": "ok"})
        except (ValueError, KeyError, TypeError) as e:
            log.warning("publish rejected: %s", e)
            self._send_json({"error": str(e)}, 400)

    def _handle_renew(self, body: dict) -> None:
        from .wire import RenewRequest
        try:
            req = RenewRequest.from_dict(body)
            req.verify_self_sig()  # authenticate before consuming the nonce
        except (ValueError, KeyError, TypeError) as e:
            log.warning("renew rejected: %s", e)
            self._send_json({"error": str(e)}, 400)
            return
        if not self.replay.check_and_add(req.nonce):
            log.warning("renew rejected: replayed nonce from %s", req.id_pub.hex()[:16])
            self._send_json({"error": "replay detected (nonce already used)"}, 400)
            return
        try:
            cred = self.ca.renew(req)
        except ValueError as e:
            cred = self._reroot_reissue(req, e)
            if cred is None:
                log.warning("renew rejected: %s", e)
                self._send_json({"error": str(e)}, 400)
                return
        self._send_json(cred.to_dict())

    def _reroot_reissue(self, req, orig_err):
        """Re-root fallback. This hub never enrolled the requester (no local
        node_info), but a *manual re-root* points existing nodes at a new hub
        that didn't issue them. If we hold a directory record for that identity
        signed by a currently-trusted CA — the outgoing hub, during the overlap
        window — re-issue under THIS CA using the record's CA-attested (level-b)
        hostname + caps. Returns the new Credential, or None to surface the
        original error.

        Only fires for 'unknown node' — auth, skew, replay, and revocation were
        already enforced above / in ca.renew. Safe because: the record's cred is
        verified against the trusted CA set (an attacker can't forge caps/name
        without a trusted CA key), and the requester proved id_priv possession.
        """
        if "unknown node" not in str(orig_err):
            return None
        rec = self.directory.get(req.id_pub.hex())
        if rec is None or rec.cred.id_pub != req.id_pub:
            return None
        try:
            rec.cred.verify(self.get_ca_pubs())   # signed by a currently-trusted CA
        except ValueError:
            return None
        log.info("re-root: re-issuing %s (hostname=%s) from a trusted record",
                 req.id_pub.hex()[:16], rec.hostname)
        return self.ca.issue(req.id_pub, req.wg_pub, rec.hostname, list(rec.cred.caps))

    def _handle_cert(self, body: dict) -> None:
        import datetime as _dt
        from .wire import CertRequest
        from .keys import derive_addr
        try:
            req = CertRequest.from_dict(body)
            req.verify_self_sig()  # proves id_priv possession
        except (ValueError, KeyError, TypeError) as e:
            self._send_json({"error": f"bad cert request: {e}"}, 400)
            return

        # Validate the leaf key length up front: it isn't touched until
        # issuance, where a non-32-byte value makes Ed25519PublicKey raise —
        # which the broad except there would surface as a 500. Reject as a 400.
        if len(req.leaf_pub) != 32:
            self._send_json(
                {"error": "leaf_pub must be a 32-byte Ed25519 public key"}, 400)
            return

        skew = abs((_dt.datetime.now(_dt.timezone.utc) - req.ts).total_seconds())
        if skew > 300:
            self._send_json({"error": f"timestamp skew too large ({skew:.0f}s); check NTP"}, 400)
            return

        if not self.replay.check_and_add(req.nonce):
            self._send_json({"error": "replay detected (nonce already used)"}, 400)
            return

        info = self.ca.node_info(req.id_pub)
        if info is None:
            self._send_json({"error": "unknown node — not enrolled"}, 403)
            return
        hostname, caps = info
        if "tls" not in caps:
            self._send_json({"error": "node lacks the 'tls' capability"}, 403)
            return

        # SAN authorization: a node may only obtain a cert for names it OWNS —
        # its CA-registered name <hostname>.<mesh_domain> (from node_info, NOT
        # from the request), subdomains of it, and its own overlay address. This
        # is what makes a client's SAN validation meaningful: without it, any
        # tls-capable node could mint a cert for another node's name and
        # impersonate it to verify-full clients.
        from .hosts import mesh_name
        own_name = mesh_name(hostname, self.mesh_domain)
        own_addr = derive_addr(req.id_pub)

        def _owned_dns(name: str) -> bool:
            return name == own_name or name.endswith("." + own_name)

        bad = [d for d in req.dns if not _owned_dns(d)]
        bad += [ip for ip in req.ips if ip != own_addr]
        if bad:
            self._send_json({
                "error": f"not authorized for SAN(s) {bad}; a node may only get a "
                         f"cert for {own_name!r}, its subdomains, and its own "
                         f"address {own_addr!r}"
            }, 403)
            return

        # Default to the node's own name + address when none were requested.
        dns = list(req.dns) or [own_name]
        ips = list(req.ips) or [own_addr]
        cn = req.cn if (req.cn and _owned_dns(req.cn)) else own_name

        ttl = self.tls_cert_ttl or _dt.timedelta(days=7)
        try:
            leaf_pem, ca_pem = self.ca.issue_tls(req.leaf_pub, cn, dns, ips, ttl)
        except Exception as e:  # noqa: BLE001
            log.error("tls issuance failed: %s", e)
            self._send_json({"error": "issuance failed", "reason": str(e)}, 500)
            return
        log.info("issued TLS cert for %s cn=%s dns=%s ips=%s", hostname, cn, dns, ips)
        self._send_json({"cert": leaf_pem, "ca_cert": ca_pem})


class _IPv6Server(HTTPServer):
    """IPv6 control plane with a BOUNDED worker pool.

    Concurrent (so one stalled client can't wedge the plane for the fleet — each
    handler also has a socket `timeout` that drops a client which stops sending),
    but capped: at most `max_workers` requests run at once. Over that, further
    connections are shed immediately rather than spawning threads/sockets without
    bound — so a connection flood from a mesh member can't exhaust the hub. The
    nodes' renew/publish/cert loops already retry with backoff, so a shed
    connection is retried, not lost."""
    address_family = socket.AF_INET6

    def __init__(self, addr, handler, max_workers: int = 32) -> None:
        super().__init__(addr, handler)
        self._max_workers = max_workers
        self._pool = concurrent.futures.ThreadPoolExecutor(
            max_workers=max_workers, thread_name_prefix="gw-http")
        # In-flight admission bound == pool size: at most max_workers requests
        # are ever accepted at once; the rest are dropped, not queued.
        self._slots = threading.BoundedSemaphore(max_workers)

    def process_request(self, request, client_address) -> None:
        if not self._slots.acquire(blocking=False):
            log.warning("control plane at worker capacity (%d) — dropping a "
                        "connection from %s", self._max_workers,
                        client_address[0] if client_address else "?")
            self.shutdown_request(request)
            return
        self._pool.submit(self._run, request, client_address)

    def _run(self, request, client_address) -> None:
        try:
            self.finish_request(request, client_address)
        except Exception:
            self.handle_error(request, client_address)
        finally:
            try:
                self.shutdown_request(request)
            finally:
                self._slots.release()

    def server_close(self) -> None:
        super().server_close()
        self._pool.shutdown(wait=False)

    def handle_error(self, request, client_address) -> None:
        # A client that hangs up mid-response (or a connection dropped at
        # shutdown) raises BrokenPipe/ConnectionReset in the handler — expected
        # for a network service, not worth a stderr traceback. Log those at
        # debug; keep the full report only for genuinely unexpected errors.
        import sys
        exc = sys.exc_info()[1]
        if isinstance(exc, (BrokenPipeError, ConnectionResetError, TimeoutError,
                            socket.timeout)):
            log.debug("client %s connection dropped: %r",
                      client_address[0] if client_address else "?", exc)
            return
        super().handle_error(request, client_address)


class ControlServer:
    def __init__(
        self,
        listen,                     # str or list[str] of "[addr]:port"
        directory: "Directory",
        get_ca_pubs,
        get_revoked,
        ca: "CA | None" = None,
        cache_path: "Path | None" = None,
        tls_cert_ttl=None,
        mesh_domain: str = "gw.internal",
        get_renew_after=lambda: None,
        request_timeout: float = 30.0,
        max_workers: int = 32,
    ) -> None:
        listens = [listen] if isinstance(listen, str) else list(listen)

        class Handler(_Handler):
            pass
        # Per-connection socket timeout (socketserver applies it in setup()):
        # a client that stops sending mid-request is dropped instead of holding
        # its handler thread forever.
        Handler.timeout = request_timeout
        Handler.directory = directory
        Handler.ca = ca
        Handler.get_ca_pubs = staticmethod(get_ca_pubs)
        Handler.get_revoked = staticmethod(get_revoked)
        Handler.cache_path = cache_path
        Handler.tls_cert_ttl = tls_cert_ttl
        Handler.mesh_domain = mesh_domain
        Handler.get_renew_after = staticmethod(get_renew_after)
        Handler.replay = _ReplayGuard()

        # Bind one socket per address — typically the hub's overlay address and
        # loopback, NOT "::". The control plane is then unreachable on the
        # underlay by construction, no firewall rule required.
        # greasewood is IPv6-only: every listen address is IPv6 (the overlay
        # address + loopback). Bind one socket per address.
        self._servers = []
        for lst in listens:
            host, _, port_str = lst.rpartition(":")
            host = host.strip("[]")  # strip brackets from "[fd8d::1]"
            self._servers.append(
                _IPv6Server((host or "::", int(port_str)), Handler, max_workers))
        # Primary server (callers/tests read its bound port).
        self._server = self._servers[0]

    def start(self) -> threading.Thread:
        threads = []
        for srv in self._servers:
            t = threading.Thread(target=srv.serve_forever, name="http", daemon=True)
            t.start()
            threads.append(t)
            log.info("control plane listening on %s", srv.server_address)
        return threads[0]

    def stop(self) -> None:
        for srv in self._servers:
            srv.shutdown()
            srv.server_close()   # close the socket AND shut the worker pool
