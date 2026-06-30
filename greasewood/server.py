"""
greasewood.server — HTTP control plane (hub role).

Endpoints:
  GET  /directory   → JSON array of NodeRecords
  POST /publish     → accept a self-signed, CA-credentialed NodeRecord
  POST /renew       → RenewRequest → Credential  (hub only)
  GET  /health      → {"status": "ok"}

There is no /enroll endpoint here. Enrollment happens out of band — over the
transient WireGuard "door" (`gw invite` / `gw join`, see greasewood.enroll), or
by manually copying a credential from `gw issue`. This server is intended to
run on the overlay address so all traffic goes through the WireGuard tunnel.

/publish is the exception that may be called before a node is fully in the
mesh: a newly installed node POSTs its own signed record so the root can
configure a WireGuard peer for it. It is safe to expose because it requires
a fully valid, CA-signed NodeRecord — a bad actor cannot forge one without
ca_priv, and the worst they can do with a valid record is cause a failed
connection, not an intercepted one.
"""
from __future__ import annotations

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
    get_bundle: "callable" = staticmethod(lambda: {"v": 1, "statements": []})
    cache_path: "Path | None" = None
    tls_cert_ttl: "dt.timedelta | None" = None
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
        return json.loads(self.rfile.read(length))

    def do_GET(self) -> None:
        if self.path == "/directory":
            self._send_json([r.to_dict() for r in self.directory.all()])
        elif self.path == "/ca-bundle":
            self._send_json(self.get_bundle())
        elif self.path == "/ca-cert":
            if self.ca is None:
                self.send_error(404)
            else:
                self._send_json({"ca_cert": self.ca.ca_cert_pem()})
        elif self.path == "/health":
            self._send_json({"status": "ok"})
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
                self.send_error(403, "not a root node")
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
            # `gw status` (which reads the on-disk cache, not live memory).
            if accepted and self.cache_path is not None:
                try:
                    self.directory.save(self.cache_path)
                except Exception as e:
                    log.warning("failed to persist directory after publish: %s", e)
            log.debug("published record from %s seq=%d", record.hostname, record.seq)
            self._send_json({"status": "ok"})
        except (ValueError, KeyError) as e:
            log.warning("publish rejected: %s", e)
            self._send_json({"error": str(e)}, 400)

    def _handle_renew(self, body: dict) -> None:
        from .wire import RenewRequest
        try:
            req = RenewRequest.from_dict(body)
            req.verify_self_sig()  # authenticate before consuming the nonce
        except (ValueError, KeyError) as e:
            log.warning("renew rejected: %s", e)
            self._send_json({"error": str(e)}, 400)
            return
        if not self.replay.check_and_add(req.nonce):
            log.warning("renew rejected: replayed nonce from %s", req.id_pub.hex()[:16])
            self._send_json({"error": "replay detected (nonce already used)"}, 400)
            return
        try:
            cred = self.ca.renew(req)
            self._send_json(cred.to_dict())
        except ValueError as e:
            log.warning("renew rejected: %s", e)
            self._send_json({"error": str(e)}, 400)

    def _handle_cert(self, body: dict) -> None:
        import datetime as _dt
        from .wire import CertRequest
        from .keys import derive_addr
        try:
            req = CertRequest.from_dict(body)
            req.verify_self_sig()  # proves id_priv possession
        except (ValueError, KeyError) as e:
            self._send_json({"error": f"bad cert request: {e}"}, 400)
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

        # SANs default to the node's overlay address if none were requested, so
        # a service reachable at the node's mesh IP works out of the box.
        dns = list(req.dns)
        ips = list(req.ips)
        if not dns and not ips:
            ips = [derive_addr(req.id_pub)]
        cn = req.cn or hostname or derive_addr(req.id_pub)

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
    address_family = socket.AF_INET6


class ControlServer:
    def __init__(
        self,
        listen,                     # str or list[str] of "[addr]:port"
        directory: "Directory",
        get_ca_pubs,
        get_revoked,
        ca: "CA | None" = None,
        cache_path: "Path | None" = None,
        get_bundle=None,
        tls_cert_ttl=None,
    ) -> None:
        listens = [listen] if isinstance(listen, str) else list(listen)

        class Handler(_Handler):
            pass
        Handler.directory = directory
        Handler.ca = ca
        Handler.get_ca_pubs = staticmethod(get_ca_pubs)
        Handler.get_revoked = staticmethod(get_revoked)
        if get_bundle is not None:
            Handler.get_bundle = staticmethod(get_bundle)
        Handler.cache_path = cache_path
        Handler.tls_cert_ttl = tls_cert_ttl
        Handler.replay = _ReplayGuard()

        # Bind one socket per address — typically the hub's overlay address and
        # loopback, NOT "::". The control plane is then unreachable on the
        # underlay by construction, no firewall rule required.
        self._servers = []
        for lst in listens:
            host, _, port_str = lst.rpartition(":")
            host = host.strip("[]")  # strip brackets from "[fd8d::1]"
            is_ipv4 = "." in host    # IPv4 literals contain dots
            if is_ipv4:
                self._servers.append(HTTPServer((host, int(port_str)), Handler))
            else:
                self._servers.append(_IPv6Server((host or "::", int(port_str)), Handler))
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
