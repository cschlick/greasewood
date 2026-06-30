"""
greasewood.server — HTTP control plane (hub role).

Endpoints:
  GET  /directory   → JSON array of NodeRecords
  POST /publish     → accept a self-signed, CA-credentialed NodeRecord
  POST /renew       → RenewRequest → Credential  (hub only)
  GET  /health      → {"status": "ok"}

There is no /enroll endpoint here. Enrollment happens out of band — over the
transient WireGuard "door" (`gw mint` / `gw join`, see greasewood.enroll), or
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
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path
    from .ca import CA
    from .directory import Directory

log = logging.getLogger(__name__)


class _Handler(BaseHTTPRequestHandler):
    directory: "Directory"
    ca: "CA | None" = None
    get_ca_pubs: "callable" = staticmethod(list)
    get_revoked: "callable" = staticmethod(set)
    get_bundle: "callable" = staticmethod(lambda: {"v": 1, "statements": []})
    cache_path: "Path | None" = None

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
        return json.loads(self.rfile.read(length))

    def do_GET(self) -> None:
        if self.path == "/directory":
            self._send_json([r.to_dict() for r in self.directory.all()])
        elif self.path == "/ca-bundle":
            self._send_json(self.get_bundle())
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
            cred = self.ca.renew(req)
            self._send_json(cred.to_dict())
        except ValueError as e:
            log.warning("renew rejected: %s", e)
            self._send_json({"error": str(e)}, 400)


class _IPv6Server(HTTPServer):
    address_family = socket.AF_INET6


class ControlServer:
    def __init__(
        self,
        listen: str,
        directory: "Directory",
        get_ca_pubs,
        get_revoked,
        ca: "CA | None" = None,
        cache_path: "Path | None" = None,
        get_bundle=None,
    ) -> None:
        host, _, port_str = listen.rpartition(":")
        # Strip brackets from IPv6 literals like "[fd8d::1]"
        host = host.strip("[]")

        class Handler(_Handler):
            pass
        Handler.directory = directory
        Handler.ca = ca
        Handler.get_ca_pubs = staticmethod(get_ca_pubs)
        Handler.get_revoked = staticmethod(get_revoked)
        if get_bundle is not None:
            Handler.get_bundle = staticmethod(get_bundle)
        Handler.cache_path = cache_path

        # Use AF_INET6 when binding to an IPv6 address or unspecified (":port").
        # On Linux, AF_INET6 with "::" accepts both IPv4 and IPv6 unless
        # IPV6_V6ONLY is set, so this is safe for dual-stack hosts too.
        is_ipv4 = "." in host  # simple heuristic: IPv4 literals contain dots
        if is_ipv4:
            self._server = HTTPServer((host, int(port_str)), Handler)
        else:
            bind_host = host or "::"
            self._server = _IPv6Server((bind_host, int(port_str)), Handler)

    def start(self) -> threading.Thread:
        t = threading.Thread(target=self._server.serve_forever, name="http", daemon=True)
        t.start()
        log.info("control plane listening on %s", self._server.server_address)
        return t

    def stop(self) -> None:
        self._server.shutdown()
