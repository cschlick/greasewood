"""
greasewood.server — HTTP control plane (root and seed roles).

Endpoints:
  GET  /directory   → JSON array of NodeRecords (root and seeds)
  POST /enroll      → EnrollRequest → Credential  (root only)
  POST /renew       → RenewRequest  → Credential  (root only)
  GET  /health      → {"status": "ok"}

Directory reads are unauthenticated — every record is self-signed so the
reader verifies locally. A compromised seed can withhold records but cannot
forge them. Enrollment and renewal are authenticated by self-signatures in
the request body; the CA also enforces token and revoke-list checks.
"""
from __future__ import annotations

import json
import logging
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .ca import CA
    from .directory import Directory

log = logging.getLogger(__name__)


class _Handler(BaseHTTPRequestHandler):
    # Set at server-build time via subclass attributes
    directory: "Directory"
    ca: "CA | None" = None

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
        elif self.path == "/health":
            self._send_json({"status": "ok"})
        else:
            self.send_error(404)

    def do_POST(self) -> None:
        if self.ca is None:
            self.send_error(403, "not a root node")
            return
        try:
            body = self._read_json()
        except Exception:
            self.send_error(400, "bad JSON")
            return
        if self.path == "/enroll":
            self._handle_enroll(body)
        elif self.path == "/renew":
            self._handle_renew(body)
        else:
            self.send_error(404)

    def _handle_enroll(self, body: dict) -> None:
        from .wire import EnrollRequest
        try:
            req = EnrollRequest.from_dict(body)
            cred = self.ca.enroll(req)
            self._send_json(cred.to_dict())
        except ValueError as e:
            log.warning("enroll rejected: %s", e)
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


class ControlServer:
    def __init__(
        self,
        listen: str,
        directory: "Directory",
        ca: "CA | None" = None,
    ) -> None:
        host, _, port_str = listen.rpartition(":")
        host = host.strip("[]") or "0.0.0.0"

        class Handler(_Handler):
            pass
        Handler.directory = directory
        Handler.ca = ca

        self._server = HTTPServer((host, int(port_str)), Handler)

    def start(self) -> threading.Thread:
        t = threading.Thread(target=self._server.serve_forever, name="http", daemon=True)
        t.start()
        log.info("control plane listening on %s", self._server.server_address)
        return t

    def stop(self) -> None:
        self._server.shutdown()
