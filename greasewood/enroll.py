"""
greasewood.enroll — TCP enroll server and door-window watcher for the hub.

EnrollServer
  Binds to [HUB_DOOR_IP]:ENROLL_PORT (only reachable through the door WG tunnel).
  Accepts exactly one connection per door window.  On success: issues a credential,
  adds the new node as a peer on the main WG interface, sends the response, then
  calls on_done() which tears down the door and deletes the window file.

DoorWatcher
  Background thread in gw-run (hub role only).  Polls data_dir/door_window.json
  every 10 s.  When a valid, unexpired window appears, it starts an EnrollServer.
  When the window is consumed, expired, or absent, it cleans up.

Wire framing: 4-byte big-endian length prefix + JSON body (max 64 KiB).
"""
from __future__ import annotations

import datetime as dt
import json
import logging
import socket
import struct
import threading
from pathlib import Path
from typing import TYPE_CHECKING, Callable

from .door import ENROLL_PORT, HUB_DOOR_IP, DOOR_IFACE

if TYPE_CHECKING:
    from .ca import CA
    from .directory import Directory
    from .keys import NodeKeys

log = logging.getLogger(__name__)
_UTC = dt.timezone.utc
_MAX_MSG = 64 * 1024


# ---------------------------------------------------------------------------
# Wire helpers
# ---------------------------------------------------------------------------

def _recvall(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError(f"short read: {len(buf)}/{n} bytes")
        buf += chunk
    return buf


def _recv_msg(sock: socket.socket) -> dict:
    length = struct.unpack(">I", _recvall(sock, 4))[0]
    if length > _MAX_MSG:
        raise ValueError(f"message too large: {length}")
    return json.loads(_recvall(sock, length))


def _send_msg(sock: socket.socket, data: dict) -> None:
    body = json.dumps(data, separators=(",", ":")).encode()
    sock.sendall(struct.pack(">I", len(body)) + body)


# ---------------------------------------------------------------------------
# EnrollServer
# ---------------------------------------------------------------------------

class EnrollServer:
    """
    One-shot TCP server bound to [HUB_DOOR_IP]:ENROLL_PORT.
    Processes exactly one enrollment per door window, then calls on_done().
    """

    def __init__(
        self,
        ca: "CA",
        directory: "Directory",
        node_keys: "NodeKeys",
        wg_iface: str,
        on_done: Callable[[], None],
        timeout_secs: float = 900.0,
    ) -> None:
        self._ca = ca
        self._directory = directory
        self._node_keys = node_keys
        self._wg_iface = wg_iface
        self._on_done = on_done
        self._timeout = timeout_secs
        self._srv: socket.socket | None = None
        self._thread = threading.Thread(target=self._serve, name="enroll", daemon=True)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        if self._srv:
            try:
                self._srv.close()
            except Exception:
                pass

    def _serve(self) -> None:
        try:
            srv = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.settimeout(self._timeout)
            srv.bind((HUB_DOOR_IP, ENROLL_PORT))
            srv.listen(1)
            self._srv = srv
            log.info("enroll server ready on [%s]:%d (window %.0fs)", HUB_DOOR_IP, ENROLL_PORT, self._timeout)

            conn, addr = srv.accept()
            log.info("enroll connection from %s", addr[0])
            with conn:
                conn.settimeout(30)
                try:
                    self._handle(conn)
                except Exception as e:
                    log.error("enroll error: %s", e)
                    try:
                        _send_msg(conn, {"v": 1, "ok": False, "error": "internal", "reason": str(e)})
                    except Exception:
                        pass

        except socket.timeout:
            log.info("enroll window expired (no connection received)")
        except OSError as e:
            if "Errno 9" in str(e) or "closed" in str(e).lower():
                pass  # stopped via stop()
            else:
                log.error("enroll server OSError: %s", e)
        finally:
            if self._srv:
                try:
                    self._srv.close()
                except Exception:
                    pass
            self._on_done()

    def _handle(self, conn: socket.socket) -> None:
        import base64
        from . import wg as wgmod
        from .keys import derive_addr

        req = _recv_msg(conn)
        if req.get("v") != 1:
            raise ValueError(f"unsupported version: {req.get('v')}")

        id_pub_bytes = bytes.fromhex(req["id_pub"])
        wg_pub_bytes = base64.b64decode(req["wg_pub"])
        hostname = str(req["hostname"])
        caps = [str(c) for c in req.get("caps", ["mesh"])]

        if len(id_pub_bytes) != 32:
            raise ValueError("id_pub must be 32 bytes")
        if len(wg_pub_bytes) != 32:
            raise ValueError("wg_pub must be 32 bytes")

        # Issue CA-signed credential
        cred = self._ca.issue(id_pub_bytes, wg_pub_bytes, hostname, caps)

        # Add new node as a peer on the main WG interface so it can establish
        # its tunnel and push its NodeRecord to the hub on first startup.
        overlay_addr = derive_addr(id_pub_bytes)
        wg_pub_b64 = base64.b64encode(wg_pub_bytes).decode()
        wgmod.set_peer(self._wg_iface, wg_pub_b64, overlay_addr)
        log.info("enrolled %s  addr=%s", hostname, overlay_addr)

        # Send back the credential + hub's own NodeRecord so the new node can
        # pre-seed its directory and configure seeds using the overlay address.
        hub_record = self._directory.get(self._node_keys.id_pub_hex)
        _send_msg(conn, {
            "v": 1,
            "ok": True,
            "credential": cred.to_dict(),
            "hub_record": hub_record.to_dict() if hub_record else None,
        })


# ---------------------------------------------------------------------------
# DoorWatcher
# ---------------------------------------------------------------------------

class DoorWatcher:
    """
    Polls data_dir/door_window.json every 10 s.
    Starts an EnrollServer when a valid window is found; cleans up when it expires.
    """

    def __init__(
        self,
        data_dir: Path,
        ca: "CA",
        directory: "Directory",
        node_keys: "NodeKeys",
        wg_iface: str,
    ) -> None:
        self._data_dir = data_dir
        self._ca = ca
        self._directory = directory
        self._node_keys = node_keys
        self._wg_iface = wg_iface
        self._enroll: EnrollServer | None = None
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._loop, name="door-watcher", daemon=True)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        with self._lock:
            if self._enroll:
                self._enroll.stop()

    def _loop(self) -> None:
        while not self._stop.wait(10):
            self._tick()

    def _tick(self) -> None:
        window_path = self._data_dir / "door_window.json"

        if not window_path.exists():
            self._clear_enroll()
            return

        try:
            data = json.loads(window_path.read_text())
            expires = dt.datetime.fromisoformat(data["expires"].replace("Z", "+00:00"))
        except Exception as e:
            log.debug("door_window.json unreadable: %s", e)
            return

        now = dt.datetime.now(_UTC)
        if now >= expires:
            log.info("door window expired, cleaning up")
            self._clear_enroll()
            _destroy_door()
            window_path.unlink(missing_ok=True)
            return

        with self._lock:
            if self._enroll is not None:
                return  # already running

            remaining = (expires - now).total_seconds()

            def on_done():
                _destroy_door()
                window_path.unlink(missing_ok=True)
                with self._lock:
                    self._enroll = None
                log.info("door enrollment complete, window closed")

            srv = EnrollServer(
                ca=self._ca,
                directory=self._directory,
                node_keys=self._node_keys,
                wg_iface=self._wg_iface,
                on_done=on_done,
                timeout_secs=remaining,
            )
            srv.start()
            self._enroll = srv
            log.info("door window detected, enroll server started (%.0fs remaining)", remaining)

    def _clear_enroll(self) -> None:
        with self._lock:
            if self._enroll:
                self._enroll.stop()
                self._enroll = None


def _destroy_door() -> None:
    from . import wg as wgmod
    wgmod.destroy_interface(DOOR_IFACE)
