"""
greasewood.enroll — TCP enroll server and door-window watcher for the hub.

EnrollServer
  Binds to [HUB_DOOR_IP]:ENROLL_PORT (only reachable through the door WG tunnel).
  Accepts exactly one connection per door window.  On success: issues a credential,
  adds the new node as a peer on the main WG interface, sends the response, then
  calls on_done() which tears down the door and deletes the window file.

DoorWatcher
  Background thread in gw-run (hub role only).  Polls data_dir/door_window.json
  every poll_interval seconds.  When a valid, unexpired window appears, it
  starts an EnrollServer.
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
import time
from pathlib import Path
from typing import TYPE_CHECKING, Callable

from . import door
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
    TCP server bound to [HUB_DOOR_IP]:ENROLL_PORT for one door window.

    Closes the window (calls on_done) on the FIRST successful enrollment, OR
    after `max_attempts` failed attempts, OR when the window times out —
    whichever comes first. Allowing a few failed attempts means a recoverable
    mistake (e.g. a hostname already taken) doesn't burn the whole invite: the
    joiner is told how many attempts remain and can retry on the same token.
    """

    def __init__(
        self,
        ca: "CA",
        directory: "Directory",
        node_keys: "NodeKeys",
        wg_iface: str,
        on_done: Callable[[], None],
        timeout_secs: float = 900.0,
        get_ca_pubs: "Callable[[], list[bytes]] | None" = None,
        get_revoked: "Callable[[], set[str]] | None" = None,
        cache_path: "Path | None" = None,
        control_port: int = 51902,
        max_attempts: int = 3,
        caps: "list[str] | None" = None,
        pinned_hostname: "str | None" = None,
        data_dir: "Path | None" = None,
    ) -> None:
        self._ca = ca
        self._directory = directory
        self._node_keys = node_keys
        self._wg_iface = wg_iface
        self._on_done = on_done
        self._timeout = timeout_secs
        # Where to persist door status/history for `gw status` (best-effort;
        # None disables it). Observability only — never blocks enrollment.
        self._data_dir = data_dir
        self._get_ca_pubs = get_ca_pubs or (lambda: [])
        self._get_revoked = get_revoked or set
        self._cache_path = cache_path
        self._control_port = control_port
        self._max_attempts = max_attempts
        # Caps the hub authorized for this window (from `gw invite`).
        # The joiner does NOT choose these — the window is authoritative.
        self._caps = list(caps) if caps else ["segment:mesh"]
        # If set (`gw invite --hostname`), the hub pins the name: the joiner's
        # requested hostname is ignored and it can't rename later.
        self._pinned_hostname = pinned_hostname
        self._srv: socket.socket | None = None
        self._stopped = threading.Event()
        self._thread = threading.Thread(target=self._serve, name="enroll", daemon=True)

    def _status(self, fn, *args) -> None:
        """Best-effort door-status update — observability must never break the
        enrollment path, so swallow everything."""
        if self._data_dir is None:
            return
        try:
            fn(self._data_dir, *args)
        except Exception as e:  # noqa: BLE001
            log.debug("door status update failed: %s", e)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        # Signal the accept loop (which polls with a short timeout, so this is
        # honored within ~1 poll) AND close the socket. Closing alone does not
        # reliably wake a blocked accept() on Linux, so the flag is what makes
        # stop responsive — e.g. when the DoorWatcher clears a consumed window.
        self._stopped.set()
        if self._srv:
            try:
                self._srv.close()
            except Exception:
                pass

    def _serve(self) -> None:
        close_reason = "superseded"   # if we bail before the accept loop
        try:
            srv = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind((HUB_DOOR_IP, ENROLL_PORT))
            srv.listen(1)
            self._srv = srv
            log.info("enroll server ready on [%s]:%d (window %.0fs, up to %d attempt(s))",
                     HUB_DOOR_IP, ENROLL_PORT, self._timeout, self._max_attempts)

            # One shared deadline across all attempts; each accept() waits only
            # for the time still left in the window.
            deadline = time.monotonic() + self._timeout
            attempts_left = self._max_attempts
            success = False
            while attempts_left > 0 and not success and not self._stopped.is_set():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    log.info("enroll window expired")
                    close_reason = "expired"
                    break
                # Poll accept() with a SHORT timeout instead of blocking for the
                # whole window, so stop() / window-consumed is honored promptly
                # (a blocked accept() can't be reliably interrupted by close()).
                srv.settimeout(min(2.0, remaining))
                try:
                    conn, addr = srv.accept()
                except socket.timeout:
                    continue  # re-check stop flag + deadline, then keep waiting
                except OSError:
                    break  # socket closed by stop()
                peer_ip = addr[0]
                log.info("enroll connection from %s", peer_ip)
                with conn:
                    conn.settimeout(30)
                    try:
                        success = self._handle(conn, peer_ip, attempts_left)
                    except Exception as e:
                        log.error("enroll error: %s", e)
                        self._status(door.mark_door_attempt, peer_ip, f"internal: {e}")
                        try:
                            _send_msg(conn, {"v": 1, "ok": False, "error": "internal",
                                             "reason": str(e),
                                             "attempts_remaining": attempts_left - 1})
                        except Exception:
                            pass
                        success = False
                if success:
                    close_reason = "enrolled"
                else:
                    attempts_left -= 1
                    if attempts_left > 0:
                        log.info("enrollment attempt failed; %d attempt(s) left", attempts_left)
                    else:
                        log.info("enrollment attempts exhausted; closing the door")
                        close_reason = "attempts_exhausted"

        except OSError as e:
            if "Errno 9" in str(e) or "closed" in str(e).lower():
                pass  # stopped via stop()
            else:
                log.error("enroll server OSError: %s", e)
        finally:
            self._status(door.mark_door_closed, close_reason)
            if self._srv:
                try:
                    self._srv.close()
                except Exception:
                    pass
            self._on_done()

    def _handle(self, conn: socket.socket, peer_ip: str, attempts_left: int) -> bool:
        """Process one enrollment attempt. Returns True if it succeeded (the
        window should close), False if it was refused (the joiner may retry
        while attempts remain)."""
        import base64
        from . import wg as wgmod
        from .keys import derive_addr

        req = _recv_msg(conn)
        if req.get("v") != 1:
            raise ValueError(f"unsupported version: {req.get('v')}")

        id_pub_bytes = bytes.fromhex(req["id_pub"])
        wg_pub_bytes = base64.b64decode(req["wg_pub"])
        # Hostname: if the hub pinned one at invite, it wins and the joiner's
        # requested name is ignored; otherwise the joiner names itself.
        hostname = self._pinned_hostname or str(req["hostname"])
        # Caps are decided by the hub at `gw invite` and carried in the
        # door window — NOT self-asserted by the joiner. Any caps in the request
        # are ignored; the window's caps are authoritative.
        caps = list(self._caps)

        if len(id_pub_bytes) != 32:
            raise ValueError("id_pub must be 32 bytes")
        if len(wg_pub_bytes) != 32:
            raise ValueError("wg_pub must be 32 bytes")

        # Issue CA-signed credential. A ValueError here is a refusal (revoked
        # id, or hostname already taken) — report it cleanly to the joiner
        # rather than as an internal error.
        try:
            cred = self._ca.issue(id_pub_bytes, wg_pub_bytes, hostname, caps)
        except ValueError as e:
            log.warning("enrollment refused: %s", e)
            self._status(door.mark_door_attempt, peer_ip, str(e))
            _send_msg(conn, {"v": 1, "ok": False, "error": "enrollment refused",
                             "reason": str(e),
                             "attempts_remaining": attempts_left - 1})
            return False

        # Add new node as a peer on the main WG interface so it can establish
        # its tunnel and push its NodeRecord to the hub on first startup.
        overlay_addr = derive_addr(id_pub_bytes)
        wg_pub_b64 = base64.b64encode(wg_pub_bytes).decode()
        wgmod.set_peer(self._wg_iface, wg_pub_b64, overlay_addr)
        log.info("enrolled %s  addr=%s", hostname, overlay_addr)
        self._status(door.mark_door_enrolled, peer_ip, hostname)

        # Send back the credential + hub's own NodeRecord so the new node can
        # pre-seed its directory and configure seeds using the overlay address.
        hub_record = self._directory.get(self._node_keys.id_pub_hex)
        _send_msg(conn, {
            "v": 1,
            "ok": True,
            "credential": cred.to_dict(),
            "hub_record": hub_record.to_dict() if hub_record else None,
            "control_port": self._control_port,
        })

        # Second leg: the node now builds + signs its NodeRecord (it embeds the
        # credential we just issued) and sends it here. We merge it into the
        # directory so the reconcile loop keeps the peer we installed above —
        # this is the bootstrap that used to be a separate POST /publish over
        # the door. Doing it on the door tunnel means the control plane never
        # has to listen on the door interface. Best-effort: a node on older
        # code simply won't send it and falls back to publishing once its
        # overlay tunnel is up.
        from .wire import NodeRecord
        try:
            rec_msg = _recv_msg(conn)
        except Exception:
            # The credential was already issued, the peer installed, and the
            # response sent — enrollment SUCCEEDED. The second leg is best-effort
            # (older nodes skip it; under load the recv may lag), so this is a
            # successful attempt: return True so the window closes, not False
            # (which would wrongly keep the door open for a "retry").
            return True
        try:
            record = NodeRecord.from_dict(rec_msg["record"])
            record.verify(self._get_ca_pubs(), self._get_revoked())
            self._directory.merge([record])
            if self._cache_path is not None:
                self._directory.save(self._cache_path)
            log.info("door-published record for %s", record.hostname)
            _send_msg(conn, {"v": 1, "ok": True})
        except (ValueError, KeyError) as e:
            log.warning("door record publish rejected: %s", e)
            try:
                _send_msg(conn, {"v": 1, "ok": False, "error": str(e)})
            except Exception:
                pass

        # The credential was issued and the peer installed, so the enrollment
        # itself succeeded — the second-leg record publish above is best-effort.
        return True


# ---------------------------------------------------------------------------
# DoorWatcher
# ---------------------------------------------------------------------------

class DoorWatcher:
    """
    Polls data_dir/door_window.json every poll_interval seconds.
    Starts an EnrollServer when a valid window is found; cleans up when it expires.
    """

    def __init__(
        self,
        data_dir: Path,
        ca: "CA",
        directory: "Directory",
        node_keys: "NodeKeys",
        wg_iface: str,
        poll_interval: float = 5.0,
        get_ca_pubs: "Callable[[], list[bytes]] | None" = None,
        get_revoked: "Callable[[], set[str]] | None" = None,
        cache_path: "Path | None" = None,
        control_port: int = 51902,
    ) -> None:
        self._data_dir = data_dir
        self._ca = ca
        self._directory = directory
        self._node_keys = node_keys
        self._wg_iface = wg_iface
        self._poll_interval = poll_interval
        self._get_ca_pubs = get_ca_pubs or (lambda: [])
        self._get_revoked = get_revoked or set
        self._cache_path = cache_path
        self._control_port = control_port
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
        while not self._stop.wait(self._poll_interval):
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
            window_path.unlink(missing_ok=True)
            try:
                door.mark_door_closed(self._data_dir, "expired")
            except Exception as e:  # noqa: BLE001
                log.debug("door status update failed: %s", e)
            return

        with self._lock:
            if self._enroll is not None:
                return  # already running

            remaining = (expires - now).total_seconds()
            # Capture expiry string for the on_done guard below.
            expires_str = data["expires"]
            # Caps the hub authorized at `gw invite` for this window.
            window_caps = data.get("caps") or ["segment:mesh"]
            # Pinned hostname, if the hub set one (`gw invite --hostname`).
            window_hostname = data.get("hostname")

            def on_done():
                # Only delete the window if it still belongs to this session.
                # If gw invite ran again while we were waiting, the new window has
                # a different expiry — leave it so the DoorWatcher can start a
                # fresh EnrollServer for the new token. The DoorWatcher's next
                # tick destroys the (now window-less) gw-door — we deliberately
                # do NOT destroy it here, to avoid racing a fresh invite that may
                # have just recreated the interface.
                try:
                    current = json.loads(window_path.read_text())
                    if current.get("expires") == expires_str:
                        window_path.unlink(missing_ok=True)
                except FileNotFoundError:
                    pass
                except Exception:
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
                get_ca_pubs=self._get_ca_pubs,
                get_revoked=self._get_revoked,
                cache_path=self._cache_path,
                control_port=self._control_port,
                caps=window_caps,
                pinned_hostname=window_hostname,
                data_dir=self._data_dir,
            )
            try:
                door.mark_door_opened(self._data_dir, expires_str, caps=window_caps,
                                      pinned_hostname=window_hostname)
            except Exception as e:  # noqa: BLE001
                log.debug("door status update failed: %s", e)
            srv.start()
            self._enroll = srv
            log.info("door window detected, enroll server started (%.0fs remaining)", remaining)

    def _clear_enroll(self) -> None:
        with self._lock:
            if self._enroll:
                self._enroll.stop()
                self._enroll = None
        _destroy_door()


def _destroy_door() -> None:
    from . import wg as wgmod
    wgmod.destroy_interface(DOOR_IFACE)
