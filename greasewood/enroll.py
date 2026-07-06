"""
greasewood.enroll — TCP enroll server and door-window watcher for the anchor.

EnrollServer
  Binds to [ANCHOR_DOOR_IP]:ENROLL_PORT (only reachable through the door WG tunnel).
  Accepts exactly one connection per door window.  On success: issues a credential,
  adds the new node as a peer on the main WG interface, sends the response, then
  calls on_done() which tears down the door and deletes the window file.

DoorWatcher
  Background thread in gw-run (anchor role only).  Polls data_dir/door_window.json
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
from .door import ENROLL_PORT, ANCHOR_DOOR_IP, DOOR_IFACE

from .loop import Loop

if TYPE_CHECKING:
    from .ca import CA
    from .directory import Directory
    from .keys import NodeKeys

log = logging.getLogger(__name__)
_UTC = dt.timezone.utc
# Wire framing lives in door.py (one definition for server + `gw join` client).
from .door import recv_msg as _recv_msg, send_msg as _send_msg


# ---------------------------------------------------------------------------
# EnrollServer
# ---------------------------------------------------------------------------

class EnrollServer:
    """
    TCP server bound to [ANCHOR_DOOR_IP]:ENROLL_PORT for one door window.

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
        standing: bool = False,
        mesh_domain: "str | None" = None,
    ) -> None:
        # The mesh's canonical name domain, advertised to joiners in the enroll
        # response so every member mounts the mesh under the SAME suffix (and
        # TLS names agree fleet-wide). None → field omitted (older anchors).
        self._mesh_domain = mesh_domain
        # A STANDING door serves any number of enrollments and never closes on
        # its own — no deadline, no attempts-exhausted, success loops back to
        # accept. It ends only via stop() (daemon shutdown, `gw close-door`, or
        # a superseding invite clearing the window).
        self._standing = standing
        self._ca = ca
        self._directory = directory
        self._node_keys = node_keys
        self._wg_iface = wg_iface
        self._on_done = on_done
        self._timeout = timeout_secs
        # Where to persist door status/history for `gw watch` (best-effort;
        # None disables it). Observability only — never blocks enrollment.
        self._data_dir = data_dir
        self._get_ca_pubs = get_ca_pubs or (lambda: [])
        self._get_revoked = get_revoked or set
        self._cache_path = cache_path
        self._control_port = control_port
        self._max_attempts = max_attempts
        # Caps the anchor authorized for this window (from `gw invite`).
        # The joiner does NOT choose these — the window is authoritative.
        self._caps = list(caps) if caps else ["segment:mesh"]
        # If set (`gw invite --hostname`), the anchor pins the name: the joiner's
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
            srv.bind((ANCHOR_DOOR_IP, ENROLL_PORT))
            srv.listen(1)
            self._srv = srv
            if self._standing:
                log.info("enroll server ready on [%s]:%d (STANDING door — serves "
                         "any number of enrollments until closed)",
                         ANCHOR_DOOR_IP, ENROLL_PORT)
            else:
                log.info("enroll server ready on [%s]:%d (window %.0fs, up to %d attempt(s))",
                         ANCHOR_DOOR_IP, ENROLL_PORT, self._timeout, self._max_attempts)

            # One shared deadline across all attempts; each accept() waits only
            # for the time still left in the window. A standing door has neither
            # deadline nor a cumulative attempt budget.
            deadline = None if self._standing else time.monotonic() + self._timeout
            attempts_left = self._max_attempts
            success = False
            while attempts_left > 0 and not success and not self._stopped.is_set():
                if deadline is None:
                    remaining = 2.0
                else:
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
                if self._standing:
                    # Success or failure, the standing door stays open: loop
                    # back to accept. Failures don't accumulate toward a close
                    # (each joiner gets the per-connection budget).
                    if success:
                        log.info("standing door: enrollment complete, staying open")
                    success = False
                    continue
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
        # Hostname: if the anchor pinned one at invite, it wins and the joiner's
        # requested name is ignored; otherwise the joiner names itself.
        hostname = self._pinned_hostname or str(req["hostname"])
        # Caps are decided by the anchor at `gw invite` and carried in the
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
        # Whether this id was registered BEFORE this attempt decides the
        # rollback below: issue() writes the registry entry that claims the
        # hostname, and if the enrollment then fails before the joiner receives
        # its credential, a brand-new registration must be rolled back — or a
        # ghost squats the name and every retry from a fresh identity (a purged
        # and re-joined machine) is refused with "hostname already in use".
        was_registered = self._ca.node_info(id_pub_bytes) is not None
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
        # its tunnel and push its NodeRecord to the anchor on first startup.
        overlay_addr = derive_addr(id_pub_bytes)
        wg_pub_b64 = base64.b64encode(wg_pub_bytes).decode()
        from subprocess import CalledProcessError
        from . import audit
        try:
            with audit.context(f"enroll: +peer {hostname} [{overlay_addr}] from {peer_ip}"):
                wgmod.set_peer(self._wg_iface, wg_pub_b64, overlay_addr)
        except CalledProcessError:
            # Almost always: the mesh interface is gone (a purge/re-create ran
            # under this daemon). Tell the joiner something actionable, not a
            # raw command dump. The reconcile loop self-heals the interface
            # within one cycle, so an immediate retry usually succeeds; an anchor
            # restart is the fallback.
            # Roll back a registration this failed attempt created: the joiner
            # never received the credential, so the entry only squats the
            # hostname (field bug: a re-keyed retry got "hostname already in
            # use" from its own failed first attempt). A pre-existing
            # registration (re-enroll of a known id) is left alone.
            if not was_registered:
                try:
                    self._ca.forget_node(id_pub_bytes)
                except Exception as e:  # noqa: BLE001
                    log.warning("rollback of failed enrollment failed: %s", e)
            reason = (f"the anchor could not add you as a WireGuard peer — its mesh "
                      f"interface {self._wg_iface!r} is missing or broken. It "
                      f"should self-heal within seconds: retry this token. If it "
                      f"keeps failing, restart the anchor daemon and retry.")
            log.error("enroll: peer install on %s failed for %s", self._wg_iface, hostname)
            self._status(door.mark_door_attempt, peer_ip,
                         f"peer install failed: {self._wg_iface} missing/broken")
            _send_msg(conn, {"v": 1, "ok": False, "error": "anchor data-plane failure",
                             "reason": reason,
                             "attempts_remaining": attempts_left - 1})
            return False
        log.info("enrolled %s  addr=%s", hostname, overlay_addr)
        self._status(door.mark_door_enrolled, peer_ip, hostname)

        # Send back the credential + anchor's own NodeRecord so the new node can
        # pre-seed its directory and configure seeds using the overlay address.
        anchor_record = self._directory.get(self._node_keys.id_pub_hex)
        reply = {
            "v": 1,
            "ok": True,
            "credential": cred.to_dict(),
            "anchor_record": anchor_record.to_dict() if anchor_record else None,
            "control_port": self._control_port,
        }
        if self._mesh_domain:
            reply["mesh_domain"] = self._mesh_domain
        _send_msg(conn, reply)

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

class DoorWatcher(Loop):
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
        door_port: "int | None" = None,
        mesh_domain: "str | None" = None,
    ) -> None:
        # Needed to re-erect the door interface for a STANDING window after a
        # anchor reboot (the window persists; the kernel interface doesn't).
        self._door_port = door_port
        # Advertised to joiners so the whole mesh shares one name domain.
        self._mesh_domain = mesh_domain
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
        super().__init__(poll_interval, "door-watcher")

    # run()/start() come from Loop; stop() also downs the live enroll server.
    def stop(self) -> None:
        super().stop()
        with self._lock:
            if self._enroll:
                self._enroll.stop()

    def _tick(self) -> None:
        window_path = self._data_dir / "door_window.json"

        if not window_path.exists():
            self._clear_enroll()
            return

        try:
            data = json.loads(window_path.read_text())
            standing = bool(data.get("standing"))
            expires = None if standing else \
                dt.datetime.fromisoformat(data["expires"].replace("Z", "+00:00"))
        except Exception as e:
            log.debug("door_window.json unreadable: %s", e)
            return

        now = dt.datetime.now(_UTC)
        if expires is not None and now >= expires:
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

            # A standing window persists across anchor reboots, but the door
            # interface is kernel state and doesn't — re-erect it from the
            # keys the window carries before serving.
            if standing and data.get("guest_pub") and data.get("psk"):
                from . import wg as wgmod
                if not wgmod.interface_exists(DOOR_IFACE):
                    log.info("standing door: re-erecting %s", DOOR_IFACE)
                    try:
                        from . import audit
                        with audit.context("standing door: re-erect after reboot"):
                            wgmod.ensure_anchor_door_interface(
                                self._data_dir / "door.key", data["guest_pub"],
                                data["psk"], self._door_port)
                    except Exception as e:
                        log.error("standing door: could not re-erect %s: %s — "
                                  "will retry next tick", DOOR_IFACE, e)
                        return

            remaining = None if standing else (expires - now).total_seconds()
            # Capture expiry string for the on_done guard below.
            expires_str = data.get("expires")
            # Caps the anchor authorized at `gw invite` for this window.
            window_caps = data.get("caps") or ["segment:mesh"]
            # Pinned hostname, if the anchor set one (`gw invite --hostname`).
            window_hostname = data.get("hostname")

            def on_done():
                # Only delete the window if it still belongs to this session.
                # If gw invite ran again while we were waiting, the new window has
                # a different expiry — leave it so the DoorWatcher can start a
                # fresh EnrollServer for the new token. The DoorWatcher's next
                # tick destroys the (now window-less) gw-door — we deliberately
                # do NOT destroy it here, to avoid racing a fresh invite that may
                # have just recreated the interface.
                # A STANDING window is never deleted here: its server exits only
                # on daemon shutdown / close-door / supersede, and the window
                # must survive (it's what re-opens the door on the next boot).
                if not standing:
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
                log.info("standing door: enroll server stopped" if standing
                         else "door enrollment complete, window closed")

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
                standing=standing,
                mesh_domain=self._mesh_domain,
            )
            try:
                door.mark_door_opened(self._data_dir, expires_str, caps=window_caps,
                                      pinned_hostname=window_hostname,
                                      standing=standing)
            except Exception as e:  # noqa: BLE001
                log.debug("door status update failed: %s", e)
            srv.start()
            self._enroll = srv
            if standing:
                log.info("standing door window detected, enroll server started")
            else:
                log.info("door window detected, enroll server started (%.0fs remaining)",
                         remaining)

    def _clear_enroll(self) -> None:
        with self._lock:
            if self._enroll:
                self._enroll.stop()
                self._enroll = None
        _destroy_door()


def _destroy_door() -> None:
    from . import wg as wgmod
    wgmod.destroy_interface(DOOR_IFACE)
