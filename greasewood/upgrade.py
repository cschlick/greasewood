"""
greasewood.upgrade — acting on the fleet's CA-signed release announcements.

`gw upgrade-all` on a holder mints one `upgrade` AnchorStatement: the release
version plus the sha256 of its published tarball, CA-signed. It rides the
ordinary statement gossip, so it reaches every node on its next directory
pull and an offline node when it returns — a level, not a push. This module
is the node side: the UpgradeManager the daemon feeds each pull's newest
hint.

The trust design, deliberately narrow:

  * OPT-IN. `auto_upgrade = true` under [network]; default off. Off, the
    announcement only surfaces in `gw watch` and the log. With it on, whoever
    holds the anchor file can cause this node to install a release they pin —
    that sentence is the whole threat-model delta, and the operator chooses it.
  * PINNED. The node downloads the announced tarball itself and verifies its
    sha256 against the CA-signed statement before anything is touched. The
    signal cannot express "run this code" — only "install this specific
    published artifact", which is *stronger* than a manual `gw upgrade` (that
    trusts whatever the package index serves at the moment).
  * PULL, fetch-first. The tarball lands on local disk (under data_dir — /tmp
    is restricted on confined hosts) and is verified before the uninstall, so
    a network failure or a bad hash aborts with the node untouched — the same
    ordering `gw upgrade --from github` learned in the field.

Scope: the auto path manages pipx installs on Linux (the fleet case). A brew
Mac, a distro package, or a dev checkout logs the announcement and leaves the
install to the operator. The announcing holder is the natural canary: the
operator upgraded it by hand to run `gw upgrade-all` at all.
"""
from __future__ import annotations

import hashlib
import logging
import os
import random
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

log = logging.getLogger(__name__)

RELEASE_URL = "https://github.com/cschlick/greasewood/archive/refs/tags/v{version}.tar.gz"

# Jitter before acting, so a ten-node fleet doesn't hit GitHub (or restart)
# in the same second. Uniform, not size-scaled like the renew spread: the
# download is against GitHub, not the anchor, so fleet size doesn't
# concentrate load anywhere greasewood must protect.
_JITTER_RANGE = (5.0, 300.0)
# After a failed attempt, don't re-try the same announcement before this.
_RETRY_AFTER = 3600.0


def running_version() -> str:
    """The installed greasewood version, read from dist metadata each call —
    so a completed reinstall (by this manager or a racing manual upgrade) is
    visible without a restart."""
    try:
        from importlib.metadata import version
        return version("greasewood")
    except Exception:
        return "0.0.0+unknown"


def version_tuple(v: str) -> tuple:
    """'0.7.0' → (0, 7, 0), tolerant of local suffixes ('0.7.0+dirty').
    Non-numeric parts end the tuple, so comparisons stay well-defined."""
    out = []
    for part in v.split("+", 1)[0].split("."):
        if not part.isdigit():
            break
        out.append(int(part))
    return tuple(out)


def is_newer(target: str, running: str) -> bool:
    return version_tuple(target) > version_tuple(running)


def fetch_release(version: str, dest_dir: Path, timeout: float = 120.0) -> Path:
    """Download the announced release tarball to local disk. Raises on any
    HTTP failure — nothing has been touched yet, so failure costs nothing."""
    url = RELEASE_URL.format(version=version)
    dest = Path(dest_dir) / f"greasewood-{version}.tar.gz"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp, \
                open(dest, "wb") as f:
            shutil.copyfileobj(resp, f)
    except urllib.error.URLError as e:
        raise RuntimeError(f"download of {url} failed: {e}") from e
    return dest


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _pipx_env():
    """(PIPX_HOME, PIPX_BIN_DIR) of THIS install, or None when greasewood
    isn't pipx-managed. Late import: greasewood.cli is a heavy package and
    fully loaded by the time a hint can arrive."""
    from .cli import svc
    return svc._pipx_install_env()


def _self_restart(key: str) -> bool:
    """Restart this mesh's daemon FROM INSIDE the daemon. systemd gets
    `--no-block`: a blocking restart would SIGTERM the very process waiting
    on it; queuing the job and letting systemd replace us is the clean path.
    Other backends get restart_now in a detached session, which survives the
    daemon's own termination. Returns False when there's no manager (the
    operator restarts by hand; the install already succeeded)."""
    from .cli import svc
    mgr = svc._service_backend()
    if mgr is None:
        return False
    if getattr(mgr, "name", "") == "systemd":
        subprocess.Popen(["systemctl", "--no-block", "restart",
                          mgr.unit_name(key)])
        return True
    subprocess.Popen([sys.executable, "-c",
                      "from greasewood.cli import svc; "
                      f"svc._service_backend().restart_now({key!r})"],
                     start_new_session=True)
    return True


class UpgradeManager:
    """Decides whether and when to act on the newest upgrade announcement.
    `offer(stmt)` is called by the sync loop after every successful pull (a
    level: the same hint arrives repeatedly); everything else is internal."""

    def __init__(self, cfg, mesh_key: str,
                 get_version=running_version,
                 pipx_env=_pipx_env,
                 restart=_self_restart) -> None:
        self._cfg = cfg
        self._key = mesh_key
        self._get_version = get_version   # injectable seams for the tests
        self._pipx_env = pipx_env
        self._restart = restart
        self._lock = threading.Lock()
        self._timer: "threading.Timer | None" = None
        self._noted_ts = None             # hint we already logged about
        self._failed_ts = None            # hint whose attempt failed...
        self._retry_at = 0.0              # ...and when it may be retried

    def offer(self, stmt) -> None:
        """Consider the newest announcement. Cheap and re-entrant — called
        once per sync pull."""
        target = stmt.upgrade.get("version", "")
        sha = stmt.upgrade.get("sha256", "")
        if not target or not sha:
            return
        if not is_newer(target, self._get_version()):
            return
        if not getattr(self._cfg, "auto_upgrade", False):
            self._note_once(stmt.ts, "release v%s announced for the fleet — "
                            "auto_upgrade is off; install with: sudo gw upgrade",
                            target)
            return
        from . import platform as gwplat
        if gwplat.IS_MACOS:
            self._note_once(stmt.ts, "release v%s announced — auto_upgrade "
                            "manages pipx installs only; on macOS run: "
                            "brew upgrade greasewood", target)
            return
        if self._pipx_env() is None:
            self._note_once(stmt.ts, "release v%s announced — this greasewood "
                            "isn't pipx-managed, upgrade it by hand", target)
            return
        with self._lock:
            if self._timer is not None:
                return                    # an attempt is already scheduled
            if stmt.ts == self._failed_ts and time.monotonic() < self._retry_at:
                return                    # failed recently; back off
            delay = random.uniform(*_JITTER_RANGE)
            log.info("release v%s announced (auto_upgrade on) — installing "
                     "in %.0fs", target, delay)
            self._timer = threading.Timer(
                delay, self._attempt, args=(stmt.ts, target, sha))
            self._timer.daemon = True
            self._timer.start()

    def _note_once(self, ts, msg: str, *args) -> None:
        with self._lock:
            if self._noted_ts == ts:
                return
            self._noted_ts = ts
        log.info(msg, *args)

    def _attempt(self, ts, target: str, sha: str) -> None:
        try:
            self._upgrade(target, sha)
        except Exception:
            log.exception("auto-upgrade to v%s failed — retrying in about an "
                          "hour (or run: sudo gw upgrade)", target)
            with self._lock:
                self._failed_ts = ts
                self._retry_at = time.monotonic() + _RETRY_AFTER
        finally:
            with self._lock:
                self._timer = None

    def _upgrade(self, target: str, sha: str) -> None:
        from . import audit
        if not is_newer(target, self._get_version()):
            return                        # a manual upgrade raced us — done
        env = self._pipx_env()
        if env is None:
            return
        home, bin_dir = env
        pipx_env = {"PIPX_HOME": str(home), "PIPX_BIN_DIR": str(bin_dir)}

        # Sweep leftovers from earlier failed attempts (kept on failure so
        # their recovery message stays actionable), then fetch + verify BEFORE
        # anything is uninstalled: a network failure or a hash mismatch must
        # leave the node untouched.
        for stale in Path(self._cfg.data_dir).glob("gw-autoupgrade-*"):
            shutil.rmtree(stale, ignore_errors=True)
        workdir = Path(tempfile.mkdtemp(prefix="gw-autoupgrade-",
                                        dir=self._cfg.data_dir))
        try:
            tarball = fetch_release(target, workdir)
            digest = sha256_file(tarball)
        except Exception:
            shutil.rmtree(workdir, ignore_errors=True)   # nothing was touched
            raise
        if digest != sha:
            shutil.rmtree(workdir, ignore_errors=True)
            raise RuntimeError(
                f"release tarball hash mismatch (got {digest}, announcement "
                f"pins {sha}) — refusing to install")

        # From here the uninstall window is open; on failure the verified
        # tarball is KEPT so the logged recovery command points at a real file.
        run_env = {**os.environ, **pipx_env}
        uninstall = ["pipx", "uninstall", "greasewood"]
        install = ["pipx", "install", str(tarball)]
        for step in (uninstall, install):
            r = subprocess.run(step, env=run_env, capture_output=True,
                               text=True)
            if r.returncode != 0:
                prefix = " ".join(f"{k}={v}" for k, v in pipx_env.items())
                raise RuntimeError(
                    f"'{' '.join(step)}' failed (exit {r.returncode}): "
                    f"{(r.stderr or r.stdout).strip()}\n"
                    f"greasewood may be uninstalled — recover with: "
                    f"sudo {prefix} pipx install {tarball}")
        audit.event("auto-upgrade", version=target, sha256=sha[:16])
        log.info("installed greasewood v%s (hash verified against the "
                 "announcement) — restarting the daemon", target)
        if not self._restart(self._key):
            log.warning("no service manager found — restart the daemon by "
                        "hand to run v%s", target)
        shutil.rmtree(workdir, ignore_errors=True)
