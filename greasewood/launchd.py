"""
greasewood.launchd — the macOS service supervisor (the systemd counterpart).

Linux runs the daemon under a systemd template unit (greasewood@<key>). macOS
has launchd: one plist per membership at
/Library/LaunchDaemons/com.greasewood.<key>.plist (LaunchDaemons = system
domain, runs as root at boot — the daemon needs root for utun/routes, same as
Linux). create/join install it, purge removes it; no separate command.

Semantics matched to the systemd unit:
  - starts at boot (RunAtLoad) and restarts on crash but NOT on clean exit
    (KeepAlive.SuccessfulExit=false ≙ Restart=on-failure),
  - an explicit PATH including the Homebrew prefixes — launchd jobs get a
    minimal environment, and wireguard-go/wg live under /opt/homebrew (arm) or
    /usr/local (intel),
  - logs to /var/log/greasewood/<key>.log (launchd has no journal; the audit
    trail is separate and unchanged in <data_dir>/audit.log).

Install uses the modern bootstrap/bootout verbs and then SETTLE-CHECKS —
launchctl reports success the moment the job is loaded, so like the systemd
path we verify the process actually reaches and holds a running state before
telling the operator it's up.
"""
from __future__ import annotations

import logging
import os
import plistlib
import shutil
import subprocess
import sys
import time
from pathlib import Path

from . import platform as gwplat

log = logging.getLogger(__name__)

LAUNCHD_DIR = Path("/Library/LaunchDaemons")
LOG_DIR = Path("/var/log/greasewood")

# launchd strips the environment; the daemon shells out to wireguard-go / wg /
# ifconfig / route, so hand it the standard prefixes plus both Homebrew homes.
_PATH = "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"


def label(key: str) -> str:
    """The launchd job label for one membership: com.greasewood.<key>."""
    return f"com.greasewood.{key}"


def plist_path(key: str) -> Path:
    return LAUNCHD_DIR / f"{label(key)}.plist"


def available() -> bool:
    """launchd management is possible: macOS with launchctl on PATH."""
    return gwplat.IS_MACOS and shutil.which("launchctl") is not None


def render_plist(key: str, cfg_path, gw_exec: str) -> bytes:
    """The LaunchDaemon plist for one membership, as plist XML bytes."""
    return plistlib.dumps({
        "Label": label(key),
        "ProgramArguments": [gw_exec, "-c", str(cfg_path), "run"],
        "RunAtLoad": True,                       # start at boot
        "KeepAlive": {"SuccessfulExit": False},  # restart on crash, not clean exit
        "EnvironmentVariables": {"PATH": _PATH},
        "StandardOutPath": str(LOG_DIR / f"{key}.log"),
        "StandardErrorPath": str(LOG_DIR / f"{key}.log"),
        "ThrottleInterval": 5,                   # crash-loop backoff (secs)
    }, sort_keys=False)


def _launchctl(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["launchctl", *args], capture_output=True, text=True)


def _is_running(key: str) -> bool:
    """Is the job's process actually running (not merely loaded)? `launchctl
    print` shows `state = running` for a live job."""
    r = _launchctl("print", f"system/{label(key)}")
    return r.returncode == 0 and "state = running" in (r.stdout or "")


def install(key: str, cfg_path, gw_exec: "str | None" = None) -> str:
    """Write the plist and (re)bootstrap the job. Returns the same states the
    systemd path reports: 'active' (came up and stayed up), 'failed' (loaded
    but not running — likely crashing), or 'manual' (couldn't manage launchd
    here — caller prints the `gw run` line)."""
    if not available():
        return "manual"
    gw_exec = gw_exec or shutil.which("gw") or os.path.realpath(sys.argv[0])
    try:
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        LAUNCHD_DIR.mkdir(parents=True, exist_ok=True)
        p = plist_path(key)
        p.write_bytes(render_plist(key, cfg_path, gw_exec))
        p.chmod(0o644)                    # launchd requires root:wheel 0644
    except OSError as e:
        log.warning("could not write %s: %s", plist_path(key), e)
        return "manual"

    # Re-bootstrap: bootout first (idempotent — fine if it wasn't loaded), so a
    # reinstall or config change always picks up the fresh plist. bootout is
    # ASYNCHRONOUS — bootstrapping the same label before the old job finishes
    # unloading fails with "Bootstrap failed: 5: Input/output error", so wait
    # for the label to actually disappear, then retry a couple of times in case
    # it's still settling. (This bites exactly on a reinstall / re-join.)
    _launchctl("bootout", f"system/{label(key)}")
    unload_deadline = time.monotonic() + 5.0
    while (time.monotonic() < unload_deadline
           and _launchctl("print", f"system/{label(key)}").returncode == 0):
        time.sleep(0.3)
    r = None
    for attempt in range(4):
        r = _launchctl("bootstrap", "system", str(plist_path(key)))
        if r.returncode == 0:
            break
        time.sleep(1.0)                   # still unloading → back off and retry
    if r is None or r.returncode != 0:
        log.warning("launchctl bootstrap failed after retries: %s",
                    (r.stderr or r.stdout or "").strip() if r else "no attempt")
        return "manual"

    # Settle: reach running, then STILL be running after the fast-crash window
    # (mirrors the systemd path — a job that execs and dies "started" too).
    deadline = time.monotonic() + 6.0
    while not _is_running(key) and time.monotonic() < deadline:
        time.sleep(0.5)
    if not _is_running(key):
        return "failed"
    time.sleep(2.0)
    return "active" if _is_running(key) else "failed"


def remove(key: str) -> bool:
    """Stop the job and remove its plist (purge / rename). True if anything
    was actually removed. Idempotent."""
    removed = False
    if shutil.which("launchctl"):
        r = _launchctl("bootout", f"system/{label(key)}")
        removed = r.returncode == 0
    p = plist_path(key)
    if p.exists():
        try:
            p.unlink()
            removed = True
        except OSError as e:
            log.warning("could not remove %s: %s", p, e)
    return removed
