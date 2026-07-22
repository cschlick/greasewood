"""
greasewood.service — OS service backend for the greasewood daemon.

`gw run` is a long-lived root process; on a normal host the init system
supervises it as a per-mesh service (greasewood@<mesh> under systemd). This
module is the seam between greasewood and that init system: a `ServiceManager`
interface with one implementation per init system, and a `detect()` that picks
the right backend for the host — or returns None, meaning no supported init
system is managing services here and the operator supervises `gw run`
themselves (the long-standing "manual" path).

Step 1 ships the systemd backend only, lifted verbatim from cli.py so behaviour
and the existing tests are unchanged. OpenRC (for Alpine and other non-systemd
hosts) is a second implementation of this same interface; the goal is that
`gw join` on such a host installs + enables a native service with no manual
init-script writing, exactly as it does under systemd today.

cli.py keeps thin `_name` wrappers around these functions so its monkeypatch
seams (the injectable `run` / `settle` / exec callables) still resolve — the
composition primitives live here, the wrappers there.
"""
from __future__ import annotations

import logging
import os
import shutil
import subprocess
import sys
import time
from abc import ABC, abstractmethod
from pathlib import Path

log = logging.getLogger(__name__)

# The greasewood@ template unit. ONE file serves every mesh membership as
# greasewood@<name> (%i = the mesh name). Kept byte-for-byte in sync with the
# committed systemd/greasewood@.service (test_units guards the match).
SYSTEMD_UNIT = """\
[Unit]
Description=greasewood mesh daemon (%i)
Documentation=https://github.com/cschlick/greasewood
After=network-online.target
Wants=network-online.target
# Only run once this membership is configured (create / join writes it).
ConditionPathExists=/etc/greasewood_%i.toml
# Bound the restart loop. Without this, RestartSec=5 never fills systemd's
# default 10s start-limit window (restarts are 5s apart), so a daemon that can't
# start loops FOREVER, invisibly. 5 failures within 2min instead trips the limit
# → the unit enters a visible `failed` state (systemctl status, and gw watch's
# daemon heartbeat goes stale) instead of thrashing silently.
StartLimitIntervalSec=120
StartLimitBurst=5

[Service]
Type=simple
# gw run creates WireGuard interfaces and edits routing → runs as root.
ExecStart={exec} -c /etc/greasewood_%i.toml run
# always, not on-failure: a mesh daemon down is a node silently rotting toward
# credential expiry, whatever stopped it. Seen in the field: a stray
# `sudo killall python` cleanly SIGTERM'd the daemon, on-failure (correctly)
# ignored the clean exit, and the node spent 20h dying politely. Restart=
# never overrides an explicit `systemctl stop`, so deliberate stops still stick.
Restart=always
RestartSec=5
# Liveness watchdog: gw run pings WATCHDOG=1 after every successful reconcile
# (~5s cadence). A daemon that is alive but no longer reconciling — wedged in
# a way no process supervisor can see — misses its pings and is killed +
# restarted after 120s. Pings are a no-op running outside systemd.
WatchdogSec=120
NotifyAccess=main

# --- sandboxing ---------------------------------------------------------
# The daemon runs as root only for CAP_NET_ADMIN (WireGuard + routing). It
# shells out to ip/wg/nft and, when hosts_sync is on, rewrites /etc/hosts.
# These directives keep an RCE in the daemon from owning the host, without
# breaking any of that. Deliberately NOT set:
#   ProtectSystem=strict/full — the daemon writes /etc/hosts (+ its temp and
#     lock siblings in /etc); strict would EROFS them. 'yes' still makes
#     /usr + /boot read-only.
#   ProtectKernelModules — `ip link add type wireguard` may autoload the
#     module on first use; blocking that would break interface creation.
NoNewPrivileges=yes
CapabilityBoundingSet=CAP_NET_ADMIN
ProtectSystem=yes
ProtectHome=yes
PrivateTmp=yes
ProtectControlGroups=yes
ProtectKernelTunables=yes
ProtectClock=yes
RestrictSUIDSGID=yes
RestrictRealtime=yes
RestrictNamespaces=yes
LockPersonality=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_NETLINK AF_UNIX
SystemCallArchitectures=native

[Install]
WantedBy=multi-user.target
"""

# Where the systemd units live. A default so tests can redirect it per-call.
SYSTEMD_UNIT_DIR = Path("/etc/systemd/system")
SYSTEMCTL_TIMEOUT = 30


def systemctl_run(argv, *, timeout: float = SYSTEMCTL_TIMEOUT,
                  **kwargs) -> subprocess.CompletedProcess:
    """Run a systemctl (or any) command with a hard timeout. A wedged systemd
    (stuck jobs / dead D-Bus) used to block the CLI forever — at its worst on
    the final daemon-reload of a SUCCESSFUL join. On timeout, hand back rc=124
    so callers fall through to their manual-guidance paths."""
    try:
        return subprocess.run(argv, timeout=timeout, **kwargs)
    except subprocess.TimeoutExpired:
        log.warning("'%s' gave no answer in %ss — systemd looks wedged "
                    "(check: systemctl list-jobs). Skipping it; run it "
                    "yourself once systemd recovers.",
                    " ".join(argv), timeout)
        return subprocess.CompletedProcess(argv, 124, "", "")


def service_exec() -> str:
    """The exec line the daemon service runs.

    Prefer `<abs-interpreter> -m greasewood` over the `gw` console-script path.
    The interpreter that ran `gw create` is where the package is installed, and
    its absolute path survives the things that MOVE the wrapper — a venv rebuilt
    at the same path, a pyenv version switch, a `pip install --upgrade` that
    regenerates the console script — so the baked ExecStart can't dangle into a
    203/EXEC (the failure that made a bare `pip install` unsafe for daemon use
    and drove the fixed /opt/greasewood venv). `-m greasewood` finds the package
    in that interpreter's own site-packages, so it needs no `gw` on PATH at all.
    Falls back to the gw path only if sys.executable is unset (frozen/embedded)."""
    if sys.executable:
        return f"{sys.executable} -m greasewood"
    return shutil.which("gw") or os.path.realpath(sys.argv[0])


def systemd_available() -> bool:
    """True only when this host is actually running systemd — `systemctl` on
    PATH AND /run/systemd/system present (the canonical sd_booted() check). A
    container with systemctl installed but `sleep` as PID 1 returns False, so
    create/join fall back to the manual `gw run` line instead of crashing on a
    systemctl that can't reach a manager."""
    return shutil.which("systemctl") is not None and Path("/run/systemd/system").is_dir()


def write_systemd_unit(unit_dir: Path, exec_path: str, *,
                       run=None) -> "str | None":
    """Write the greasewood@ template unit (idempotent) and daemon-reload.
    Returns the systemctl path (None if this host has no systemd)."""
    run = run or systemctl_run            # resolve at call time (monkeypatchable)
    unit_dir.mkdir(parents=True, exist_ok=True)
    (unit_dir / "greasewood@.service").write_text(SYSTEMD_UNIT.format(exec=exec_path))
    systemctl = shutil.which("systemctl")
    if systemctl:
        run([systemctl, "daemon-reload"], check=False)
    return systemctl


def refresh_systemd_unit(unit_dir: Path, desired_exec: str, *,
                         run=None) -> bool:
    """Daemon-startup self-heal for the unit template: upgrades ship unit
    improvements (Restart=always, the watchdog, …), but the installed
    greasewood@.service is only written at create/join — so without this an
    existing mesh would NEVER pick them up. If a template is installed and its
    text differs from this version's, rewrite it + daemon-reload (safe mid-run;
    applies from each instance's next restart). Never installs a template where
    none exists — a host running `gw run` by hand stays unmanaged. Returns True
    if it refreshed."""
    tmpl = unit_dir / "greasewood@.service"
    try:
        if not tmpl.exists():
            return False
        if tmpl.read_text() == SYSTEMD_UNIT.format(exec=desired_exec):
            return False
        write_systemd_unit(unit_dir, desired_exec, run=run)
        log.info("systemd unit template updated to this greasewood version "
                 "(greasewood@.service) — applies from each instance's next restart")
        return True
    except OSError as e:
        log.debug("could not refresh the unit template: %s", e)
        return False


def wait_systemd_settled(systemctl: str, unit: str, wait_secs: float = 6.0, *,
                         run=None) -> str:
    """Wait for `unit` to reach 'active' and STAY there briefly; return the
    final is-active state ('active', 'activating', 'failed', ...). A unit that
    execs and crashes within a couple of seconds flaps active→activating
    (auto-restart) — the settle re-check catches exactly that."""
    run = run or systemctl_run
    def _state() -> str:
        r = run([systemctl, "is-active", unit], capture_output=True, text=True)
        return (r.stdout or "").strip()

    deadline = time.monotonic() + wait_secs
    state = _state()
    while state != "active" and time.monotonic() < deadline:
        time.sleep(0.5)
        state = _state()
    if state == "active":
        time.sleep(2.0)          # survive the fast-crash window
        state = _state()
    return state


def enable_systemd_now(unit_dir: Path, key: str, *,
                       run=None, settle=None) -> str:
    """Enable this membership's daemon as greasewood@<key> — an instance of the
    template unit. Returns 'active' (came up and stayed up), 'failed' (crashed
    at/after start), or 'manual' (no systemd management here — caller prints the
    gw run line).

    The settle-check matters: Type=simple reports the start job done the instant
    the process execs, so `enable --now` "succeeds" even for a daemon that
    crashes a second later. We verify it reaches AND holds 'active' before
    telling the operator it's up."""
    run = run or systemctl_run
    if settle is None:
        settle = lambda sc, u: wait_systemd_settled(sc, u, run=run)
    unit = f"greasewood@{key}.service"
    systemctl = shutil.which("systemctl")
    if not systemctl or not (unit_dir / "greasewood@.service").exists():
        return "manual"
    r = run([systemctl, "is-active", "--quiet", unit], capture_output=True)
    if r.returncode == 0:
        return "active"
    r = run([systemctl, "enable", "--now", unit], capture_output=True)
    if r.returncode != 0:
        return "manual"            # systemctl present but no live manager → manual
    return settle(systemctl, unit)


# ===========================================================================
# OpenRC backend (Alpine and other non-systemd hosts)
# ===========================================================================
#
# OpenRC has no template units. The idiom for many instances of one service is
# a symlink to the base init script — /etc/init.d/greasewood.<mesh> -> greasewood
# — from which OpenRC sets RC_SVCNAME and the script derives the mesh name (cf.
# net.<iface>). supervise-daemon respawns on death (Restart=always); a wedged-
# but-alive daemon self-exits via WedgeWatchdog (there's no NOTIFY_SOCKET here),
# so death + wedge are both covered without an init-system-specific healthcheck.
#
# NOT reproducible on OpenRC: the systemd unit's exec sandbox (CAP_NET_ADMIN
# bounding, ProtectSystem, RestrictAddressFamilies, syscall filters). The OpenRC
# daemon therefore runs as unconfined root — a real posture difference the
# operator-facing surface should state plainly, not hide.

OPENRC_INIT_DIR = Path("/etc/init.d")

# @COMMAND@ / @ARGS@ are substituted (not str.format — the script is full of
# shell ${...} braces). @ARGS@ is "" for a bare `gw`, "-m greasewood " for the
# interpreter-module launch form.
OPENRC_SCRIPT = r"""#!/sbin/openrc-run
# greasewood mesh daemon. ONE script serves every mesh membership: a symlink
# /etc/init.d/greasewood.<mesh> -> greasewood, from which OpenRC sets RC_SVCNAME
# and we derive the mesh name (the multi-instance idiom, cf. net.<iface>).
# Installed and kept in sync by greasewood's OpenRC service backend.
#
# supervise-daemon respawns the daemon if it dies; a daemon that is alive but
# wedged self-exits via greasewood's own watchdog (there's no systemd notify
# socket here), so this one script covers BOTH death and wedge — the OpenRC
# analog of Restart=always + WatchdogSec. respawn_max/period mirror the systemd
# unit's StartLimitBurst/IntervalSec so a crash-loop gives up instead of
# thrashing forever.

mesh="${RC_SVCNAME#greasewood.}"
description="greasewood mesh daemon (${mesh})"

command="@COMMAND@"
command_args="@ARGS@-c /etc/greasewood_${mesh}.toml run"
supervisor=supervise-daemon
respawn_delay=5
respawn_max=5
respawn_period=120
pidfile="/run/greasewood.${mesh}.pid"

depend() {
	need net
	after firewall
}

start_pre() {
	if [ "${RC_SVCNAME}" = "greasewood" ]; then
		eerror "start greasewood.<mesh>, not the base 'greasewood' service"
		return 1
	fi
	if [ ! -f "/etc/greasewood_${mesh}.toml" ]; then
		eerror "no config at /etc/greasewood_${mesh}.toml — run 'gw create' or 'gw join' first"
		return 1
	fi
}
"""


def rc_run(argv, *, timeout: float = SYSTEMCTL_TIMEOUT,
           **kwargs) -> subprocess.CompletedProcess:
    """rc-service / rc-update with the same hard timeout guard as systemctl_run,
    so a stuck OpenRC can't hang the CLI. rc=124 on timeout → manual fallback."""
    try:
        return subprocess.run(argv, timeout=timeout, **kwargs)
    except subprocess.TimeoutExpired:
        log.warning("'%s' gave no answer in %ss — OpenRC looks stuck; skipping "
                    "it, run it yourself once it recovers.",
                    " ".join(argv), timeout)
        return subprocess.CompletedProcess(argv, 124, "", "")


def openrc_available() -> bool:
    """True only when OpenRC is actually managing services here — rc-service +
    rc-update on PATH AND /run/openrc present (OpenRC's booted marker, the
    analog of systemd's /run/systemd/system). A host with the binaries but a
    different init returns False, so we fall back to the manual `gw run` line."""
    return (shutil.which("rc-service") is not None
            and shutil.which("rc-update") is not None
            and Path("/run/openrc").is_dir())


def render_openrc_script(exec_path: str) -> str:
    """The init-script text for a given daemon launch command. Splits the launch
    line into command + args (`/opt/py/bin/python3 -m greasewood` →
    command=/opt/py/bin/python3, args prefix `-m greasewood `)."""
    command, _, rest = exec_path.partition(" ")
    args = f"{rest} " if rest else ""
    return OPENRC_SCRIPT.replace("@COMMAND@", command).replace("@ARGS@", args)


def write_openrc_script(init_dir: Path, exec_path: str) -> "str | None":
    """Write the base /etc/init.d/greasewood script (idempotent, chmod 0755).
    Returns the rc-service path (None if OpenRC's tools aren't present)."""
    init_dir.mkdir(parents=True, exist_ok=True)
    script = init_dir / "greasewood"
    script.write_text(render_openrc_script(exec_path))
    try:
        os.chmod(script, 0o755)
    except OSError:
        pass
    return shutil.which("rc-service")


def refresh_openrc_script(init_dir: Path, desired_exec: str) -> bool:
    """Self-heal an installed base script to this version's text. Never installs
    one where none exists (a host running `gw run` by hand stays unmanaged).
    No reload needed — supervise-daemon picks it up on the next restart."""
    script = init_dir / "greasewood"
    try:
        if not script.exists():
            return False
        if script.read_text() == render_openrc_script(desired_exec):
            return False
        write_openrc_script(init_dir, desired_exec)
        log.info("OpenRC service script updated to this greasewood version "
                 "(/etc/init.d/greasewood) — applies from each instance's next restart")
        return True
    except OSError as e:
        log.debug("could not refresh the OpenRC script: %s", e)
        return False


def wait_openrc_started(svc: str, wait_secs: float = 6.0, *, run=None) -> str:
    """Wait for `svc` to reach AND hold 'started' (rc-service status rc=0); the
    OpenRC analog of the systemd settle re-check. Returns 'active' / 'failed'."""
    run = run or rc_run

    def _started() -> bool:
        return run(["rc-service", svc, "status"], capture_output=True).returncode == 0

    deadline = time.monotonic() + wait_secs
    ok = _started()
    while not ok and time.monotonic() < deadline:
        time.sleep(0.5)
        ok = _started()
    if ok:
        time.sleep(2.0)          # survive the fast-crash window
        ok = _started()
    return "active" if ok else "failed"


def enable_openrc_now(init_dir: Path, key: str, *, runlevel: str = "default",
                      run=None, settle=None) -> str:
    """Symlink greasewood.<key> -> greasewood, add it to the boot runlevel, and
    start it. Returns 'active' / 'failed' / 'manual'."""
    run = run or rc_run
    svc = f"greasewood.{key}"
    if not shutil.which("rc-service") or not (init_dir / "greasewood").exists():
        return "manual"
    if run(["rc-service", svc, "status"], capture_output=True).returncode == 0:
        return "active"                      # already running
    link = init_dir / svc
    if not link.exists():
        try:
            link.symlink_to("greasewood")    # relative symlink within init_dir
        except OSError:
            return "manual"
    run(["rc-update", "add", svc, runlevel], capture_output=True)
    if run(["rc-service", svc, "start"], capture_output=True).returncode != 0:
        return "failed"
    if settle is None:
        settle = lambda s: wait_openrc_started(s, run=run)
    return settle(svc)


class ServiceManager(ABC):
    """An init-system backend for the per-mesh greasewood daemon. One
    implementation per init system (systemd today; OpenRC next). `detect()`
    returns the one for the current host, or None for the manual path."""

    name: str

    @abstractmethod
    def available(self) -> bool:
        """True when this init system is actually managing services here."""

    @abstractmethod
    def write_template(self, exec_path: "str | None" = None) -> "str | None":
        """Install the service definition (idempotent). Returns a truthy handle
        when the manager is usable, None otherwise."""

    @abstractmethod
    def refresh_template(self) -> bool:
        """Self-heal an installed template to this version's text. Returns True
        if it changed anything; never installs one where none exists."""

    @abstractmethod
    def enable_now(self, key: str) -> str:
        """Enable + start this mesh's instance; return a settle state
        ('active' / 'failed' / 'manual')."""

    @abstractmethod
    def unit_name(self, key: str) -> str:
        """The service name for mesh `key` (e.g. greasewood@home.service)."""

    @abstractmethod
    def restart_hint(self, key: str) -> str:
        """A copy-pasteable command to restart this mesh's daemon."""


class SystemdManager(ServiceManager):
    name = "systemd"

    def __init__(self, unit_dir: Path = SYSTEMD_UNIT_DIR) -> None:
        self.unit_dir = unit_dir

    def available(self) -> bool:
        return systemd_available()

    def write_template(self, exec_path: "str | None" = None) -> "str | None":
        return write_systemd_unit(self.unit_dir, exec_path or service_exec())

    def refresh_template(self) -> bool:
        return refresh_systemd_unit(self.unit_dir, service_exec())

    def enable_now(self, key: str) -> str:
        return enable_systemd_now(self.unit_dir, key)

    def unit_name(self, key: str) -> str:
        return f"greasewood@{key}.service"

    def restart_hint(self, key: str) -> str:
        return f"sudo systemctl restart greasewood@{key}"


class OpenRCManager(ServiceManager):
    name = "openrc"

    def __init__(self, init_dir: Path = OPENRC_INIT_DIR,
                 runlevel: str = "default") -> None:
        self.init_dir = init_dir
        self.runlevel = runlevel

    def available(self) -> bool:
        return openrc_available()

    def write_template(self, exec_path: "str | None" = None) -> "str | None":
        return write_openrc_script(self.init_dir, exec_path or service_exec())

    def refresh_template(self) -> bool:
        return refresh_openrc_script(self.init_dir, service_exec())

    def enable_now(self, key: str) -> str:
        return enable_openrc_now(self.init_dir, key, runlevel=self.runlevel)

    def unit_name(self, key: str) -> str:
        return f"greasewood.{key}"

    def restart_hint(self, key: str) -> str:
        return f"sudo rc-service greasewood.{key} restart"


def detect(unit_dir: Path = SYSTEMD_UNIT_DIR) -> "ServiceManager | None":
    """The service backend for this host, or None when no supported init system
    is managing services here (the operator supervises `gw run` themselves).
    systemd wins when both are somehow present — it's the one greasewood's unit
    and tests target."""
    if systemd_available():
        return SystemdManager(unit_dir)
    if openrc_available():
        return OpenRCManager()
    return None
