"""greasewood.cli.svc — Service management: the systemd/OpenRC/launchd seam's CLI side (gw service), template refresh, restarts, and gw upgrade (pipx reinstall)."""
import datetime as dt
import logging
import os
import shutil
import re
import subprocess
import sys
from pathlib import Path

from .. import service
from ..config import membership_key
from ..status import _version

# The package namespace is the late-binding seam: cross-module helpers are
# called as cli.<name> so a monkeypatch on the package (the tests' historic
# patch point) reaches every caller, exactly as it did when this was one file.
import greasewood.cli as cli

_UTC = dt.timezone.utc
log = logging.getLogger("greasewood")




# The systemd service surface now lives in greasewood.service, behind the
# ServiceManager interface (systemd today; OpenRC next). These module names are
# kept as thin re-exports / delegators so cli's callers and the existing test
# monkeypatch seams (patch cli._UNIT_DIR, cli._service_exec, cli._systemctl_run,
# …) keep resolving here — the composition primitives moved down, not away.
_SERVICE_UNIT = service.SYSTEMD_UNIT



# Where the systemd units live. A module constant so tests can redirect it.
_UNIT_DIR = Path("/etc/systemd/system")




# systemd can wedge (a stuck job queue, a dead D-Bus), and a bare systemctl
# call then blocks FOREVER. Seen in the field at the worst possible spot: the
# final daemon-reload of an otherwise-successful join, which made the whole
# join look hung. Every systemctl greasewood runs goes through this wrapper:
# hard timeout, one loud warning, and a synthetic rc=124 (the timeout(1)
# convention) so each caller's existing nonzero-rc handling degrades to its
# manual-fallback path instead of hanging.
_SYSTEMCTL_TIMEOUT = 30




def _systemctl_run(argv, **kwargs) -> subprocess.CompletedProcess:
    # Delegates to service.systemctl_run, injecting the module-level timeout so
    # tests can still patch cli._SYSTEMCTL_TIMEOUT to shorten it.
    return service.systemctl_run(argv, timeout=cli._SYSTEMCTL_TIMEOUT, **kwargs)




def _membership_service(key: str) -> str:
    """Enable this membership's daemon as greasewood@<key>; return the settle
    state ('active' / 'failed' / 'manual'). Thin wrapper over
    service.enable_systemd_now that injects cli's patchable run/settle seams."""
    return service.enable_systemd_now(
        cli._UNIT_DIR, key, run=cli._systemctl_run, settle=cli._wait_service_settled)




_REPO_URL = "https://github.com/cschlick/greasewood"




def _pipx_install_env() -> "tuple[Path, Path] | None":
    """Where pipx put THIS install: ``(PIPX_HOME, PIPX_BIN_DIR)``, or None if we
    aren't running from a pipx venv.

    Read off the running interpreter rather than assumed: a pipx venv lives at
    ``<PIPX_HOME>/venvs/<package>``, and the app symlink that launched us sits
    in PIPX_BIN_DIR. Fleet installs deliberately use a non-default PIPX_HOME
    (``/opt/pipx``, so root's install isn't buried in a user's home) — guessing
    the default would install a SECOND copy elsewhere while the service kept
    running the old one, which is exactly the confusion this command exists to
    end.
    """
    venv = Path(sys.prefix)
    if venv.parent.name != "venvs":
        return None                      # apt/rpm, a dev checkout, or a venv we don't own
    home = venv.parent.parent
    exe = shutil.which("gw") or sys.argv[0]
    bin_dir = Path(exe).parent if os.path.isabs(exe) else Path("/usr/local/bin")
    # If PATH found the venv's own bin, that's not the shared bin dir pipx links
    # into — fall back rather than point PIPX_BIN_DIR inside the venv.
    if home in bin_dir.parents or bin_dir == venv / "bin":
        bin_dir = Path("/usr/local/bin")
    return home, bin_dir




def _prune_dangling_apps(bin_dir: Path, venv: Path) -> list:
    """Remove app symlinks in PIPX_BIN_DIR that point into this venv but no
    longer resolve — entry points the package USED to declare.

    pipx never prunes these: `gw-admin-upgrade` was dropped in 0.3.0, and its
    symlink sat in /usr/local/bin afterwards, dangling, with pipx cheerfully
    re-announcing it as "globally available" on every install. Deliberately
    narrow — only BROKEN links, and only ones pointing inside our own venv.
    """
    pruned = []
    try:
        entries = sorted(bin_dir.iterdir())
    except OSError:
        return pruned
    for p in entries:
        if not p.is_symlink() or p.exists():
            continue                      # live link (or not a link at all)
        target = Path(os.readlink(p))
        if target.is_absolute() and venv in target.parents:
            try:
                p.unlink()
                pruned.append(p.name)
            except OSError as e:
                log.warning("could not remove stale app link %s: %s", p, e)
    return pruned




def cmd_upgrade(args) -> int:
    """[sudo] Reinstall greasewood in place, then restart this mesh's daemon.

    A clean uninstall+install, not ``pipx upgrade``: upgrading in place has been
    seen to leave the previous version's ``__pycache__`` behind in the venv, so
    the running code doesn't always match what was installed. Two sources — the
    published PyPI release (default) or the git repo (``--from github``), the
    latter for running a fix that isn't released yet.

    Always prints the exact commands and asks before running any of them: the
    uninstall step briefly removes ``gw`` from a machine you may well be
    connected through.
    """
    from ..config import load_config

    env = _pipx_install_env()
    if env is None:
        sys.exit("'gw upgrade' only manages a pipx install, and this greasewood "
                 f"isn't one (running from {sys.prefix}).\n"
                 "A distro package upgrades with your package manager; a dev "
                 "checkout with 'pip install -e .'.")
    home, bin_dir = env
    cli._require_root("upgrade", "it reinstalls the package and restarts the service")
    cfg = load_config(Path(args.config))
    key = membership_key(cfg.mesh_domain)

    # For the github source, FETCH BEFORE UNINSTALL. The uninstall→install
    # window used to include the full network clone, so a GitHub outage in
    # that window stranded the node with greasewood uninstalled (seen in the
    # field: a 133s connect timeout mid-clone → pip failed → no venv, the
    # daemon alive only on deleted inodes, one restart from going dark). With
    # the payload cloned to local disk first, a network failure aborts while
    # the node is still untouched; only the local-path install (deps usually
    # wheel-cached) remains inside the window.
    fetch_steps: list = []
    if args.source == "github":
        if not shutil.which("git"):
            sys.exit("installing from the repo needs git, which isn't installed.\n"
                     "Try: sudo apt install git   # or: sudo apk add git")
        import tempfile
        ref = args.ref or "main"
        origin = f"the repo @ {ref}"
        # Under data_dir, not /tmp: confined hosts (AppArmor/SELinux) restrict
        # /tmp, which has bitten greasewood before — see tests/test_no_tmp.py.
        workdir = Path(tempfile.mkdtemp(prefix="gw-upgrade-", dir=cfg.data_dir))
        clone = workdir / "greasewood"
        # clone + checkout (not --branch): --branch takes branches/tags only,
        # while --ref is documented to accept a commit too.
        fetch_steps = [["git", "clone", "--quiet", _REPO_URL, str(clone)],
                       ["git", "-C", str(clone), "checkout", "--quiet", ref]]
        spec = str(clone)
    else:
        workdir = None
        spec = f"greasewood=={args.ref}" if args.ref else "greasewood"
        origin = f"PyPI {args.ref}" if args.ref else "PyPI (latest release)"

    pipx_env = {"PIPX_HOME": str(home), "PIPX_BIN_DIR": str(bin_dir)}
    prefix = " ".join(f"{k}={v}" for k, v in pipx_env.items())
    steps = fetch_steps + [["pipx", "uninstall", "greasewood"],
                           ["pipx", "install", spec]]

    print(f"greasewood {_version()}  →  reinstall from {origin}\n")
    for step in steps:
        p = "" if step in fetch_steps else prefix + " "
        print(f"  {p}{' '.join(step)}")
    print(f"\nthen: restart the daemon for '{key}'\n")
    print("The uninstall step removes 'gw' until the install finishes. If the "
          "install fails\n(no network, bad ref), recover by re-running the "
          "install line above by hand.\n")

    if not args.yes and input("Proceed? [y/N] ").strip().lower() not in ("y", "yes"):
        print("cancelled — nothing changed.")
        if workdir is not None:
            shutil.rmtree(workdir, ignore_errors=True)
        return 1

    venv = home / "venvs" / "greasewood"
    # BEFORE pipx runs, not just after: a stale link left by an older version is
    # still there when pipx links the new install, and pipx announces it as
    # "globally available" — the confusing line this is meant to stop. Only
    # broken links go, so the live `gw` is untouched.
    stale = _prune_dangling_apps(bin_dir, venv)

    run_env = {**os.environ, **pipx_env}
    for step in steps:
        print(f"\n$ {' '.join(step)}")
        r = subprocess.run(step, env=run_env)
        if r.returncode != 0:
            if step in fetch_steps:
                # Nothing has been removed yet — this is the failure mode the
                # fetch-first ordering exists for. Say so plainly.
                if workdir is not None:
                    shutil.rmtree(workdir, ignore_errors=True)
                sys.exit(f"\n'{' '.join(step)}' failed (exit {r.returncode}).\n"
                         f"Nothing was changed — the fetch runs before the "
                         f"uninstall precisely so a network failure can't strand "
                         f"the node. Re-run when the network is back.")
            # The clone (if any) is still on disk and valid — name it in the
            # recovery command rather than a spec that needs the network again.
            sys.exit(f"\n'{' '.join(step)}' failed (exit {r.returncode}).\n"
                     f"greasewood may be uninstalled right now — recover with:\n"
                     f"  sudo {prefix} pipx install {spec}")

    # Again afterwards: this install may itself have dropped an entry point.
    stale += [n for n in _prune_dangling_apps(bin_dir, venv) if n not in stale]
    if stale:
        print(f"\nremoved stale app link(s) pipx left behind: {', '.join(stale)}")

    gw = bin_dir / "gw"
    if gw.exists():
        v = subprocess.run([str(gw), "--version"], capture_output=True, text=True)
        if v.returncode == 0:
            print(f"\ninstalled: {v.stdout.strip()}")
    if not cli._service_restart(key, why="to run the new code"):
        print(f"restart the daemon to run the new code:\n  {_svc_restart_hint(key)}")
    if workdir is not None:
        shutil.rmtree(workdir, ignore_errors=True)
    return 0




def _unit_for_config(cfg_path) -> str:
    """The systemd unit serving this membership: greasewood@<key> when the
    config follows the /etc/greasewood_<key>.toml scheme, else a generic
    'greasewood@<name>' placeholder for messages."""
    m = re.fullmatch(r"greasewood_([a-z0-9-]+)\.toml", Path(cfg_path).name)
    return f"greasewood@{m.group(1)}" if m else "greasewood@<name>"




def _service_backend():
    """The detected service backend for THIS host (systemd / OpenRC / None),
    with the test-redirectable systemd unit dir wired in so create/join/purge
    honour cli._UNIT_DIR."""
    return service.detect(cli._UNIT_DIR)




def cmd_service(args) -> int:
    """[sudo] Enable or disable this config's daemon service — the adoption
    path for a membership whose service was never installed here (a config
    migrated from another machine or VM, a --no-service join revisited). On
    systemd/OpenRC the shared template plus the per-mesh instance; on launchd
    the per-mesh plist (which only greasewood can write — there is no shared
    template to enable by hand there)."""
    from ..config import load_config
    cli._require_root("service", "it installs/removes the daemon service")
    cfg = load_config(Path(args.config))
    key = membership_key(cfg.mesh_domain)
    mgr = cli._service_backend()
    if mgr is None:
        sys.exit("no supported init system is managing services on this host — "
                 "run the daemon yourself:\n  sudo gw run")
    if args.action == "disable":
        was = mgr.disable_now(key)
        print(f"{mgr.unit_name(key)}: {'stopped and ' if was else ''}removed from boot.")
        return 0
    if mgr.write_template() is None:
        sys.exit(f"{mgr.name} is not usable here — run the daemon yourself:\n"
                 f"  sudo gw run")
    state = mgr.enable_now(key)
    if state == "active":
        print(f"{mgr.unit_name(key)} is running (and starts at boot).")
        print(f"  {mgr.status_hint(key)}")
        return 0
    if state == "failed":
        print(f"{mgr.unit_name(key)} was installed but is NOT running — see why:")
        print(f"  {mgr.logs_hint(key)}")
        return 1
    print(f"couldn't manage {mgr.name} here — run the daemon yourself:")
    print("  sudo gw run")
    return 1




def _svc_restart_hint(key: str = "<mesh>") -> str:
    """The backend-correct 'restart this mesh's daemon' command for THIS host —
    rc-service on OpenRC, systemctl on systemd (systemctl-shaped fallback)."""
    return service.restart_hint(key, cli._UNIT_DIR)




def _service_restart(key: str, *, why: str = "to apply the change") -> bool:
    """Restart the managed daemon for this mesh if a service backend is present.
    Returns True if the restart succeeded (and the daemon settled active); False
    if there is no manager or the restart failed. Prints status on success."""
    mgr = cli._service_backend()
    if mgr is None:
        return False
    try:
        if mgr.restart_now(key):
            print(f"daemon restarted ({mgr.unit_name(key)}) {why}.")
            return True
    except Exception as e:
        log.warning("managed daemon restart failed: %s", e)
    return False




def _print_daemon_guidance(key: str, cfg_path, then: str = "",
                           no_service: bool = False) -> None:
    """Bring up (and report) this membership's daemon. By default create/join
    install the host's native service (systemd unit / OpenRC script) and enable
    this mesh's instance so it's running and boot-persistent with no extra
    command; --no-service (or no service manager) prints the manual `gw run`
    line. `then` is an optional trailing clause."""
    tail = f" — {then}" if then else ""
    mgr = cli._service_backend()
    if no_service or mgr is None:
        print(f"Start this mesh's daemon{tail}:")
        print(f"  sudo gw -c {cfg_path} run")
        if no_service and mgr is not None:
            print(f"  (or let {mgr.name} manage it: 'gw create/join' installs the "
                  f"service — enable with '{mgr.enable_hint(key)}')")
        return

    mgr.write_template()               # ensure the service definition exists, then enable
    state = mgr.enable_now(key)
    unit = mgr.unit_name(key)
    if state == "active":
        print(f"{unit} is running{tail} (and starts at boot).")
        print(f"  {mgr.status_hint(key)}")
    elif state == "manual":
        print(f"No service manager here — start this mesh's daemon{tail}:")
        print(f"  sudo gw -c {cfg_path} run")
    else:
        # enabled, but it did NOT come up and stay up (a fast crash = a silent
        # restart loop). Say so, and point at the logs.
        print(f"⚠ {unit} is enabled but {state or 'not running'} — it is likely "
              f"crashing at startup, so the mesh isn't up yet.")
        print(f"  see why:  {mgr.logs_hint(key)}")
        print(f"  or run it in the foreground to watch:  sudo gw -c {cfg_path} run")




# ---------------------------------------------------------------------------
# service management — the greasewood@ template unit (create/join install it,
# purge removes it; no separate install/uninstall command, no Ansible)
# ---------------------------------------------------------------------------

# These systemd helpers are thin delegators to greasewood.service. They stay in
# cli as named module attributes so the existing test seams keep working:
# callers reference cli._UNIT_DIR (redirectable) and the wrappers inject cli's
# patchable _service_exec / _systemctl_run into the service primitives.
_systemd_available = service.systemd_available


_systemd_available = service.systemd_available
_service_exec = service.service_exec




def _write_service_template(exec_path: "str | None" = None) -> "str | None":
    """Write the greasewood@ template unit (idempotent) and daemon-reload;
    returns the systemctl path (None if no systemd). Shared by create/join."""
    return service.write_systemd_unit(
        cli._UNIT_DIR, exec_path or cli._service_exec(), run=cli._systemctl_run)




def _refresh_service_template() -> bool:
    """Daemon-startup self-heal: rewrite the installed template if it differs
    from this version's text. Never installs one where none exists."""
    return service.refresh_systemd_unit(cli._UNIT_DIR, cli._service_exec(), run=cli._systemctl_run)




def _wait_service_settled(systemctl: str, unit: str, wait_secs: float = 6.0) -> str:
    """Wait for `unit` to reach AND hold 'active'; return the final is-active
    state — the settle re-check that catches a Type=simple fast-crash flap."""
    return service.wait_systemd_settled(systemctl, unit, wait_secs, run=cli._systemctl_run)
