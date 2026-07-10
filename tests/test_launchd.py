"""
launchd service management (macOS), tested from Linux: the rendered plist, the
launchctl command sequence, the settle-check states, and removal. launchctl is
mocked; the real behavior is verified on a Mac.
"""
import plistlib
import subprocess as _subprocess
import types

import pytest

from greasewood import launchd
from greasewood import platform as gwplat


@pytest.fixture
def macos(monkeypatch, tmp_path):
    monkeypatch.setattr(gwplat, "IS_MACOS", True)
    monkeypatch.setattr(gwplat, "IS_LINUX", False)
    monkeypatch.setattr(launchd, "LAUNCHD_DIR", tmp_path / "LaunchDaemons")
    monkeypatch.setattr(launchd, "LOG_DIR", tmp_path / "log")
    monkeypatch.setattr(launchd.shutil, "which",
                        lambda n: "/bin/launchctl" if n == "launchctl" else None)
    # os.chown(plist, 0, 0) needs root on a real Mac; no-op it here (a dedicated
    # test overrides this with a recorder to check the root:wheel enforcement).
    monkeypatch.setattr(launchd.os, "chown", lambda *a, **k: None)
    return tmp_path


class _Ctl:
    """Scripted launchctl: records calls; `print` reports the job ABSENT until a
    bootstrap has run (so the async-bootout unload-wait exits at once), then the
    configured running state."""
    def __init__(self, running=True):
        self.calls = []
        self.running = running
        self._up = False

    def __call__(self, cmd, capture_output=True, text=True):
        self.calls.append(list(cmd))
        verb = cmd[1]
        if verb == "bootstrap":
            self._up = True
            return _subprocess.CompletedProcess(cmd, 0, "", "")
        if verb == "print":
            if not self._up:
                return _subprocess.CompletedProcess(cmd, 1, "", "not found")
            state = "state = running" if self.running else "state = not running"
            return _subprocess.CompletedProcess(cmd, 0, f"\t{state}\n", "")
        return _subprocess.CompletedProcess(cmd, 0, "", "")


# ---------------------------------------------------------------------------
# the plist
# ---------------------------------------------------------------------------

def test_plist_contents():
    data = plistlib.loads(launchd.render_plist(
        "pm", "/etc/greasewood_pm.toml", "/usr/local/bin/gw"))
    assert data["Label"] == "com.greasewood.pm"
    assert data["ProgramArguments"] == \
        ["/usr/local/bin/gw", "-c", "/etc/greasewood_pm.toml", "run"]
    assert data["RunAtLoad"] is True
    # always restart while loaded — `gw run` exits 0 on SIGTERM, and launchd
    # can't tell an operator stop from a stray signal, so a conditional
    # KeepAlive would leave the mesh down after any clean SIGTERM (intentional
    # stops go through bootout, which unloads the job entirely).
    assert data["KeepAlive"] is True
    # launchd strips env; wireguard-go/wg live under the Homebrew prefixes
    path = data["EnvironmentVariables"]["PATH"]
    assert "/opt/homebrew/bin" in path and "/usr/local/bin" in path
    assert data["StandardOutPath"].endswith("pm.log")


def test_label_and_path_naming():
    assert launchd.label("pm") == "com.greasewood.pm"
    assert launchd.plist_path("pm").name == "com.greasewood.pm.plist"


# ---------------------------------------------------------------------------
# install: write → bootout → bootstrap → settle
# ---------------------------------------------------------------------------

def test_install_writes_plist_and_bootstraps(macos, monkeypatch):
    ctl = _Ctl(running=True)
    monkeypatch.setattr(launchd.subprocess, "run", ctl)
    monkeypatch.setattr(launchd.time, "sleep", lambda s: None)  # fast settle
    state = launchd.install("pm", "/etc/greasewood_pm.toml", gw_exec="/x/gw")
    assert state == "active"
    plist = launchd.plist_path("pm")
    assert plist.exists()
    data = plistlib.loads(plist.read_bytes())
    assert data["Label"] == "com.greasewood.pm"
    verbs = [c[1] for c in ctl.calls]
    # bootout (idempotent refresh) BEFORE bootstrap, then an explicit kickstart
    # to deterministically start the loaded job, then settle via print.
    assert verbs.index("bootout") < verbs.index("bootstrap") < verbs.index("kickstart")
    boot = next(c for c in ctl.calls if c[1] == "bootstrap")
    assert boot == ["launchctl", "bootstrap", "system", str(plist)]
    ks = next(c for c in ctl.calls if c[1] == "kickstart")
    assert ks == ["launchctl", "kickstart", "-k", "system/com.greasewood.pm"]


def test_install_forces_root_wheel_ownership(macos, monkeypatch):
    """The plist MUST land root:wheel — a wrong group makes launchd silently
    refuse to auto-load it at boot (the job then needs a manual bootstrap)."""
    ctl = _Ctl(running=True)
    monkeypatch.setattr(launchd.subprocess, "run", ctl)
    monkeypatch.setattr(launchd.time, "sleep", lambda s: None)
    chowns = []
    monkeypatch.setattr(launchd.os, "chown",
                        lambda p, u, g: chowns.append((str(p), u, g)))
    launchd.install("pm", "/etc/x.toml", gw_exec="/x/gw")
    assert chowns == [(str(launchd.plist_path("pm")), 0, 0)]   # root (0), wheel (0)


def test_install_reports_failed_when_job_never_runs(macos, monkeypatch):
    ctl = _Ctl(running=False)                    # loaded but crashing
    monkeypatch.setattr(launchd.subprocess, "run", ctl)
    monkeypatch.setattr(launchd.time, "sleep", lambda s: None)
    monkeypatch.setattr(launchd.time, "monotonic",
                        _ticker(0.0, step=1.0))  # fast-forward the deadline
    assert launchd.install("pm", "/etc/x.toml", gw_exec="/x/gw") == "failed"


def test_install_manual_when_not_macos(monkeypatch):
    monkeypatch.setattr(gwplat, "IS_MACOS", False)
    assert launchd.install("pm", "/etc/x.toml") == "manual"


def _ticker(start, step):
    t = {"v": start}
    def tick():
        t["v"] += step
        return t["v"]
    return tick


# ---------------------------------------------------------------------------
# remove (purge / rename)
# ---------------------------------------------------------------------------

def test_remove_boots_out_and_unlinks(macos, monkeypatch):
    ctl = _Ctl()
    monkeypatch.setattr(launchd.subprocess, "run", ctl)
    launchd.LAUNCHD_DIR.mkdir(parents=True)
    launchd.plist_path("pm").write_bytes(
        launchd.render_plist("pm", "/etc/x.toml", "/x/gw"))
    assert launchd.remove("pm")
    assert not launchd.plist_path("pm").exists()
    assert ["launchctl", "bootout", "system/com.greasewood.pm"] in ctl.calls
    assert not launchd.remove("pm") or True      # idempotent (no crash)


# ---------------------------------------------------------------------------
# purge on macOS (regression: a local membership_key re-import shadowed the
# module-level name and crashed the launchd block with UnboundLocalError)
# ---------------------------------------------------------------------------

def test_purge_on_macos_removes_launchd_job(macos, monkeypatch, tmp_path):
    from greasewood import cli, hosts as _hosts, wg
    monkeypatch.setattr(cli.gwplat, "IS_MACOS", True, raising=False)
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)
    monkeypatch.setattr(_hosts, "remove_block", lambda *a, **k: False)
    monkeypatch.setattr(cli, "_memberships", lambda etc=None: [])
    monkeypatch.setattr(cli, "_UNIT_DIR", tmp_path / "units")
    monkeypatch.setattr(wg, "interface_exists", lambda i: False)
    monkeypatch.setattr(wg, "teardown_door_routing", lambda: None)
    removed_jobs = []
    monkeypatch.setattr(launchd, "remove",
                        lambda key: removed_jobs.append(key) or True)
    monkeypatch.setattr(cli.subprocess, "run", lambda *a, **k:
                        _subprocess.CompletedProcess(a, 1, "", ""))
    monkeypatch.setattr(cli.shutil, "which", lambda n: None)   # no systemctl/nft

    data_dir = tmp_path / "data"; data_dir.mkdir()
    cfg = tmp_path / "gw.toml"
    cfg.write_text(f'''[node]
hostname = "melvin2"
data_dir = "{data_dir}"
role = "node"
[network]
interface = "gw-pm"
mesh_domain = "pm.internal"
seeds = []
root_url = ""
''')
    args = types.SimpleNamespace(config=str(cfg), yes=True)
    assert cli.cmd_purge(args) == 0                 # no UnboundLocalError
    assert removed_jobs == ["pm"]                   # launchd job torn down
    assert not data_dir.exists() and not cfg.exists()


class _CtlRetry:
    """launchctl where bootstrap fails once with the async-bootout I/O error,
    then succeeds. `print` reports the job absent until bootstrapped (so the
    unload-wait exits immediately), running afterwards (so settle passes)."""
    def __init__(self):
        self.calls = []
        self._attempts = 0
        self._up = False

    def __call__(self, cmd, capture_output=True, text=True):
        self.calls.append(list(cmd))
        verb = cmd[1]
        if verb == "bootstrap":
            self._attempts += 1
            if self._attempts == 1:
                return _subprocess.CompletedProcess(
                    cmd, 5, "", "Bootstrap failed: 5: Input/output error")
            self._up = True
            return _subprocess.CompletedProcess(cmd, 0, "", "")
        if verb == "print":
            if self._up:
                return _subprocess.CompletedProcess(cmd, 0, "\tstate = running\n", "")
            return _subprocess.CompletedProcess(cmd, 1, "", "not found")
        return _subprocess.CompletedProcess(cmd, 0, "", "")


def test_install_retries_bootstrap_after_async_bootout(macos, monkeypatch):
    """Regression: bootout is async; bootstrapping the same label too soon fails
    with 'Bootstrap failed: 5'. install() must retry, not give up (seen on a
    real Mac during a re-join)."""
    ctl = _CtlRetry()
    monkeypatch.setattr(launchd.subprocess, "run", ctl)
    monkeypatch.setattr(launchd.time, "sleep", lambda s: None)
    state = launchd.install("pm", "/etc/greasewood_pm.toml", gw_exec="/x/gw")
    assert state == "active"
    assert len([c for c in ctl.calls if c[1] == "bootstrap"]) == 2   # retried once
