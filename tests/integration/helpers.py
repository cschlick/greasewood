"""
Shared helpers for integration tests — thin wrappers around podman CLI.
"""
from __future__ import annotations

import json
import subprocess
import time


def podman(*args: str, check: bool = True, input: str | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["podman"] + list(args),
        capture_output=True, text=True,
        check=check, input=input,
    )


def pexec(container: str, *args: str, check: bool = True, input: str | None = None) -> subprocess.CompletedProcess:
    return podman("exec", container, *args, check=check, input=input)


def container_ipv6(container: str, network: str) -> str:
    info = json.loads(podman("inspect", container).stdout)[0]
    return info["NetworkSettings"]["Networks"][network]["GlobalIPv6Address"]


# The control plane binds only to the overlay address + loopback, so it is NOT
# reachable from the host. Query it from inside the hub container over loopback.
_GET_SNIPPET = (
    "import sys,urllib.request;"
    "sys.stdout.write(urllib.request.urlopen("
    "'http://[::1]:7946'+sys.argv[1], timeout=5).read().decode())"
)


def hub_get(hub_cid: str, path: str) -> str:
    """GET a control-plane path from inside the hub container (via ::1)."""
    r = pexec(hub_cid, "python3", "-c", _GET_SNIPPET, path, check=False)
    if r.returncode != 0:
        raise RuntimeError(r.stderr.strip() or "control-plane GET failed")
    return r.stdout


def wait_for_control_plane(hub_cid: str, timeout: int = 20) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            hub_get(hub_cid, "/health")
            return True
        except Exception:
            time.sleep(0.5)
    return False


def wait_for_ping(container: str, addr: str, timeout: int = 30) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        r = pexec(container, "ping", "-6", "-c1", "-W2", addr, check=False)
        if r.returncode == 0:
            return True
        time.sleep(1)
    return False


def ping_once(container: str, addr: str, timeout: int = 2) -> bool:
    """Single ping, no retry — use once the mesh is known to be converged."""
    r = pexec(container, "ping", "-6", "-c1", "-W", str(timeout), addr, check=False)
    return r.returncode == 0


def wg_peer_count(container: str, iface: str = "gw0") -> int:
    """Number of WireGuard peers currently installed on the interface."""
    r = pexec(container, "wg", "show", iface, "peers", check=False)
    if r.returncode != 0:
        return 0
    return len([ln for ln in r.stdout.splitlines() if ln.strip()])


def wait_for_peer_count(container: str, expected: int, iface: str = "gw0",
                        timeout: int = 90) -> int:
    """
    Block until the interface has at least `expected` peers. Returns the final
    observed count (== expected on success, < expected on timeout).
    """
    deadline = time.time() + timeout
    last = 0
    while time.time() < deadline:
        last = wg_peer_count(container, iface)
        if last >= expected:
            return last
        time.sleep(1)
    return last


def directory_records(hub_cid: str) -> list:
    return json.loads(hub_get(hub_cid, "/directory"))


def directory_hostnames(hub_cid: str) -> set[str]:
    return {r["hostname"] for r in directory_records(hub_cid)}


def directory_size(hub_cid: str) -> int:
    return len(directory_records(hub_cid))


def wait_for_directory_size(hub_cid: str, expected: int, timeout: int = 60) -> int:
    """Block until the hub's directory holds at least `expected` records."""
    deadline = time.time() + timeout
    last = 0
    while time.time() < deadline:
        try:
            last = directory_size(hub_cid)
        except Exception:
            last = 0
        if last >= expected:
            return last
        time.sleep(1)
    return last


def wait_for_hostname(hub_cid: str, hostname: str, timeout: int = 20) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if hostname in directory_hostnames(hub_cid):
                return True
        except Exception:
            pass
        time.sleep(1)
    return False
