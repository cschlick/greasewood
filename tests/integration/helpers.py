"""
Shared helpers for integration tests — thin wrappers around podman CLI.
"""
from __future__ import annotations

import json
import subprocess
import time
import urllib.request


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


def wait_for_http(url: str, timeout: int = 20) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            urllib.request.urlopen(url, timeout=2)
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


def directory_hostnames(root_url: str) -> set[str]:
    resp = urllib.request.urlopen(f"{root_url}/directory")
    return {r["hostname"] for r in json.loads(resp.read())}


def directory_size(root_url: str) -> int:
    resp = urllib.request.urlopen(f"{root_url}/directory")
    return len(json.loads(resp.read()))


def wait_for_directory_size(root_url: str, expected: int, timeout: int = 60) -> int:
    """Block until root's directory holds at least `expected` records."""
    deadline = time.time() + timeout
    last = 0
    while time.time() < deadline:
        last = directory_size(root_url)
        if last >= expected:
            return last
        time.sleep(1)
    return last


def wait_for_hostname(root_url: str, hostname: str, timeout: int = 20) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if hostname in directory_hostnames(root_url):
            return True
        time.sleep(1)
    return False
