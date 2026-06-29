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


def directory_hostnames(root_url: str) -> set[str]:
    resp = urllib.request.urlopen(f"{root_url}/directory")
    return {r["hostname"] for r in json.loads(resp.read())}


def wait_for_hostname(root_url: str, hostname: str, timeout: int = 20) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if hostname in directory_hostnames(root_url):
            return True
        time.sleep(1)
    return False
