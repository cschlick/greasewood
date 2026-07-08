"""
greasewood.platform — OS detection and the seam between the Linux and macOS
backends.

greasewood was Linux-only. The macOS port keeps the entire control plane, crypto,
directory, enrollment, and policy layers byte-identical and swaps only the
OS-touching pieces:

    data plane    Linux: kernel WireGuard + iproute2 (`ip`)
                  macOS: wireguard-go + utun + `ifconfig`/`route`
    door isolate  Linux: source-scoped blackhole (`ip -6 rule` + route table)
                  macOS: assert IPv6 forwarding is off (no policy routing needed)
    services      Linux: systemd unit template
                  macOS: launchd plist
    port enforce  Linux: nftables (greasewood's own table)
                  macOS: NOT in v1 — a pf backend is a later add-on

This module is the ONE place that answers "which OS" and "what can this host
do", so the rest of the code branches on a named capability, not on scattered
`platform.system()` checks.

Note the name clash: this shadows the stdlib `platform` inside the package, so
we import the stdlib as `_stdlib_platform`. Callers do `from . import platform
as gwplat`.
"""
import platform as _stdlib_platform
import shutil
from pathlib import Path

_SYSTEM = _stdlib_platform.system()

IS_LINUX = _SYSTEM == "Linux"
IS_MACOS = _SYSTEM == "Darwin"


def os_name() -> str:
    """'Linux' | 'Darwin' | ... — the raw platform.system() value."""
    return _SYSTEM


def require_supported() -> None:
    """greasewood runs on Linux and macOS. Anything else exits cleanly rather
    than failing deep in an `ip`/`ifconfig` call with a confusing error."""
    if not (IS_LINUX or IS_MACOS):
        import sys
        sys.exit(f"greasewood supports Linux and macOS; this host is {_SYSTEM}.")


def port_enforcement_available() -> bool:
    """Can this host run greasewood's own packet-filter port enforcement?

    Linux: yes (nftables). macOS: NOT in v1 — the pf backend is a planned
    add-on, so on macOS `enforce_ports` is unavailable and the mesh runs with
    ports advisory (tunnel existence is still enforced by the grant table; only
    the per-port layer is absent). The door stays isolated regardless, via
    WireGuard keys + IPv6-forwarding-off (see wg.setup_door_routing)."""
    return IS_LINUX


def service_manager() -> str:
    """'systemd' | 'launchd' | 'none' — the init system that supervises the
    daemon on this host. 'none' when neither is usable (a container with
    `sleep` as PID 1, an unmanaged host), in which case create/join print the
    manual `gw run` line instead of installing a unit."""
    if IS_LINUX and shutil.which("systemctl") and Path("/run/systemd/system").is_dir():
        return "systemd"
    if IS_MACOS and shutil.which("launchctl"):
        return "launchd"
    return "none"
