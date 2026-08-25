"""
greasewood.platform — OS detection: the seam between the Linux and macOS
backends.

greasewood was Linux-only; the macOS port (revived from tag macos-port-archive
after the Lima-VM approach was abandoned — see tag lima-era-archive) keeps the
entire control plane, crypto, directory, enrollment, and policy layers
byte-identical and swaps only the OS-touching pieces:

    data plane    Linux: kernel WireGuard + iproute2 (`ip`)
                  macOS: wireguard-go + utun + `ifconfig`/`route`
    door isolate  Linux: source-scoped blackhole (`ip -6 rule` + route table)
                  macOS: assert IPv6 forwarding is off (no policy routing needed)
    services      greasewood.service's ServiceManager backends
                  (systemd | OpenRC | launchd), selected by service.detect()
    port enforce  Linux: nftables (greasewood's own table)
                  macOS: not yet — a pf backend is a later add-on; ports run
                  advisory (tunnel existence is still policy-enforced)

This module is the ONE place that answers "which OS", so the rest of the code
branches on a named capability, not on scattered platform.system() checks.
Unlike the archived port, service-manager detection does NOT live here — that
seam already exists in greasewood.service (detect()), and one seam is enough.

Note the name clash: this shadows the stdlib `platform` inside the package, so
we import the stdlib as _stdlib_platform. Callers do
`from . import platform as gwplat`.
"""
import platform as _stdlib_platform

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

    Linux: yes (nftables). macOS: not yet — the pf backend is a planned
    add-on, so on macOS `enforce_ports` is unavailable and the mesh runs with
    ports advisory (tunnel existence is still enforced by the grant table;
    only the per-port layer is absent). The door stays isolated regardless,
    via WireGuard keys + IPv6-forwarding-off (see wg.setup_door_routing)."""
    return IS_LINUX
