"""greasewood.cli.netdetect — Underlay address detection and door-host ordering — every heuristic that decides what this machine advertises or dials (the twice-bitten code: VM ULA, VPN /128)."""
import datetime as dt
import ipaddress
import logging
import subprocess

from .. import platform as gwplat

# The package namespace is the late-binding seam: cross-module helpers are
# called as cli.<name> so a monkeypatch on the package (the tests' historic
# patch point) reaches every caller, exactly as it did when this was one file.
import greasewood.cli as cli

_UTC = dt.timezone.utc
log = logging.getLogger("greasewood")




# ---------------------------------------------------------------------------
# create  (one-shot anchor bootstrap: CA + door key + routing + self-credential)
# ---------------------------------------------------------------------------

def _detect_public_ipv6() -> str | None:
    """
    Return the most stable Global Unicast Address on this machine.

    Preference order:
      1. non-deprecated, non-temporary GUA  (EUI-64 / static SLAAC)
      2. non-deprecated, temporary GUA
      3. any GUA (fallback)

    GUA = 2000::/3 (first 3 bits are 001).  ULA (fc/fd) and link-local
    (fe80) are excluded because they are not routable across the internet.

    Within each class, a non-/128 address beats a /128, and the interface
    holding the v6 default route breaks ties. A lone /128 on some tunnel
    interface is the signature of a VPN client address — commercial WireGuard
    VPNs hand EVERY client the same "global" /128, so it passes the GUA test
    while being (a) NATed from the internet and (b) a LOCAL address on any
    other machine running the same VPN, which then dials ITSELF. Field
    incident: the anchor advertised its VPN /128 as its endpoint; a returning
    node on the same VPN hung forever joining through its own loopback. The
    /128 stays a last resort (DHCPv6 IA_NA legitimately assigns /128s) rather
    than being excluded outright.
    """
    candidates = []                      # (is_128, class_rank, off_def, addr)

    def_iface = _default_iface6()
    for raw, iface, prefixlen, line in _inet6_addrs():
        try:
            addr = ipaddress.IPv6Address(raw)
        except ValueError:
            continue

        # GUA: 2000::/3  (first 3 bits == 001)
        if addr.packed[0] & 0xe0 != 0x20:
            continue

        flags = line
        if "deprecated" in flags:
            rank = 2
        elif "temporary" in flags:
            rank = 1
        else:
            rank = 0
        candidates.append((
            prefixlen == 128,                                  # real prefix first:
            rank,                                              # this outranks the
            0 if (def_iface and iface == def_iface) else 1,    # stability class —
            str(addr),                                         # a rotating privacy
        ))                                                     # address is still
        # reachable while it lives; a VPN /128 never is.

    return min(candidates)[3] if candidates else None




def _default_iface6() -> "str | None":
    """The interface carrying the v6 default route, or None."""
    cmd = (["route", "-n", "get", "-inet6", "default"] if gwplat.IS_MACOS
           else ["ip", "-6", "route", "show", "default"])
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, check=False)
    except FileNotFoundError:
        return None
    if gwplat.IS_MACOS:
        for line in r.stdout.splitlines():
            parts = line.split()
            if len(parts) == 2 and parts[0] == "interface:":
                return parts[1]
        return None
    toks = r.stdout.split()
    return toks[toks.index("dev") + 1] if "dev" in toks[:-1] else None




def _inet6_addrs() -> "list[tuple[str, str, int, str]]":
    """Every global-ish inet6 address on this host as (addr, iface, prefixlen,
    flags-line) tuples — the OS-specific parse behind _detect_public_ipv6.
    Linux reads `ip -6 -o addr show scope global`; macOS reads `ifconfig -a`
    (its inet6 lines carry the same temporary/deprecated flag words, the
    interface comes from the preceding `en0: flags=` header, and zone ids like
    %en0 are stripped — a zoned address is link-local anyway and fails the GUA
    check). A missing prefixlen parses as 128 (the conservative reading: a
    lone host address ranks as tunnel-like, never better)."""
    out: "list[tuple[str, str, int, str]]" = []
    if gwplat.IS_MACOS:
        try:
            r = subprocess.run(["ifconfig", "-a"],
                               capture_output=True, text=True, check=False)
        except FileNotFoundError:
            return out
        iface = ""
        for line in r.stdout.splitlines():
            # "en0: flags=8863<UP,...> mtu 1500" opens each interface block
            if line and not line[0].isspace() and ":" in line:
                iface = line.split(":", 1)[0]
                continue
            parts = line.split()
            # "inet6 <addr>[%zone] prefixlen N [autoconf secured temporary ...]"
            if len(parts) >= 2 and parts[0] == "inet6":
                pl = 128
                if "prefixlen" in parts:
                    try:
                        pl = int(parts[parts.index("prefixlen") + 1])
                    except (IndexError, ValueError):
                        pass
                out.append((parts[1].split("%")[0], iface, pl, line))
        return out
    try:
        r = subprocess.run(["ip", "-6", "-o", "addr", "show", "scope", "global"],
                           capture_output=True, text=True, check=False)
    except FileNotFoundError:
        return out
    for line in r.stdout.splitlines():
        # "<idx>: <iface>    inet6 <addr/prefix> scope global [flags...]"
        parts = line.split()
        if len(parts) >= 4 and parts[2] == "inet6":
            addr, _, plraw = parts[3].partition("/")
            try:
                pl = int(plraw) if plraw else 128
            except ValueError:
                pl = 128
            out.append((addr, parts[1], pl, line))
    return out




_CGNAT4 = ipaddress.ip_network("100.64.0.0/10")   # RFC 6598 carrier-grade NAT




def _globally_reachable_v4(addr: "ipaddress.IPv4Address") -> bool:
    """Is this v4 something a peer could actually dial? `is_global` excludes
    RFC1918 / loopback / link-local; the explicit CGNAT (100.64.0.0/10) test is
    the belt-and-suspenders: carrier-NAT space is NOT `is_private`, and its
    `is_global` was only corrected in CPython 3.11.9 / 3.12.4 — so on an older
    interpreter in the distro matrix `is_global` alone would wrongly pass it."""
    return addr.is_global and addr not in _CGNAT4




def _detect_public_ipv4() -> str | None:
    """Best-effort public IPv4 on this machine — a globally-reachable v4 on an
    interface. Behind 1:1 NAT (e.g. EC2, where the interface holds only a private
    v4) OR carrier-grade NAT (a 100.64/10 address) this returns None, so those
    nodes advertise nothing (correctly outbound-only) unless the operator passes
    `--endpoint <public-v4>`. Only the underlay may be v4; the overlay stays IPv6."""
    cmd = (["ifconfig", "-a"] if gwplat.IS_MACOS
           else ["ip", "-4", "-o", "addr", "show", "scope", "global"])
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, check=False)
    except FileNotFoundError:
        return None
    for line in r.stdout.splitlines():
        parts = line.split()
        # macOS: "inet <a.b.c.d> netmask ..." / Linux: "N: eth0 inet <a.b.c.d>/nn ..."
        if gwplat.IS_MACOS:
            if len(parts) < 2 or parts[0] != "inet":
                continue
            raw = parts[1]
        else:
            if len(parts) < 4 or parts[2] != "inet":
                continue
            raw = parts[3].split("/")[0]
        try:
            addr = ipaddress.IPv4Address(raw)
        except ValueError:
            continue
        if _globally_reachable_v4(addr):
            return str(addr)
    return None




def _local_families() -> set[int]:
    """Which underlay families this node can originate connections on, by
    default-route presence. Used to pick a reachable peer endpoint. Falls back to
    assuming both if detection fails."""
    fams: set[int] = set()
    for fam, cmd in ((6, (["route", "-n", "get", "-inet6", "default"]
                          if gwplat.IS_MACOS else
                          ["ip", "-6", "route", "show", "default"])),
                     (4, (["route", "-n", "get", "default"]
                          if gwplat.IS_MACOS else
                          ["ip", "-4", "route", "show", "default"]))):
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, check=False)
            # macOS `route get` exits non-zero with "not in table" when absent;
            # Linux `ip route show default` prints nothing.
            if gwplat.IS_MACOS:
                if r.returncode == 0 and "gateway" in (r.stdout or ""):
                    fams.add(fam)
            elif r.stdout.strip():
                fams.add(fam)
        except FileNotFoundError:
            pass
    return fams or {4, 6}




def _local_global_addrs() -> "set":
    """Every global-scope address (v6 and v4) THIS host owns, as ip_address
    objects. Used to refuse dialing an 'anchor' host that is actually one of
    our own addresses — which happens in the wild: a shared commercial VPN
    assigns every client the same 'global' address, so a token minted on an
    anchor running that VPN can carry an address the joiner also owns, and
    dialing it loops back to the joiner forever."""
    addrs = set()
    for raw, _iface, _pl, _line in _inet6_addrs():
        try:
            addrs.add(ipaddress.ip_address(raw))
        except ValueError:
            continue
    cmd = (["ifconfig", "-a"] if gwplat.IS_MACOS
           else ["ip", "-4", "-o", "addr", "show"])
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, check=False)
    except FileNotFoundError:
        return addrs
    for line in r.stdout.splitlines():
        parts = line.split()
        raw = None
        if gwplat.IS_MACOS:
            if len(parts) >= 2 and parts[0] == "inet":
                raw = parts[1]
        elif len(parts) >= 4 and parts[2] == "inet":
            raw = parts[3].split("/")[0]
        if raw:
            try:
                addrs.add(ipaddress.ip_address(raw))
            except ValueError:
                continue
    return addrs




def _order_door_hosts(hosts: "list[str]") -> "tuple[list[str], list[tuple[str, str]]]":
    """Order the token's candidate door hosts for dialing and drop the ones
    that can never work. Returns (ordered_hosts, skipped) where skipped is
    (host, reason) pairs for the final report.

    - A host that is one of OUR OWN addresses is dropped: dialing it loops
      back to this machine (the shared-VPN failure — see _local_global_addrs).
    - Hosts whose family this node can't originate on are demoted, not
      dropped (family detection is a heuristic; the handshake is the proof).
    - Within each group the token's order (v6 first) is preserved."""
    local = cli._local_global_addrs()
    fams = cli._local_families()
    ordered, demoted, skipped = [], [], []
    for h in hosts:
        h = h.strip()
        if not h:
            continue
        try:
            if ipaddress.ip_address(h) in local:
                skipped.append((h, "this is one of THIS machine's own addresses "
                                   "(a VPN tunnel shared by both ends?) — dialing "
                                   "it would loop back to this host"))
                continue
        except ValueError:
            pass                                    # a DNS name — always dialable
        fam = 6 if ":" in h else 4
        (ordered if fam in fams else demoted).append(h)
    return ordered + demoted, skipped




def _endpoint_with_port(explicit: str, listen_port: int) -> str:
    """Normalize an operator-supplied --endpoint to a formatted wg endpoint.
    Accepts a bare address ('1.2.3.4', 'fd8d::1'), a bracketed v6 ('[fd8d::1]'),
    or a full endpoint ('1.2.3.4:51900', '[fd8d::1]:51900')."""
    from .. import wg as wgmod
    s = explicit.strip()
    if s.startswith("["):
        return s if "]:" in s else wgmod.format_endpoint(s[1:-1], listen_port)
    # v4:port  (a dot in the host and exactly one colon)
    if "." in s and s.count(":") == 1:
        return s
    # bare address (v4 like 1.2.3.4, or v6 like fd8d::1)
    return wgmod.format_endpoint(s, listen_port)




def _advertised_endpoints(explicit: "str | None", listen_port: int,
                          prior: "list[str] | None" = None) -> list[str]:
    """The underlay endpoint(s) this node advertises. Explicit --endpoint wins;
    else best-effort detect a public v6 and/or v4. Empty = unreachable
    (outbound-only). May return both families for a dual-stack node."""
    from .. import wg as wgmod
    if explicit:
        return [_endpoint_with_port(explicit, listen_port)]
    eps: list[str] = []
    v6 = _detect_public_ipv6()
    if v6:
        eps.append(wgmod.format_endpoint(v6, listen_port))
    v4 = _detect_public_ipv4()
    if v4:
        eps.append(wgmod.format_endpoint(v4, listen_port))
    if not eps and prior:
        return list(prior)
    return eps
