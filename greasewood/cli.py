"""
gw — CLI entry point (every subcommand lives here; `gw --help` is the index).

The core ceremony — enrollment is door-based: a transient WireGuard tunnel,
no SSH, no HTTP on the underlay:

  On the anchor:
    gw create <name>      # one-shot: CA, door key, routing, self-credential
    gw run                # start the daemon (serves control plane + door)
    gw invite             # open a window, print a single-use join token

  On the new node:
    gw join <token>       # enroll over the door, then:
    gw run                # join the mesh

Everything else groups around that: observe (watch — which now also shows the
host-firewall port check — diagnose, narrate, config), administer nodes on the
anchor (invite/close-door, revoke, set-caps,
set-roles, renew-all), maintain this node (renew, rename-node, rename-mesh,
purge), TLS service certs (cert-request/-profiles/-status/-remove), and anchor
lifecycle (anchor-promote, anchor-backup, anchor-restore).
"""
from __future__ import annotations

import argparse
import base64
import datetime as dt
import ipaddress
import json
import logging
import os
import shutil
import signal
import socket
import re
import subprocess
import sys
import threading
import time
from pathlib import Path

from . import service
from .config import membership_key, render_config
from .keys import _key_file_warnings, _own_identity, _secret_key_paths
from .status import _dur_short, _version, cmd_diagnose, cmd_watch

_UTC = dt.timezone.utc
log = logging.getLogger("greasewood")


def _setup_logging(verbose: bool) -> None:
    from .audit import UTCFormatter
    level = logging.DEBUG if verbose else logging.INFO
    handler = logging.StreamHandler()
    # Full ISO-8601 UTC timestamps: a command trail spanning days must be
    # unambiguous (the old format was time-only).
    handler.setFormatter(UTCFormatter(
        "%(asctime)s %(levelname)s %(name)s: %(message)s"))
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level)


# The systemd service surface now lives in greasewood.service, behind the
# ServiceManager interface (systemd today; OpenRC next). These module names are
# kept as thin re-exports / delegators so cli's callers and the existing test
# monkeypatch seams (patch cli._UNIT_DIR, cli._service_exec, cli._systemctl_run,
# …) keep resolving here — the composition primitives moved down, not away.
_SERVICE_UNIT = service.SYSTEMD_UNIT

# Where the systemd units live. A module constant so tests can redirect it.
_UNIT_DIR = Path("/etc/systemd/system")


def _config_aliases(cfg) -> list:
    """The node's published service labels from [network] aliases, keeping only
    valid DNS labels (a bad entry is dropped, not mangled)."""
    from . import hosts
    return [a for a in cfg.aliases if hosts.valid_label(a)]


def _san_to_owned_label(san: str, cfg) -> "str | None":
    """If `san` is a strict subdomain of this node's own mesh name, return the
    single label under it (e.g. 'pg.db01.gw.internal' → 'pg'); else None.
    Cert SANs live in the mesh's CANONICAL namespace (see cert-request)."""
    from . import hosts
    own = hosts.mesh_name(cfg.hostname, cfg.mesh_domain)
    suffix = "." + own
    if san.endswith(suffix):
        label = san[: -len(suffix)]
        if hosts.valid_label(label):        # single label only, DNS-safe
            return label
    return None


def _add_config_aliases(cfg_path: Path, cfg, labels: list) -> list:
    """Merge `labels` into [network] aliases in the TOML, in place. Returns the
    labels actually added (empty if all were already present / couldn't edit)."""
    have = set(cfg.aliases)
    new = [l for l in labels if l not in have]
    if not new:
        return []
    merged = json.dumps(sorted(have | set(new)))
    text = cfg_path.read_text()
    line = f"aliases = {merged}"
    if re.search(r"(?m)^\s*aliases\s*=", text):
        text = re.sub(r"(?m)^\s*aliases\s*=.*$", line, text, count=1)
    elif re.search(r"(?m)^\[network\]\s*$", text):
        text = re.sub(r"(?m)^(\[network\]\s*)$", r"\1\n" + line, text, count=1)
    else:
        return []                            # no place to put it — caller warns
    cfg_path.write_text(text)
    return new


def _get_passphrase(env_var: str | None) -> bytes | None:
    if not env_var:
        return None
    val = os.environ.get(env_var)
    if not val:
        sys.exit(f"{env_var} is set in config but that environment variable is empty")
    return val.encode()


def _print_firewall_help(listen_port: int = 51900, control_port: int = 51902,
                         mesh_iface: str = "gw-mesh", header: bool = True,
                         enforce_ports: bool = True, role: str = "anchor") -> None:
    """
    Print (never apply) the recommended firewall posture for THIS node's role.
    greasewood binds its control/enroll planes only to the overlay + loopback, so
    nothing it runs is exposed on the underlay regardless of firewall. On a
    default-drop host you still allow the few things below to *reach* those
    sockets. Role-specific: a plain node needs only its mesh UDP port + the coarse
    overlay admit; the enrollment door (port + iface) is the ANCHOR's alone.
    """
    from .door import DOOR_PORT, DOOR_IFACE, ENROLL_PORT
    is_anchor = role == "anchor"
    who = "an anchor" if is_anchor else "a node"
    if header:
        print(f"Firewall (greasewood never edits it). Recommended posture for {who}.")
        print("On a default-drop host, allow (nftables):")
    else:
        print(f"Recommended posture for {who}. On a default-drop input chain (nftables):")
    if is_anchor:
        print(f"  udp dport {{ {listen_port}, {DOOR_PORT} }} accept   # WireGuard (underlay: mesh + door)")
    else:
        print(f"  udp dport {listen_port} accept              # WireGuard (underlay: mesh)")
    print("  iifname \"lo\" accept                    # this host talks to itself")
    if enforce_ports:
        # Enforcement on (default): greasewood's own nftables table filters the
        # overlay interfaces (control plane, enrollment + door lockdown, and the
        # grant-derived ports). The firewall just admits the overlay so that
        # table can act — it can only tighten what you admit, never open it.
        print("  iifname \"gw-*\" accept                  # admit the overlay; greasewood's")
        print("                                         # nftables table filters the ports on it")
    elif is_anchor:
        # Enforcement off on an anchor: greasewood installs no table, so YOU gate
        # its overlay ports. (These need nftables too; if you have it, prefer
        # leaving enforce_ports on and greasewood applies all of this.)
        print("  # (these need nftables; if you have it, prefer enforce_ports = true)")
        print(f"  iifname \"{mesh_iface}\" tcp dport {control_port} accept   # control plane")
        print(f"  iifname \"{DOOR_IFACE}\" tcp dport {ENROLL_PORT} accept   # enrollment")
        print(f"  iifname \"{DOOR_IFACE}\" drop                    # door carries ONLY enrollment")
    else:
        # Enforcement off on a plain node: no greasewood overlay service to gate,
        # just admit the overlay coarsely (no table to filter it).
        print(f"  iifname \"{mesh_iface}\" accept          # admit the overlay (no table filters it)")


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
    """
    try:
        r = subprocess.run(
            ["ip", "-6", "-o", "addr", "show", "scope", "global"],
            capture_output=True, text=True, check=False,
        )
    except FileNotFoundError:
        return None

    stable, temporary, any_gua = [], [], []

    for line in r.stdout.splitlines():
        # Format: <idx>: <iface>    inet6 <addr/prefix> scope global [flags...]
        parts = line.split()
        if len(parts) < 4 or parts[2] != "inet6":
            continue
        try:
            addr = ipaddress.IPv6Address(parts[3].split("/")[0])
        except ValueError:
            continue

        # GUA: 2000::/3  (first 3 bits == 001)
        if addr.packed[0] & 0xe0 != 0x20:
            continue

        flags = line
        is_temp = "temporary" in flags
        is_deprecated = "deprecated" in flags

        if not is_deprecated and not is_temp:
            stable.append(str(addr))
        elif not is_deprecated:
            temporary.append(str(addr))
        else:
            any_gua.append(str(addr))

    return (stable or temporary or any_gua or [None])[0]


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
    try:
        r = subprocess.run(
            ["ip", "-4", "-o", "addr", "show", "scope", "global"],
            capture_output=True, text=True, check=False,
        )
    except FileNotFoundError:
        return None
    for line in r.stdout.splitlines():
        parts = line.split()
        if len(parts) < 4 or parts[2] != "inet":
            continue
        try:
            addr = ipaddress.IPv4Address(parts[3].split("/")[0])
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
    for fam, flag in ((6, "-6"), (4, "-4")):
        try:
            r = subprocess.run(["ip", flag, "route", "show", "default"],
                               capture_output=True, text=True, check=False)
            if r.stdout.strip():
                fams.add(fam)
        except FileNotFoundError:
            pass
    return fams or {4, 6}


def _pick_reachable_host(hosts: list[str]) -> str:
    """From candidate bare underlay hosts (v6 and/or v4), pick one this node can
    originate on. Order matters — callers list v6 first — so a dual-stack node
    prefers v6. Falls back to the first host if no family matches."""
    fams = _local_families()
    for h in hosts:
        fam = 6 if ":" in h else 4
        if fam in fams:
            return h
    return hosts[0]


def _endpoint_with_port(explicit: str, listen_port: int) -> str:
    """Normalize an operator-supplied --endpoint to a formatted wg endpoint.
    Accepts a bare address ('1.2.3.4', 'fd8d::1'), a bracketed v6 ('[fd8d::1]'),
    or a full endpoint ('1.2.3.4:51900', '[fd8d::1]:51900')."""
    from . import wg as wgmod
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
    from . import wg as wgmod
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


def _enforce_ports_default() -> bool:
    """The enforce_ports value to write into a fresh config (create/join): on
    iff nftables is usable on this host right now. An nft-less host is written
    `enforce_ports = false` explicitly, so its daemon never trips the startup
    guard — the restart-loop this avoids."""
    from .portfilter import nft_usable
    if nft_usable():
        return True
    log.warning("nftables not usable here — writing enforce_ports = false "
                "(port scopes advisory; grants still gate which tunnels exist). "
                "Install nftables and set enforce_ports = true to enforce ports.")
    return False


def _daemon_fatal(cfg, msg: str):
    """Exit the daemon on an unrecoverable STARTUP condition — but VISIBLY.
    Under the systemd unit's Restart=on-failure, a bare sys.exit is about the
    most invisible failure possible: a silent 5s restart loop. This makes it
    loud on both channels the operator actually watches:
      - CRITICAL to the journal (`logs :` in the watch header points here);
      - a breadcrumb `gw watch` surfaces as the daemon's death reason, so you
        don't have to already know to read journalctl.
    The unit also bounds the loop (StartLimit) so it lands in a `failed` state
    rather than thrashing forever. Then exit non-zero (systemd sees the failure)."""
    from . import reconcile as rmod
    log.critical("FATAL: cannot start daemon: %s", msg)
    try:
        rmod.write_daemon_fatal(cfg.data_dir, msg)
    except Exception as e:                       # never mask the real cause
        log.warning("could not write daemon-fatal breadcrumb: %s", e)
    sys.exit(msg)


def _make_port_enforcer(cfg, args, grant_policy):
    """Decide port enforcement for `gw run`: return a PortFilter (enforcing) or
    None (unenforced). `gw create`/`gw join` write [network] enforce_ports
    explicitly (on iff nftables was usable then); --no-enforce-ports overrides
    for this run.

    Crucially this NEVER raises or exits on a missing/broken nftables — it
    degrades to None with a loud error. Exiting here would be a systemd restart
    loop that never resolves (exactly the bug an nft-less host hit). An
    unenforced node still peers per policy — grants gate which tunnels exist
    regardless; only the per-port scopes within them drop to advisory."""
    from . import reconcile as _rec
    if not (cfg.enforce_ports and not getattr(args, "no_enforce_ports", False)):
        log.info("port enforcement OFF (enforce_ports=false): grants still "
                 "control which tunnels exist; port scopes are advisory")
        _rec.clear_enforce_degraded(cfg.data_dir)    # OFF is deliberate, not degraded
        return None
    from .portfilter import (PortFilter, NftUnavailable, ensure_available,
                             table_name)
    from .config import membership_key
    try:
        ensure_available()
    except NftUnavailable as e:
        log.error("port enforcement requested (enforce_ports=true) but "
                  "nftables is unusable: %s", e)
        log.error("running WITHOUT port enforcement to avoid a crash loop — "
                  "install nftables, or set `enforce_ports = false` under "
                  "[network] in %s to make this the intended state.",
                  getattr(args, "config", "the config"))
        # Leave a breadcrumb so the unfiltered state is VISIBLE in gw watch /
        # --json, not just a line in the journal. (H2)
        _rec.write_enforce_degraded(cfg.data_dir, str(e))
        return None
    log.info("port enforcement ON: greasewood's own nftables table on %s "
             "(realizing the grant table — default-closed on a fresh anchor)",
             cfg.wg_interface)
    _rec.clear_enforce_degraded(cfg.data_dir)        # healthy
    return PortFilter(table_name(membership_key(cfg.mesh_domain)),
                      cfg.wg_interface, _control_port(cfg), cfg.caps, grant_policy,
                      local_hostname=cfg.hostname)


_IFACE_RE = re.compile(r"^[A-Za-z0-9_-]{1,15}$")


def _reject_bad_interface(name: str) -> None:
    """Refuse an interface name that isn't a valid Linux ifname (1-15 chars of
    [A-Za-z0-9_-]). The derived `gw-<mesh>` names always pass; this guards an
    operator-supplied --interface, whose value is interpolated verbatim into
    greasewood's `nft -f` ruleset and into filesystem paths — a `"`, newline, or
    `;` would otherwise break the ruleset render (falling open) or escape a path."""
    if not _IFACE_RE.match(name or ""):
        sys.exit(f"--interface {name!r} must be 1-15 characters of "
                 f"[A-Za-z0-9_-] (a valid Linux interface name)")


def cmd_create(args) -> int:
    _require_root("create")
    _require_tools()
    from .hosts import valid_label as _vl
    if not _vl(args.name):
        sys.exit(f"mesh name {args.name!r} must be a DNS label "
                 "(lowercase letters/digits/hyphens, e.g. 'prod-fleet')")
    if args.interface is not None:
        _reject_bad_interface(args.interface)
    from .keys import CAKeys, NodeKeys
    from .ca import CA
    from .wire import NodeRecord
    from .directory import Directory
    from .config import _parse_duration
    from .door import load_or_generate_door_key
    from . import wg as wgmod

    # Everything derives from the mesh name unless explicitly overridden —
    # nothing unsuffixed exists: the first mesh on a host is named like the Nth.
    _mp = _membership_paths(args.name)
    cfg_path = Path(args.config) if args.config else _mp["config"]
    data_dir = Path(args.data_dir) if args.data_dir else _mp["data_dir"]
    ca_key_path = data_dir / "ca.key"
    # The role is "anchor"; the hostname is just this machine's name by default
    # (short form, no domain), overridable with --hostname.
    from .keys import set_overlay_prefix, parse_overlay_prefix
    hostname = args.hostname or socket.gethostname().split(".")[0] or "anchor"
    listen_port = args.listen_port if args.listen_port is not None else _free_listen_port()
    control_port = args.control_port
    # The anchor's roles, each load-bearing:
    #   role:*      reach-all — it peers with every node (serves control + door).
    #   role:anchor the single-member name grants address it by (`to=["anchor"]`).
    #   role:admin  terminal access — makes the default-closed policy's ssh grant
    #               (`from admin -> to anchor,node : tcp/22`) open on every node
    #               FROM the anchor, so admin-only SSH bootstraps out of the box.
    # Plus any ability caps (--caps).
    caps = ["role:*", "role:anchor", "role:admin"]
    if args.caps:
        caps += [c.strip() for c in args.caps.split(",") if c.strip()]
    ttl = _parse_duration(args.credential_ttl)
    interface = args.interface or _mp["interface"]
    if args.interface is None:
        clash = _iface_collision(interface, cfg_path)
        if clash:
            sys.exit(f"derived interface name {interface!r} (gw- + first 12 "
                     f"chars of {args.name!r}) is already used by the membership "
                     f"at {clash} — pass an explicit --interface.")
    overlay_prefix = args.overlay_prefix
    # The mesh's ONE name domain, everywhere, forever (changed only by a
    # deliberate fleet-wide rename-mesh). Rides in every join token.
    mesh_domain = args.mesh_domain or f"{args.name}.internal"
    # Activate this fleet's overlay /64 before we derive the anchor's own address.
    try:
        set_overlay_prefix(parse_overlay_prefix(overlay_prefix))
    except Exception:
        sys.exit(f"invalid --overlay-prefix {overlay_prefix!r} (want e.g. fd12:3456:789a:0::)")

    endpoints = _advertised_endpoints(args.endpoint, listen_port)
    if endpoints:
        log.info("advertising underlay endpoint(s): %s", ", ".join(endpoints))

    data_dir.mkdir(parents=True, exist_ok=True)
    try:
        # 0755, not 0700: the dir holds world-readable public files (id_pub.hex,
        # directory.json, *.pub) that root-free commands like `gw watch --snapshot` read;
        # every secret inside is its own 0600 root-owned file. Root owns all of
        # it — state is never chowned to the invoking user (the CA key on a
        # login account would let that account mint credentials).
        os.chmod(data_dir, 0o755)
    except PermissionError:
        pass

    # CA keypair
    if ca_key_path.exists() and not args.force:
        ca_keys = CAKeys.load(ca_key_path)
        log.info("loaded existing CA key from %s", ca_key_path)
    else:
        regenerated = ca_key_path.exists()   # --force over a live mesh's CA
        ca_keys = CAKeys.generate()
        ca_keys.save(ca_key_path)
        log.info("generated CA key → %s", ca_key_path)
        if regenerated:
            # A new CA orphans everything signed by the old one. Say so NOW —
            # the failures otherwise surface later, on other machines, as
            # unexplained signature errors at join/renew (seen in the field).
            log.warning(
                "--force replaced the CA key: every outstanding invite token "
                "is now invalid, enrolled nodes stop renewing (re-enroll them "
                "or follow the re-root SOP in the RUNBOOK), and an "
                "already-RUNNING daemon keeps signing with the OLD key until "
                "restarted — run: %s, then "
                "mint fresh invites.", _svc_restart_hint(args.name))

    # Door keypair (persistent across invites)
    load_or_generate_door_key(data_dir)
    log.info("door key ready → %s/door.key", data_dir)

    # Set up door routing (idempotent — also called in gw run for reboots)
    wgmod.setup_door_routing()

    ca_pub_hex = ca_keys.ca_pub_bytes.hex()

    node_keys = NodeKeys.load_or_generate(data_dir)
    log.info("overlay addr: %s", node_keys.addr)

    cfg_path.parent.mkdir(parents=True, exist_ok=True)
    cfg_path.write_text(render_config(
        hostname=hostname, data_dir=data_dir, role="anchor", caps=caps,
        endpoints=endpoints, interface=interface, listen_port=listen_port,
        overlay_prefix=overlay_prefix, seeds=[],
        root_url=f"http://[::1]:{control_port}",
        hosts_sync=getattr(args, "hosts_sync", True), mesh_domain=mesh_domain,
        trusted_pubs=[ca_pub_hex], enforce_ports=_enforce_ports_default(),
        endpoint_auto=(args.endpoint is None),   # pinned iff --endpoint was given
        anchor={"ca_key_file": ca_key_path, "control_port": control_port,
                "credential_ttl": args.credential_ttl,
                "door_port": args.door_port}))
    log.info("wrote config → %s", cfg_path)

    # Drop the default grant table: DEFAULT-CLOSED (a secure star — only
    # role:admin, i.e. the anchor, can SSH nodes; nodes reach only the control
    # plane). Alternatives ship commented in the file. Idempotent: never clobber
    # an existing grants.toml on re-create.
    from .policy import GRANTS_BASENAME, DEFAULT_GRANTS_TOML, sign_default_policy
    grants_path = data_dir / GRANTS_BASENAME
    if not grants_path.exists():
        grants_path.write_text(DEFAULT_GRANTS_TOML)
        log.info("wrote default grant table → %s (default-closed: admin-only SSH)",
                 grants_path)
    # Sign it into policy.json v1 now, so the anchor has a real signed policy
    # sourced from grants.toml from birth — the daemon runs on grants.toml's
    # content, not an implicit default. The running daemon re-signs on edits.
    sign_default_policy(data_dir, ca_keys)

    ca = CA(ca_keys, data_dir, ttl)
    cred = ca.issue(node_keys.id_pub_bytes, node_keys.wg_pub_bytes, hostname, caps)

    dir_cache = data_dir / "directory.json"
    directory = Directory.load(dir_cache)
    existing = directory.get(node_keys.id_pub_hex)
    seq = (existing.seq + 1) if existing else 1
    record = NodeRecord(
        id_pub=node_keys.id_pub_bytes,
        seq=seq,
        endpoints=endpoints,
        cred=cred,
    ).sign(node_keys.id_priv)
    directory.put(record)
    directory.save(dir_cache)

    # The control plane binds the OVERLAY address (+loopback), so that's the URL
    # nodes use — not the underlay endpoint.
    control_url = f"http://[{node_keys.addr}]:{control_port}"

    print(f"\nAnchor setup complete.")
    print(f"  overlay addr : {node_keys.addr}")
    print(f"  CA pub key   : {ca_pub_hex}")
    print(f"  credential   : expires {cred.exp:%Y-%m-%d %H:%M UTC}")
    print()
    _print_daemon_guidance(args.name, cfg_path, "then invite nodes to enroll them",
                           no_service=getattr(args, "no_service", False))
    print()
    print(f"Enroll a new node:")
    print(f"  TOKEN=$(sudo gw invite)          # on this machine")
    print(f"  sudo gw join \"$TOKEN\" --hostname <name>   # on the new machine")
    print()
    _print_firewall_help(listen_port, control_port, interface)
    print()
    from . import firewall as _fw
    _fw.check(_fw.anchor_rules(listen_port, control_port, interface), log)
    return 0


# ---------------------------------------------------------------------------
# invite  (anchor — generate a join token and open a door window)
# ---------------------------------------------------------------------------

def _extract_token(text: str) -> str:
    """Pull the join token out of arbitrary text — a clean token, or the full
    stdout of `gw invite`. Returns the first line that looks like a token so
    `gw join -` works whether or not the producer used `invite -q`."""
    from .door import TOKEN_PREFIX
    for line in text.splitlines():
        s = line.strip()
        if s.startswith(TOKEN_PREFIX):
            return s
    s = text.strip()
    if s.startswith(TOKEN_PREFIX):
        return s
    sys.exit("no join token (gw1.…) found in input")


def _reject_reserved_roles(names, where: str) -> None:
    """Refuse any anchor-reserved role on an assignment path. Keeps 'anchor' a
    single-member role (only the create-time anchor holds it) and '*' (reach-all)
    unassignable to a joiner or node. `names` are bare role names (no role:)."""
    from .policy import RESERVED_ROLES
    bad = [r for r in names if r in RESERVED_ROLES]
    if bad:
        sys.exit(f"role(s) {', '.join(bad)} are reserved for the anchor and "
                 f"cannot be assigned via {where}: 'anchor' is single-member "
                 f"(the anchor is its sole member) and '*' is reach-all. Use a "
                 f"concrete role (e.g. node, web, admin).")


def _reject_derived_caps(caps) -> None:
    """Refuse anchor-DERIVED caps on the user-supplied caps path. `hostname-pinned`
    is added by the invite path itself, ONLY when --hostname fixes the name; hand-
    supplying it via --caps or [anchor] default_caps is always wrong — with no
    pinned name it marks a self-naming node permanently un-renameable, and on a
    --standing door it back-doors the "one pinned name for many nodes" state the
    --hostname + --standing guard forbids."""
    if "hostname-pinned" in caps:
        sys.exit("`hostname-pinned` can't be set via --caps/default_caps — it's "
                 "added automatically by --hostname. To pin a name, use "
                 "--hostname NAME (not on a --standing door).")


def _menu_from_grants(data_dir: "Path") -> list:
    """The role menu derived from grants.toml (`gw invite --self-roles-from-grants`):
    every role name referenced in any grant's from/to, minus the roles that must
    never be self-serve — the reserved set ('*', 'anchor'), the default 'node'
    (it's what a plain invite grants anyway), and 'admin' (fleet-wide terminal
    access doesn't belong on an auto-derived standing token; offer it explicitly
    with --self-roles if you mean it). grants.toml is the human-authored source
    of truth, so the menu tracks the policy vocabulary with no second list."""
    from .policy import parse_grants_toml, GRANTS_BASENAME, RESERVED_ROLES
    path = data_dir / GRANTS_BASENAME
    if not path.exists():
        sys.exit(f"--self-roles-from-grants: no {GRANTS_BASENAME} at {path} to "
                 f"derive a menu from")
    try:
        grants = parse_grants_toml(path.read_text())
    except ValueError as e:
        sys.exit(f"--self-roles-from-grants: {e}")
    referenced = {r for g in grants for r in (g["from"] + g["to"])}
    excluded = set(RESERVED_ROLES) | {"node", "admin"}
    # host: entries name a specific machine, not a role — a menu offering
    # "host:nas" would let any joiner self-select into another machine's
    # grants, so they are never menu material.
    menu = sorted(r for r in referenced - excluded if ":" not in r)
    if not menu:
        sys.exit("--self-roles-from-grants: grants.toml references no offerable "
                 "roles (only built-ins: " +
                 ", ".join(sorted(referenced & excluded)) + "). Add role-to-role "
                 "grants first, or list a menu explicitly with --self-roles.")
    return menu


def cmd_invite(args) -> int:
    _require_root("invite")
    if getattr(args, "quiet", False):
        # -q: emit only the token on stdout — silence the informational stderr
        # chatter (superseding-window warning, door/wg setup logs) for scripting.
        logging.getLogger().setLevel(logging.ERROR)
    from .config import load_config
    from .door import (
        generate_seed, derive_door_params, encode_token,
        load_or_generate_door_key, door_pub_bytes_from_key,
    )
    from . import wg as wgmod

    cfg = load_config(Path(args.config))
    if cfg.role != "anchor":
        sys.exit("gw invite must be run on the anchor node (role = anchor)")
    if cfg.ca_key_file is None:
        sys.exit("invite requires ca_key_file in [anchor]")

    # Preflight: a token is only redeemable if the daemon is up (it hosts the
    # enroll server) with its mesh interface present (it installs the joiner as
    # a peer). Catch both NOW, when the operator can act — not minutes later as
    # a cryptic rejection on the joining node.
    _mgr = _service_backend()
    _key = membership_key(cfg.mesh_domain)
    _start = (_mgr.restart_hint(_key) if _mgr
              else f"sudo systemctl start {_unit_for_config(args.config)}")
    _logs = (_mgr.logs_hint(_key) if _mgr
             else f"journalctl -u {_unit_for_config(args.config)} -n 20")
    if not wgmod.interface_exists(cfg.wg_interface):
        sys.exit(f"the anchor's mesh interface {cfg.wg_interface!r} doesn't exist — "
                 f"the daemon isn't running (or the interface was deleted under "
                 f"it). A joiner would be rejected at enrollment. Start the "
                 f"daemon first: {_start}   "
                 f"(or: sudo gw -c {args.config} run)\n"
                 f"If you already started it and this persists, it's crashing on "
                 f"startup — look at: {_logs}")
    import urllib.request as _url
    try:
        _url.urlopen(f"http://[::1]:{_control_port(cfg)}/directory", timeout=3)
    except Exception:
        sys.exit(f"the anchor daemon isn't answering on loopback (port "
                 f"{_control_port(cfg)}) — it hosts the enroll server, so this "
                 f"token could never be redeemed. Start it first: "
                 f"{_start}   "
                 f"(or: sudo gw -c {args.config} run)")

    data_dir = cfg.data_dir

    # The door is a single slot: a new invite regenerates the guest key and
    # overwrites the one window, so any previously issued-but-unused token
    # stops working. Warn (don't fail) if we're clobbering a still-open
    # window — for orderly provisioning, run the next invite only after the
    # current node has joined (the window clears automatically on success).
    if args.hostname and getattr(args, "standing", False):
        sys.exit("--hostname cannot be combined with --standing: a standing "
                 "door enrolls many nodes, which can't all share one pinned name")

    from . import door as doormod
    current_window = doormod.read_window(data_dir)
    if current_window and current_window.get("standing"):
        # Superseding a STANDING door invalidates the token baked into a whole
        # image/launch pipeline — that must never happen as a side effect of
        # inviting one laptop. Demand an explicit flag.
        if not getattr(args, "supersede", False):
            sys.exit("a STANDING door is open — a new invite would invalidate the "
                     "standing token everywhere it's baked (images, launch "
                     "templates). Close it deliberately first: sudo gw close-door"
                     "\n(or pass --supersede to replace it in one step)")
        log.warning("superseding the STANDING door — its token is now INVALID "
                    "everywhere it was distributed.")
    elif current_window is not None:
        log.warning(
            "superseding an open door window (expires %s) — the previously "
            "issued token is now INVALID. The door enrolls one node at a time; "
            "run the next invite only after the current node has joined.",
            current_window.get("expires"),
        )

    door_key_raw = load_or_generate_door_key(data_dir)
    anchor_door_pub = door_pub_bytes_from_key(door_key_raw)
    door_key_b64 = base64.b64encode(door_key_raw).decode()

    from .keys import CAKeys
    ca_keys = CAKeys.load(cfg.ca_key_file, _get_passphrase(cfg.ca_key_passphrase_env))

    # Anchor underlay host(s) for the token (bare addresses; the joiner adds the
    # door port). Carry v6 and/or v4 so a joiner reaches the anchor over whichever
    # family it has — stored comma-separated in the token's single host field
    # (a v6 literal has colons but never commas, so the split is unambiguous).
    if args.endpoint:
        anchor_hosts = [args.endpoint]
    else:
        anchor_hosts = []
        v6 = _detect_public_ipv6()
        if v6:
            anchor_hosts.append(v6)
        v4 = _detect_public_ipv4()
        if v4:
            anchor_hosts.append(v4)
        if not anchor_hosts:
            sys.exit("could not detect a public address; use --endpoint <addr>")
    endpoint = ",".join(anchor_hosts)

    window = cfg.door_window

    # The anchor decides caps + roles HERE and issues them to whoever redeems the
    # token — the joiner does not choose (no self-assertion). They're stored in
    # the door window; the enroll server issues from them, ignoring the joiner's.
    #   roles (role:<name>) are the grant-table vocabulary (who-talks-to-whom).
    #   --caps grants abilities, e.g. tls.
    # When a flag is omitted, fall back to the anchor's configured defaults for new
    # nodes ([anchor] default_roles / default_caps, read fresh each invite — so
    # editing them changes what future enrollments get). --roles/--caps
    # override for this one token.
    # Role MENU (--self-roles): the joiner self-selects a subset of these at
    # `gw join --roles`, letting ONE standing invite provision many classes. The
    # anchor still CA-signs the result, and the joiner can never land outside the
    # menu (subset-checked at enroll) — bounded self-selection, not self-assertion.
    # A menu invite's BASE carries no default role: the joiner opts into a class
    # (explicit beats implicit for provisioning); --roles still adds a fixed base.
    # NEVER offer '*' (reach-all) as self-serve — that's the anchor's role.
    # --self-roles-from-grants derives the menu from grants.toml instead of a
    # hand-typed list, so the policy vocabulary IS the provisioning menu.
    if getattr(args, "self_roles_from_grants", False):
        if getattr(args, "self_roles", None):
            sys.exit("--self-roles and --self-roles-from-grants are mutually "
                     "exclusive: list the menu yourself, or derive it — not both.")
        allowed_roles = _menu_from_grants(cfg.data_dir)
        log.info("role menu derived from grants.toml: %s (excluded: *, anchor, "
                 "node, admin — list admin explicitly via --self-roles to offer it)",
                 ",".join(allowed_roles))
    else:
        allowed_roles = ([r.strip() for r in args.self_roles.split(",") if r.strip()]
                         if getattr(args, "self_roles", None) else [])
    _reject_reserved_roles(allowed_roles, "--self-roles")   # never self-serve *, anchor
    if args.roles is not None:
        roles = [r.strip() for r in args.roles.split(",") if r.strip()]
        _reject_reserved_roles(roles, "--roles")
        # --roles ADDS the class on top of the default membership role(s)
        # ([anchor] default_roles, ships as 'node') rather than replacing them:
        # a web box is still an ordinary member, and the fleet grants that
        # target 'node' (the shipped admin ssh, ...) should keep covering it.
        # --exact makes --roles the complete list.
        if not getattr(args, "exact", False):
            extra = [r for r in cfg.default_roles if r not in roles]
            if extra:
                roles += extra
                print(f"roles: {args.roles} + default {','.join(extra)} "
                      f"(--exact for exactly --roles)")
    elif allowed_roles:
        roles = []                                 # menu invite → no default role
    else:
        roles = list(cfg.default_roles)
    caps = ["role:" + r for r in roles]
    if args.caps is not None:
        caps += [c.strip() for c in args.caps.split(",") if c.strip()]
    else:
        caps += list(cfg.default_caps)
    # Screen the MERGED caps too, not just --roles/--self-roles: --caps and the
    # [anchor] default_caps/default_roles are also role-assignment paths, so a
    # stray `role:*`/`role:anchor` there would bypass the reserved-role guard
    # every other path enforces (mirrors cmd_set_caps). (L4)
    _reject_reserved_roles([c[len("role:"):] for c in caps if c.startswith("role:")],
                           "the invite's caps/default_roles")
    # `hostname-pinned` is DERIVED: the --hostname path re-adds it below, and only
    # there. Screen it out of the user-supplied caps first (see the helper). (L4-adjacent)
    _reject_derived_caps(caps)
    # --hostname pins the name: the anchor fixes it at enrollment (the joiner's
    # requested name is ignored) and marks the credential `hostname-pinned` so the
    # node can't rename itself afterward. Without it, the node names itself at
    # join and may `gw rename-node` later (today's behavior).
    pinned_hostname = args.hostname
    if pinned_hostname:
        # The anchor is choosing the name, so it verifies uniqueness NOW — a pinned
        # name is guaranteed free before the token goes out, so it can't collide
        # at enrollment (the joiner can't fix a name it didn't pick). Unpinned
        # names are still checked at enroll, where the node can retry a new one.
        from .ca import CA as _CA
        owner = _CA(ca_keys, data_dir).hostname_owner(pinned_hostname)
        if owner is not None:
            sys.exit(
                f"hostname {pinned_hostname!r} is already in use (node {owner[:16]}…). "
                "Free it first (revoke + remove the old node on the anchor) or pin a "
                "different name."
            )
        caps.append("hostname-pinned")
    caps = list(dict.fromkeys(caps))          # de-dup, order-preserving
    log.info("this token grants caps=%s%s%s", caps,
             f"; self-select roles from {allowed_roles}" if allowed_roles else "",
             f"; hostname pinned to {pinned_hostname!r}" if pinned_hostname else "")

    seed = generate_seed()
    params = derive_door_params(seed)

    # Set up door routing (idempotent — survives reboots if called here too)
    wgmod.setup_door_routing()

    # Bring up the anchor's door WG interface on the configured door port
    door_key_path = data_dir / "door.key"
    from . import audit
    audit.attach_file(data_dir / "audit.log")   # one-shot door commands → the trail
    with audit.context("invite: bring up anchor door interface"):
        wgmod.ensure_anchor_door_interface(door_key_path, params.guest_pub_b64,
                                        params.psk_b64, cfg.door_port)

    # Write window file so the running gw-run daemon starts the enroll server.
    window_path = data_dir / "door_window.json"
    token = encode_token(anchor_door_pub, ca_keys.ca_pub_bytes, endpoint, seed,
                         cfg.door_port, mesh_domain=cfg.mesh_domain,
                         self_roles=allowed_roles)

    if getattr(args, "standing", False):
        # STANDING door: no expiry; serves any number of enrollments until
        # `gw close-door` (or a --supersede invite). The guest key + PSK are
        # persisted (0600, same posture as door.key) so the daemon can re-erect
        # the door interface after a reboot — the window outlives the kernel
        # state. Every join is still the full one-node ceremony: fresh identity,
        # CA-signed credential, blackhole isolation, audit trail.
        # The token itself is stored too: a standing token is long-lived and
        # bakeable, so the operator can re-retrieve it later (via anchor `gw
        # status`) without re-issuing — re-issuing would invalidate the copies
        # already baked into images. Same 0600-root posture as the guest key.
        # atomic_write => 0600 from creation (mkstemp), so the PSK/token never sit
        # world-readable in a pre-chmod window a co-tenant could race. Same
        # primitive every other secret file uses.
        from .keys import atomic_write
        atomic_write(window_path, json.dumps({
            "v": 1,
            "standing": True,
            "caps": caps,
            "allowed_roles": allowed_roles,   # menu: roles a joiner may self-select
            "hostname": None,          # standing doors can't pin one name
            "guest_pub": params.guest_pub_b64,
            "psk": params.psk_b64,
            "token": token,
        }), mode=0o600)
        log.info("STANDING door opened — this token enrolls any number of "
                 "nodes until: sudo gw close-door")
    else:
        expires = dt.datetime.now(dt.timezone.utc) + window
        # atomic_write (0600 from creation) — no world-readable pre-chmod window.
        # No key material here (the timed door isn't persisted for reboot), but it
        # discloses the caps/roles being granted, and consistency avoids the L6
        # class of bug entirely. (L1)
        from .keys import atomic_write
        atomic_write(window_path, json.dumps({
            "v": 1,
            "expires": expires.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "caps": caps,
            "allowed_roles": allowed_roles,   # menu: roles a joiner may self-select
            "hostname": pinned_hostname,   # None → joiner names itself (unpinned)
        }), mode=0o600)

    print(token)
    return 0


def cmd_close_door(args) -> int:
    """[anchor] Close the current door window — the issued token (standing or
    single-use) is permanently invalid from this moment: the guest key and PSK
    live only in the window, and seeds are never reused, so nothing can ever
    handshake against it again. Enrolled nodes are untouched (their credentials
    come from the CA, not the door). This is the revocation half of standing-
    token rotation; the next `gw invite --standing` mints the new epoch."""
    from .config import load_config
    from . import door as doormod
    from . import wg as wgmod

    _require_root("close-door", "it removes the anchor's door window and interface")
    cfg = load_config(Path(args.config))
    if cfg.role != "anchor":
        sys.exit("gw close-door must be run on the anchor (role = anchor)")

    window = doormod.read_window(cfg.data_dir)
    wpath = doormod.window_path(cfg.data_dir)
    existed = wpath.exists()
    wpath.unlink(missing_ok=True)
    # Take the interface down NOW for an immediate kill; the daemon's watcher
    # notices the missing window within a tick and stops the enroll server.
    wgmod.destroy_interface(doormod.DOOR_IFACE)
    try:
        doormod.mark_door_closed(cfg.data_dir, "closed by operator (close-door)")
    except Exception:
        pass

    if not existed:
        print("no door window was open — nothing to close (interface torn down "
              "if it existed).")
        return 0
    kind = "standing" if (window or {}).get("standing") else "single-use"
    print(f"{kind} door closed — its token is now permanently invalid everywhere "
          f"it was distributed. Enrolled nodes are unaffected.")
    if kind == "standing":
        print("Rotate: sudo gw invite --standing ...  (fresh seed → fresh token)")
    return 0


# ---------------------------------------------------------------------------
# join  (new node — door-based enrollment, no SSH)
# ---------------------------------------------------------------------------

# Memberships are keyed by the MESH NAME (given once at `gw create <name>`,
# carried in every join token as <name>.internal). Nothing is unsuffixed and
# nothing is numbered: the very first mesh on a host gets the same name-derived
# artifacts as the fifth — /etc/greasewood_<name>.toml, /var/lib/
# greasewood_<name>, interface gw-<name[:12]>, service greasewood@<name>.
# Explicit flags override any derived value.

def _membership_paths(key: str, etc: "Path" = Path("/etc"),
                      var: "Path" = Path("/var/lib")) -> dict:
    """The derived artifacts for membership `key`. The interface truncates to
    the kernel's 15-char limit (gw- + 12); a truncation collision between two
    memberships is a loud join/create-time refusal, never a silent rename."""
    return {
        "config": etc / f"greasewood_{key}.toml",
        "data_dir": var / f"greasewood_{key}",
        "interface": f"gw-{key[:12].rstrip('-')}",
        "unit": f"greasewood@{key}",
    }


def _memberships(etc: "Path" = Path("/etc")) -> "list[tuple[str, Path]]":
    """Existing membership configs on this host as (key, config_path)."""
    out = []
    for p in etc.glob("greasewood_*.toml"):
        m = re.fullmatch(r"greasewood_([a-z0-9-]+)\.toml", p.name)
        if m:
            out.append((m.group(1), p))
    return sorted(out)


def _anchor_membership(etc: "Path" = Path("/etc")) -> "tuple[str, Path] | None":
    """The (key, config_path) of a role=anchor membership on this host, or None.

    `gw join` refuses on an anchor host: the enrollment door is a shared singleton
    (one gw-door interface, one door subnet, one policy-routing table), so the
    anchor's permanent door isolation would blackhole any join this host attempts
    — it hangs at 'connecting to enroll daemon'. Better to refuse loudly up front."""
    from .config import load_config
    for key, p in _memberships(etc):
        try:
            if getattr(load_config(p), "role", "node") == "anchor":
                return key, p
        except Exception:
            continue
    return None


def _membership_for_ca(ca_pub_hex: str, etc: "Path" = Path("/etc")) -> "str | None":
    """The membership key already trusting this CA, or None. This is how a
    token is routed: its CA pub identifies WHICH mesh it belongs to, so a token
    for a mesh we're already on refreshes that membership (even after a re-root
    — trusted_pubs carries old+new during migration), and an unknown CA means a
    genuinely new mesh."""
    from .config import load_config
    for key, p in _memberships(etc):
        try:
            if ca_pub_hex in load_config(p).ca_pubs_hex:
                return key
        except Exception:
            continue
    return None


def _free_listen_port(etc: "Path" = Path("/etc")) -> int:
    """First of 51900, 51910, 51920, … claimed by neither an existing membership
    config NOR a live WireGuard interface. The latter matters: a purged mesh can
    leave a kernel interface still bound to its port with no config to show for
    it, and picking that port would crash the new daemon at interface-up with
    EADDRINUSE."""
    from .config import load_config
    used = set()
    for _k, p in _memberships(etc):
        try:
            used.add(load_config(p).listen_port)
        except Exception:
            continue
    try:
        from . import wg as wgmod
        used.update(wgmod.wg_interface_ports().values())
    except Exception:
        pass
    port = 51900
    while port in used:
        port += 10
    return port


def _iface_collision(iface: str, cfg_path: "Path",
                     etc: "Path" = Path("/etc")) -> "Path | None":
    """Another membership already using `iface` (the 15-char truncation can
    collide for long names sharing a 12-char prefix), or None."""
    from .config import load_config
    for _k, p in _memberships(etc):
        if p.resolve() == Path(cfg_path).resolve():
            continue
        try:
            if load_config(p).wg_interface == iface:
                return p
        except Exception:
            continue
    return None


def _discover_config(etc: "Path" = Path("/etc")) -> "Path":
    """Resolve the config when -c wasn't given: exactly one membership → use it
    (the single-mesh experience needs no flags); several → demand -c, loudly;
    none → say how to start."""
    ms = _memberships(etc)
    if len(ms) == 1:
        return ms[0][1]
    if not ms:
        sys.exit("no greasewood mesh is configured on this host — run "
                 "'sudo gw create <name>' (anchor) or 'sudo gw join <token>' first")
    listing = "\n".join(f"  -c {p}   ({k})" for k, p in ms)
    sys.exit(f"this host is on {len(ms)} meshes — say which one:\n{listing}")


def _warn_shared_overlay_prefix(cfg_path: "Path", my_prefix: str,
                                etc: "Path" = Path("/etc")) -> bool:
    """Warn when another membership on this host uses the same overlay /64.
    NOT a functional failure — greasewood's data plane is /128-only (address,
    kernel route, and WireGuard allowed-ip are all identity-derived host
    routes), so two meshes on one prefix never produce an ambiguous route.
    What a shared prefix DOES break is prefix-based reasoning: a firewall rule
    or script scoped to the /64 now silently matches BOTH meshes, and an
    address no longer tells a human which mesh it belongs to. Returns True if
    it warned (for tests)."""
    from .config import load_config
    try:
        mine = ipaddress.ip_network(f"{my_prefix}/64")
    except ValueError:
        return False
    for n, p in _memberships(etc):
        if p.resolve() == Path(cfg_path).resolve():
            continue
        try:
            theirs = ipaddress.ip_network(f"{load_config(p).overlay_prefix}/64")
        except Exception:
            continue
        if theirs == mine:
            log.warning(
                "this mesh uses the SAME overlay /64 (%s) as membership %r "
                "(%s). Everything still works — greasewood routes only "
                "identity-derived /128s, never the /64 — but the prefix no "
                "longer identifies a mesh on this host: any firewall rule or "
                "script scoped to %s now matches BOTH meshes, and addresses "
                "are indistinguishable by eye. For legibility, create meshes "
                "with distinct `create --overlay-prefix`.",
                mine, n, p, mine)
            return True
    return False


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
    return service.systemctl_run(argv, timeout=_SYSTEMCTL_TIMEOUT, **kwargs)


def _membership_service(key: str) -> str:
    """Enable this membership's daemon as greasewood@<key>; return the settle
    state ('active' / 'failed' / 'manual'). Thin wrapper over
    service.enable_systemd_now that injects cli's patchable run/settle seams."""
    return service.enable_systemd_now(
        _UNIT_DIR, key, run=_systemctl_run, settle=_wait_service_settled)


def _migrate_membership(cfg_path: "Path", new_key: str,
                        etc: "Path" = Path("/etc"),
                        var: "Path" = Path("/var/lib")) -> "Path":
    """Move a membership old-name → new-name: config file, data dir, kernel
    interface, systemd instance, name domain — everything is keyed to the mesh
    name, so a rename renames it all (brief tunnel blip at the interface
    rename). Leaves the OLD domain's /etc/hosts block in place and drops a
    grace marker in the new data dir: the daemon keeps old names resolving
    until the grace deadline, then retires them. Returns the new config path."""
    from .config import load_config
    from . import wg as wgmod

    cfg = load_config(cfg_path)
    old_key = membership_key(cfg.mesh_domain)
    new_domain = f"{new_key}.internal"
    mp = _membership_paths(new_key, etc=etc, var=var)
    if mp["config"].exists():
        sys.exit(f"{mp['config']} already exists — is this host already on a "
                 f"mesh named {new_key!r}?")
    clash = _iface_collision(mp["interface"], mp["config"], etc=etc)
    if clash:
        sys.exit(f"derived interface {mp['interface']!r} is already used by "
                 f"{clash} — rename to something whose first 12 chars differ")

    svc_mgr = _service_backend()
    if svc_mgr is not None:
        svc_mgr.disable_now(old_key)       # stop + de-boot the old instance

    # Data dir moves first (the new config points at it).
    new_data = mp["data_dir"]
    if Path(cfg.data_dir).resolve() != new_data.resolve():
        shutil.move(str(cfg.data_dir), str(new_data))

    if wgmod.interface_exists(cfg.wg_interface):
        wgmod.rename_interface(cfg.wg_interface, mp["interface"])

    # Rewrite the three name-keyed fields; everything else carries over.
    text = cfg_path.read_text()
    text = re.sub(r'(?m)^mesh_domain\s*=.*$',
                   f'mesh_domain = "{new_domain}"', text)
    text = re.sub(r'(?m)^interface\s*=.*$',
                   f'interface = "{mp["interface"]}"', text)
    text = re.sub(r'(?m)^data_dir\s*=.*$',
                   f'data_dir = "{new_data}"', text)
    mp["config"].write_text(text)
    cfg_path.unlink()

    # Re-point the TLS cert manifest at the new domain: each managed cert's
    # SANs move old→new so renewals AFTER grace use the new names; during
    # grace the cert loop adds the old name back as an extra SAN, so clients
    # dialing either verify throughout (see certs._grace_dual_names).
    _rewrite_cert_manifest_domain(new_data, cfg.mesh_domain, new_domain)

    # This membership just migrated — drop the pending-rename flag the sync
    # loop raised (a member adopting the anchor's rename), so `gw watch` clears.
    (new_data / "pending_rename.json").unlink(missing_ok=True)

    # Grace: old names keep resolving for one credential TTL, then retire.
    until = (dt.datetime.now(_UTC) + cfg.credential_ttl).replace(microsecond=0)
    (new_data / "rename_grace.json").write_text(json.dumps(
        {"old_domain": cfg.mesh_domain, "until": until.isoformat()}))

    if svc_mgr is not None and svc_mgr.template_installed():
        svc_mgr.enable_now(new_key)        # symlink/enable + start the new instance
    return mp["config"]


def _rewrite_cert_manifest_domain(data_dir: "Path", old_domain: str,
                                  new_domain: str) -> None:
    """Swap old_domain → new_domain in every managed cert's SANs/CN, so cert
    auto-renewal targets the mesh's new names once the rename grace ends. A
    no-op if there's no manifest. Explicit non-mesh SANs are left untouched."""
    from . import certs as certmod
    mpath = certmod.manifest_path(data_dir)
    if not mpath.exists():
        return
    try:
        entries = json.loads(mpath.read_text())
    except (OSError, ValueError):
        return

    def _swap(name: str) -> str:
        return (name[: -len(old_domain)] + new_domain
                if name.endswith("." + old_domain) else name)

    for e in entries:
        e["dns"] = [_swap(n) for n in e.get("dns", [])]
        if e.get("cn"):
            e["cn"] = _swap(e["cn"])
    try:
        mpath.write_text(json.dumps(entries, indent=2))
    except OSError:
        pass


def cmd_rename_mesh(args) -> int:
    """Rename THIS membership's mesh — domain, config, data dir, interface,
    service — in one consistent move. Run on the ANCHOR to rename the mesh itself
    (members are then told on their next directory poll, with the exact command
    to migrate themselves); run on a member to adopt a rename the anchor already
    made."""
    from .config import load_config
    from .hosts import valid_label

    _require_root("rename-mesh", "it moves this mesh's config/state/interface")
    if not valid_label(args.new_name):
        sys.exit(f"mesh name {args.new_name!r} must be a DNS label "
                 "(lowercase letters/digits/hyphens)")
    cfg_path = Path(args.config)
    cfg = load_config(cfg_path)
    old_domain = cfg.mesh_domain
    new_cfg = _migrate_membership(cfg_path, args.new_name)

    print(f"mesh renamed: {old_domain} → {args.new_name}.internal")
    print(f"  config    : {new_cfg}")
    print(f"  data dir  : /var/lib/greasewood_{args.new_name}")
    print(f"  interface : gw-{args.new_name[:12].rstrip('-')}")
    print(f"  service   : greasewood@{args.new_name} (old instance disabled)")
    print(f"Old *.{old_domain} names keep resolving for one credential TTL, "
          f"then retire.")
    if cfg.role == "anchor":
        print("Members will see the rename on their next directory poll and be "
              "told to run:  sudo gw rename-mesh " + args.new_name)
        print("New invites/tokens already carry the new name.")
    return 0


def _republish_own_record(cfg, keys, directory, *, cred=None, endpoints=None,
                          aliases=None, reachable=None, push_to=(),
                          quiet_push=False):
    """Re-sign this node's record (seq+1) carrying forward whatever isn't
    overridden, save the cache, and best-effort push. Renewal, rename,
    config-refresh, and the reachable-set publish ALL go through here — the
    directory is the single seq source, so they compose with no shared state.
    Returns the new record, or None if there's nothing to re-sign yet (no
    record and no fresh credential supplied)."""
    from .wire import NodeRecord
    from .sync import push_record
    existing = directory.get(keys.id_pub_hex)
    if existing is None and cred is None:
        return None

    def carry(override, attr, default):
        if override is not None:
            return list(override)
        return list(getattr(existing, attr)) if existing else default

    record = NodeRecord(
        id_pub=keys.id_pub_bytes,
        seq=(existing.seq + 1) if existing else 1,
        endpoints=carry(endpoints, "endpoints", list(cfg.endpoints)),
        cred=cred if cred is not None else existing.cred,
        aliases=carry(aliases, "aliases", _config_aliases(cfg)),
        reachable=carry(reachable, "reachable", []),
    ).sign(keys.id_priv)
    directory.put(record)
    directory.save(cfg.dir_cache_path)
    for url in push_to:
        try:
            push_record(url, record)
        except Exception as e:
            (log.debug if quiet_push else log.warning)(
                "published locally but push to %s failed (will sync): %s", url, e)
    return record


def _enroll_over_door(*args, **kwargs):
    """Crash guard around the door dance: the inner function's graceful
    refusals tear gw-door down themselves before sys.exit, but a CRASH path
    (missing binary, Ctrl-C mid-wait, unexpected error) used to leave the
    half-made interface behind (seen in the field). On success the door is
    deliberately left UP — the caller pushes the signed record back through
    it."""
    from . import wg as wgmod
    try:
        return _enroll_over_door_inner(*args, **kwargs)
    except SystemExit:
        raise                     # graceful paths already tore the door down
    except BaseException:
        try:
            wgmod.destroy_interface("gw-door")   # idempotent; no-op if never made
        except Exception:
            pass                  # e.g. `ip` itself missing — nothing to clean
        raise


def _enroll_over_door_inner(data_dir, node_keys, hostname: str, anchor_host: str,
                            anchor_door_pub_b64: str, params, door_port,
                            ca_pub_bytes: bytes, already_enrolled: bool,
                            requested_roles: "list | tuple" = ()):
    """The door dance: bring up the transient gw-door interface, connect to the
    anchor's enroll daemon through it, exchange request → credential, and
    verify the credential against the token's CA. Every failure exits with an
    actionable message (tearing the door down first). On success the door is
    left UP and the socket OPEN: the caller pushes its signed record back on
    the same connection as the second leg, then tears down. Returns
    (conn, resp, cred)."""
    from . import wg as wgmod
    from .wire import Credential

    # Bring up the local door interface (door port comes from the token)
    from . import audit
    audit.attach_file(data_dir / "audit.log")   # one-shot door commands → the trail
    with audit.context("join: bring up node door interface"):
        wgmod.ensure_node_door_interface(
            params.guest_priv_bytes, anchor_door_pub_b64, params.psk_b64, anchor_host,
            door_port,
        )

    # Connect to anchor's enroll daemon via the door tunnel (retry for WG handshake)
    from .door import ANCHOR_DOOR_IP, ENROLL_PORT
    log.info("connecting to enroll daemon at [%s]:%d ...", ANCHOR_DOOR_IP, ENROLL_PORT)
    conn: socket.socket | None = None
    for attempt in range(15):
        try:
            s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((ANCHOR_DOOR_IP, ENROLL_PORT))
            conn = s
            break
        except OSError:
            if attempt < 14:
                time.sleep(1)
    if conn is None:
        wgmod.destroy_interface("gw-door")
        sys.exit(f"could not connect to enroll daemon at [{ANCHOR_DOOR_IP}]:{ENROLL_PORT} — is the anchor daemon running and the token valid?")

    # The 5s above was only for *reaching* the daemon. The exchange itself (the
    # anchor signs a credential, runs `wg set peer`, merges our record, and replies)
    # can take much longer when the anchor is under load — e.g. enrolling a burst of
    # nodes while already serving a large mesh — so give it a generous timeout.
    # Both legs (cred fetch + record push) share this socket.
    conn.settimeout(30)

    # Send enroll request. `roles` is the joiner's self-selection for a menu
    # invite (`gw join --roles`); the anchor authorizes it against the window's
    # menu and ignores it entirely for a classic invite — never trusted as-is.
    req = {
        "v": 1,
        "id_pub": node_keys.id_pub_hex,
        "wg_pub": node_keys.wg_pub_b64,
        "hostname": hostname,
        "roles": list(requested_roles),
    }
    # Proof-of-possession: sign id_pub↔wg_pub↔hostname with id_priv, so the anchor
    # can confirm we actually hold the private key for the id_pub we present — the
    # door seed alone can't (id_pubs are public). Blocks a token holder enrolling
    # under someone else's identity.
    import base64 as _b64mod
    from .wire import enroll_pop_body
    req["id_sig"] = _b64mod.b64encode(node_keys.id_priv.sign(
        enroll_pop_body(node_keys.id_pub_bytes, node_keys.wg_pub_bytes,
                        hostname or ""))).decode()
    from .door import recv_msg as _recv_framed, send_msg as _send_framed

    # Leave the connection OPEN after the response — we send our signed record
    # back on it as a second leg (see below).
    try:
        _send_framed(conn, req)
        resp = _recv_framed(conn)
    except Exception as e:
        conn.close()
        wgmod.destroy_interface("gw-door")
        sys.exit(f"enroll RPC failed: {e}")

    if not resp.get("ok"):
        wgmod.destroy_interface("gw-door")
        msg = f"enrollment rejected: {resp.get('error')} — {resp.get('reason')}"
        left = resp.get("attempts_remaining")
        if isinstance(left, int) and left > 0:
            # The anchor keeps the door open for a few attempts — retry on the SAME
            # token (it rebuilds the door tunnel and reconnects).
            plural = "s" if left != 1 else ""
            msg += (f"\n{left} attempt{plural} left in this window — fix it and retry:\n"
                    f"  sudo gw join <token> --hostname <unique-name>")
        else:
            msg += ("\nNo attempts left — run 'sudo gw invite' on the anchor for a "
                    "fresh token.")
        sys.exit(msg)

    # Verify and install the credential (gw-door still up — needed for door publish below)
    cred = Credential.from_dict(resp["credential"])
    try:
        cred.verify([ca_pub_bytes])
    except Exception as e:
        wgmod.destroy_interface("gw-door")
        hint = ""
        if "no trusted CA signature" in str(e):
            # The door key matched (we got this far through the tunnel) but the
            # CA didn't: the classic cause is an anchor re-created after its
            # daemon started — the daemon signs with the stale in-memory CA
            # while this token carries the new disk one. (New anchors refuse
            # this at issue time; the hint covers older ones.)
            hint = ("\nThe anchor answered through the door this token pinned, "
                    "but signed with a CA key the token doesn't carry. If the "
                    "anchor was re-created since its daemon started, the daemon "
                    "is signing with a stale in-memory CA — on the anchor:\n"
                    "  sudo systemctl restart greasewood@<mesh>\n"
                    "  sudo gw invite     # mint the token AFTER the restart")
        sys.exit(f"credential verification failed: {e}{hint}")

    return conn, resp, cred


def _route_join(args, ca_pub_hex: str, token_domain: "str | None"):
    """Where does this join land? Routes by the token's CA when every location
    knob is at its default: a known CA refreshes that membership; an unknown CA
    provisions a new one named by the token's mesh domain. Explicit -c/
    --data-dir win. Also the HARD domain-collision refusal — all of this runs
    BEFORE the door dance, so a refusal never burns the invite. Returns
    (cfg_path, data_dir, listen_port, joined_key); may set args.interface for
    a newly provisioned membership."""
    from .config import load_config

    if args.interface is not None:                # covers every join branch
        _reject_bad_interface(args.interface)

    cfg_path = Path(args.config) if args.config else None
    data_dir = Path(args.data_dir) if args.data_dir else None
    listen_port = args.listen_port

    joined_key = None
    auto = args.config is None and args.data_dir is None
    if auto:
        known = _membership_for_ca(ca_pub_hex)
        if known is not None:
            # Re-join: use the existing membership's config as-is (its real,
            # possibly-customized values win; `prior` below supplies the rest).
            cfg_path = _membership_paths(known)["config"]
            existing = load_config(cfg_path)
            data_dir, listen_port = existing.data_dir, existing.listen_port
            joined_key = known
            log.info("token's CA matches membership %r — refreshing it "
                     "(config %s)", known, cfg_path)
        else:
            if not token_domain:
                sys.exit("token carries no mesh domain (older anchor?) — re-issue "
                         "the invite on a current anchor, or pass -c/--data-dir/"
                         "--interface/--listen-port explicitly")
            key = membership_key(token_domain)
            mp = _membership_paths(key)
            cfg_path, data_dir = mp["config"], mp["data_dir"]
            listen_port = (args.listen_port
                           if args.listen_port is not None else _free_listen_port())
            if args.interface is None:
                args.interface = mp["interface"]
                clash = _iface_collision(args.interface, cfg_path)
                if clash:
                    sys.exit(
                        f"derived interface name {args.interface!r} (gw- + first "
                        f"12 chars of {key!r}) is already used by the membership "
                        f"at {clash} — the kernel caps interface names at 15 "
                        f"chars, so long mesh names can collide after "
                        f"truncation. Re-run with an explicit --interface. "
                        f"The token was NOT consumed.")
            joined_key = key
            log.info(
                "token is for a mesh this host isn't on — provisioning "
                "membership %r: config %s, data %s, interface %s, UDP %d "
                "(every value overridable with join flags)",
                key, cfg_path, data_dir, args.interface, listen_port)
    else:
        if args.config is None or args.data_dir is None:
            sys.exit("explicit joins need BOTH -c and --data-dir (any other "
                     "flags optional); omit both for the derived defaults")
        if args.listen_port is None:
            listen_port = _free_listen_port()

    # HARD domain-collision refusal, BEFORE the door dance (so a refusal never
    # burns the invite): a mesh has ONE domain everywhere, and a node cannot
    # bridge two meshes that share one — no alias, no flag, no exception. The
    # only membership that may legitimately carry this domain is the one being
    # REFRESHED — identified by CA, not by config path: a *different* mesh with
    # the same name derives the same config path, so excluding by path would
    # mask exactly the collision we must catch.
    if token_domain:
        _rk = _membership_for_ca(ca_pub_hex)
        _refresh_cfg = _membership_paths(_rk)["config"].resolve() if _rk else None
        for _n, _p in _memberships():
            if _refresh_cfg is not None and _p.resolve() == _refresh_cfg:
                continue
            try:
                if load_config(_p).mesh_domain == token_domain:
                    sys.exit(
                        f"this mesh's domain {token_domain!r} is already used by "
                        f"membership {_n!r} ({_p}) — a node cannot bridge two "
                        f"meshes with the same domain. Rename one of them on its "
                        f"anchor (gw rename-mesh <new-name>) and re-run this join. "
                        f"The token was NOT consumed.")
            except SystemExit:
                raise
            except Exception:
                continue

    return cfg_path, data_dir, listen_port, joined_key


def cmd_join(args) -> int:
    _require_root("join")
    _require_tools()
    from .keys import NodeKeys
    from .wire import Credential, NodeRecord
    from .directory import Directory
    from .door import decode_token, derive_door_params
    from .config import load_config
    from . import wg as wgmod
    # way we tolerantly extract the gw1.… line, so `gw invite | ssh B gw join -`
    # works even without `invite -q`.
    token = _extract_token(sys.stdin.read() if args.token == "-" else args.token)

    # Decode token → anchor_door_pub, ca_pub, anchor_host(s), seed, door_port.
    # Decoded FIRST because the CA pub routes the join (see below).
    try:
        (anchor_door_pub_bytes, ca_pub_bytes, anchor_host, seed, door_port,
         token_domain, token_menu) = decode_token(token)
    except ValueError as e:
        sys.exit(f"invalid token: {e}")
    ca_pub_hex = ca_pub_bytes.hex()

    # Refuse on an anchor host BEFORE touching the door: the door plane (gw-door,
    # subnet fd8d:e5c1:db1a:d::/64, table 51820) is a shared singleton, so the
    # anchor's door isolation blackholes this join — it would hang forever at
    # 'connecting to enroll daemon' with no hint why. Fail loudly with the reason.
    anchored = _anchor_membership()
    if anchored:
        from .door import DOOR_TABLE, GUEST_DOOR_IP
        akey, apath = anchored
        sys.exit(
            f"this host is the anchor for mesh '{akey}' ({apath}). A host can't be "
            f"an anchor AND join another mesh — the enrollment door (gw-door, table "
            f"{DOOR_TABLE}) is a shared singleton, so the anchor's door isolation "
            f"would blackhole this join (it hangs at 'connecting to enroll daemon'). "
            f"Join from a non-anchor host. To override for a one-off: "
            f"`sudo ip -6 rule del from {GUEST_DOOR_IP} lookup {DOOR_TABLE}`, run the "
            f"join, then `{_svc_restart_hint(akey)}` to restore it.")

    # Roles the joiner self-selects (menu invite). Validate against the token's
    # menu client-side for a friendly early error — the anchor re-checks and is
    # authoritative. With a menu + no --roles, nudge the operator to pick.
    requested_roles = ([r.strip() for r in args.roles.split(",") if r.strip()]
                       if getattr(args, "roles", None) else [])
    if token_menu:
        if not requested_roles:
            log.info("this invite lets you self-select a role: %s "
                     "(pass --roles <name>); joining with none.", ", ".join(token_menu))
        else:
            bad = [r for r in requested_roles if r not in token_menu]
            if bad:
                sys.exit(f"role(s) {', '.join(bad)} not offered by this invite; "
                         f"choose from: {', '.join(token_menu)}")
    elif requested_roles:
        log.warning("--roles %s ignored: this invite doesn't offer self-selected "
                    "roles (the anchor sets them).", ",".join(requested_roles))

    # -c/--data-dir default to None (derived below from the token's mesh name);
    # the auto/explicit block after this always leaves both set.
    cfg_path, data_dir, listen_port, joined_key = _route_join(
        args, ca_pub_hex, token_domain)

    # Re-join is a re-enrollment: keys are reused (same id_pub → same overlay
    # address), so this just refreshes the credential. Detect it so we can (a)
    # tell the operator and (b) preserve the existing config instead of silently
    # resetting hostname/caps to defaults.
    already_enrolled = (data_dir / "id_priv.pem").exists()
    prior = None
    if cfg_path.exists():
        try:
            prior = load_config(cfg_path)
        except Exception:
            prior = None

    # hostname / caps: explicit flag wins, else keep the prior value, else default.
    if args.hostname:
        hostname = args.hostname
    elif prior and prior.hostname:
        hostname = prior.hostname
    else:
        # Default to the machine's short hostname (first label, no domain).
        hostname = socket.gethostname().split(".")[0] or "node"

    # Caps/roles are NOT chosen here. The anchor decides them at `gw invite` and
    # binds them into the credential issued over the door; we read them back
    # from that credential below and write them to config. (No self-assertion:
    # whatever a joiner might request is ignored by the anchor.)
    caps: list[str] = []

    # Endpoint(s) = where other nodes dial this one for a direct tunnel. If not
    # given, best-effort detect a public v6 and/or v4. A node with no endpoint
    # can still reach the anchor (it initiates outbound), but peers can't dial it,
    # so node<->node links won't form unless the other side is reachable.
    node_endpoints = _advertised_endpoints(
        args.endpoint, listen_port,
        prior.endpoints if prior else None,
    )
    if node_endpoints:
        log.info("advertising underlay endpoint(s): %s", ", ".join(node_endpoints))
    else:
        log.warning(
            "no public endpoint detected — this node will be reachable only by "
            "initiating outbound (e.g. to the anchor); other nodes cannot dial it, "
            "so direct node-to-node links may not form. Pass --endpoint <addr> "
            "if this node is publicly reachable.")

    # (token was decoded up top — its CA pub routed the join to a slot)
    # The token may carry several anchor underlay hosts (v4 and/or v6, comma-sep);
    # dial one this node can actually reach.
    anchor_host = _pick_reachable_host(anchor_host.split(","))

    anchor_door_pub_b64 = base64.b64encode(anchor_door_pub_bytes).decode()

    # Derive door params from seed (same derivation the anchor ran at invite time)
    params = derive_door_params(seed)
    log.info("guest_pub: ...%s", params.guest_pub_b64[-8:])

    # Generate this node's permanent keypairs
    data_dir.mkdir(parents=True, exist_ok=True)
    try:
        # 0755, not 0700: the dir holds world-readable public files (id_pub.hex,
        # directory.json, *.pub) that root-free commands like `gw watch --snapshot` read;
        # every secret inside is its own 0600 root-owned file. Root owns all of
        # it — state is never chowned to the invoking user (the CA key on a
        # login account would let that account mint credentials).
        os.chmod(data_dir, 0o755)
    except PermissionError:
        pass
    node_keys = NodeKeys.load_or_generate(data_dir)
    if already_enrolled:
        log.info(
            "re-enrolling existing node %s (keys reused; refreshing credential, "
            "hostname=%s; caps assigned by the anchor)", node_keys.addr, hostname,
        )
    log.info("overlay addr: %s", node_keys.addr)

    conn, resp, cred = _enroll_over_door(
        data_dir, node_keys, hostname, anchor_host, anchor_door_pub_b64,
        params, door_port, ca_pub_bytes, already_enrolled,
        requested_roles=requested_roles)

    # The anchor decided our name + caps; adopt them from the issued credential
    # (the authoritative record of what we were granted) so config matches. For
    # an anchor-pinned hostname, cred.hostname differs from what we requested.
    caps = list(cred.caps)
    if cred.hostname != hostname:
        log.info("anchor assigned hostname %r (requested %r)", cred.hostname, hostname)
    hostname = cred.hostname
    log.info("anchor assigned caps=%s", caps)
    if cred.id_pub != node_keys.id_pub_bytes:
        wgmod.destroy_interface("gw-door")
        sys.exit("credential id_pub mismatch — something went wrong")
    log.info("credential verified, expires %s", cred.exp.strftime("%Y-%m-%d %H:%M UTC"))

    # Learn the fleet's overlay /64 from the credential the CA just issued (the
    # authoritative source), and activate it so our own address / record are
    # built under the right prefix. This is what lets a node join a mesh on any
    # prefix without being told out of band.
    import ipaddress as _ip
    from .keys import set_overlay_prefix, format_overlay_prefix
    overlay_prefix = format_overlay_prefix(_ip.IPv6Address(cred.addr).packed[:8])
    set_overlay_prefix(_ip.IPv6Address(cred.addr).packed[:8])
    # Multi-mesh legibility check: same /64 as another membership on this host?
    _warn_shared_overlay_prefix(cfg_path, overlay_prefix)

    # Build directory with our record + anchor's record
    dir_cache = data_dir / "directory.json"
    directory = Directory.load(dir_cache)

    # Anchor's record — pre-seeds so the daemon knows the anchor immediately. The anchor
    # tells us its control port (it's configurable) so we build the right URL.
    anchor_control_port = int(resp.get("control_port", 51902))
    anchor_overlay_url = ""
    if resp.get("anchor_record"):
        anchor_rec = NodeRecord.from_dict(resp["anchor_record"])
        try:
            anchor_rec.verify([ca_pub_bytes], set())
            directory.put(anchor_rec)
            log.info("pre-seeded anchor record (hostname=%s)", anchor_rec.hostname)
            anchor_overlay_url = f"http://[{anchor_rec.cred.addr}]:{anchor_control_port}"
        except Exception as e:
            log.warning("anchor record verify failed: %s", e)

    # Our own record. We advertise whatever endpoint we detected; a node that
    # detects none is naturally outbound-only, and peers back off a dead one.
    existing = directory.get(node_keys.id_pub_hex)
    seq = (existing.seq + 1) if existing else 1
    record = NodeRecord(
        id_pub=node_keys.id_pub_bytes,
        seq=seq,
        endpoints=list(node_endpoints),
        cred=cred,
    ).sign(node_keys.id_priv)
    directory.put(record)
    directory.save(dir_cache)

    # Pre-seed the signed policy the anchor sent, so this node's first `gw run`
    # enforces the real grant table immediately — no implicit-open window before
    # its first directory sync. The daemon re-verifies it under the CA on load.
    if resp.get("policy"):
        from .policy import POLICY_BASENAME
        (data_dir / POLICY_BASENAME).write_text(json.dumps(resp["policy"], indent=2))

    # Send our signed record back over the SAME door connection; the anchor merges
    # it into its directory so the ReconcileLoop keeps the peer it just installed
    # (the bootstrap chicken-and-egg). Doing this on the door tunnel — rather
    # than a separate POST /publish — means the control plane never has to listen
    # on the door interface.
    from .door import recv_msg, send_msg
    try:
        send_msg(conn, {"v": 1, "record": record.to_dict()})
        ack = recv_msg(conn)
        if ack.get("ok"):
            log.info("published record to anchor via door tunnel")
        else:
            log.warning("anchor rejected door publish: %s", ack.get("error"))
    except (OSError, ValueError) as e:
        # The EXPECTED, recoverable failure: the door tunnel dropped or timed
        # out (OSError), or the anchor returned a short/oversized/undecodable
        # frame (ValueError). Enrollment already SUCCEEDED and our record is
        # saved locally, so this costs only immediacy — the daemon republishes
        # over the overlay on its next sync.
        log.warning("door publish failed (anchor learns this node on next sync): %s", e)
    except Exception:
        # Anything else is a BUG, not a network condition — surface it loudly
        # (full traceback) instead of hiding it behind the soft "next sync"
        # message, which is what let a NameError here masquerade as a benign
        # I/O hiccup. Still don't fail the already-successful enrollment.
        log.error("door publish hit an unexpected error — this is a bug; the "
                  "node is enrolled and will sync", exc_info=True)
    finally:
        try:
            conn.close()
        except Exception:
            pass

    # Tear down the door interface
    wgmod.destroy_interface("gw-door")

    # hosts sync: on by default; --no-hosts-sync turns it off; a re-join keeps a
    # previously-disabled setting.
    if args.hosts_sync is False:            # --no-hosts-sync given
        hosts_sync = False
    elif prior is not None:                 # re-join → keep the prior setting
        hosts_sync = prior.hosts_sync
    else:
        hosts_sync = True
    # Name domain: the mesh has exactly ONE, carried in the token (declared at
    # its anchor's create / rename-mesh). The joiner adopts it, period — a collision
    # with another membership already hard-refused before the door dance. A
    # re-join of an existing membership keeps its config; token wins if both.
    mesh_domain = (token_domain
                   or (prior.mesh_domain if prior and getattr(prior, "mesh_domain", None)
                       else "gw.internal"))
    interface = (args.interface or (prior.wg_interface if prior and getattr(prior, "wg_interface", None)
                 else "gw-mesh"))

    cfg_path.parent.mkdir(parents=True, exist_ok=True)
    cfg_path.write_text(render_config(
        hostname=hostname, data_dir=data_dir, role="node", caps=caps,
        endpoints=node_endpoints, interface=interface, listen_port=listen_port,
        overlay_prefix=overlay_prefix,
        seeds=[anchor_overlay_url] if anchor_overlay_url else [],
        root_url=anchor_overlay_url or "", hosts_sync=hosts_sync,
        mesh_domain=mesh_domain, trusted_pubs=[ca_pub_hex],
        enforce_ports=_enforce_ports_default(),
        endpoint_auto=(args.endpoint is None)))   # pinned iff --endpoint was given
    log.info("wrote config → %s", cfg_path)

    print(f"\nNode enrolled successfully.")
    print(f"  hostname     : {hostname}")
    print(f"  overlay addr : {node_keys.addr}")
    print(f"  credential   : expires {cred.exp:%Y-%m-%d %H:%M UTC}")
    if anchor_overlay_url:
        print(f"  anchor control  : {anchor_overlay_url}")
    print()
    if joined_key:
        # Name-keyed path → the greasewood@ template can serve it. Install +
        # enable (unless --no-service), settle-checked, same as create.
        _print_daemon_guidance(joined_key, cfg_path,
                               no_service=getattr(args, "no_service", False))
    else:
        # Explicit custom -c path: the template's ExecStart hardcodes
        # /etc/greasewood_%i.toml, so systemd can't serve it — run it yourself.
        print("Start this mesh's daemon:")
        print(f"  sudo gw -c {cfg_path} run")
        print("  (custom -c path isn't served by the greasewood@ template; run "
              "it yourself or write your own unit)")
    print()
    from . import firewall as _fw
    _print_firewall_help(listen_port, mesh_iface=interface, role="node")
    print()
    _fw.check(_fw.node_rules(listen_port), log)
    return 0



# ---------------------------------------------------------------------------
# revoke
# ---------------------------------------------------------------------------

def cmd_revoke(args) -> int:
    # Same anchor-only guard as set-caps/set-roles: explicit role check first,
    # then ca_key_file + CA load — so a non-anchor fails with one clear message and
    # never reaches a traceback.
    cfg, ca = _load_anchor_ca(args, "revoke")

    # Accept a hostname / mesh name as well as a raw id hex; a hostname resolves
    # via the registry, a raw id is honored even if already forgotten.
    id_pub_bytes, name = _resolve_node(ca, cfg, args.node, require_enrolled=False)

    freed = ca.add_revoke(id_pub_bytes)
    print(f"revoked: {name}  ({id_pub_bytes.hex()})")
    if freed:
        print("Its hostname is now free for reuse by a different node.")
    print("Takes effect live — the running daemon refuses its renew/publish and "
          "evicts it on the next reconcile; its credential also expires naturally.")
    return 0


# ---------------------------------------------------------------------------
# set-caps / set-roles — change an enrolled node's caps on the anchor
# ---------------------------------------------------------------------------

def _load_anchor_ca(args, cmd: str):
    """Shared setup for anchor-side registry commands: load config + CA."""
    from .config import load_config
    from .keys import CAKeys
    from .ca import CA
    # Gate up front: the registry (nodes/*.json) and CA key are root-owned, and
    # these commands write them. Without this, a non-root run fails partway with
    # whatever file access breaks first — historically misread as the node not
    # existing at all.
    _require_root(cmd, "it reads and writes the anchor's registry and CA key")
    cfg = load_config(Path(args.config))
    if cfg.role != "anchor":
        sys.exit(f"gw {cmd} must be run on the anchor (role = anchor)")
    if cfg.ca_key_file is None:
        sys.exit(f"{cmd} requires ca_key_file in [anchor]")
    ca_keys = CAKeys.load(cfg.ca_key_file, _get_passphrase(cfg.ca_key_passphrase_env))
    return cfg, CA(ca_keys, cfg.data_dir)


def _resolve_node(ca, cfg, handle: str, *, require_enrolled: bool = True):
    """Resolve a node handle — a hostname, a full `<host>.<mesh_domain>` mesh
    name, or a 64-char id_pub hex — to (id_pub_bytes, hostname). A hostname
    always needs the anchor's registry (the only name→id map). With
    require_enrolled=False a raw id hex is accepted even if the node isn't in
    the registry — so `revoke` can still deny an already-forgotten identity."""
    s = handle.strip()
    if len(s) == 64 and all(c in "0123456789abcdefABCDEF" for c in s):
        info = ca.node_info(bytes.fromhex(s))
        if info is None:
            if require_enrolled:
                sys.exit(f"no enrolled node with id {s[:16]}…")
            return bytes.fromhex(s), s[:16] + "…"      # raw id, name unknown
        return bytes.fromhex(s), info[0]
    suffix = "." + cfg.mesh_domain
    if s.endswith(suffix):
        s = s[: -len(suffix)]
    owner = ca.hostname_owner(s)
    if owner is None:
        sys.exit(f"no node named {handle!r} on this anchor — pass its hostname, "
                 f"its <host>.{cfg.mesh_domain} name, or its 64-char id_pub hex "
                 f"(see `gw watch`)")
    return bytes.fromhex(owner), s


_NEXT_RENEWAL_NOTE = (
    "Takes effect at the node's next renewal (~half the credential TTL); no "
    "re-join needed. To apply now WITHOUT touching the node, run `sudo gw "
    "renew-all` on the anchor — its daemon renews and adopts the new roles "
    "live (no restart). (`sudo gw renew` on the node works too, but that CLI "
    "path needs a daemon restart to take effect.)"
)


def cmd_set_caps(args) -> int:
    cfg, ca = _load_anchor_ca(args, "set-caps")
    id_pub, name = _resolve_node(ca, cfg, args.node)
    caps = [c.strip() for c in args.caps.split(",") if c.strip()]
    # set-caps takes raw caps, so it's also a role-assignment path — reject the
    # reserved role: tags here too (else `set-caps role:anchor` would bypass the
    # single-member guard).
    _reject_reserved_roles([c[len("role:"):] for c in caps if c.startswith("role:")],
                           "set-caps")
    if not any(c.startswith("role:") for c in caps):
        log.warning("caps %s include no role: tag — once a grant table is "
                    "applied, %r will reach only the anchor (add e.g. "
                    "role:node)", caps, name)
    ca.set_caps(id_pub, caps)
    print(f"caps for {name} ({id_pub.hex()}) → {caps}")
    print(_NEXT_RENEWAL_NOTE)
    return 0


def _request_fleet_renewal(cfg) -> "dt.datetime":
    """Write the anchor's fleet-wide renew_after=now hint (served in GET
    /directory). Shared by `gw renew-all` and `gw set-roles --now`. Returns the
    timestamp written."""
    now = dt.datetime.now(_UTC).replace(microsecond=0)
    (cfg.data_dir / "renew_after").write_text(now.isoformat())
    return now


def _grants_naming_role(cfg, role: str) -> str:
    """Human lines for the active grants that name `role` — the concrete
    coverage a host loses when it leaves that role. '' when there is no
    policy cache, or none name it (display-only, like status's grant read)."""
    from .policy import POLICY_BASENAME
    from .wire import GrantTable
    try:
        grants = GrantTable.from_dict(json.loads(
            (cfg.data_dir / POLICY_BASENAME).read_text())).grants
    except Exception:
        return ""
    return "\n".join(
        f"    {', '.join(g['from'])} -> {', '.join(g['to'])} : "
        f"{', '.join(g['ports'])}"
        for g in grants or [] if role in list(g["from"]) + list(g["to"]))


def cmd_set_roles(args) -> int:
    cfg, ca = _load_anchor_ca(args, "set-roles")
    id_pub, name = _resolve_node(ca, cfg, args.node)
    # Declarative mode: a host listed in grants.toml's [assign] table has its
    # roles DECLARED there — an imperative edit would silently drift from the
    # file (and be reverted by the next `gw policy apply`). Point at the file.
    from .policy import parse_assignments, GRANTS_BASENAME
    _gp = cfg.data_dir / GRANTS_BASENAME
    try:
        _assigns = parse_assignments(_gp.read_text()) if _gp.exists() else None
    except ValueError:
        _assigns = None                    # invalid file: apply will complain
    if _assigns is not None and name in _assigns:
        sys.exit(f"{name}'s roles are DECLARED in {_gp} ([assign] table) — "
                 f"edit that entry and run `sudo gw policy apply` (or use the "
                 f"gw watch role editor, which writes the same file). "
                 f"set-roles would silently drift from the declared state.")
    _, current = ca.node_info(id_pub)
    # Replace only the role: tags; keep tls/hostname-pinned and anything else.
    kept = [c for c in current if not c.startswith("role:")]
    names = [r.strip() for r in args.roles.split(",") if r.strip()] or ["node"]
    _reject_reserved_roles(names, "set-roles")
    # role:node is STICKY. It's the default membership role, and fleet grants
    # (the shipped admin -> node ssh, metrics scrapes, ...) target it — so a
    # set-roles list that merely doesn't mention it must not silently seal the
    # box out of that coverage. Keep it unless the operator says --exact, and
    # under --exact show exactly which grants stop covering the host.
    current_roles = [c[len("role:"):] for c in current if c.startswith("role:")]
    if "node" in current_roles and "node" not in names:
        if getattr(args, "exact", False):
            refs = _grants_naming_role(cfg, "node")
            print(f"⚠ --exact: {name} leaves role:node — grants targeting "
                  f"'node' no longer cover it" + (":\n" + refs if refs else "."))
        else:
            names.append("node")
            print("kept role:node — the default membership role; drop it "
                  "explicitly with --exact")
    caps = kept + ["role:" + r for r in names]
    ca.set_caps(id_pub, caps)
    print(f"roles for {name} ({id_pub.hex()}) → {names}  (caps now {caps})")
    if getattr(args, "now", False):
        # Expedite: the SAME hint `gw renew-all` writes. It's fleet-wide (a
        # single renew_after level), so re-roling several nodes is better done
        # as several `set-roles` then ONE `renew-all` — but for a single change
        # this is the one-command path. The node adopts the new roles live.
        now = _request_fleet_renewal(cfg)
        print(f"--now: requested a fleet renewal (renew_after = "
              f"{now:%Y-%m-%d %H:%M UTC}) — {name}'s daemon renews within a poll "
              f"interval and adopts the new roles live, no restart. (Fleet-wide; "
              f"for a batch, prefer several set-roles then one `gw renew-all`.)")
    else:
        print(_NEXT_RENEWAL_NOTE)
    return 0


# ---------------------------------------------------------------------------
# anchor-promote — turn an enrolled node into an anchor (generate a CA)
# ---------------------------------------------------------------------------

def _control_port(cfg) -> int:
    """The control-plane port from cfg.control_listen (':51902' -> 51902)."""
    try:
        return int(cfg.control_listen.rsplit(":", 1)[1])
    except (ValueError, IndexError):
        return 51902


def _require_root(cmd: str, why: "str | None" = None) -> None:
    """Exit cleanly if not root, instead of crashing partway through on EACCES —
    the complaint comes FIRST, loudly, not from whichever file access happens to
    fail deepest into the command. For commands that create WireGuard
    interfaces, edit routing, write /etc, or read/write root-owned state."""
    if os.geteuid() != 0:
        why = why or "it changes WireGuard/routing/system files"
        sys.exit(f"'gw {cmd}' needs root ({why}).\nTry: sudo gw {cmd}")


def _require_tools() -> None:
    """Exit cleanly if the wg/ip binaries are missing — BEFORE any state is
    created. Same posture as _require_root: the complaint comes first, not
    from whichever subprocess call happens to crash deepest into the command
    (seen in the field: a join with no wireguard-tools died mid-door-bringup
    with a raw FileNotFoundError, leaving the half-made interface behind)."""
    from . import wg as wgmod
    missing = wgmod.missing_tools()
    if missing:
        pkgs = {"wg": "wireguard-tools", "ip": "iproute2"}
        need = " ".join(dict.fromkeys(pkgs[t] for t in missing))
        sys.exit(f"required tool(s) not installed: {', '.join(missing)} — "
                 f"greasewood drives the data plane with the stock tools "
                 f"(pipx installs only the Python side).\n"
                 f"Install them first:  sudo apt install {need}   "
                 f"# or your distro's equivalent")


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
    return service.detect(_UNIT_DIR)


def _svc_restart_hint(key: str = "<mesh>") -> str:
    """The backend-correct 'restart this mesh's daemon' command for THIS host —
    rc-service on OpenRC, systemctl on systemd, systemctl-shaped as the fallback
    when no service manager is detected (a bare `gw run` host)."""
    mgr = _service_backend()
    return mgr.restart_hint(key) if mgr else f"sudo systemctl restart greasewood@{key}"


def _print_daemon_guidance(key: str, cfg_path, then: str = "",
                           no_service: bool = False) -> None:
    """Bring up (and report) this membership's daemon. By default create/join
    install the host's native service (systemd unit / OpenRC script) and enable
    this mesh's instance so it's running and boot-persistent with no extra
    command; --no-service (or no service manager) prints the manual `gw run`
    line. `then` is an optional trailing clause."""
    tail = f" — {then}" if then else ""
    mgr = _service_backend()
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


def cmd_anchor_promote(args) -> int:
    """On a prospective new anchor (currently a node): generate its own CA key and
    rewrite its config to role=anchor, so a restart makes it serve as an anchor.
    Prints the CA public key + control endpoint to add to the fleet's
    trusted_pubs (a manual re-root — see the printed steps)."""
    _require_root("anchor-promote")
    from .config import load_config
    from .keys import CAKeys, NodeKeys

    cfg_path = Path(args.config)
    if not cfg_path.exists():
        sys.exit(f"no config at {cfg_path} — this command runs on an enrolled node")
    cfg = load_config(cfg_path)

    # An anchor must be reachable (it serves the control plane + door), so it
    # needs an advertised endpoint. A node that advertises none can't be one.
    if not cfg.endpoints:
        sys.exit(
            "this node advertises no endpoint, so peers can't reach its control "
            "plane — an anchor must be reachable. Set [node] endpoints in its "
            "config first, then re-run anchor-promote."
        )

    keys = NodeKeys.load_or_generate(cfg.data_dir)
    ca_key_path = cfg.data_dir / "ca.key"
    if ca_key_path.exists():
        ca_keys = CAKeys.load(ca_key_path)
        log.info("loaded existing CA key from %s", ca_key_path)
    else:
        ca_keys = CAKeys.generate()
        ca_keys.save(ca_key_path)
        log.info("generated CA key → %s", ca_key_path)
    ca_pub_hex = ca_keys.ca_pub_bytes.hex()

    control_port = args.control_port
    # Nodes reach the anchor control plane over the overlay, so advertise the
    # overlay address (not the underlay).
    endpoint = f"http://[{keys.addr}]:{control_port}"

    # Trust our own CA as a root, in addition to whatever we already trust, so
    # this anchor accepts the credentials it issues.
    trusted = list(dict.fromkeys([*cfg.ca_pubs_hex, ca_pub_hex]))

    # An anchor must reach every node — ensure the wildcard role. (Its own
    # credential picks this up on the next renewal under the new CA.)
    anchor_caps = list(cfg.caps)
    if "role:*" not in anchor_caps:
        anchor_caps.append("role:*")

    cfg_path.write_text(render_config(
        hostname=cfg.hostname, data_dir=cfg.data_dir, role="anchor",
        caps=anchor_caps, endpoints=cfg.endpoints, interface=cfg.wg_interface,
        listen_port=cfg.listen_port, overlay_prefix=cfg.overlay_prefix,
        seeds=cfg.seeds, root_url=cfg.root_url, hosts_sync=cfg.hosts_sync,
        mesh_domain=cfg.mesh_domain, trusted_pubs=trusted,
        enforce_ports=cfg.enforce_ports,          # preserve the operator's choices
        endpoint_auto=cfg.endpoint_auto,
        anchor={"ca_key_file": ca_key_path, "control_port": control_port,
                "credential_ttl": args.credential_ttl,
                "door_port": cfg.door_port}))
    log.info("promoted to anchor role in %s", cfg_path)

    print("\nReady to become an anchor. CA key generated; config set to role=anchor.")
    print(f"  CA pub key   : {ca_pub_hex}")
    print(f"  anchor endpoint : {endpoint}")
    print()
    print("To move the fleet to this anchor (manual re-root — live tunnels stay up):")
    print("  1. Add this CA pub to [ca] trusted_pubs on EVERY node (keep the old")
    print("     one during the overlap), e.g. via Ansible, and restart their daemons:")
    print(f"       {ca_pub_hex}")
    print(f"  2. Repoint nodes' root_url + seeds to this anchor: {endpoint}")
    print("  3. Once every node has renewed here, drop the old CA pub from")
    print("     trusted_pubs fleet-wide. Then decommission the old anchor.")
    print("Start the daemon here:  sudo gw run")
    print()
    from . import firewall as _fw
    _fw.check(_fw.anchor_rules(cfg.listen_port, control_port, cfg.wg_interface), log)
    return 0


# ---------------------------------------------------------------------------
# TLS service certificates (§12) — cert-request / cert-status
# ---------------------------------------------------------------------------

def _shipped_profiles_dir() -> "Path":
    return Path(__file__).resolve().parent / "profiles"


def _shipped_profile_names() -> list:
    d = _shipped_profiles_dir()
    return sorted(p.stem for p in d.glob("*.toml")) if d.is_dir() else []


def _load_cert_profile(ref: str) -> dict:
    """Resolve a --profile argument to {reload, files, path, text}. `ref` is a
    file path, or the bare name of a shipped template (postgres, nginx, …)."""
    import tomllib
    p = Path(ref)
    if not p.exists():
        cand = _shipped_profiles_dir() / f"{ref}.toml"
        if not cand.exists():
            names = ", ".join(_shipped_profile_names()) or "(none)"
            sys.exit(f"no cert profile {ref!r} — pass a file path, or a shipped "
                     f"name: {names}")
        p = cand
    text = p.read_text()
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as e:
        sys.exit(f"profile {p}: invalid TOML — {e}")
    files = data.get("file", [])
    if not files:
        sys.exit(f"profile {p}: no [[file]] entries (need role + path each)")
    for f in files:
        if "role" not in f or "path" not in f:
            sys.exit(f"profile {p}: every [[file]] needs a role and a path")
        if f["role"] not in ("key", "cert", "ca", "fullchain", "bundle"):
            sys.exit(f"profile {p}: unknown role {f['role']!r} "
                     f"(key|cert|ca|fullchain|bundle)")
    return {"reload": data.get("reload"), "dns": data.get("dns", []),
            "files": files, "path": str(p), "text": text}


def cmd_cert_profiles(args) -> int:
    """List the bundled cert profile templates (starting points to copy + edit
    for common TLS services). They record the OS/software version they were
    written against; adapt paths to yours."""
    names = _shipped_profile_names()
    if not names:
        print("no bundled profiles found")
        return 0
    print("bundled cert profiles (templates — copy + adapt to your paths):")
    for n in names:
        based = ""
        for ln in (_shipped_profiles_dir() / f"{n}.toml").read_text().splitlines():
            if "based on" in ln:
                based = ln.split(":", 1)[1].strip() if ":" in ln else ""
                break
        print(f"  {n:<10} {('· ' + based) if based else ''}")
    print("\nView/copy one:   gw cert-request --profile <name> --show")
    print("Use one:         sudo gw cert-request --profile <name|path.toml>")
    return 0


def _cert_already_current(data_dir, name: str, *, dns, ips, files=None,
                          paths=None, renew: bool) -> "dt.datetime | None":
    """If re-requesting `name` would be a no-op — same SANs, same placement, and
    a cert that's present and not yet due for renewal — return its expiry (so
    the caller can say 'nothing to do'). Otherwise None: a first request, a
    changed request (new SAN/paths), a missing/old cert, or --renew all proceed."""
    if renew:
        return None
    from . import certs as certmod
    entry = next((c for c in certmod.load_manifest(data_dir)
                  if c.get("name") == name), None)
    if entry is None:
        return None
    if sorted(entry.get("dns", [])) != sorted(dns) or \
       sorted(entry.get("ips", [])) != sorted(ips):
        return None
    if files is not None:
        if entry.get("files") != files:            # placement (paths/owner/mode) changed
            return None
    else:
        if (entry.get("key_path"), entry.get("crt_path"), entry.get("ca_path")) \
                != tuple(str(p) for p in paths):
            return None
    crt = certmod.ManagedCert.from_dict(entry).cert_path
    if crt is None or certmod.cert_due_for_renewal(crt):   # missing/old → re-issue
        return None
    return certmod.cert_expiry(crt)


def _print_cert_noop(name: str, exp, *, via: str) -> None:
    left = (exp - dt.datetime.now(_UTC)).total_seconds()
    print(f"TLS cert '{name}' already present ({via}), valid until "
          f"{exp:%Y-%m-%d %H:%M UTC} ({_dur_short(left)}) — nothing to do.")
    print(f"  re-issue now: --renew   ·   stop managing it: gw cert-remove {name}")


def cmd_cert_remove(args) -> int:
    """Stop managing a TLS cert: drop it from the auto-renewal manifest (and its
    profile snapshot). By default the placed key/cert/ca files are LEFT in place
    — a running service may still be reading them; pass --delete-files to remove
    them too."""
    from .config import load_config
    from . import certs as certmod
    _require_root("cert-remove",
                  "it edits the managed-cert manifest and may delete cert files")
    cfg = load_config(Path(args.config))
    entries = certmod.load_manifest(cfg.data_dir)
    entry = next((c for c in entries if c.get("name") == args.name), None)
    if entry is None:
        have = ", ".join(c.get("name", "?") for c in entries) or "(none managed)"
        sys.exit(f"no managed cert named {args.name!r} — have: {have}")

    certmod.remove_managed(cfg.data_dir, args.name)
    certmod.profile_snapshot_path(cfg.data_dir, args.name).unlink(missing_ok=True)
    print(f"deregistered '{args.name}' — the daemon will no longer renew it.")

    paths = certmod.ManagedCert.from_dict(entry).placed_paths()
    if args.delete_files:
        for p in paths:
            try:
                Path(p).unlink()
                print(f"  removed {p}")
            except FileNotFoundError:
                pass
    else:
        print("  the placed files are LEFT in place (a service may be using them):")
        for p in paths:
            print(f"    {p}")
        print("  pass --delete-files to remove them too.")
    return 0


def cmd_cert_request(args) -> int:
    """Request an x509 TLS cert from the anchor for a local service (e.g. Postgres).
    Generates the leaf key locally; only its public key is sent to the anchor. Unless
    --no-auto-renew is given, the cert is recorded so the daemon renews it at
    ~half its TTL (and runs --reload-cmd afterward)."""
    from .config import load_config
    from .keys import NodeKeys
    from . import certs as certmod

    # A cert PROFILE bundles the file placements (paths + owner + mode) and the
    # reload command for a service, so one command issues, places, chowns, and
    # registers renewal. --show just prints the template (to copy + adapt) and
    # needs neither root nor config.
    profile = None
    if getattr(args, "profile", None):
        profile = _load_cert_profile(args.profile)
        if getattr(args, "show", False):
            print(profile["text"], end="")
            return 0

    _require_root("cert-request",
                  "it reads the node's identity key and writes the TLS key (0600)")

    cfg = load_config(Path(args.config))
    keys = NodeKeys.load(cfg.data_dir)

    # Classify each --san as an IP or a DNS name.
    dns, ips = [], []
    for s in args.san:
        try:
            ipaddress.ip_address(s)
            ips.append(s)
        except ValueError:
            dns.append(s)

    # Default to this node's own mesh name + overlay address, so the cert is
    # valid for exactly the name peers resolve it by. That's the mesh's
    # CANONICAL domain — identical to mesh_domain except on a multi-mesh host
    # whose local mount had to fall back (domain collision): peers still
    # resolve this node under the canonical suffix, so that's the cert name.
    if not dns and not ips:
        if profile and profile["dns"]:
            dns = list(profile["dns"])
        else:
            from .hosts import mesh_name
            dns = [mesh_name(cfg.hostname, cfg.mesh_domain)]
            ips = [keys.addr]

    # CN is not operator-settable: it's cosmetic under verify-full (the SAN is
    # what's checked) and the anchor constrains it to an owned name anyway, so we
    # just derive it from the first SAN.
    cn = dns[0] if dns else (ips[0] if ips else keys.addr)
    name = args.name or (Path(profile["path"]).stem if profile
                         else (dns[0] if dns else "service"))

    anchor_url = args.anchor or cfg.root_url
    if not anchor_url:
        sys.exit("no anchor URL — set root_url in config or pass --anchor")

    if profile:
        # Idempotent: an unchanged re-request of a still-fresh cert is a no-op.
        exp = _cert_already_current(cfg.data_dir, name, dns=dns, ips=ips,
                                    files=profile["files"], renew=getattr(args, "renew", False))
        if exp:
            _print_cert_noop(name, exp, via=f"profile '{Path(profile['path']).name}'")
            return 0
        # Pre-validate every owner before we bother the anchor, so a typo'd
        # user fails instantly rather than after burning a cert.
        for f in profile["files"]:
            if f.get("owner"):
                try:
                    certmod._resolve_owner(f["owner"])
                except RuntimeError as e:
                    sys.exit(str(e))
        try:
            key_pem, cert_pem, ca_pem = certmod.fetch_cert(
                anchor_url, keys, dns=dns, ips=ips, cn=cn)
            certmod.place_cert_files(profile["files"], key_pem, cert_pem, ca_pem)
        except certmod.CertRejected as e:
            sys.exit(f"cert request rejected: {e}")
        except (RuntimeError, OSError) as e:
            sys.exit(f"cert request/placement failed: {e}")

        reload_cmd = args.reload_cmd or profile["reload"]
        auto = not args.no_auto_renew
        certmod.record_managed(cfg.data_dir, {
            "name": name, "cn": cn, "dns": dns, "ips": ips,
            "files": profile["files"], "reload_cmd": reload_cmd,
            "auto_renew": auto, "profile": Path(profile["path"]).stem,
        })
        # Record-keeping: snapshot the exact profile used (with its provenance
        # comments), separate from the manifest's effective config.
        certmod.snapshot_profile(cfg.data_dir, name, profile["text"])
        print(f"TLS certificate issued + placed via profile "
              f"'{Path(profile['path']).name}'.")
        print(f"  cn / SAN : {cn}" + (f"  (+{len(dns) - 1} more)" if len(dns) > 1 else ""))
        for f in profile["files"]:
            own = f.get("owner", "root:root")
            mode = int(f["mode"], 8) if f.get("mode") else \
                certmod._ROLE_MODE.get(f["role"], 0o644)
            print(f"  {f['role']:<9}→ {f['path']}  [{own} {mode:04o}]")
        if reload_cmd:
            print(f"  reload   : {reload_cmd}")
        if auto:
            print("The daemon re-issues, re-places (with owner/mode), and runs "
                  "reload at ~half TTL — the whole lifecycle is hands-off.")
        else:
            print("Auto-renewal disabled (--no-auto-renew) — re-run before expiry.")
        return 0

    # Resolve the three destinations. Default is <out-dir>/<name>.{key,crt} +
    # <out-dir>/ca.crt; each can be overridden independently so the key, cert,
    # and CA cert may live in different directories.
    out_dir = Path(args.out_dir) if args.out_dir else (cfg.data_dir / "tls")
    key_path = Path(args.key_out) if args.key_out else out_dir / f"{name}.key"
    crt_path = Path(args.cert_out) if args.cert_out else out_dir / f"{name}.crt"
    ca_path = Path(args.ca_out) if args.ca_out else out_dir / "ca.crt"

    # Idempotent: an unchanged re-request of a still-fresh cert is a no-op.
    exp = _cert_already_current(cfg.data_dir, name, dns=dns, ips=ips,
                                paths=(key_path, crt_path, ca_path),
                                renew=getattr(args, "renew", False))
    if exp:
        _print_cert_noop(name, exp, via=f"at {crt_path}")
        return 0

    # Re-requesting an existing name RELOCATES it (record_managed keys on name).
    # Capture the prior destinations so we can flag any that are now orphaned.
    prior = [c for c in certmod.load_manifest(cfg.data_dir) if c.get("name") == name]
    old_paths = set(certmod.entry_paths(prior[0])) if prior else set()

    try:
        key_path, crt_path, ca_path = certmod.issue_cert(
            anchor_url, keys, dns=dns, ips=ips, cn=cn,
            key_path=key_path, crt_path=crt_path, ca_path=ca_path)
    except certmod.CertRejected as e:
        sys.exit(f"cert request rejected: {e}")
    except RuntimeError as e:
        sys.exit(f"cert request to {anchor_url} failed: {e}")

    # Record it for the daemon's auto-renewal loop (skipped iff --no-auto-renew).
    auto = not args.no_auto_renew
    certmod.record_managed(cfg.data_dir, {
        "name": name, "cn": cn, "dns": dns, "ips": ips,
        "key_path": str(key_path), "crt_path": str(crt_path),
        "ca_path": str(ca_path),
        "reload_cmd": args.reload_cmd, "auto_renew": auto,
    })

    print("TLS certificate issued.")
    print(f"  cn       : {cn}")
    if dns:
        print(f"  dns SANs : {', '.join(dns)}")
    if ips:
        print(f"  ip SANs  : {', '.join(ips)}")
    print(f"  key      : {key_path}")
    print(f"  cert     : {crt_path}")
    print(f"  ca cert  : {ca_path}")
    print(f"  config   : {args.config}  (managed-cert manifest: "
          f"{certmod.manifest_path(cfg.data_dir)})")
    print()
    print("Point your service at these (e.g. Postgres ssl_cert_file / ssl_key_file,")
    print("clients ssl_ca_file = ca.crt).")
    if auto:
        note = "The daemon will auto-renew this cert at ~half its TTL"
        note += f" and then run: {args.reload_cmd}" if args.reload_cmd else \
            " (pass --reload-cmd next time to reload your service on renewal)"
        print(note + ".")
    else:
        print("Auto-renewal disabled (--no-auto-renew) — re-run before expiry.")

    # If re-requesting relocated the cert, the daemon now renews into the paths
    # above; the old files won't be touched again. Point them out rather than
    # deleting key material a service might still be reading.
    orphans = sorted(str(p) for p in old_paths - {key_path, crt_path, ca_path}
                     if p.exists())
    if orphans:
        print()
        print(f"note: {name!r} was previously managed at other paths — these "
              "old files are no longer updated; remove them once nothing reads "
              "them:")
        for p in orphans:
            print(f"  orphaned: {p}")

    # A subdomain SAN (e.g. pg.<myname>) resolves nowhere on the mesh unless we
    # also advertise it. Register the label so the daemon publishes
    # <label>.<myname> → our address into everyone's /etc/hosts.
    from .hosts import mesh_name as _mesh_name
    labels = [lbl for d in dns if (lbl := _san_to_owned_label(d, cfg))]
    if labels:
        added = _add_config_aliases(Path(args.config), cfg, labels)
        own = _mesh_name(cfg.hostname, cfg.mesh_domain)
        if added:
            print()
            print("published name(s) so peers can resolve this service on the mesh:")
            for lbl in added:
                print(f"  {lbl}.{own}")
            print("Restart the daemon to advertise them now "
                  "(else they propagate at the next renewal): "
                  f"{_svc_restart_hint()}  (or re-run sudo gw run).")
    return 0


def cmd_cert_status(args) -> int:
    """Show every daemon-MANAGED TLS cert (from the manifest) — its expiry,
    renewal state, SANs, placed files, and profile — wherever the files live.
    (Reads the cert files, so a 0600 bundle needs sudo to show its expiry.)"""
    from .config import load_config
    from . import certs as certmod

    cfg = load_config(Path(args.config))
    entries = sorted(certmod.load_manifest(cfg.data_dir),
                     key=lambda e: e.get("name", ""))
    if not entries:
        print("no managed TLS certs — 'gw cert-request' (optionally --profile) "
              "creates one.")
        return 0

    now = dt.datetime.now(_UTC)
    for e in entries:
        name = e.get("name", "?")
        head = f"● {name}"
        if e.get("profile"):
            head += f"   (profile: {e['profile']})"
        print(head)

        crt = certmod.ManagedCert.from_dict(e).cert_path
        exp = certmod.cert_expiry(crt) if crt else None
        auto = "auto-renew on" if e.get("auto_renew", True) else "auto-renew OFF"
        if exp is None:
            print(f"    expires : ⚠ cert file missing/unreadable ({crt}) · {auto}")
        else:
            left = (exp - now).total_seconds()
            when = "EXPIRED" if left < 0 else f"in {_dur_short(left)}"
            flag = "⚠ " if left < 0 else ""
            print(f"    expires : {flag}{exp:%Y-%m-%d %H:%M UTC} ({when}) · {auto}")

        sans = list(e.get("dns", [])) + list(e.get("ips", []))
        if sans:
            print(f"    SANs    : {', '.join(sans)}")
        if e.get("files"):
            for f in e["files"]:
                print(f"    {f['role']:<9}: {f['path']}")
        else:
            k, c, a = certmod.entry_paths(e)
            print(f"    files   : key={k}  cert={c}  ca={a}")
        if e.get("reload_cmd"):
            print(f"    reload  : {e['reload_cmd']}")
    return 0


# ---------------------------------------------------------------------------
# rename-node — change this node's mesh hostname (anchor-validated, no re-join)
# ---------------------------------------------------------------------------

def cmd_rename_node(args) -> int:
    """Rename this node in the mesh without re-joining. Asks the anchor to re-issue
    the credential under the new name over the existing control plane; the anchor
    enforces uniqueness (refused if taken) and frees the old name. Keys and the
    overlay address are unchanged. Requires the mesh to be up (the daemon
    running) so the anchor is reachable."""
    _require_root("rename-node")
    import secrets
    import urllib.error
    import urllib.request
    from .config import load_config
    from .keys import NodeKeys
    from .directory import Directory
    from .wire import RenewRequest, Credential, NodeRecord

    cfg_path = Path(args.config)
    if not cfg_path.exists():
        sys.exit(f"no config at {cfg_path}")
    cfg = load_config(cfg_path)

    newname = args.hostname.strip()
    if not newname:
        sys.exit("provide a non-empty hostname: gw rename-node <newname>")
    if newname == cfg.hostname:
        print(f"already named {newname!r} — nothing to do")
        return 0

    # Anchor-pinned nodes (enrolled via `gw invite --hostname`) can't rename. Fail
    # fast locally; the anchor enforces this too (defense in depth).
    if "hostname-pinned" in cfg.caps:
        sys.exit("this node's hostname is anchor-pinned; rename is disabled. "
                 "To change it, re-invite the node with a new --hostname on the anchor.")

    # A rename silently detaches this node from any `host:<oldname>` grants in
    # the active policy — access drops (fail closed, but surprising) until the
    # anchor's grants.toml says host:<newname> and is re-applied. Check the
    # local signed policy cache and confirm BEFORE asking the anchor.
    try:
        from .wire import GrantTable as _GT
        from . import policy as _polmod
        _pp = cfg.data_dir / _polmod.POLICY_BASENAME
        if _pp.exists():
            _tags = set()
            for _g in _GT.from_dict(json.loads(_pp.read_text())).grants:
                _tags |= set(_g["from"]) | set(_g["to"])
            if f"host:{cfg.hostname}" in _tags:
                print(f"⚠ the active policy grants by this node's NAME "
                      f"(host:{cfg.hostname}) — renaming to {newname!r} detaches "
                      f"it from those grants until the anchor's grants.toml says "
                      f"host:{newname} and `gw policy apply` runs.")
                try:
                    if input("rename anyway? [y/N] ").strip().lower() not in ("y", "yes"):
                        print("not renamed.")
                        return 1
                except EOFError:
                    sys.exit("not renamed (no confirmation on a non-interactive "
                             "run; update grants.toml first, or confirm at a tty).")
    except (ValueError, KeyError, OSError) as e:
        log.debug("could not check the policy cache for host grants: %s", e)

    try:
        keys = NodeKeys.load(cfg.data_dir)
    except FileNotFoundError:
        sys.exit("this node isn't enrolled yet (no keys) — run 'gw join' first")

    anchor_url = cfg.root_url
    if not anchor_url:
        sys.exit("no anchor URL known — is this node enrolled and the mesh up?")

    # Ask the anchor to re-issue under the new name (same authenticated path as
    # renewal; the hostname field turns it into a rename).
    req = RenewRequest(
        id_pub=keys.id_pub_bytes,
        wg_pub=keys.wg_pub_bytes,
        nonce=secrets.token_hex(16),
        ts=dt.datetime.now(_UTC).replace(microsecond=0),
        hostname=newname,
    ).sign(keys.id_priv)

    body = json.dumps(req.to_dict()).encode()
    url = f"{anchor_url.rstrip('/')}/renew"
    http_req = urllib.request.Request(
        url, data=body, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(http_req, timeout=15) as resp:
            data = json.loads(resp.read())
    except urllib.error.HTTPError as e:
        try:
            data = json.loads(e.read())
        except Exception:
            data = {"error": f"HTTP {e.code}"}
    except urllib.error.URLError as e:
        sys.exit(f"could not reach the anchor at {anchor_url}: {e} — is the mesh up?")
    if "error" in data:
        sys.exit(f"rename rejected by anchor: {data['error']}")

    cred = Credential.from_dict(data)

    # Re-sign our record with the new name + fresh credential and publish it, so
    # peers and /etc/hosts pick up the rename promptly.
    _republish_own_record(cfg, keys, Directory.load(cfg.dir_cache_path),
                          cred=cred, push_to=[anchor_url])

    # Persist the new name in config.
    text = cfg_path.read_text()
    new, n = re.subn(r'(?m)^\s*hostname\s*=\s*".*?"\s*$',
                     f'hostname = "{newname}"', text, count=1)
    if n:
        cfg_path.write_text(new)
    else:
        log.warning("could not update hostname in %s — edit it by hand", cfg_path)

    print(f"renamed {cfg.hostname!r} -> {newname!r} (overlay addr unchanged)")
    print("Restart the daemon so it keeps advertising the new name: "
          f"{_svc_restart_hint()}  (or re-run sudo gw run)")
    return 0


# ---------------------------------------------------------------------------
# run
# ---------------------------------------------------------------------------

def _start_anchor_control_plane(cfg, keys, directory, get_ca_pubs, grant_policy):
    """Bring up the anchor-only services and return (get_revoked, door_watcher):
    load the CA, start the HTTP control plane, and start the enrollment door
    watcher. get_revoked is the live revoke-list reader the reconcile loop uses;
    door_watcher is returned so cmd_run can stop it at shutdown (the HTTP server
    is a daemon thread that dies with the process, so it isn't returned)."""
    from .ca import CA
    from .keys import CAKeys
    from .server import ControlServer, ControlPlaneAddrInUse
    from .enroll import DoorWatcher, EnrollContext
    from . import wg as wgmod

    if not cfg.ca_key_file:
        _daemon_fatal(cfg, "anchor role requires ca_key_file in [anchor]")
    ca_keys = CAKeys.load(cfg.ca_key_file, _get_passphrase(cfg.ca_key_passphrase_env))
    # key_file arms the stale-key guard: this CA lives as long as the daemon,
    # and must refuse to sign if ca.key changes on disk underneath it.
    ca = CA(ca_keys, cfg.data_dir, cfg.credential_ttl,
            key_file=Path(cfg.ca_key_file))
    get_revoked = ca.load_revoked_set
    log.info("CA loaded, pub=%s...", ca_keys.ca_pub_bytes.hex()[:16])
    # Re-apply door routing in case the machine rebooted since create.
    wgmod.setup_door_routing()

    # Bind the control plane to the overlay address (reachable only through the
    # mesh) and loopback (for the anchor talking to itself) — NOT "::". This
    # keeps it off the underlay structurally, no firewall rule needed.
    port = _control_port(cfg)
    listen_addrs = [f"[{keys.addr}]:{port}", f"[::1]:{port}"]

    # Fleet-wide renew hint (gw renew-all): served in /directory, re-read per
    # request so a bump takes effect without restarting the anchor.
    def read_renew_after():
        try:
            return (cfg.data_dir / "renew_after").read_text().strip() or None
        except FileNotFoundError:
            return None

    # grants.toml is the SOURCE OF TRUTH, but changes are APPLIED DELIBERATELY:
    # `gw policy apply` previews the X→Y change and asks to confirm before
    # signing it into policy.json. The daemon does NOT silently auto-apply edits
    # — a background daemon can't prompt, and a policy change tears down tunnels,
    # so it should be confirmed, not triggered by a stray file save. At startup
    # (and via `gw policy show`) an unapplied edit is surfaced, so a forgotten
    # apply is visible rather than silently ineffective.
    from .policy import unapplied_edits
    pending = unapplied_edits(cfg.data_dir)
    if pending:
        log.warning("grants.toml has unapplied changes (%s) — run "
                    "`sudo gw policy apply` to review and apply them", pending)

    def read_policy():
        # Serve the signed, APPLIED policy.json (or None). Nodes trust the CA
        # signature; they never see raw grants.toml.
        from .policy import POLICY_BASENAME
        try:
            return json.loads((cfg.data_dir / POLICY_BASENAME).read_text())
        except FileNotFoundError:
            return None
        except (OSError, ValueError) as e:
            log.warning("policy.json unreadable, serving none: %s", e)
            return None

    try:
        server = ControlServer(
            listen_addrs, directory, get_ca_pubs=get_ca_pubs, get_revoked=get_revoked,
            ca=ca, cache_path=cfg.dir_cache_path, tls_cert_ttl=cfg.tls_cert_ttl,
            mesh_domain=cfg.mesh_domain, get_renew_after=read_renew_after,
            get_policy=read_policy)
    except ControlPlaneAddrInUse as e:
        _daemon_fatal(cfg, f"anchor control plane can't start: {e}")
    server.start()

    door_watcher = DoorWatcher(
        EnrollContext(
            ca=ca, directory=directory, node_keys=keys, wg_iface=cfg.wg_interface,
            get_ca_pubs=get_ca_pubs, get_revoked=get_revoked,
            cache_path=cfg.dir_cache_path, control_port=port,
            mesh_domain=cfg.mesh_domain, data_dir=cfg.data_dir),
        door_port=cfg.door_port)
    door_watcher.start()
    log.info("door watcher started")

    # Garbage-collect abandoned nodes: the CA stops recertifying (and the
    # directory sheds) any node that's been expired longer than drop_grace, so a
    # churned cloud fleet left to expire is forgotten without manual `gw revoke`.
    from .sweep import StaleSweep
    StaleSweep(ca, directory, cfg.drop_grace, cfg.dir_cache_path).start()
    log.info("stale-node sweep started (drop_grace=%s)", cfg.drop_grace)
    return get_revoked, door_watcher


def cmd_run(args) -> int:
    _require_root("run")
    _require_tools()
    from .config import load_config
    from .keys import NodeKeys
    from .directory import Directory
    from .reconcile import ReconcileLoop
    from .sync import SyncLoop, push_record
    from .renewal import RenewalLoop
    from . import wg as wgmod

    cfg = load_config(Path(args.config))

    # Durable data-plane command trail: attach the rotating audit file so every
    # ip/wg command the daemon issues is recorded independently of the journal.
    if cfg.audit_log is not None:
        from . import audit
        if audit.attach_file(cfg.audit_log):
            log.info("data-plane command audit → %s", cfg.audit_log)

    log.info("starting — role=%s hostname=%s", cfg.role, cfg.hostname)

    # Service-definition self-heal: pick up improvements shipped by upgrades
    # (no-op when unchanged, on an unmanaged host, or running by hand). Backend
    # of the host: systemd unit or OpenRC script.
    _svc = _service_backend()
    if _svc is not None:
        _svc.refresh_template()

    # Roles are the grant-table vocabulary. With no policy applied everyone
    # peers regardless; once one exists, a node with no role: tag reaches only
    # the anchor — worth saying once, up front.
    if not any(c.startswith("role:") for c in cfg.caps):
        log.warning("[node] caps = %s contains no role:<name> tag — once a "
                    "grant table is applied, this node will reach only the "
                    "anchor (add e.g. role:node)", cfg.caps)

    keys = NodeKeys.load_or_generate(cfg.data_dir)
    log.info("overlay addr: %s", keys.addr)

    # Key-hygiene check at every daemon start: a secret owned by a non-root
    # user, or readable past its owner, is a standing hole (for the CA key,
    # credential-minting). Catches legacy installs whose create chowned the
    # data dir to the operator.
    for w in _key_file_warnings(_secret_key_paths(cfg)):
        log.warning("%s", w)

    directory = Directory.load(cfg.dir_cache_path)

    # Trust is static, straight from config: the trusted CA set, the seeds to
    # pull the directory from, and the anchor URL. (Moving the anchor is a deliberate
    # re-root — a trusted_pubs/root_url config change — not a runtime event.)
    ca_pubs = [bytes.fromhex(h) for h in cfg.ca_pubs_hex]
    def get_ca_pubs():
        return ca_pubs

    from . import audit
    with audit.context(f"startup: ensure interface {cfg.wg_interface} [{keys.addr}]"):
        try:
            wgmod.ensure_interface(
                cfg.wg_interface, keys.addr, cfg.listen_port, cfg.wg_key_path
            )
        except wgmod.PortInUse as e:
            # A fatal, operator-fixable startup condition — exit VISIBLY (journal
            # + a breadcrumb gw watch shows) rather than a silent crash-loop
            # under the systemd unit's Restart=on-failure.
            _daemon_fatal(cfg, str(e))

    sync: SyncLoop | None = None
    renewal: RenewalLoop | None = None
    door_watcher = None

    # Revoke list is re-read live (not snapshotted) so `gw revoke` takes effect
    # without a daemon restart — both for control-plane refusal and local
    # eviction. Plain nodes have no revoke list (expiry-based revocation).
    # The live grant table (roles → roles : ports) drives tunnel existence.
    # Loaded from last-known-good on disk; the sync loop offers fresh tables
    # (CA-verified, seq-monotonic). Built BEFORE the anchor block so the anchor
    # can feed its own copy from grants.toml (see _start_anchor_control_plane).
    from .policy import GrantPolicy, POLICY_BASENAME
    grant_policy = GrantPolicy(cache_path=cfg.data_dir / POLICY_BASENAME,
                               get_ca_pubs=get_ca_pubs)
    grant_policy.load_cache()

    get_revoked: "callable" = set
    if cfg.role == "anchor":
        get_revoked, door_watcher = _start_anchor_control_plane(
            cfg, keys, directory, get_ca_pubs, grant_policy)

    # Directory sync — pull from the configured seeds (the anchor). The renewal loop
    # is built below; the callback reads it lazily (the first pull is one interval
    # out), so acting on the anchor's fleet renew hint needs no reordering.
    sync = SyncLoop(
        directory, lambda: cfg.seeds, cfg.dir_cache_path,
        on_renew_after=lambda ts: renewal.maybe_renew_after(ts) if renewal else None,
        expected_domain=cfg.mesh_domain,
        on_policy=grant_policy.offer,
    )
    sync.start()

    # Name resolution via a managed /etc/hosts block (opt-in). When off, remove
    # any block we left behind before (clean opt-out).
    from . import hosts as _hosts
    if cfg.hosts_sync:
        log.info("hosts: maintaining /etc/hosts mesh block under .%s", cfg.mesh_domain)
    else:
        try:
            if _hosts.remove_block(cfg.mesh_domain):
                log.info("hosts: removed managed /etc/hosts block (sync disabled)")
        except Exception as e:
            log.warning("hosts: could not clean /etc/hosts: %s", e)

    def _ensure_mesh_iface():
        # Self-heal hook: recreate the mesh interface if it vanishes under a
        # running daemon (purge/re-create on this host, manual ip link del).
        with audit.context(f"heal: recreate missing interface {cfg.wg_interface}"):
            wgmod.ensure_interface(
                cfg.wg_interface, keys.addr, cfg.listen_port, cfg.wg_key_path
            )

    def _publish_reachable(reachable: list) -> None:
        # Re-sign our record with the new live-link set and push it, so the
        # fleet sees the edge change. quiet_push: the anchor being down already
        # warns via the sync loop; a 30s-cadence publish shouldn't pile on.
        if _republish_own_record(cfg, keys, directory, reachable=reachable,
                                 push_to=cfg.seeds, quiet_push=True):
            log.debug("published reachable set (%d live links)", len(reachable))

    port_enforcer = _make_port_enforcer(cfg, args, grant_policy)

    recon = ReconcileLoop(
        iface=cfg.wg_interface,
        directory=directory,
        local_id_pub=keys.id_pub_bytes,
        local_caps=cfg.caps,
        get_ca_pubs=get_ca_pubs,
        get_revoked=get_revoked,
        policy=grant_policy,
        hosts_domain=cfg.mesh_domain if cfg.hosts_sync else None,
        get_local_families=_local_families,   # re-detected each cycle (v6→v4 mid-run)
        ensure_iface=_ensure_mesh_iface,
        data_dir=cfg.data_dir,
        on_reachable=_publish_reachable,
        port_enforcer=port_enforcer,
        policy_refresh=grant_policy.refresh_from_cache,
        local_hostname=cfg.hostname,
    )
    recon.start()

    # Roles live in the CA-signed credential, not the config file. The loops were
    # built with cfg.caps, but the credential is authoritative — so adopt its
    # roles now (in case the anchor changed them while we were down) and on every
    # renewal, feeding the reconcile loop + port enforcer live. That's what makes
    # `gw set-roles` + `gw renew-all` take full effect with no restart. A routine
    # renewal (roles unchanged) is a no-op, so this is quiet in steady state.
    _applied_caps = [sorted(cfg.caps)]

    def _adopt_caps(cred):
        caps = list(cred.caps)
        if sorted(caps) == _applied_caps[0]:
            return
        _applied_caps[0] = sorted(caps)
        recon.set_local_caps(caps)
        if port_enforcer is not None:
            port_enforcer.set_local_caps(caps)
        roles = [c[len("role:"):] for c in caps if c.startswith("role:")]
        log.info("roles changed by the anchor — adopted live from the credential: "
                 "%s (no restart needed)", roles or "(none)")

    # We advertise whatever endpoint config gives us (empty = naturally
    # outbound-only; peers back off a dead one).
    eff_endpoints = list(cfg.endpoints)

    # Honor config changes on (re)start: if our record's endpoints/aliases no
    # longer match config (e.g. a `gw cert-request` that added a service name),
    # re-sign it so what we advertise is current — the daemon reads config only
    # at startup.
    want_aliases = _config_aliases(cfg)
    own_record = directory.get(keys.id_pub_hex)
    if own_record and (list(own_record.endpoints) != list(eff_endpoints)
                       or sorted(own_record.aliases) != sorted(want_aliases)):
        own_record = _republish_own_record(cfg, keys, directory,
                                           endpoints=eff_endpoints,
                                           aliases=want_aliases)
        log.info("updated own record (endpoints=%s, aliases=%s)",
                 eff_endpoints, want_aliases)

    if own_record:
        _adopt_caps(own_record.cred)      # honor a role change made while we were down

    # Push our own record so the rest of the mesh knows about us. This gets a
    # newly enrolled node into the anchor's directory; it is also how endpoint
    # changes propagate without waiting for the next renewal cycle.
    if own_record:
        for seed in cfg.seeds:
            try:
                push_record(seed, own_record)
                log.info("pushed own record to %s", seed)
            except Exception as e:
                log.warning("push to %s failed (will retry on next sync): %s", seed, e)

    # Renewal loop — targets the configured anchor.
    if own_record:
        renewal = RenewalLoop(
            node_keys=keys,
            directory=directory,
            get_anchor_url=lambda: cfg.root_url,
            current_cred=own_record.cred,
            hostname=cfg.hostname,
            endpoints=eff_endpoints,
            cache_path=cfg.dir_cache_path,
            aliases=want_aliases,
            on_renew=_adopt_caps,         # adopt anchor-side role changes live
        )
        renewal.start()
    else:
        log.warning("no credential in directory — run 'gw join <token>' first")

    # TLS service-cert auto-renewal: renew each cert recorded by `gw cert-request`
    # at ~half its lifetime and run its reload_cmd. No-op if none are managed.
    from .certs import CertRenewalLoop, load_manifest as _load_cert_manifest
    cert_renewal = None
    _managed = _load_cert_manifest(cfg.data_dir)
    if _managed:
        cert_renewal = CertRenewalLoop(keys, lambda: cfg.root_url,
                                       cfg.data_dir, mesh_domain=cfg.mesh_domain)
        cert_renewal.start()
        log.info("TLS cert auto-renewal started (%d managed cert(s))", len(_managed))

    # Advertised-endpoint auto-refresh: re-detect our public endpoint(s) and
    # re-advertise on a REAL change (an IPv6 prefix renumbering swaps the stable
    # GUA; a v6→v4 move). Detection prefers the stable address, so privacy-
    # extension rotation never trips it and steady state is a no-op. Opt-out with
    # [node] endpoint_auto=false — set when the operator pinned an --endpoint.
    endpoint_loop = None
    if cfg.endpoint_auto:
        from .endpoints import EndpointLoop
        def _current_endpoints():
            own = directory.get(keys.id_pub_hex)
            return list(own.endpoints) if own else list(eff_endpoints)
        endpoint_loop = EndpointLoop(
            detect=lambda: _advertised_endpoints(None, cfg.listen_port),
            current=_current_endpoints,
            republish=lambda eps: _republish_own_record(
                cfg, keys, directory, endpoints=eps, push_to=cfg.seeds),
        )
        endpoint_loop.start()
        log.info("endpoint auto-refresh on (re-advertise on address change)")

    # Liveness watchdog. Under systemd, sd_notify + WatchdogSec owns wedge
    # detection (a NOTIFY_SOCKET is present), so we stay out of its way. Off
    # systemd there's no notify socket — arm the portable self-exit watchdog so
    # a death-restart supervisor (OpenRC's supervise-daemon, runit, a bare
    # respawn) can recover a wedged daemon the same way systemd would.
    watchdog = None
    if not os.environ.get("NOTIFY_SOCKET"):
        from .loop import WedgeWatchdog
        from .reconcile import seconds_since_reconcile
        watchdog = WedgeWatchdog(
            age_fn=lambda: seconds_since_reconcile(cfg.data_dir))
        watchdog.start()
        log.info("liveness watchdog on (self-exit if reconcile wedges; "
                 "no systemd notify socket)")

    # Startup fully succeeded (interface up, control plane up, loops running) —
    # forget any death breadcrumb from a prior failed boot so `gw watch` stops
    # reporting a stale fatal reason.
    from . import reconcile as _rmod
    _rmod.clear_daemon_fatal(cfg.data_dir)

    # Block until SIGTERM / SIGINT
    stop_flag = threading.Event()

    def _handle_signal(signum, frame):
        log.info("caught signal %d, shutting down", signum)
        stop_flag.set()

    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    stop_flag.wait()

    recon.stop()
    if sync:
        sync.stop()
    if renewal:
        renewal.stop()
    if cert_renewal:
        cert_renewal.stop()
    if endpoint_loop:
        endpoint_loop.stop()
    if watchdog:
        watchdog.stop()
    if door_watcher:
        door_watcher.stop()
    log.info("shutdown complete")
    return 0


# ---------------------------------------------------------------------------
# narrate / config — the thin read-only commands (the heavyweight
# presentation — watch, diagnose, the roster — lives in status.py)
# ---------------------------------------------------------------------------

def cmd_narrate(args) -> int:
    """Read the data-plane command trail and translate it into plain English —
    what greasewood did to the kernel's network state, when, why, and whether it
    worked. Reads <data_dir>/audit.log by default; a path, or '-' for stdin."""
    from .config import load_config, _parse_duration
    from . import narrate as N

    # Where to read from.
    src = getattr(args, "source", None)
    if src == "-":
        lines = sys.stdin.read().splitlines()
    else:
        if src:
            path = Path(src)
        else:
            cfg_path = Path(args.config)
            path = None
            if cfg_path.exists():
                cfg = load_config(cfg_path)
                path = cfg.audit_log or (cfg.data_dir / "audit.log")
            path = path or Path("/var/lib/greasewood/audit.log")
        if not path.exists():
            sys.exit(f"no audit log at {path} (the daemon writes it; run `gw run`, "
                     f"or pass a path / '-' for stdin)")
        lines = path.read_text(errors="replace").splitlines()

    entries = [e for e in (N.parse_line(ln) for ln in lines) if e is not None]

    # Filters.
    if getattr(args, "since", None):
        cutoff = dt.datetime.now(_UTC) - _parse_duration(args.since)
        def _fresh(e):
            try:
                return dt.datetime.fromisoformat(e.ts.replace("Z", "+00:00")) >= cutoff
            except (ValueError, AttributeError):
                return True
        entries = [e for e in entries if _fresh(e)]
    if getattr(args, "failures", False):
        entries = [e for e in entries if e.failed]
    if getattr(args, "peer", None):
        entries = [e for e in entries if args.peer.lower() in e.ctx.lower()]
    if getattr(args, "grep", None):
        g = args.grep.lower()
        entries = [e for e in entries if g in N.searchable(e)]

    if not entries:
        print("no matching data-plane commands.")
        return 0

    color = sys.stdout.isatty() and not getattr(args, "no_color", False)
    if getattr(args, "stats", False):
        print(N.summarize(entries))
        print()
    for line in N.narrate(entries, color=color, raw=getattr(args, "raw", False)):
        print(line)
    return 0


def cmd_config(args) -> int:
    """Print resolved config facts, machine-readable — for scripting. With no
    argument, one `key<TAB>value` line per fact; with a key, just that value
    (e.g. `IFACE=$(gw config interface)` to scope a firewall rule to the mesh
    interface). Reads config only — no root, no network."""
    from .config import load_config
    cfg = load_config(Path(args.config))
    facts = {
        "role": cfg.role,
        "hostname": cfg.hostname,
        "interface": cfg.wg_interface,
        "mesh_domain": cfg.mesh_domain,
        "listen_port": str(cfg.listen_port),
        "overlay_prefix": cfg.overlay_prefix,
        "data_dir": str(cfg.data_dir),
        "config": str(args.config),
        "root_url": cfg.root_url or "",
    }
    if cfg.role == "anchor":
        facts["control_port"] = str(_control_port(cfg))
        facts["door_port"] = str(cfg.door_port)
    if args.key:
        if args.key not in facts:
            sys.exit(f"unknown config key {args.key!r} — have: {', '.join(facts)}")
        print(facts[args.key])
        return 0
    for k, v in facts.items():
        print(f"{k}\t{v}")
    return 0


# ---------------------------------------------------------------------------
# policy — the mesh's grant table (roles → roles : ports; derives the topology)
# ---------------------------------------------------------------------------

def _resolve_editor() -> list:
    """The editor argv for `gw policy edit`, visudo-style: $SUDO_EDITOR, then
    $VISUAL, then $EDITOR (any may carry arguments, e.g. 'code --wait'), else
    nano, else vi. Under sudo the user's EDITOR is often stripped by env_reset,
    which is exactly why the nano fallback matters."""
    import shlex
    for var in ("SUDO_EDITOR", "VISUAL", "EDITOR"):
        val = os.environ.get(var)
        if val:
            argv = shlex.split(val)
            if argv and shutil.which(argv[0]):
                return argv
    for fallback in ("nano", "vi"):
        if shutil.which(fallback):
            return [fallback]
    sys.exit("no editor found — set $EDITOR, or install nano")


def cmd_policy(args) -> int:
    """`gw policy show` — render the active grant table (any node, no root).
    `gw policy edit` — anchor: open grants.toml in the operator's editor,
    validate on save (re-edit loop on a parse error, so a typo never lands),
    then offer to run the apply preview immediately — the edit → apply gap is
    where forgotten applies come from.
    `gw policy apply [file]` — anchor: validate grants.toml, PREVIEW the change
    (grant diff + tunnel delta), ask to confirm, then sign + publish. This is
    the deliberate path a policy change takes — grants.toml is the source, but
    it is never applied silently: a change tears down tunnels, so it is
    confirmed, not triggered by a stray file save."""
    from .config import load_config
    from . import policy as polmod
    from .wire import GrantTable

    if args.action == "show":
        cfg = load_config(Path(args.config))
        table = None
        cache = cfg.data_dir / polmod.POLICY_BASENAME
        if cache.exists():
            try:
                table = GrantTable.from_dict(json.loads(cache.read_text()))
            except (ValueError, KeyError) as e:
                sys.exit(f"policy cache at {cache} is corrupt: {e}")
        print(polmod.render_grants(table))
        pending = polmod.unapplied_edits(cfg.data_dir)
        if pending:
            print(f"\n⚠ grants.toml has unapplied changes ({pending}) — run "
                  f"`sudo gw policy apply` to review and apply them.")
        return 0

    # ---- edit (anchor, root: editor → validate loop → offer apply) ----
    if args.action == "edit":
        _require_root("policy edit", "grants.toml lives in the root-owned data dir")
        cfg = load_config(Path(args.config))
        if cfg.role != "anchor":
            sys.exit("gw policy edit must run on the anchor — grants.toml is "
                     "authored there; this node only receives the signed policy")
        gpath = Path(args.file) if args.file else cfg.data_dir / polmod.GRANTS_BASENAME
        if not gpath.exists():
            gpath.write_text(polmod.DEFAULT_GRANTS_TOML)
            print(f"no grants.toml yet — seeded the default-closed template at {gpath}")
        editor = _resolve_editor()
        print(f"editing {gpath}  ({' '.join(editor)})")
        while True:
            r = subprocess.run([*editor, str(gpath)])
            if r.returncode != 0:
                sys.exit(f"{editor[0]} exited {r.returncode} — {gpath} left "
                         f"as-is, nothing applied")
            try:
                _text = gpath.read_text()
                polmod.parse_grants_toml(_text)
                polmod.parse_assignments(_text)   # the [assign] table too
                break
            except ValueError as e:
                print(f"  ✗ {e}")
                try:
                    again = input("re-edit? [Y/n] ").strip().lower()
                except EOFError:
                    again = "n"
                if again in ("n", "no"):
                    sys.exit(f"saved but INVALID — {gpath} cannot be applied "
                             f"until fixed (`gw policy show` will flag it)")
        if args.file is None:
            pending = polmod.unapplied_edits(cfg.data_dir)
            if not pending:
                print("✓ valid — identical to the applied policy; nothing to do")
                return 0
            print(f"✓ valid — {pending}")
        else:
            print("✓ valid")
        try:
            go = input("run the apply preview now? [Y/n] ").strip().lower()
        except EOFError:
            go = "n"
        if go in ("n", "no"):
            print("not applied — edits are inert until:  sudo gw policy apply")
            return 0
        # confirmed: fall through into apply below (it re-reads + previews).

    # ---- apply (anchor, root: signs with the CA key) ----
    from .directory import Directory
    from .keys import CAKeys, atomic_write
    _require_root("policy apply", "it signs the table with the CA key")
    cfg = load_config(Path(args.config))
    if cfg.role != "anchor":
        sys.exit("gw policy apply must be run on the anchor (role = anchor)")
    if cfg.ca_key_file is None:
        sys.exit("policy apply requires ca_key_file in [anchor]")

    grants_path = Path(args.file) if args.file else cfg.data_dir / polmod.GRANTS_BASENAME
    if not grants_path.exists():
        sys.exit(f"no grants file at {grants_path} — write one (see "
                 f"grants.toml.example) or pass a path")
    try:
        grants_text = grants_path.read_text()
        grants = polmod.parse_grants_toml(grants_text)
        assignments = polmod.parse_assignments(grants_text)
    except ValueError as e:
        sys.exit(str(e))

    # Current table (for seq + delta) and the fleet (for delta + typo check).
    old_table = None
    cache = cfg.data_dir / polmod.POLICY_BASENAME
    if cache.exists():
        try:
            old_table = GrantTable.from_dict(json.loads(cache.read_text()))
        except (ValueError, KeyError):
            log.warning("existing policy cache unreadable; treating as none")
    directory = Directory.load(cfg.dir_cache_path)
    records = directory.all()

    # Declarative role assignments ([assign]): compute role diffs up front —
    # they feed the typo check (a role granted and assigned in the SAME apply
    # is not a typo) and the tunnel delta (caps_override), and print with the
    # grant diff so the whole change previews as one.
    caps_override, assign_lines = {}, []
    if assignments is not None:
        by_host = {r.cred.hostname: r for r in records}
        for host, roles in sorted(assignments.items()):
            rec = by_host.get(host)
            if rec is None:
                assign_lines.append(
                    f"  ⚠ [assign] names {host!r} but no current member has "
                    f"that hostname — reconciles once it joins")
                continue
            cur = sorted(c[len('role:'):] for c in rec.cred.caps
                         if c.startswith('role:'))
            if cur != list(roles):
                kept = [c for c in rec.cred.caps if not c.startswith("role:")]
                caps_override[rec.id_pub.hex()] = \
                    kept + [f"role:{r}" for r in roles]
                assign_lines.append(
                    f"  ~ roles  {host}: {', '.join(cur) or '(none)'} → "
                    f"{', '.join(roles) or '(none)'}")

    for tag in sorted(polmod.unmatched_tags(grants, records, caps_override)):
        if tag.startswith("host:"):
            print(f"  ⚠ grant names {tag!r} but NO current member has that "
                  f"hostname — typo, or a not-yet-joined machine? Until then it "
                  f"grants nothing; when a node DOES take that name it inherits "
                  f"these grants, so pin the name at invite "
                  f"(gw invite --hostname {tag[len('host:'):]}).")
        else:
            print(f"  ⚠ grant names {tag!r} but NO current node holds role:{tag} "
                  f"— typo? (it grants nothing until a node holds it)")
    for name in polmod.unpinned_host_grants(grants, records):
        print(f"  ⚠ host grant on {name!r}, but that node named ITSELF (its "
              f"hostname isn't anchor-pinned): it could rename away from its "
              f"grants, and after decommissioning the freed name — and these "
              f"grants — pass to whoever claims it. Prefer pinning: re-invite "
              f"with `gw invite --hostname {name}`.")

    new_seq = (old_table.seq + 1) if old_table else 1
    old_grants = old_table.grants if old_table else []
    print(f"this will change the policy: v{old_table.seq if old_table else '—'} "
          f"→ v{new_seq}")

    # Grant-level diff (the rules themselves — the "X → Y").
    def _fmt(g):
        return (f"{', '.join(g['from'])} -> {', '.join(g['to'])} : "
                f"{', '.join(g['ports'])}")
    added = [g for g in grants if g not in old_grants]
    dropped = [g for g in old_grants if g not in grants]
    if not added and not dropped:
        print("  grants: (unchanged)")
    for g in dropped:
        print(f"  - grant  {_fmt(g)}")
    for g in added:
        print(f"  + grant  {_fmt(g)}")

    for line in assign_lines:
        print(line)

    # Tunnel-level effect (what actually connects/disconnects on the wire).
    created, removed = polmod.tunnel_delta(records, old_grants or None, grants,
                                           caps_override=caps_override)
    for a, b in created:
        print(f"  + tunnel {a} ↔ {b}")
    for a, b in removed:
        print(f"  - tunnel {a} ↔ {b}")
    if not created and not removed:
        print("  tunnels: (no change — port scopes only)")

    if not getattr(args, "yes", False):
        answer = input("apply? [y/N] ").strip().lower()
        if answer not in ("y", "yes"):
            print("not applied.")
            return 1

    ca_keys = CAKeys.load(cfg.ca_key_file, _get_passphrase(cfg.ca_key_passphrase_env))
    table = GrantTable(seq=new_seq, grants=grants).sign(ca_keys.ca_priv)
    atomic_write(cache, json.dumps(table.to_dict(), indent=2), mode=0o644)
    print(f"policy v{new_seq} applied — nodes adopt it on their next directory "
          f"sync; tunnels reconcile within a cycle.")

    # Reconcile the registry to [assign] (idempotent — a no-change apply is
    # silent). One fleet renew hint for the whole batch, so every re-roled
    # node adopts its new credential within a poll interval.
    if assignments is not None:
        from .ca import CA as _CA
        changed, _missing = polmod.apply_assignments(
            assignments, _CA(ca_keys, cfg.data_dir, cfg.credential_ttl))
        for host, old, new in changed:
            print(f"  ~ roles {host}: {', '.join(old) or '(none)'} → "
                  f"{', '.join(new) or '(none)'}")
        if changed:
            _request_fleet_renewal(cfg)
            print(f"  {len(changed)} node(s) re-roled — fleet renewal "
                  f"requested; they adopt live within a poll interval.")
    return 0


def cmd_renew(args) -> int:
    """
    Force an immediate credential renewal for THIS node. Normally the daemon
    renews on its own (~half the credential TTL); this fetches a fresh credential
    from the anchor right now, re-publishes the record so peers stop serving the old
    expiry, and adopts any caps/roles the anchor changed in the meantime (so
    `gw set-caps` / `gw set-roles` take effect immediately instead of at the
    next scheduled renewal).

    Run it ON THE NODE: renewal is self-signed by the node's id_priv, so the anchor
    cannot renew a node on its behalf — there is no "renew everyone from the anchor".
    """
    _require_root("renew")
    from .config import load_config
    from .keys import NodeKeys
    from .directory import Directory
    from .wire import NodeRecord
    from .renewal import _do_renew
    from .sync import push_record
    cfg_path = Path(args.config)
    if not cfg_path.exists():
        sys.exit(f"not configured (no config file at {cfg_path})")
    cfg = load_config(cfg_path)
    try:
        keys = NodeKeys.load(cfg.data_dir)
    except Exception:
        sys.exit("this node isn't enrolled yet (no keys) — run 'gw join <token>' first")
    if not cfg.root_url:
        sys.exit("no anchor URL configured (root_url) — is this node enrolled?")

    try:
        cred = _do_renew(cfg.root_url, keys)
    except Exception as e:
        sys.exit(f"renew failed: {e}\n(is the mesh up and the anchor reachable? "
                 f"renewal goes over the overlay)")

    # Re-publish our record with the fresh credential — highest-seq-wins means
    # peers adopt this promptly.
    _republish_own_record(cfg, keys, Directory.load(cfg.dir_cache_path),
                          cred=cred, push_to=[cfg.root_url])

    print(f"renewed — credential now expires {cred.exp:%Y-%m-%d %H:%M UTC}")

    # Adopt caps/roles if the anchor changed them since we last renewed. Editing
    # this line grants nothing on its own (peers enforce against the credential),
    # but the daemon reads its LOCAL side of the peering policy from here, so we
    # keep it in sync with what the CA just issued.
    if list(cred.caps) != list(cfg.caps):
        text = cfg_path.read_text()
        new, n = re.subn(r'(?m)^\s*caps\s*=\s*\[.*\]\s*$',
                         f'caps = {json.dumps(list(cred.caps))}', text, count=1)
        if n:
            cfg_path.write_text(new)
            print(f"caps updated by the anchor: {list(cfg.caps)} -> {list(cred.caps)}")
        else:
            log.warning("anchor changed caps to %s but couldn't update %s — edit by hand",
                        list(cred.caps), cfg_path)

    print("Restart the daemon to fully adopt it: "
          f"{_svc_restart_hint()}  (or re-run sudo gw run)")
    return 0


# ---------------------------------------------------------------------------
# renew-all  (anchor: advertise a fleet-wide "renew asap" hint)
# ---------------------------------------------------------------------------

def cmd_renew_all(args) -> int:
    """
    [anchor] Request a fleet-wide credential renewal. Writes renew_after = now, which
    the anchor advertises in GET /directory; every cooperating node whose credential
    was issued before that timestamp renews after a jittered delay. The jitter
    window scales with the mesh size (window = N * spread), so the anchor's
    renewals/sec stays roughly constant no matter how big the fleet is.

    Pull-based, not a push: nodes act on their next directory poll, and a node
    that's offline now renews when it returns — renew_after is a level, not an
    edge. Handy after a re-root (pull the fleet onto the new CA before the overlap
    window closes) or any fleet-wide policy change.
    """
    from .config import load_config
    _require_root("renew-all", "it writes the anchor's root-owned renewal state")
    cfg = load_config(Path(args.config))
    if cfg.role != "anchor":
        sys.exit("gw renew-all must be run on the anchor (role = anchor)")

    now = _request_fleet_renewal(cfg)
    print(f"fleet renewal requested: renew_after = {now:%Y-%m-%d %H:%M UTC}")
    print("Cooperating nodes whose credential predates this will renew within a "
          "poll interval + jitter; offline nodes renew when they return.")
    print(f"(To stop advertising it later, delete {cfg.data_dir / 'renew_after'}.)")
    return 0


# ---------------------------------------------------------------------------
# anchor-backup / anchor-restore  (encrypted CA + registry snapshot)
# ---------------------------------------------------------------------------

def _backup_passphrase(confirm: bool) -> bytes:
    """Passphrase for the backup blob. From $GW_BACKUP_PASSPHRASE if set (for
    unattended/cron use), else prompted — twice when confirm=True (backup)."""
    import getpass
    env = os.environ.get("GW_BACKUP_PASSPHRASE")
    if env:
        return env.encode()
    pw = getpass.getpass("Backup passphrase: ")
    if not pw:
        sys.exit("empty passphrase — aborting")
    if confirm and getpass.getpass("Confirm passphrase: ") != pw:
        sys.exit("passphrases did not match — aborting")
    return pw.encode()


def cmd_anchor_backup(args) -> int:
    """Write a single encrypted archive of this anchor's trust state (CA key, the
    nodes/ registry, revoke list, door key). Restoring the same key onto a new
    host is a restore, not a re-root — no fleet-wide trust change."""
    from .config import load_config
    from . import backup as bak

    _require_root("anchor-backup", "it reads the CA key and the anchor registry")
    cfg = load_config(Path(args.config))
    if cfg.role != "anchor":
        sys.exit("gw anchor-backup must be run on the anchor (role = anchor)")
    if cfg.ca_key_file is None:
        sys.exit("anchor-backup requires ca_key_file in [anchor]")

    files = bak.collect_anchor_state(cfg.data_dir, cfg.ca_key_file)
    if "ca.key" not in files:
        sys.exit(f"CA key not found at {cfg.ca_key_file} — nothing to back up")

    to_stdout = args.out == "-"                # `-` → stream the blob (for a pipe)
    passphrase = _backup_passphrase(confirm=not to_stdout)
    # This passphrase is the ONLY thing protecting the CA key (and anchor id_priv)
    # at rest — a weak one undoes the whole backup. Warn, but don't block. (For a
    # stream the passphrase is an ephemeral env value, so skip the length nag.)
    if not to_stdout and len(passphrase) < 12:
        print(f"⚠ warning: backup passphrase is short ({len(passphrase)} chars). "
              "This one secret guards your entire fleet's root key — use a long, "
              "high-entropy passphrase (a diceware phrase is ideal).")
    blob = bak.pack(files, passphrase)

    node_count = sum(1 for n in files if n.startswith("nodes/"))
    if to_stdout:
        sys.stdout.buffer.write(blob)          # binary to stdout; notes to stderr
        sys.stdout.buffer.flush()
        print(f"streamed anchor backup ({node_count} node(s))", file=sys.stderr)
        return 0

    out = Path(args.out) if args.out else \
        cfg.data_dir / f"greasewood-anchor-backup-{cfg.hostname}.gwbk"
    from .keys import atomic_write
    atomic_write(Path(out), blob)          # 0600, atomic: the fleet's root key
    print(f"wrote encrypted anchor backup → {out}")
    print(f"  CA key + {node_count} enrolled node(s) + revoke list + door key")
    print("Store it OFFLINE. Anyone with this file AND the passphrase can "
          "impersonate your CA. Test-restore it before you rely on it.")
    return 0


def cmd_anchor_restore(args) -> int:
    """Decrypt an anchor backup into a data dir. For standing up a replacement anchor
    on the same CA key (see RUNBOOK 'destroyed anchor')."""
    _require_root("anchor-restore")
    from . import backup as bak

    blob = sys.stdin.buffer.read() if args.archive == "-" \
        else Path(args.archive).read_bytes()   # `-` → read the blob from a pipe
    data_dir = Path(args.data_dir).expanduser()

    # Guard against clobbering a live anchor's CA key by accident.
    if (data_dir / "ca.key").exists() and not args.force:
        sys.exit(f"{data_dir / 'ca.key'} already exists — refusing to overwrite "
                 f"a live anchor. Pass --force if you really mean to restore over it.")

    passphrase = _backup_passphrase(confirm=False)
    try:
        files = bak.unpack(blob, passphrase)
        written = bak.restore_files(data_dir, files)
    except bak.BackupError as e:
        sys.exit(f"restore failed: {e}")

    node_count = sum(1 for n in written if n.startswith("nodes/"))
    print(f"restored {len(written)} file(s) into {data_dir}")
    print(f"  CA key + {node_count} enrolled node(s) + revoke list + door key")
    print("Next: write /etc/greasewood.toml pointing ca_key_file at "
          f"{data_dir / 'ca.key'} (role = anchor), then `sudo gw run`. Because the "
          "CA key is unchanged, existing nodes keep trusting it — no re-root.")
    return 0


def _dest_is_overlay(dest: str, cfg) -> bool:
    """Best-effort: does this SSH destination point INTO the mesh overlay? The
    transfer must ride the underlay (out-of-band) — an overlay dest is a footgun
    (the target assumes this anchor's overlay address mid-handoff). Catches a name
    in the mesh domain and an IPv6 literal inside the mesh's overlay /64; anything
    it can't classify is treated as underlay (allow) rather than block a legit
    transfer. NOT a security check — a guardrail against an obvious mistake."""
    import ipaddress
    host = dest.rsplit("@", 1)[-1]                 # drop user@
    if host.endswith("." + cfg.mesh_domain) or host == cfg.mesh_domain:
        return True
    lit = host                                     # try to read a bare IP literal
    if host.startswith("[") and "]" in host:       # [v6] or [v6]:port
        lit = host[1:host.index("]")]
    lit = lit.split("%")[0]                         # drop a zone id
    try:
        addr = ipaddress.ip_address(lit)
        return addr in ipaddress.ip_network(f"{cfg.overlay_prefix}/64", strict=False)
    except ValueError:
        return False                               # a name / host:port → assume underlay


def _do_handoff(unit, *, stop_local, start_remote, remote_active, start_local) -> bool:
    """The atomic core of an anchor transfer: stop the local anchor, start the
    remote one, verify it came up. If it DIDN'T, restart the local anchor (roll
    back) — there is only ever one live anchor, and a failed transfer must leave
    the ORIGINAL running. Pure orchestration over injected steps, so the ordering
    and the rollback are unit-testable. Returns True iff the remote took over."""
    stop_local(unit)
    if start_remote(unit) and remote_active(unit):
        return True
    start_local(unit)                 # rollback: the original anchor is back up
    return False


def cmd_anchor_transfer(args) -> int:
    """[sudo, anchor] Hand the anchor role to another host over SSH — SAME CA, no
    re-root. The target ASSUMES this anchor's identity (CA + registry + overlay
    address), so the fleet reconnects to it automatically; this host is stopped as
    part of the handoff (there is only ever ONE live anchor).

    SSH is the transport by design: the encrypted state rides YOUR channel, so
    the CA never touches the greasewood wire.

    REQUIRES an UNDERLAY (out-of-band) SSH path to the target — NOT the overlay.
    The target assumes this anchor's overlay identity/address, so the handoff
    can't ride the overlay it's changing (the address moves out from under the
    SSH mid-transfer, and both hosts would briefly claim it). If you run
    overlay-only SSH, open underlay SSH to the target for the (rare) transfer
    window — a root-of-trust move wants an out-of-band channel anyway. Also needs
    greasewood + systemd on the target and passwordless sudo to it."""
    import secrets
    import shlex
    import time
    from .config import load_config, membership_key

    _require_root("anchor-transfer", "it moves the CA key and stops the local anchor")
    cfg = load_config(Path(args.config))
    if cfg.role != "anchor":
        sys.exit("anchor-transfer must be run on the anchor (role = anchor)")
    if cfg.ca_key_file is None:
        sys.exit("anchor-transfer requires ca_key_file in [anchor]")
    if _dest_is_overlay(args.dest, cfg):
        sys.exit(f"{args.dest!r} looks like an OVERLAY address — anchor-transfer "
                 "needs an UNDERLAY (out-of-band) SSH path. The target takes over "
                 "this anchor's overlay address, so the handoff can't ride the "
                 "overlay it's changing. Use the target's real (underlay) address; "
                 "open underlay SSH to it for the transfer if you have to.")
    if not _systemd_available():
        sys.exit("anchor-transfer orchestrates the handoff via systemd, not running "
                 "here. Do it by hand:\n"
                 "  gw anchor-backup - | ssh <dest> sudo gw anchor-restore - --data-dir <dir>\n"
                 "  copy your config over, stop the daemon here, start it there.")

    dest = args.dest
    key = membership_key(cfg.mesh_domain)
    unit = f"greasewood@{key}"
    cfg_path = Path(args.config)
    remote_cfg = f"/etc/greasewood_{key}.toml"
    remote_data = f"/var/lib/greasewood_{key}"
    ssh = ["ssh"] + shlex.split(args.ssh_opts or "") + [dest]

    def rssh(remote, **kw):
        return subprocess.run(ssh + [remote], **kw)

    # --- preflight (change nothing until every check passes) ---
    if rssh("true", capture_output=True).returncode != 0:
        sys.exit(f"cannot SSH to {dest} — check the address and your key/agent.")
    if rssh("command -v gw >/dev/null 2>&1", capture_output=True).returncode != 0:
        sys.exit(f"greasewood (gw) is not installed on {dest} — install it there first.")
    if (rssh(f"sudo test -e {remote_data}/ca.key", capture_output=True).returncode == 0
            and not args.force):
        sys.exit(f"{dest} already holds an anchor at {remote_data}/ca.key. "
                 "Pass --force to overwrite it.")

    if not args.yes:
        print(f"Transfer this anchor to {dest}:")
        print("  • copy the encrypted CA + registry + config over SSH")
        print(f"  • STOP the anchor here ({unit}), START it on {dest}")
        print(f"  • {dest} takes this anchor's identity — the fleet reconnects, no re-root")
        print("  • this host becomes a stopped standby")
        if input("Proceed? [y/N] ").strip().lower() != "y":
            sys.exit("aborted — nothing changed.")

    # --- move state + config (SSH is the secure channel; CA never on the mesh) ---
    pw = secrets.token_urlsafe(32)           # ephemeral: guards the blob in flight
    print(f"→ transferring encrypted state to {dest} …")
    backup = subprocess.Popen(
        [sys.executable, "-m", "greasewood", "-c", str(cfg_path), "anchor-backup", "-"],
        stdout=subprocess.PIPE, env={**os.environ, "GW_BACKUP_PASSPHRASE": pw})
    restore = subprocess.run(
        ssh + [f"sudo env GW_BACKUP_PASSPHRASE={shlex.quote(pw)} gw anchor-restore - "
               f"--data-dir {remote_data} --force"],
        stdin=backup.stdout, capture_output=True, text=True)
    backup.stdout.close()
    backup.wait()
    if backup.returncode or restore.returncode:
        sys.exit(f"state transfer failed (nothing changed here):\n{restore.stderr.strip()}")
    with open(cfg_path, "rb") as f:          # the config too (B assumes this identity)
        cp = subprocess.run(ssh + [f"sudo tee {remote_cfg} >/dev/null"],
                            stdin=f, capture_output=True, text=True)
    if cp.returncode:
        sys.exit(f"could not copy the config to {dest} (nothing changed here):\n"
                 f"{cp.stderr.strip()}")

    # --- HANDOFF: stop here → start there → verify, roll back on failure ---
    print(f"→ handing off: stop {unit} here, start it on {dest} …")

    def remote_active(u):
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if rssh(f"systemctl is-active --quiet {u}", capture_output=True).returncode == 0:
                return True
            time.sleep(1)
        return False

    ok = _do_handoff(
        unit,
        stop_local=lambda u: _systemctl_run(["systemctl", "stop", u]),
        start_remote=lambda u: rssh(f"sudo systemctl enable --now {u}",
                                    capture_output=True).returncode == 0,
        remote_active=remote_active,
        start_local=lambda u: _systemctl_run(["systemctl", "start", u]),
    )
    if not ok:
        sys.exit(f"⚠ {dest} did not come up as the anchor — ROLLED BACK; this anchor "
                 "is running again. Check the target (journalctl -eu " + unit + ") "
                 "and retry.")

    _systemctl_run(["systemctl", "disable", unit], capture_output=True)  # no auto-restart
    print(f"✓ anchor transferred to {dest} — same CA, the fleet reconnects, no re-root.")
    print(f"  This host is stopped and won't auto-start. Decommission when ready: "
          "sudo gw purge")
    return 0


# ---------------------------------------------------------------------------
# purge  (decommission or start-over — removes all local greasewood state)
# ---------------------------------------------------------------------------

def _gw_daemons_for_mesh(cfg_path: Path) -> "tuple[list[int], list[int]]":
    """(mine, others): PIDs of running greasewood `run` daemons, split into those
    that belong to THIS mesh (safe for purge to kill — the user is destroying it)
    and those referencing a DIFFERENT config (another mesh — never touched).

    A daemon's mesh is read from its `-c <config>` argument; a bare `gw run` with
    no -c is discovery-based, which only starts on a single-mesh host, so it is
    treated as this mesh."""
    import re
    r = subprocess.run(["pgrep", "-af", "run"], capture_output=True, text=True)
    mine, others = [], []
    me = os.getpid()
    want = cfg_path.name
    for line in (r.stdout or "").splitlines():
        pid_s, _, cmd = line.partition(" ")
        if not pid_s.isdigit() or int(pid_s) == me:
            continue
        # A greasewood daemon: the `gw` entrypoint running the `run` subcommand.
        if not re.search(r"(^|/)gw\b", cmd) or not re.search(r"\brun\b", cmd):
            continue
        m = re.search(r"-c\s+(\S+)", cmd)
        if m:
            (mine if os.path.basename(m.group(1)) == want else others).append(int(pid_s))
        else:
            mine.append(int(pid_s))     # bare `gw run` → single-mesh → this mesh
    return mine, others


def _kill_daemons(pids: "list[int]") -> None:
    """SIGTERM the given daemons, then SIGKILL any that don't exit within a few
    seconds. Best-effort: a PID that's already gone (or unkillable) is skipped."""
    import signal
    for pid in pids:
        try:
            os.kill(pid, signal.SIGTERM)
        except (ProcessLookupError, PermissionError):
            pass
    deadline = time.monotonic() + 3.0
    alive = list(pids)
    while alive and time.monotonic() < deadline:
        time.sleep(0.2)
        alive = [p for p in alive if _pid_alive(p)]
    for pid in alive:                   # stragglers → hard kill
        try:
            os.kill(pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True                     # exists, just not ours to signal


def _other_peer_count(cfg) -> int:
    """How many mesh members OTHER than this node are in the directory cache —
    sizes the anchor-purge warning ('dissolves the mesh for N peers'). Best
    effort: 0 if the directory or identity can't be read."""
    try:
        from .directory import Directory
        from .keys import _own_identity
        own_id, _ = _own_identity(cfg.data_dir)
        recs = Directory.load(cfg.dir_cache_path).all()
        return sum(1 for r in recs if r.id_pub.hex() != own_id)
    except Exception:
        return 0


def cmd_purge(args) -> int:
    _require_root("purge")
    cfg_path = Path(args.config)

    # Nothing is unsuffixed anymore, so there are no guessable defaults: the
    # config must exist (main() discovery already resolved -c, or errored).
    try:
        from .config import load_config
        cfg = load_config(cfg_path)
        iface = cfg.wg_interface
        data_dir = cfg.data_dir
        mesh_domain = cfg.mesh_domain
    except Exception as e:
        sys.exit(f"can't read {cfg_path} ({e}) — pass -c <this mesh's config> "
                 f"(purge won't guess which mesh to destroy)")
    key = membership_key(cfg.mesh_domain)
    svc_mgr = _service_backend()
    unit = svc_mgr.unit_name(key) if svc_mgr else _unit_for_config(cfg_path)

    if not args.yes:
        last = not [k for k, p in _memberships() if p.resolve() != cfg_path.resolve()]
        print(f"This will permanently remove this mesh from the host:")
        print(f"  service instance    : {unit} (stop + disable)")
        print(f"  WireGuard interface : {iface}")
        print(f"  data directory      : {data_dir}  (keys, CA, credentials)")
        print(f"  config file         : {cfg_path}")
        if last and svc_mgr is not None:
            print(f"  service definition  : {svc_mgr.template_name()} (last mesh → "
                  f"full reset)")
        answer = input("Proceed? [y/N] ").strip().lower()
        if answer != "y":
            print("Aborted.")
            return 1

        # Purging the ANCHOR is categorically worse than a leaf node: it destroys
        # the CA and the control plane, so every other member loses enrollment,
        # renewal, and directory sync — the mesh cannot be recovered from here.
        # Gate that behind a second, explicit confirmation.
        if cfg.role == "anchor":
            n = _other_peer_count(cfg)
            if n > 0:
                print(f"\n⚠ THIS HOST IS THE ANCHOR. Purging it destroys the CA "
                      f"and control plane and dissolves the mesh for {n} other "
                      f"peer{'s' if n != 1 else ''}: they lose enrollment, "
                      f"renewal, and directory sync, and the mesh cannot be "
                      f"recovered from here.")
                if input("Are you REALLY sure? [y/N] ").strip().lower() != "y":
                    print("Aborted.")
                    return 1

    removed = []
    failed = []

    # Stop the daemon FIRST. A daemon left running through a purge haunts the
    # next mesh on this host: it keeps its stale CA and keys in memory, keeps
    # serving door enrollments, and its mesh interface is gone — so every join
    # against the re-created anchor fails with a peer-install error.
    if svc_mgr is not None and svc_mgr.disable_now(key):
        removed.append(f"stopped {unit}")
    # A stray daemon that survives the purge haunts the next mesh: it holds the
    # control port (the next create crash-loops on EADDRINUSE) and self-heals
    # its interface (recreating what we delete below). The systemd instance is
    # already stopped; this catches a manual `gw run` or an orphan from an older
    # version whose unit is gone. Kill the ones that belong to THIS mesh (the
    # user already confirmed destroying it) — but never another mesh's daemon.
    mine, others = _gw_daemons_for_mesh(cfg_path)
    if mine:
        _kill_daemons(mine)
        removed.append(f"stray daemon(s) pid {', '.join(str(p) for p in mine)}")
    if others:
        print(f"⚠ other greasewood daemon(s) are running (pid "
              f"{', '.join(str(p) for p in others)}) — left alone (they belong "
              f"to a different mesh). Not this mesh's, so not killed.")

    # Tear down the mesh WireGuard interface — both the current hyphenated name
    # and the legacy underscore form (gw_<mesh>), so an interface left by a
    # pre-upgrade daemon is cleaned up too.
    for name in dict.fromkeys([iface, iface.replace("-", "_")]):
        r = subprocess.run(["ip", "link", "show", name], capture_output=True)
        if r.returncode == 0:
            subprocess.run(["ip", "link", "set", name, "down"], capture_output=True)
            subprocess.run(["ip", "link", "delete", name], capture_output=True)
            removed.append(f"interface {name}")

    # Anchor door residue: the transient door interface (may linger if the daemon
    # died mid-window) and the door isolation routing (blackhole table + ip rule,
    # which setup_door_routing installs and nothing else removes). Both are safe
    # no-ops when absent, so purge attempts them regardless of last-known role.
    from .door import DOOR_IFACE
    for name in dict.fromkeys([DOOR_IFACE, DOOR_IFACE.replace("-", "_")]):
        r = subprocess.run(["ip", "link", "show", name], capture_output=True)
        if r.returncode == 0:
            subprocess.run(["ip", "link", "delete", name], capture_output=True)
            removed.append(f"door interface {name}")
    try:
        from . import wg as wgmod
        wgmod.teardown_door_routing()
    except Exception as e:
        failed.append(f"door routing: {e}")

    # Remove greasewood's own nftables table (port enforcement). It PERSISTS
    # across daemon stop by design (fail closed); purge is its explicit
    # teardown. Idempotent — a no-op if enforcement was never on.
    from .portfilter import table_name as _nft_table
    _tbl = _nft_table(key)                        # membership_key(cfg.mesh_domain)
    chk = subprocess.run(["nft", "list", "table", "inet", _tbl], capture_output=True)
    if chk.returncode == 0:
        subprocess.run(["nft", "delete", "table", "inet", _tbl], capture_output=True)
        removed.append(f"nftables table inet {_tbl}")

    # Remove data directory
    if data_dir.exists():
        try:
            shutil.rmtree(data_dir)
            removed.append(str(data_dir))
        except OSError as e:
            failed.append(f"{data_dir}: {e}")

    # Remove config file
    if cfg_path.exists():
        try:
            cfg_path.unlink()
            removed.append(str(cfg_path))
        except OSError as e:
            failed.append(f"{cfg_path}: {e}")

    # Remove the managed /etc/hosts block, if any
    try:
        from . import hosts
        if hosts.remove_block(mesh_domain):
            removed.append("/etc/hosts greasewood block")
    except Exception as e:
        failed.append(f"/etc/hosts: {e}")

    # Service teardown. This membership's instance was already disabled above;
    # if it was the LAST mesh on the host, remove the shared template unit too,
    # so `gw purge` on a single-mesh host is a true from-scratch reset. Other
    # meshes still need the template, so it stays while any remain.
    if svc_mgr is not None:
        remaining = _memberships()   # cfg_path is already unlinked above
        if not remaining:
            if svc_mgr.remove_template():
                removed.append(f"{svc_mgr.template_name()} (last mesh)")
        elif svc_mgr.template_installed():
            print(f"note: kept {svc_mgr.template_name()} — {len(remaining)} other "
                  f"mesh{'es' if len(remaining) != 1 else ''} still use it "
                  f"({', '.join(k for k, _ in remaining)}).")

    for item in removed:
        print(f"removed: {item}")
    for item in failed:
        print(f"failed:  {item}")

    if failed:
        return 1
    print("purge complete")
    return 0


# ---------------------------------------------------------------------------
# service management — the greasewood@ template unit (create/join install it,
# purge removes it; no separate install/uninstall command, no Ansible)
# ---------------------------------------------------------------------------

# These systemd helpers are thin delegators to greasewood.service. They stay in
# cli as named module attributes so the existing test seams keep working:
# callers reference cli._UNIT_DIR (redirectable) and the wrappers inject cli's
# patchable _service_exec / _systemctl_run into the service primitives.
_systemd_available = service.systemd_available
_service_exec = service.service_exec


def _write_service_template(exec_path: "str | None" = None) -> "str | None":
    """Write the greasewood@ template unit (idempotent) and daemon-reload;
    returns the systemctl path (None if no systemd). Shared by create/join."""
    return service.write_systemd_unit(
        _UNIT_DIR, exec_path or _service_exec(), run=_systemctl_run)


def _refresh_service_template() -> bool:
    """Daemon-startup self-heal: rewrite the installed template if it differs
    from this version's text. Never installs one where none exists."""
    return service.refresh_systemd_unit(_UNIT_DIR, _service_exec(), run=_systemctl_run)


def _wait_service_settled(systemctl: str, unit: str, wait_secs: float = 6.0) -> str:
    """Wait for `unit` to reach AND hold 'active'; return the final is-active
    state — the settle re-check that catches a Type=simple fast-crash flap."""
    return service.wait_systemd_settled(systemctl, unit, wait_secs, run=_systemctl_run)


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def _require_supported_os() -> None:
    """Exit cleanly on a non-Linux host instead of failing deep in an ip/wg call.
    greasewood is Linux-only (in-kernel WireGuard, nftables, ip, systemd); PyPI
    is public, so a non-Linux user could pip-install and run a command. --version
    and -h are handled by parse_args before this, so they work everywhere."""
    import platform as _plat
    if _plat.system() != "Linux":
        sys.exit(f"greasewood is a Linux-only tool (this host is {_plat.system()}).")


def build_parser() -> argparse.ArgumentParser:
    """Construct the full `gw` argument parser (all subcommands wired to their
    cmd_* handlers via set_defaults(fn=…)). Split out of main() so the same
    parser object feeds both runtime dispatch and offline tooling — the man page
    (argparse-manpage) and shell completions are generated from THIS, so they
    can't drift from `--help`."""
    p = argparse.ArgumentParser(
        prog="gw",
        description="Minimal WireGuard mesh overlay — direct-or-fail; IPv6-only overlay, v4-or-v6 underlay",
        epilog=(
            "sudo requirements ([sudo] in a command's help = root-gated):\n"
            "  sudo gw create <name>   -- one-shot anchor bootstrap\n"
            "  sudo gw invite          -- open a door window, print a join token\n"
            "  sudo gw join <token>    -- enroll this machine (creates WG interfaces)\n"
            "  sudo gw run             -- start the daemon\n"
            "  sudo gw watch           -- live dashboard (reads live WireGuard state)\n"
            "  sudo gw purge           -- remove this mesh's local state\n"
            "\n"
            "no sudo needed (read-only):\n"
            "  gw watch --snapshot · config · cert-status · cert-profiles\n"
            "  gw diagnose   (add sudo for live link state + firewall inference)\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("-c", "--config", default=None, metavar="FILE",
                   help="membership config (default: the host's single "
                        "/etc/greasewood_<name>.toml, discovered; required "
                        "when the host is on several meshes)")
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("--version", action="version", version=f"greasewood {_version()}")
    # required=False: bare `gw` routes to the dashboard (see _cmd_bare), not a
    # usage error — the naive invocation should answer, not scold.
    sub = p.add_subparsers(dest="cmd", required=False)

    # create
    sp = sub.add_parser("create",
                        help="[sudo] one-shot anchor bootstrap: CA + door key + routing + self-credential")
    sp.add_argument("name",
                    help="the mesh's name (a DNS label, e.g. 'prod-fleet') — "
                         "members resolve as <hostname>.<name>.internal. "
                         "Required so no two meshes sit on the same default: "
                         "a node can never bridge two meshes with one domain.")
    sp.add_argument("--hostname", default=None,
                    help="this anchor's hostname in the mesh "
                         "(default: the machine's hostname)")
    sp.add_argument("--data-dir", dest="data_dir", default=None,
                    help="state directory (default: /var/lib/greasewood_<name>)")
    sp.add_argument("--listen-port", dest="listen_port", type=int, default=None,
                    help="mesh WireGuard UDP port (default: first free of 51900, 51910, …)")
    sp.add_argument("--control-port", dest="control_port", type=int, default=51902)
    sp.add_argument("--door-port", dest="door_port", type=int, default=51901,
                    help="UDP port for the enrollment door (carried in tokens)")
    sp.add_argument("--endpoint", default=None, metavar="ADDR",
                    help="underlay address, v6 or v4 (auto-detected if omitted)")
    sp.add_argument("--interface", default=None,
                    help="WireGuard interface name (default: gw-<name[:12]>)")
    sp.add_argument("--overlay-prefix", dest="overlay_prefix",
                    default="fd8d:e5c1:db1a:7::",
                    help="the fleet's overlay /64 ULA (default: fd8d:e5c1:db1a:7::)")
    sp.add_argument("--mesh-domain", dest="mesh_domain", default=None,
                    help="full domain override (default: <name>.internal)")
    sp.add_argument("--caps", default="",
                    help="extra ability caps for the anchor (it always carries "
                         "role:* to reach every node), e.g. 'tls'")
    sp.add_argument("--credential-ttl", dest="credential_ttl", default="24h")
    sp.add_argument("--force", action="store_true", help="overwrite existing CA key")
    sp.add_argument("--no-hosts-sync", dest="hosts_sync", action="store_false",
                    help="don't maintain the managed /etc/hosts block "
                         "(<name>.gw.internal -> overlay addr); it's on by default")
    sp.add_argument("--no-service", action="store_true",
                    help="don't set up the systemd service; print the manual "
                         "'gw run' line instead (for non-systemd hosts)")
    sp.set_defaults(fn=cmd_create, hosts_sync=True)

    # invite
    sp = sub.add_parser("invite",
                        help="[sudo, anchor] open a 15-min door window and print a single-use join token")
    sp.add_argument("--hostname", default=None,
                    help="pin the invited node's mesh hostname (the anchor fixes it; "
                         "the joiner can't choose or later `gw rename-node` it). Omit "
                         "to let the node name itself at join.")
    sp.add_argument("--roles", default=None, metavar="R1,R2",
                    help="roles the invited node holds (comma-sep) — the grant-table "
                         "vocabulary (`gw policy`). The anchor decides this; the "
                         "joiner cannot. ADDS to the anchor's [anchor] "
                         "default_roles (ships as 'node') unless --exact. "
                         "Omitted → just the defaults. With no policy applied "
                         "every node peers regardless; grants reference these roles.")
    sp.add_argument("--exact", action="store_true",
                    help="--roles is the complete role list — don't add the "
                         "default membership role(s) ([anchor] default_roles)")
    sp.add_argument("--caps", default=None,
                    help="ability caps granted to the invited node (comma-sep), "
                         "e.g. 'tls'. Omitted → the anchor's [anchor] default_caps "
                         "(ships as 'tls'). Roles are set with --roles.")
    sp.add_argument("--self-roles", default=None, metavar="R1,R2",
                    help="role MENU the joiner may self-select from at `gw join "
                         "--roles` (comma-sep) — one standing invite provisions many "
                         "classes. The anchor still signs, and the joiner can never "
                         "land outside this set. Sets no default role (the joiner "
                         "opts in). NEVER include '*' (reach-all). Combine with "
                         "--roles to also grant a fixed base role.")
    sp.add_argument("--self-roles-from-grants", action="store_true",
                    dest="self_roles_from_grants",
                    help="derive the menu from grants.toml instead: offer every "
                         "role referenced in a grant, minus the built-ins (*, "
                         "anchor, node, admin). The policy vocabulary becomes the "
                         "provisioning menu — no second list to maintain. Mutually "
                         "exclusive with --self-roles.")
    sp.add_argument("--endpoint", default=None, metavar="ADDR",
                    help="underlay address, v6 or v4, to embed in the token (auto-detected if omitted)")
    sp.add_argument("--standing", action="store_true",
                    help="open a STANDING door: the token enrolls any number of "
                         "nodes (one at a time) and never expires — for baked "
                         "images / autoscaling. Each join is still the full "
                         "per-node ceremony (fresh identity, CA-signed "
                         "credential, door isolation). Revoke the token any "
                         "time with 'gw close-door'. Cannot pin --hostname.")
    sp.add_argument("--supersede", action="store_true",
                    help="required to replace an open STANDING door (which "
                         "would invalidate its token everywhere it's baked)")
    sp.add_argument("-q", "--quiet", action="store_true",
                    help="print only the token; silence informational messages")
    sp.set_defaults(fn=cmd_invite)

    # close-door
    sp = sub.add_parser("close-door",
                        help="[sudo, anchor] close the current door window — "
                             "permanently invalidates its token (standing or "
                             "single-use); enrolled nodes are unaffected")
    sp.set_defaults(fn=cmd_close_door)

    # join
    sp = sub.add_parser("join",
                        help="[sudo] enroll this machine using a token from 'gw invite'")
    sp.add_argument("token",
                    help="join token from 'gw invite', or '-' to read it from "
                         "stdin (raw `gw invite` output is accepted — the gw1.… "
                         "line is extracted)")
    sp.add_argument("--hostname", default=None,
                    help="this node's hostname in the mesh "
                         "(default: keep existing, else the machine's hostname)")
    sp.add_argument("--roles", default=None, metavar="R1,R2",
                    help="role(s) to self-select (comma-sep) when the invite offers "
                         "a menu (`gw invite --self-roles`). Must be within the "
                         "menu; the anchor authorizes and signs. Ignored (with a "
                         "warning) for a classic invite, where the anchor sets roles.")
    sp.add_argument("--data-dir", dest="data_dir", default=None,
                    help="state directory (default: /var/lib/greasewood_<name>)")
    sp.add_argument("--listen-port", dest="listen_port", type=int, default=None,
                    help="mesh WireGuard UDP port (default: first free of 51900, 51910, …)")
    sp.add_argument("--interface", default=None,
                    help="WireGuard interface name (default: keep existing, else "
                         "gw-mesh; use a distinct name per mesh on one host)")
    sp.add_argument("--endpoint", default=None, metavar="[ADDR]:PORT",
                    help="this node's underlay endpoint, v6 or v4 (auto-detected if omitted)")
    sp.add_argument("--no-hosts-sync", dest="hosts_sync", action="store_const",
                    const=False, default=None,
                    help="don't maintain the managed /etc/hosts block "
                         "(<name>.gw.internal -> overlay addr); on by default")
    sp.add_argument("--no-service", action="store_true",
                    help="don't set up the systemd service; print the manual "
                         "'gw run' line instead (for non-systemd hosts)")
    sp.set_defaults(fn=cmd_join)

    # purge
    sp = sub.add_parser("purge",
                        help="[sudo] remove this mesh entirely — stop+disable its "
                             "service, tear down the interface, delete data dir + "
                             "config + /etc/hosts block (and the systemd template "
                             "if it was the last mesh). A from-scratch reset.")
    sp.add_argument("--yes", "-y", action="store_true", help="skip confirmation prompt")
    sp.set_defaults(fn=cmd_purge)

    # run
    sp = sub.add_parser("run", help="[sudo] start the daemon (creates WireGuard interface)")
    sp.add_argument("--no-enforce-ports", dest="no_enforce_ports",
                    action="store_true",
                    help="run WITHOUT nftables port enforcement (on by default). "
                         "For a host with no usable nftables — grants still "
                         "control which tunnels exist; port scopes go advisory. "
                         "The persistent form is `enforce_ports = false` under "
                         "[network] (systemd runs `gw run` with no flags).")
    sp.set_defaults(fn=cmd_run)

    # watch — live mesh view by default; --snapshot for a static one-shot
    sp = sub.add_parser("watch",
                        help="[sudo] live mesh dashboard (redraws in place): the "
                             "roster + link state, per-second throughput, and a "
                             "latency column that fills in as pings return. "
                             "Ctrl-C to exit. Use --snapshot for a static view.")
    sp.add_argument("--snapshot", action="store_true",
                    help="print a single static view and exit (no root needed) — "
                         "for piping/logging. Auto-used when there's no terminal.")
    sp.add_argument("--json", action="store_true",
                    help="emit one-shot machine-readable JSON (stable versioned "
                         "schema) instead of the text view — for monitors/jq. "
                         "Add live WireGuard stats by running as root.")
    sp.add_argument("--by-role", dest="by_role", action="store_true",
                    help="group into one table per role (a node appears under "
                         "each of its roles; the anchor appears under all) with "
                         "per-group connectivity health")
    sp.add_argument("--interval", type=float, default=2.0, metavar="SECS",
                    help="live refresh interval (default 2s; min 1s)")
    sp.add_argument("--all", action="store_true",
                    help="also show expired nodes (hidden by default — the roster "
                         "shows only the live mesh)")
    sp.add_argument("--firewall", action="store_true",
                    help="expand the firewall area (the host-rule check + "
                         "greasewood's own nftables table, verbatim). Default is "
                         "a one-line summary; in the live view the f key toggles")
    sp.add_argument("--total", action="store_true",
                    help="live view shows cumulative traffic instead of per-second "
                         "rate (toggle with 't' while watching)")
    sp.set_defaults(fn=cmd_watch)

    # config — machine-readable resolved facts, for scripting
    sp = sub.add_parser("config",
                        help="print resolved config facts (machine-readable) for "
                             "scripting, e.g. `gw config interface`")
    sp.add_argument("key", nargs="?",
                    help="print just this value (interface, mesh_domain, "
                         "listen_port, data_dir, role, hostname, root_url, …); "
                         "omit to list all as key<TAB>value")
    sp.set_defaults(fn=cmd_config)

    # (No `firewall` subcommand — the host-firewall port check lives in gw watch
    #  now, and create/join still print the recommended rules at setup.)

    # diagnose
    sp = sub.add_parser(
        "diagnose",
        help="pairwise link diagnosis: compare up to two nodes + the anchor side "
             "by side and explain whether a tunnel can form (policy/roles, "
             "reachability, firewall directionality). No args = this host ↔ anchor.")
    sp.add_argument("nodes", nargs="*", metavar="NODE",
                    help="0, 1, or 2 node hostnames. none → this host ↔ anchor; "
                         "one → this host ↔ NODE; two → NODE ↔ NODE (anchor shown "
                         "as reference either way)")
    sp.set_defaults(fn=cmd_diagnose)

    # revoke
    sp = sub.add_parser("revoke", help="[sudo, anchor] revoke a node — deny its "
                        "renew/publish, evict it, free its hostname")
    sp.add_argument("node", help="the node: its hostname, its <host>.<mesh_domain> "
                    "mesh name, or its 64-char id_pub hex")
    sp.set_defaults(fn=cmd_revoke)

    # set-caps (anchor) — change an enrolled node's full tag set
    sp = sub.add_parser("set-caps",
                        help="[sudo, anchor] change an enrolled node's caps (effective next renewal)")
    sp.add_argument("node", help="node hostname (or its 64-char id_pub hex)")
    sp.add_argument("caps", help="comma-separated full tag set, e.g. "
                                 "'role:web,tls' (replaces the node's current caps)")
    sp.set_defaults(fn=cmd_set_caps)

    # set-roles (anchor) — change only a node's roles
    sp = sub.add_parser("set-roles",
                        help="[sudo, anchor] change an enrolled node's roles "
                             "(effective next renewal)")
    sp.add_argument("node", help="node hostname (or its 64-char id_pub hex)")
    sp.add_argument("roles", help="comma-separated roles, e.g. 'web,worker' "
                                  "(replaces role: tags; keeps tls; the default "
                                  "'node' role is kept unless --exact; empty = "
                                  "mesh default)")
    sp.add_argument("--exact", action="store_true",
                    help="use exactly this role list — allows dropping the "
                         "default 'node' role, which is otherwise kept (fleet "
                         "grants like `admin -> node : tcp/22` target it)")
    sp.add_argument("--now", action="store_true",
                    help="apply immediately — also request a fleet renewal (as "
                         "`gw renew-all` does) so the node adopts the new roles "
                         "live, no restart. Omit and it takes effect at the node's "
                         "next natural renewal (~half TTL). Fleet-wide, so for a "
                         "batch prefer several set-roles then one renew-all.")
    sp.set_defaults(fn=cmd_set_roles)

    # policy — the grant table (roles → roles : ports; derives the topology)
    sp = sub.add_parser("policy",
                        help="show the mesh's grant table, or [sudo, anchor] "
                             "apply grants.toml — the allow-only role policy "
                             "that derives which tunnels exist")
    sp.add_argument("action", choices=["show", "edit", "apply"],
                    help="show: render the active table (no root). "
                         "edit: [sudo, anchor] open grants.toml in your editor "
                         "($SUDO_EDITOR/$VISUAL/$EDITOR, else nano), validate "
                         "on save, then offer the apply preview. "
                         "apply: validate + preview tunnel delta + sign + publish")
    sp.add_argument("file", nargs="?", default=None,
                    help="grants.toml path (apply only; default: "
                         "<data_dir>/grants.toml)")
    sp.add_argument("-y", "--yes", action="store_true",
                    help="apply without the interactive confirmation")
    sp.set_defaults(fn=cmd_policy)

    # anchor-promote (on the prospective new anchor)
    sp = sub.add_parser("anchor-promote",
                        help="[sudo] turn this enrolled node into an anchor (generate CA key, set role=anchor)")
    sp.add_argument("--control-port", dest="control_port", type=int, default=51902)
    sp.add_argument("--credential-ttl", dest="credential_ttl", default="24h")
    sp.set_defaults(fn=cmd_anchor_promote)

    # cert-request (on a node with the 'tls' capability)
    sp = sub.add_parser("cert-request",
                        help="[sudo] request an x509 TLS cert from the anchor for a local service")
    sp.add_argument("--san", action="append", default=[], metavar="NAME|IP",
                    help="subject alternative name (repeatable; DNS or IP). "
                         "Must be a name the node owns (its <hostname>.<mesh_domain>, "
                         "a subdomain of it, or its overlay address). Defaults to the "
                         "node's own name + address if omitted.")
    sp.add_argument("--name", default=None,
                    help="basename for the written .key/.crt (default: first SAN)")
    sp.add_argument("--out-dir", dest="out_dir", default=None,
                    help="directory for key/cert/ca (default: <data_dir>/tls). "
                         "The per-file flags below override individual paths.")
    sp.add_argument("--key-out", dest="key_out", default=None, metavar="PATH",
                    help="exact path for the private key (overrides --out-dir; "
                         "e.g. /etc/ssl/private/pg.key)")
    sp.add_argument("--cert-out", dest="cert_out", default=None, metavar="PATH",
                    help="exact path for the leaf certificate (overrides --out-dir)")
    sp.add_argument("--ca-out", dest="ca_out", default=None, metavar="PATH",
                    help="exact path for the CA certificate (overrides --out-dir)")
    sp.add_argument("--anchor", default=None, help="override the anchor control-plane URL")
    sp.add_argument("--reload-cmd", dest="reload_cmd", default=None, metavar="CMD",
                    help="command the daemon runs after auto-renewing this cert, "
                         "e.g. 'systemctl reload postgresql'. Run as an argv, not "
                         "through a shell — for pipes/redirects wrap it: "
                         "\"sh -c '...'\"")
    sp.add_argument("--no-auto-renew", dest="no_auto_renew", action="store_true",
                    help="do not auto-renew this cert in the daemon (one-shot; "
                         "re-run manually before expiry)")
    sp.add_argument("--profile", default=None, metavar="NAME|PATH",
                    help="a cert profile (a shipped template name like 'postgres', "
                         "or a path to your own .toml): issues + places the "
                         "key/cert/ca where the service wants them, with the "
                         "right owner/mode, and registers its reload. The daemon "
                         "re-places them on every renewal too. See 'gw cert-profiles'.")
    sp.add_argument("--show", action="store_true",
                    help="with --profile, print that profile template (to copy "
                         "and adapt) and exit — no root/config needed")
    sp.add_argument("--renew", action="store_true",
                    help="re-issue even if a current cert already exists "
                         "(cert-request is otherwise idempotent: an unchanged "
                         "re-request of a valid cert is a no-op)")
    sp.set_defaults(fn=cmd_cert_request)

    # cert-profiles
    sp = sub.add_parser("cert-profiles",
                        help="list the bundled cert profile templates for common "
                             "TLS services (postgres, nginx, haproxy, redis, nats, minio, mosquitto)")
    sp.set_defaults(fn=cmd_cert_profiles)

    # cert-remove
    sp = sub.add_parser("cert-remove",
                        help="[sudo] stop managing a cert (drop it from auto-renewal); "
                             "--delete-files also removes the placed key/cert/ca")
    sp.add_argument("name", help="the managed cert's name (see gw cert-status)")
    sp.add_argument("--delete-files", dest="delete_files", action="store_true",
                    help="also delete the placed key/cert/ca files (default: "
                         "leave them — a service may still be reading them)")
    sp.set_defaults(fn=cmd_cert_remove)

    # cert-status
    sp = sub.add_parser("cert-status",
                        help="show every daemon-managed TLS cert (expiry, renewal, "
                             "SANs, files, profile) from the manifest")
    sp.set_defaults(fn=cmd_cert_status)

    # narrate — translate the data-plane command trail into plain English
    sp = sub.add_parser("narrate",
                        help="translate the ip/wg command trail (audit.log) into a "
                             "plain-English story of what greasewood did and why")
    sp.add_argument("source", nargs="?", default=None,
                    help="audit log path, or '-' for stdin (default: <data_dir>/audit.log)")
    sp.add_argument("--since", metavar="DUR", default=None,
                    help="only commands newer than DUR (e.g. 30m, 2h, 7d)")
    sp.add_argument("--peer", default=None, metavar="NAME",
                    help="only operations mentioning this peer/hostname")
    sp.add_argument("--grep", default=None, metavar="TEXT",
                    help="only operations matching TEXT (context, argv, or description)")
    sp.add_argument("--failures", action="store_true",
                    help="only commands that failed")
    sp.add_argument("--raw", action="store_true",
                    help="also show the raw argv under each translated command")
    sp.add_argument("--stats", action="store_true",
                    help="print a one-line tally before the narrative")
    sp.add_argument("--no-color", dest="no_color", action="store_true",
                    help="disable ANSI colour")
    sp.set_defaults(fn=cmd_narrate)

    # rename
    sp = sub.add_parser("rename-mesh",
                        help="[sudo] rename this mesh — domain, config, data "
                             "dir, interface, and service move together (run on "
                             "the anchor to rename the mesh; on a member to adopt "
                             "a rename the anchor made). Old names resolve for one "
                             "credential TTL.")
    sp.add_argument("new_name", help="the mesh's new name (a DNS label)")
    sp.set_defaults(fn=cmd_rename_mesh)

    sp = sub.add_parser("rename-node",
                        help="[sudo] change this node's mesh hostname (anchor-validated, no re-join)")
    sp.add_argument("hostname", help="the new hostname")
    sp.set_defaults(fn=cmd_rename_node)

    # renew
    sp = sub.add_parser("renew",
                        help="[sudo] force an immediate credential renewal for THIS "
                             "node (applies an anchor-side set-caps/set-roles now, "
                             "instead of waiting ~half the TTL)")
    sp.set_defaults(fn=cmd_renew)

    # renew-all
    sp = sub.add_parser("renew-all",
                        help="[sudo, anchor] request a fleet-wide renewal — advertise "
                             "renew_after=now so cooperating nodes renew (jittered, "
                             "rate ~constant with mesh size)")
    sp.set_defaults(fn=cmd_renew_all)

    # anchor-backup
    sp = sub.add_parser("anchor-backup",
                        help="[sudo, anchor] write an encrypted backup of the CA key + "
                             "node registry + revoke list (passphrase via prompt "
                             "or $GW_BACKUP_PASSPHRASE)")
    sp.add_argument("--out", default=None, metavar="PATH",
                    help="output file (default: <data_dir>/greasewood-anchor-backup-"
                         "<hostname>.gwbk); '-' streams the blob to stdout (for a pipe)")
    sp.set_defaults(fn=cmd_anchor_backup)

    # anchor-restore
    sp = sub.add_parser("anchor-restore",
                        help="[sudo] restore an anchor backup into a data dir (stand "
                             "up a replacement anchor on the same CA key — not a re-root)")
    sp.add_argument("archive", help="the .gwbk backup file, or '-' to read from stdin")
    sp.add_argument("--data-dir", default="/var/lib/greasewood",
                    help="where to restore (default: /var/lib/greasewood)")
    sp.add_argument("--force", action="store_true",
                    help="overwrite an existing ca.key in the target dir")
    sp.set_defaults(fn=cmd_anchor_restore)

    # anchor-transfer
    sp = sub.add_parser("anchor-transfer",
                        help="[sudo, anchor] hand the anchor role to another host over "
                             "SSH — same CA, no re-root; stops this anchor as part of "
                             "the handoff. The target assumes this anchor's identity.")
    sp.add_argument("dest", metavar="[user@]host",
                    help="UNDERLAY (out-of-band) SSH destination of the target — its "
                         "real address, NOT its overlay/mesh address. The target "
                         "takes over this anchor's overlay identity, so the handoff "
                         "can't ride the overlay; open underlay SSH for the transfer "
                         "if you normally run overlay-only.")
    sp.add_argument("--ssh-opts", default=None,
                    help="extra options passed to ssh (e.g. '-p 2222 -i key')")
    sp.add_argument("--force", action="store_true",
                    help="overwrite an existing anchor on the target")
    sp.add_argument("--yes", "-y", action="store_true", help="skip the confirmation")
    sp.set_defaults(fn=cmd_anchor_transfer)

    return p


_EVERYDAY_COMMANDS = """\
everyday commands:
  sudo gw watch                 live mesh dashboard (peers, links, firewall)
  gw watch --snapshot           the same, static — no root, pipeable
  gw diagnose [peer]            why a pair can or can't tunnel
  sudo gw invite                mint a join token            (anchor)
  sudo gw join <token>          enroll this machine in a mesh
  sudo gw policy edit           edit grants.toml: validate, preview, apply (anchor)
  gw policy show                the active grant table
  sudo gw cert-request          mesh-CA TLS certs for a service
  sudo gw set-roles <node> ...  change a node's roles         (anchor)
  sudo gw revoke <node>         revoke a node; frees its name (anchor)
  gw narrate --since 2h         the audit trail, in plain English

full reference:  gw --help   ·   man gw"""


def _cmd_bare(args) -> int:
    """Bare `gw` — the dashboard, not a usage error. The naive invocation
    answers both questions a naive typist has: what is my mesh doing (the
    watch view) and what can I type (the everyday commands). Context decides
    the shape: root + a terminal → the live TUI; otherwise the no-root static
    snapshot with the commands below it; unconfigured or multi-mesh → the
    commands, with how to start (or which -c) front and center."""
    if getattr(args, "config", None):
        target = Path(args.config)
    else:
        ms = _memberships()
        if not ms:
            print("no greasewood mesh is configured on this host.\n"
                  "  start one:  sudo gw create <name>   (this machine becomes "
                  "the anchor)\n"
                  "  join one:   sudo gw join <token>    (token from `sudo gw "
                  "invite` on the anchor)\n")
            print(_EVERYDAY_COMMANDS)
            return 0
        if len(ms) > 1:
            listing = "\n".join(f"  gw -c {p} watch   ({k})" for k, p in ms)
            print(f"this host is on {len(ms)} meshes — say which one:\n"
                  f"{listing}\n")
            print(_EVERYDAY_COMMANDS)
            return 0
        target = ms[0][1]
    live = sys.stdout.isatty() and os.geteuid() == 0
    wargs = argparse.Namespace(config=str(target), snapshot=not live)
    rc = cmd_watch(wargs)
    if not live:
        print(_EVERYDAY_COMMANDS)
    return rc


def main(argv=None) -> int:
    p = build_parser()
    args = p.parse_args(argv)
    _setup_logging(args.verbose)
    _require_supported_os()   # after parse_args, so --version/-h still work
    if args.cmd is None:
        return _cmd_bare(args)
    # -c discovery: with one membership on the host, every command finds it
    # unaided; with several, demand -c (loudly, listing them). create/join
    # derive their own config from the mesh name; cert-profiles (and
    # cert-request --show) just read bundled templates — no mesh needed.
    _no_config = args.cmd in ("create", "join", "cert-profiles") or (
        args.cmd == "cert-request" and getattr(args, "show", False))
    if args.config is None and not _no_config:
        args.config = str(_discover_config())
    try:
        return args.fn(args)
    except FileNotFoundError as e:
        # Safety net for a data-plane tool vanishing mid-command (the entry
        # points preflight wg/ip, but nft is optional-per-feature and a tool
        # can be missing on paths preflight doesn't cover). A missing data
        # FILE is not ours to prettify — re-raise anything else.
        tool = getattr(e, "filename", None)
        pkg = {"wg": "wireguard-tools", "ip": "iproute2", "nft": "nftables"}.get(tool)
        if pkg is not None:
            sys.exit(f"'{tool}' is not installed — greasewood shells out to the "
                     f"stock tools for every data-plane change.\n"
                     f"Install it:  sudo apt install {pkg}   "
                     f"# or your distro's equivalent")
        raise
    except PermissionError as e:
        # Safety net: turn a raw EACCES traceback into a clean hint. Most
        # greasewood data lives at 0600/root (keys) or is written by the daemon
        # running as root, so the usual cause is "needs sudo".
        path = getattr(e, "filename", None)
        where = f" ({path})" if path else ""
        if os.geteuid() == 0:
            # ALREADY root and still denied: almost always a file owned by a
            # non-root user (legacy chowned install) under the sandboxed
            # systemd unit, which drops CAP_DAC_OVERRIDE — so root can't read
            # other users' 0600 files. Seen in the field as a service that
            # "starts" then crash-loops.
            sys.exit(f"permission denied{where} while running AS ROOT — the file "
                     f"is likely owned by a non-root user, and the sandboxed "
                     f"systemd unit drops the capability that lets root bypass "
                     f"that (CAP_DAC_OVERRIDE). "
                     f"Fix: chown root:root {path or '<the file>'}   "
                     f"then restart the service.")
        sys.exit(f"permission denied{where} — this command likely needs root. "
                 f"Try: sudo gw {args.cmd}")


if __name__ == "__main__":
    raise SystemExit(main())
