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

Everything else groups around that: observe (watch, diagnose, narrate, config,
firewall), administer nodes on the anchor (invite/close-door, revoke, set-caps,
set-segments, renew-all), maintain this node (renew, rename-node, rename-mesh,
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

from .config import membership_key

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


def _version() -> str:
    try:
        from importlib.metadata import version
        return version("greasewood")
    except Exception:
        return "0.0.0+unknown"


# systemd template unit, embedded so create/join can install it on a pip-only install
# (no repo checkout needed). Kept in sync with systemd/ in the repo.
# Template unit: one file serves every mesh membership as greasewood@<name>
# (create/join enable the instance for you). %i is the mesh name.
_SERVICE_UNIT = """\
[Unit]
Description=greasewood mesh daemon (%i)
Documentation=https://gitlab.com/cschlick/greasewood
After=network-online.target
Wants=network-online.target
# Only run once this membership is configured (create / join writes it).
ConditionPathExists=/etc/greasewood_%i.toml

[Service]
Type=simple
# gw run creates WireGuard interfaces and edits routing → runs as root.
ExecStart={exec} -c /etc/greasewood_%i.toml run
Restart=on-failure
RestartSec=5

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
                         mesh_iface: str = "gw-mesh", header: bool = True) -> None:
    """
    Print (never apply) the recommended firewall posture. greasewood binds its
    control/enroll planes only to the overlay + loopback, so nothing it runs is
    exposed on the underlay regardless of firewall. On a default-drop host you
    still allow the few things below to *reach* those sockets.

    Recommended: apply the SAME rules on EVERY node, not just the current anchor.
    Since any node can be promoted to anchor (gw anchor-promote), a uniform ruleset
    means an anchor handover needs no firewall change anywhere. A rule allowing a
    port nothing is bound to is harmless — the kernel just refuses the
    connection until that node actually becomes an anchor and binds it.
    """
    from .door import DOOR_PORT, DOOR_IFACE, ENROLL_PORT
    if header:
        print("Firewall (greasewood never edits it). Recommended posture — the SAME")
        print("rules on every node, so any node can become the anchor with no firewall")
        print("change. On a default-drop host, allow (nftables):")
    else:
        print("Recommended posture — the SAME rules on every node (anchor or not), so")
        print("promoting a node to anchor needs no firewall change. On a default-drop")
        print("input chain (nftables):")
    print(f"  udp dport {{ {listen_port}, {DOOR_PORT} }} accept            # WireGuard (underlay)")
    print(f"  iifname \"lo\" accept                          # anchor talks to itself")
    print(f"  iifname \"{mesh_iface}\" tcp dport {control_port} accept        # control plane (when anchor)")
    print(f"  iifname \"{DOOR_IFACE}\" tcp dport {ENROLL_PORT} accept    # enrollment (when anchor)")


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


def _detect_public_ipv4() -> str | None:
    """Best-effort public IPv4 on this machine — a global, non-private, non-
    loopback v4 on an interface. Behind 1:1 NAT (e.g. EC2, where the interface
    holds only a private v4) this returns None, so inbound v4 nodes should pass
    `--endpoint <public-v4>` explicitly. Only the underlay may be v4; the overlay
    stays IPv6."""
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
        if not (addr.is_private or addr.is_loopback or addr.is_link_local):
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


def cmd_create(args) -> int:
    _require_root("create")
    from .hosts import valid_label as _vl
    if not _vl(args.name):
        sys.exit(f"mesh name {args.name!r} must be a DNS label "
                 "(lowercase letters/digits/hyphens, e.g. 'prod-fleet')")
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
    # The anchor must reach every segment (it serves the control plane + door), so
    # it carries the reach-all wildcard segment. Plus any ability caps (--caps).
    caps = ["segment:*"]
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
        ca_keys = CAKeys.generate()
        ca_keys.save(ca_key_path)
        log.info("generated CA key → %s", ca_key_path)

    # Door keypair (persistent across invites)
    load_or_generate_door_key(data_dir)
    log.info("door key ready → %s/door.key", data_dir)

    # Set up door routing (idempotent — also called in gw run for reboots)
    wgmod.setup_door_routing()

    ca_pub_hex = ca_keys.ca_pub_bytes.hex()

    node_keys = NodeKeys.load_or_generate(data_dir)
    log.info("overlay addr: %s", node_keys.addr)

    endpoint_line = f'\nendpoints = {json.dumps(endpoints)}' if endpoints else ""
    hosts_sync = "true" if getattr(args, "hosts_sync", True) else "false"
    cfg_path.parent.mkdir(parents=True, exist_ok=True)
    cfg_path.write_text(f"""[node]
hostname = "{hostname}"
data_dir = "{data_dir}"
role = "anchor"
caps = {json.dumps(caps)}{endpoint_line}

[network]
interface = "{interface}"
listen_port = {listen_port}
overlay_prefix = "{overlay_prefix}"
seeds = []
root_url = "http://[::1]:{control_port}"
hosts_sync = {hosts_sync}
mesh_domain = "{mesh_domain}"

[ca]
trusted_pubs = ["{ca_pub_hex}"]

[anchor]
ca_key_file = "{ca_key_path}"
control_listen = ":{control_port}"
credential_ttl = "{args.credential_ttl}"
renew_before = "12h"
door_window = "15m"
door_port = {args.door_port}
# Defaults granted to new nodes at `gw invite` (when --segments/--caps are
# omitted). Edit anytime — the next invite reads them fresh, no restart.
default_segments = ["mesh"]
default_caps = ["tls"]
""")
    log.info("wrote config → %s", cfg_path)

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
    if not wgmod.interface_exists(cfg.wg_interface):
        sys.exit(f"the anchor's mesh interface {cfg.wg_interface!r} doesn't exist — "
                 f"the daemon isn't running (or the interface was deleted under "
                 f"it). A joiner would be rejected at enrollment. Start the "
                 f"daemon first: sudo systemctl start {_unit_for_config(args.config)}   "
                 f"(or: sudo gw -c {args.config} run)\n"
                 f"If you already started it and this persists, it's crashing on "
                 f"startup — look at: journalctl -u {_unit_for_config(args.config)} -n 20")
    import urllib.request as _url
    try:
        _url.urlopen(f"http://[::1]:{_control_port(cfg)}/directory", timeout=3)
    except Exception:
        sys.exit(f"the anchor daemon isn't answering on loopback (port "
                 f"{_control_port(cfg)}) — it hosts the enroll server, so this "
                 f"token could never be redeemed. Start it first: "
                 f"sudo systemctl start {_unit_for_config(args.config)}   "
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

    # The anchor decides caps + segments HERE and issues them to whoever redeems the
    # token — the joiner does not choose (no self-assertion). They're stored in
    # the door window; the enroll server issues from them, ignoring the joiner's.
    #   segments (segment:<name>) control who-talks-to-whom.
    #   --caps grants abilities, e.g. tls.
    # When a flag is omitted, fall back to the anchor's configured defaults for new
    # nodes ([anchor] default_segments / default_caps, read fresh each invite — so
    # editing them changes what future enrollments get). --segments/--caps
    # override for this one token.
    if args.segments is not None:
        segments = [s.strip() for s in args.segments.split(",") if s.strip()]
    else:
        segments = list(cfg.default_segments)
    caps = ["segment:" + s for s in segments]
    if args.caps is not None:
        caps += [c.strip() for c in args.caps.split(",") if c.strip()]
    else:
        caps += list(cfg.default_caps)
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
    _seen: set[str] = set()
    caps = [c for c in caps if not (c in _seen or _seen.add(c))]
    log.info("this token grants caps=%s%s", caps,
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
                         cfg.door_port, mesh_domain=cfg.mesh_domain)

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
        window_path.write_text(json.dumps({
            "v": 1,
            "standing": True,
            "caps": caps,
            "hostname": None,          # standing doors can't pin one name
            "guest_pub": params.guest_pub_b64,
            "psk": params.psk_b64,
            "token": token,
        }))
        os.chmod(window_path, 0o600)   # it now carries key material
        log.info("STANDING door opened — this token enrolls any number of "
                 "nodes until: sudo gw close-door")
    else:
        expires = dt.datetime.now(dt.timezone.utc) + window
        window_path.write_text(json.dumps({
            "v": 1,
            "expires": expires.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "caps": caps,
            "hostname": pinned_hostname,   # None → joiner names itself (unpinned)
        }))

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


def _membership_for_ca(ca_pub_hex: str, etc: "Path" = Path("/etc")) -> "str | None":
    """The membership key already trusting this CA, or None. This is how a
    token is routed: its CA pub identifies WHICH mesh it belongs to, so a token
    for a mesh we're already on refreshes that membership (even after a re-root
    — trusted_pubs carries old+new during migration), and an unknown CA means a
    genuinely new mesh."""
    from .config import load_config
    for key, p in _memberships(etc):
        try:
            if ca_pub_hex in load_config(p).ca_pubs:
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


def _membership_service(key: str) -> str:
    """Enable this membership's daemon as greasewood@<key> — an instance of the
    template unit create/join install (ExecStart=gw -c /etc/greasewood_%i.toml
    run). Returns 'active' (came up and stayed up), 'installed' (enabled but not
    confirmed running), 'failed' (crashed at/after start), or 'manual' (no
    systemd management here — caller prints the gw run line).

    The settle-check matters: Type=simple reports the start job done the instant
    the process execs, so `enable --now` "succeeds" even for a daemon that
    crashes a second later (and then crash-loops under Restart=on-failure). We
    verify it reaches AND holds 'active' before telling the operator it's up."""
    unit = f"greasewood@{key}.service"
    systemctl = shutil.which("systemctl")
    if not systemctl or not (_UNIT_DIR / "greasewood@.service").exists():
        return "manual"
    r = subprocess.run([systemctl, "is-active", "--quiet", unit],
                       capture_output=True)
    if r.returncode == 0:
        return "active"
    r = subprocess.run([systemctl, "enable", "--now", f"{unit}"],
                       capture_output=True)
    if r.returncode != 0:
        return "manual"            # systemctl present but no live manager → manual
    return _wait_service_settled(systemctl, unit)


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

    systemctl = shutil.which("systemctl")
    old_unit = f"greasewood@{old_key}.service"
    if systemctl:
        subprocess.run([systemctl, "disable", "--now", old_unit],
                       capture_output=True)

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

    if systemctl and (_UNIT_DIR / "greasewood@.service").exists():
        subprocess.run([systemctl, "enable", "--now",
                        f"greasewood@{new_key}.service"], check=False)
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


def cmd_join(args) -> int:
    _require_root("join")
    import struct
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
         token_domain) = decode_token(token)
    except ValueError as e:
        sys.exit(f"invalid token: {e}")
    ca_pub_hex = ca_pub_bytes.hex()

    # -c/--data-dir default to None (derived below from the token's mesh name);
    # the auto/explicit block after this always leaves both set.
    cfg_path = Path(args.config) if args.config else None
    data_dir = Path(args.data_dir) if args.data_dir else None
    listen_port = args.listen_port

    # Auto-slotting: when every location knob is at its default, route the join
    # by the token's CA. A token for a mesh this host is already on refreshes
    # that membership; a token for a NEW mesh (unknown CA, default slot already
    # by the token's CA: known CA → refresh that membership; unknown CA → a new
    # membership named by the mesh itself (the token's domain). Explicit flags
    # override any derived value.
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

    # Caps/segments are NOT chosen here. The anchor decides them at `gw invite` and
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

    # Send enroll request
    req = {
        "v": 1,
        "id_pub": node_keys.id_pub_hex,
        "wg_pub": node_keys.wg_pub_b64,
        "hostname": hostname,
    }
    req_body = json.dumps(req, separators=(",", ":")).encode()

    def _recv_framed(sock):
        hdr = b""
        while len(hdr) < 4:
            chunk = sock.recv(4 - len(hdr))
            if not chunk:
                raise ConnectionError("connection closed")
            hdr += chunk
        length = struct.unpack(">I", hdr)[0]
        raw = b""
        while len(raw) < length:
            chunk = sock.recv(length - len(raw))
            if not chunk:
                raise ConnectionError("connection closed")
            raw += chunk
        return json.loads(raw)

    def _send_framed(sock, obj):
        b = json.dumps(obj, separators=(",", ":")).encode()
        sock.sendall(struct.pack(">I", len(b)) + b)

    # Leave the connection OPEN after the response — we send our signed record
    # back on it as a second leg (see below).
    try:
        conn.sendall(struct.pack(">I", len(req_body)) + req_body)
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
        sys.exit(f"credential verification failed: {e}")

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

    # Send our signed record back over the SAME door connection; the anchor merges
    # it into its directory so the ReconcileLoop keeps the peer it just installed
    # (the bootstrap chicken-and-egg). Doing this on the door tunnel — rather
    # than a separate POST /publish — means the control plane never has to listen
    # on the door interface.
    try:
        _send_framed(conn, {"v": 1, "record": record.to_dict()})
        ack = _recv_framed(conn)
        if ack.get("ok"):
            log.info("published record to anchor via door tunnel")
        else:
            log.warning("anchor rejected door publish: %s", ack.get("error"))
    except Exception as e:
        log.warning("door publish failed (anchor learns this node on next sync): %s", e)
    finally:
        try:
            conn.close()
        except Exception:
            pass

    # Tear down the door interface
    wgmod.destroy_interface("gw-door")

    endpoint_line = f'\nendpoints = {json.dumps(node_endpoints)}' if node_endpoints else ""
    seeds_list = json.dumps([anchor_overlay_url]) if anchor_overlay_url else "[]"
    root_url_val = json.dumps(anchor_overlay_url) if anchor_overlay_url else '""'
    # hosts sync: on by default; --no-hosts-sync turns it off; a re-join keeps a
    # previously-disabled setting.
    if getattr(args, "hosts_sync", None) is False:      # --no-hosts-sync given
        hosts_sync = "false"
    elif prior is not None and not prior.hosts_sync:    # re-join kept disabled
        hosts_sync = "false"
    else:
        hosts_sync = "true"
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
    cfg_path.write_text(f"""[node]
hostname = "{hostname}"
data_dir = "{data_dir}"
role = "node"
caps = {json.dumps(caps)}{endpoint_line}

[network]
interface = "{interface}"
listen_port = {listen_port}
overlay_prefix = "{overlay_prefix}"
seeds = {seeds_list}
root_url = {root_url_val}
hosts_sync = {hosts_sync}
mesh_domain = "{mesh_domain}"

[ca]
trusted_pubs = ["{ca_pub_hex}"]
""")
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
    _print_firewall_help(listen_port, mesh_iface=interface)
    print()
    _fw.check(_fw.node_rules(listen_port), log)
    return 0



# ---------------------------------------------------------------------------
# revoke
# ---------------------------------------------------------------------------

def cmd_revoke(args) -> int:
    # Same anchor-only guard as set-caps/set-segments: explicit role check first,
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
# set-caps / set-segments — change an enrolled node's caps on the anchor
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
    "re-join needed. To apply immediately, run `sudo gw renew` on that node."
)


def cmd_set_caps(args) -> int:
    cfg, ca = _load_anchor_ca(args, "set-caps")
    id_pub, name = _resolve_node(ca, cfg, args.node)
    caps = [c.strip() for c in args.caps.split(",") if c.strip()]
    if not any(c.startswith("segment:") for c in caps):
        log.warning("caps %s include no segment — %r will peer with no one "
                    "(add e.g. segment:mesh)", caps, name)
    ca.set_caps(id_pub, caps)
    print(f"caps for {name} ({id_pub.hex()}) → {caps}")
    print(_NEXT_RENEWAL_NOTE)
    return 0


def cmd_set_segments(args) -> int:
    cfg, ca = _load_anchor_ca(args, "set-segments")
    id_pub, name = _resolve_node(ca, cfg, args.node)
    _, current = ca.node_info(id_pub)
    # Replace only the segment: tags; keep tls/hostname-pinned and anything else.
    kept = [c for c in current if not c.startswith("segment:")]
    segs = [s.strip() for s in args.segments.split(",") if s.strip()] or ["mesh"]
    segments = ["segment:" + s for s in segs]
    caps = kept + segments
    ca.set_caps(id_pub, caps)
    print(f"segments for {name} ({id_pub.hex()}) → {segs}  (caps now {caps})")
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


def _key_file_warnings(paths, expect_uid: int = 0) -> list:
    """Sanity-check secret key files: each should be owned by `expect_uid`
    (root) and readable by owner only. A key owned by another user means that
    account can read it — for the CA key, mint mesh credentials — usually a
    leftover from a pre-1.0 create that chowned the data dir to the operator.
    Returns human-readable warnings; missing files are fine (not all roles have
    all keys)."""
    import stat as statmod
    warns = []
    for p in paths:
        if p is None:
            continue
        try:
            st = os.stat(p)
        except OSError:
            continue
        if st.st_uid != expect_uid:
            warns.append(
                f"SECURITY: {p} is owned by uid {st.st_uid}, not root — that "
                f"account can read this key"
                + (" and mint mesh credentials" if "ca" in Path(p).name else "")
                + f". Fix: chown root:root {p}")
        if statmod.S_IMODE(st.st_mode) & 0o077:
            warns.append(f"SECURITY: {p} is group/world-accessible "
                         f"(mode {statmod.S_IMODE(st.st_mode):o}). "
                         f"Fix: chmod 600 {p}")
    return warns


def _secret_key_paths(cfg) -> list:
    """The secret key files this install may have (missing ones are skipped)."""
    return [cfg.data_dir / "id_priv.pem", cfg.data_dir / "wg.key",
            cfg.data_dir / "door.key", getattr(cfg, "ca_key_file", None)]


def _own_identity(data_dir: "Path") -> "tuple[str | None, str | None]":
    """(id_pub_hex, overlay_addr) from the world-readable id_pub.hex — never the
    private key. Read-only commands (nodes, diagnose) use this so they work
    without sudo: the public id is enough to mark 'self' and derive the addr."""
    from .keys import derive_addr
    try:
        h = (data_dir / "id_pub.hex").read_text().strip()
        return h, derive_addr(bytes.fromhex(h))
    except (FileNotFoundError, ValueError):
        return None, None


def _unit_for_config(cfg_path) -> str:
    """The systemd unit serving this membership: greasewood@<key> when the
    config follows the /etc/greasewood_<key>.toml scheme, else a generic
    'greasewood@<name>' placeholder for messages."""
    m = re.fullmatch(r"greasewood_([a-z0-9-]+)\.toml", Path(cfg_path).name)
    return f"greasewood@{m.group(1)}" if m else "greasewood@<name>"


def _print_daemon_guidance(key: str, cfg_path, then: str = "",
                           no_service: bool = False) -> None:
    """Bring up (and report) this membership's daemon. By default create/join
    install the systemd template + enable this mesh's instance so it's running
    and boot-persistent with no extra command; --no-service skips systemd and
    prints the manual `gw run` line. `then` is an optional trailing clause."""
    tail = f" — {then}" if then else ""
    if no_service or not _systemd_available():
        print(f"Start this mesh's daemon{tail}:")
        print(f"  sudo gw -c {cfg_path} run")
        if no_service and _systemd_available():
            print(f"  (or switch to systemd later: 'gw create/join' installs the "
                  f"greasewood@ template — enable with 'systemctl enable --now "
                  f"greasewood@{key}')")
        return

    _write_service_template()          # ensure the template exists, then enable
    state = _membership_service(key)
    if state == "active":
        print(f"greasewood@{key} is running{tail} (and starts at boot).")
        print(f"  status: systemctl status greasewood@{key}   "
              f"logs: journalctl -u greasewood@{key} -f")
    elif state == "manual":
        print(f"No systemd here — start this mesh's daemon{tail}:")
        print(f"  sudo gw -c {cfg_path} run")
    else:
        # enabled, but it did NOT come up and stay up (Type=simple + a crash =
        # a silent restart loop). Say so, and point at the journal.
        print(f"⚠ greasewood@{key} is enabled but {state or 'not running'} — it "
              f"is likely crashing at startup, so the mesh isn't up yet.")
        print(f"  see why:  sudo journalctl -u greasewood@{key} -n 40 --no-pager")
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
    trusted = list(dict.fromkeys([*cfg.ca_pubs, ca_pub_hex]))

    # An anchor must reach every segment — ensure the wildcard segment. (Its own
    # credential picks this up on the next renewal under the new CA.)
    anchor_caps = list(cfg.caps)
    if "segment:*" not in anchor_caps:
        anchor_caps.append("segment:*")

    endpoint_line = (
        f'\nendpoints = {json.dumps(cfg.endpoints)}' if cfg.endpoints else ""
    )
    hosts_sync = "true" if cfg.hosts_sync else "false"
    cfg_path.write_text(f"""[node]
hostname = "{cfg.hostname}"
data_dir = "{cfg.data_dir}"
role = "anchor"
caps = {json.dumps(anchor_caps)}{endpoint_line}

[network]
interface = "{cfg.wg_interface}"
listen_port = {cfg.listen_port}
overlay_prefix = "{cfg.overlay_prefix}"
seeds = {json.dumps(cfg.seeds)}
root_url = "{cfg.root_url}"
hosts_sync = {hosts_sync}
mesh_domain = "{cfg.mesh_domain}"

[ca]
trusted_pubs = {json.dumps(trusted)}

[anchor]
ca_key_file = "{ca_key_path}"
control_listen = ":{control_port}"
credential_ttl = "{args.credential_ttl}"
renew_before = "12h"
door_window = "15m"
door_port = {cfg.door_port}
# Defaults granted to new nodes at `gw invite` (edit anytime; read fresh).
default_segments = ["mesh"]
default_caps = ["tls"]
""")
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
    crt = certmod.entry_cert_path(entry)
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

    if entry.get("files"):
        paths = [f["path"] for f in entry["files"]]
    else:
        paths = [str(p) for p in certmod.entry_paths(entry)]
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
                  "sudo systemctl restart greasewood@<name>  (or re-run sudo gw run).")
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

        crt = certmod.entry_cert_path(e)
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
    directory = Directory.load(cfg.dir_cache_path)
    existing = directory.get(keys.id_pub_hex)
    seq = (existing.seq + 1) if existing else 1
    endpoints = list(existing.endpoints) if existing else list(cfg.endpoints)
    aliases = list(existing.aliases) if existing else _config_aliases(cfg)
    record = NodeRecord(
        id_pub=keys.id_pub_bytes, seq=seq, endpoints=endpoints,
        cred=cred, aliases=aliases,
    ).sign(keys.id_priv)
    directory.put(record)
    directory.save(cfg.dir_cache_path)
    from .sync import push_record
    try:
        push_record(anchor_url, record)
    except Exception as e:
        log.warning("published locally but push to anchor failed (will sync): %s", e)

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
          "sudo systemctl restart greasewood@<name>  (or re-run sudo gw run)")
    return 0


# ---------------------------------------------------------------------------
# run
# ---------------------------------------------------------------------------

def cmd_run(args) -> int:
    _require_root("run")
    from .config import load_config
    from .keys import NodeKeys, CAKeys
    from .ca import CA
    from .directory import Directory
    from .reconcile import ReconcileLoop
    from .sync import SyncLoop, push_record
    from .server import ControlServer
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

    # Peering is decided by shared segment:<name> tags. A caps list without one
    # (e.g. a hand-written legacy "mesh") peers with NOBODY and fails silently
    # per-record at reconcile — say it loudly once, up front.
    if not any(c.startswith("segment:") for c in cfg.caps):
        log.warning("[node] caps = %s contains no segment:<name> tag — this "
                    "node will not peer with anyone (add e.g. segment:mesh)",
                    cfg.caps)

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
    ca_pubs = [bytes.fromhex(h) for h in cfg.ca_pubs]
    def get_ca_pubs():
        return ca_pubs

    from . import audit
    with audit.context(f"startup: ensure interface {cfg.wg_interface} [{keys.addr}]"):
        try:
            wgmod.ensure_interface(
                cfg.wg_interface, keys.addr, cfg.listen_port, cfg.wg_key_path
            )
        except wgmod.PortInUse as e:
            # A fatal, operator-fixable startup condition — exit cleanly with the
            # actionable message instead of a traceback that crash-loops under
            # the systemd unit's Restart=on-failure.
            sys.exit(str(e))

    ca: CA | None = None
    sync: SyncLoop | None = None
    renewal: RenewalLoop | None = None
    door_watcher = None

    # Revoke list is re-read live (not snapshotted) so `gw revoke` takes effect
    # without a daemon restart — both for control-plane refusal and local
    # eviction. Plain nodes have no revoke list (expiry-based revocation).
    get_revoked: "callable" = set
    is_anchor = cfg.role == "anchor"

    if is_anchor:
        if not cfg.ca_key_file:
            sys.exit("anchor role requires ca_key_file in [anchor]")
        ca_keys = CAKeys.load(cfg.ca_key_file, _get_passphrase(cfg.ca_key_passphrase_env))
        ca = CA(ca_keys, cfg.data_dir, cfg.credential_ttl)
        get_revoked = ca.load_revoked_set
        log.info("CA loaded, pub=%s...", ca_keys.ca_pub_bytes.hex()[:16])
        # Re-apply door routing in case the machine rebooted since create
        wgmod.setup_door_routing()

        # Bind the control plane to the overlay address (reachable only through
        # the mesh) and loopback (for the anchor talking to itself) — NOT "::".
        # This keeps it off the underlay structurally, no firewall rule needed.
        port = _control_port(cfg)
        listen_addrs = [f"[{keys.addr}]:{port}", f"[::1]:{port}"]

        # Fleet-wide renew hint (gw renew-all): served in /directory, re-read
        # per request so a bump takes effect without restarting the anchor.
        def _read_renew_after():
            try:
                return (cfg.data_dir / "renew_after").read_text().strip() or None
            except FileNotFoundError:
                return None

        srv = ControlServer(
            listen_addrs,
            directory,
            get_ca_pubs=get_ca_pubs,
            get_revoked=get_revoked,
            ca=ca,
            cache_path=cfg.dir_cache_path,
            tls_cert_ttl=cfg.tls_cert_ttl,
            mesh_domain=cfg.mesh_domain,
            get_renew_after=_read_renew_after,
        )
        srv.start()

        from .enroll import DoorWatcher
        door_watcher = DoorWatcher(
            data_dir=cfg.data_dir,
            ca=ca,
            directory=directory,
            node_keys=keys,
            wg_iface=cfg.wg_interface,
            get_ca_pubs=get_ca_pubs,
            get_revoked=get_revoked,
            cache_path=cfg.dir_cache_path,
            control_port=_control_port(cfg),
            door_port=cfg.door_port,
            mesh_domain=cfg.mesh_domain,
        )
        door_watcher.start()
        log.info("door watcher started")

    # Directory sync — pull from the configured seeds (the anchor). The renewal loop
    # is built below; the callback reads it lazily (the first pull is one interval
    # out), so acting on the anchor's fleet renew hint needs no reordering.
    sync = SyncLoop(
        directory, lambda: cfg.seeds, cfg.dir_cache_path,
        on_renew_after=lambda ts: renewal.maybe_renew_after(ts) if renewal else None,
        expected_domain=cfg.mesh_domain,
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
        # fleet sees the edge change. Reads the current record from the directory
        # and bumps seq (composing cleanly with renewal, which preserves
        # reachable the same way) — the directory is the single seq source.
        from .wire import NodeRecord
        cur = directory.get(keys.id_pub_hex)
        if cur is None:
            return
        new = NodeRecord(
            id_pub=keys.id_pub_bytes, seq=cur.seq + 1,
            endpoints=list(cur.endpoints), cred=cur.cred,
            aliases=list(cur.aliases), reachable=list(reachable),
        ).sign(keys.id_priv)
        directory.put(new)
        directory.save(cfg.dir_cache_path)
        for seed in cfg.seeds:
            try:
                push_record(seed, new)
            except Exception as e:
                log.debug("reachable push to %s failed: %s", seed, e)
        log.debug("published reachable set (%d live links)", len(reachable))

    recon = ReconcileLoop(
        iface=cfg.wg_interface,
        directory=directory,
        local_id_pub=keys.id_pub_bytes,
        local_caps=cfg.caps,
        get_ca_pubs=get_ca_pubs,
        get_revoked=get_revoked,
        hosts_domain=cfg.mesh_domain if cfg.hosts_sync else None,
        local_families=_local_families(),
        ensure_iface=_ensure_mesh_iface,
        data_dir=cfg.data_dir,
        on_reachable=_publish_reachable,
    )
    recon.start()

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
        from .wire import NodeRecord
        own_record = NodeRecord(
            id_pub=keys.id_pub_bytes,
            seq=own_record.seq + 1,
            endpoints=eff_endpoints,
            cred=own_record.cred,
            aliases=want_aliases,
        ).sign(keys.id_priv)
        directory.put(own_record)
        directory.save(cfg.dir_cache_path)
        log.info("updated own record (endpoints=%s, aliases=%s)",
                 eff_endpoints, want_aliases)

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
    if door_watcher:
        door_watcher.stop()
    log.info("shutdown complete")
    return 0


# ---------------------------------------------------------------------------
# watch — the mesh dashboard (live by default; --snapshot for one static frame)
# ---------------------------------------------------------------------------

def _underlay_addrs(endpoints: list[str]) -> tuple[str, str]:
    """(v6_host, v4_host) from a node's advertised underlay endpoints, '-' if it
    advertises none of that family. Endpoints are formatted 'host:port' /
    '[v6]:port'; the port is dropped for the table."""
    v6 = v4 = "-"
    for ep in endpoints:
        if ep.startswith("["):                 # [v6]:port
            v6 = ep[1:].split("]")[0]
        elif ep:                               # host:port (v4)
            v4 = ep.rsplit(":", 1)[0]
    return v6, v4


def _record_segments(r) -> list[str]:
    """The segment names a record belongs to (from its `segment:` caps)."""
    return [c[len("segment:"):] for c in r.cred.caps if c.startswith("segment:")]


def _fmt_bytes(n) -> str:
    """Human byte size: 4200000 → '4.0M'."""
    x = float(n)
    for unit in ("B", "K", "M", "G"):
        if x < 1024:
            return f"{int(x)}{unit}" if unit == "B" else f"{x:.1f}{unit}"
        x /= 1024
    return f"{x:.1f}T"


def _fmt_hs_age(age_s: float) -> str:
    """Compact age for a handshake: 12→'12s', 90→'1m', 7200→'2h', bigger→'Nd'."""
    if age_s < 60:
        return f"{int(age_s)}s"
    if age_s < 3600:
        return f"{int(age_s // 60)}m"
    if age_s < 86400:
        return f"{int(age_s // 3600)}h"
    return f"{int(age_s // 86400)}d"


def _roster_lines(records, cfg, now, own_id, live_peers, is_root,
                  latency=None, rates=None) -> list:
    """The split roster as a list of lines: LEFT is the mesh (fleet-wide, same on
    every node — name, addr, reachable, segments, credential); RIGHT is THIS
    node's view. Without root the right side is just the policy 'would I peer'
    answer. With root it's the live link + cumulative traffic. In LIVE mode
    (latency dict supplied) the right side is link + per-second RATE + a latency
    column that fills in asynchronously (blank until each peer's ping returns)."""
    from .hosts import mesh_name
    from .reconcile import default_policy

    have_live = live_peers is not None
    is_live = latency is not None
    now_epoch = int(now.timestamp())

    def _exp(r):
        left = (r.cred.exp - now).total_seconds()
        if left < 0:
            return "EXPIRED"
        if left < 3600:
            return "<1h!"
        h = int(left // 3600)
        return f"{h // 24}d" if h >= 48 else f"{h}h"

    def _right(r, is_self, peers, lp):
        if is_live:                             # link · rate · latency
            if is_self:
                return ("(self)", "", latency.get(r.cred.addr, "…"))
            if not peers:
                return ("— not a peer", "", "")
            if lp is None:
                return ("not installed", "", "")
            if lp.latest_handshake and (now_epoch - lp.latest_handshake) <= 180:
                return (f"● up, {_fmt_hs_age(now_epoch - lp.latest_handshake)}",
                        (rates or {}).get(r.cred.addr, ""),
                        latency.get(r.cred.addr, "…"))   # … = ping in flight
            return ("○ no handshake", "", "—")
        if not have_live:                       # policy only (no root)
            return ("self" if is_self else ("yes" if peers else "no"),)
        if is_self:
            return ("(self)", "")
        if not peers:
            return ("— not a peer", "")
        if lp is None:
            return ("not installed", "")
        if lp.latest_handshake and (now_epoch - lp.latest_handshake) <= 180:
            return (f"● up, {_fmt_hs_age(now_epoch - lp.latest_handshake)} ago",
                    f"↓{_fmt_bytes(lp.rx_bytes)} ↑{_fmt_bytes(lp.tx_bytes)}")
        return ("○ no handshake", "")

    left_hdr = ("name", "addr", "in", "segments", "exp")
    if is_live:
        right_hdr = ("link", "rate", "latency")
    elif have_live:
        right_hdr = ("link", "traffic")
    else:
        right_hdr = ("peer?",)

    left_rows, right_rows = [], []
    for r in records:
        left_rows.append((
            mesh_name(r.hostname, cfg.mesh_domain), r.cred.addr,
            "yes" if r.endpoints else "no",
            ",".join(_record_segments(r)) or "-", _exp(r),
        ))
        lp = (live_peers or {}).get(base64.b64encode(r.cred.wg_pub).decode())
        right_rows.append(_right(r, r.id_pub.hex() == own_id,
                                 default_policy(cfg.caps, r.cred.caps), lp))

    def _w(hdr, i, rows):
        return max(len(hdr), *(len(row[i]) for row in rows)) if rows else len(hdr)
    lw = [_w(left_hdr[i], i, left_rows) for i in range(len(left_hdr))]
    rw = [_w(right_hdr[i], i, right_rows) for i in range(len(right_hdr))]

    def _fl(cells):     # left: name right-justified, rest left
        return " ".join([f"{cells[0]:>{lw[0]}}"]
                        + [f"{cells[i]:<{lw[i]}}" for i in range(1, len(cells))])
    def _fr(cells):
        return " ".join(f"{cells[i]:<{rw[i]}}" for i in range(len(cells)))

    lwidth = len(_fl(left_hdr))
    out = [f"{'mesh — the fleet (same on every node)':<{lwidth}} │ this node",
           _fl(left_hdr) + " │ " + _fr(right_hdr),
           "-" * lwidth + "-+-" + "-" * max(len(_fr(right_hdr)), 9)]
    out += [_fl(lr) + " │ " + _fr(rr) for lr, rr in zip(left_rows, right_rows)]
    if not have_live and not is_live:
        note = ("run 'sudo gw watch' for live data links + traffic" if not is_root
                else "no live WireGuard state — is the daemon running?")
        out.append(f"({note})")
    return out


def _print_node_table(records, cfg, now, own_id, live_peers, is_root) -> None:
    for line in _roster_lines(records, cfg, now, own_id, live_peers, is_root):
        print(line)


def _segment_analysis(members):
    """Fleet-wide connectivity within a segment, from each node's self-reported
    `reachable` set (synced in the directory — no root or live wg needed).
    Returns (components, missing_edges). An edge is UP if EITHER end reports the
    other (a session is bidirectional, so one end suffices — robust to one-sided
    staleness). An edge is EXPECTED (so its absence is a fault) when at least one
    end advertises an endpoint, i.e. a dialable direction exists."""
    def linked(a, b):
        return b.cred.addr in a.reachable or a.cred.addr in b.reachable
    parent = {r.cred.addr: r.cred.addr for r in members}

    def find(x):
        root = x
        while parent[root] != root:
            root = parent[root]
        while parent[x] != root:               # path-compress
            parent[x], x = root, parent[x]
        return root

    missing = []
    for i, a in enumerate(members):
        for b in members[i + 1:]:
            if linked(a, b):
                parent[find(a.cred.addr)] = find(b.cred.addr)
            elif a.endpoints or b.endpoints:   # a link was possible but is absent
                missing.append((a, b))
    comps = {}
    for r in members:
        comps.setdefault(find(r.cred.addr), []).append(r)
    return list(comps.values()), missing


def _edge_down_hint(a, b, cfg) -> str:
    """A directional hint for a down edge, derived from who advertises an
    endpoint (the dialable direction) — the discovery-vs-firewall first question."""
    from .hosts import mesh_name
    na = mesh_name(a.hostname, cfg.mesh_domain)
    nb = mesh_name(b.hostname, cfg.mesh_domain)
    ea, eb = bool(a.endpoints), bool(b.endpoints)
    if ea and eb:
        return f"{na} ✗ {nb}  (both advertise endpoints — check firewalls at both ends)"
    if ea:                                      # only a is dialable → b must reach it
        return f"{na} ✗ {nb}  ({nb} can't reach {na} at {a.endpoints[0]} — {na}'s firewall/NAT?)"
    return f"{na} ✗ {nb}  ({na} can't reach {nb} at {b.endpoints[0]} — {nb}'s firewall/NAT?)"


def _print_segment_health(members, cfg) -> None:
    """Under a segment's roster: fully-connected, or the partition/down-edge
    breakdown. Uses only the synced `reachable` sets, so it works non-root."""
    from .hosts import mesh_name
    if len(members) < 2:
        return
    comps, missing = _segment_analysis(members)
    if len(comps) <= 1 and not missing:
        print("  ✓ fully connected")
        return
    if len(comps) > 1:
        print(f"  ⚠ PARTITIONED — {len(comps)} islands that can't reach each other:")
        for c in sorted(comps, key=len, reverse=True):
            names = ", ".join(sorted(mesh_name(r.hostname, cfg.mesh_domain) for r in c))
            tail = "   ← isolated" if len(c) == 1 else ""
            print(f"      {{ {names} }}{tail}")
    if missing:
        n = len(missing)
        print(f"  ⚠ {n} expected link{'' if n == 1 else 's'} down:")
        for a, b in missing:
            print(f"      {_edge_down_hint(a, b, cfg)}")


def _fmt_rate(bytes_per_s: float) -> str:
    return f"{_fmt_bytes(max(0.0, bytes_per_s))}/s"


def _ping_rtt(addr: str) -> str:
    """Round-trip time to an overlay address via one ICMPv6 echo, as 'Nms', or
    '—' on timeout/unreachable. Numeric only (-n), 1s deadline (-W1)."""
    try:
        r = subprocess.run(["ping", "-6", "-n", "-c", "1", "-W", "1", addr],
                           capture_output=True, text=True, timeout=3)
    except Exception:
        return "—"
    if r.returncode != 0:
        return "—"
    m = re.search(r"time=([\d.]+)\s*ms", r.stdout)
    return f"{float(m.group(1)):.0f}ms" if m else "—"


class _LatencyProber:
    """Background prober for `gw watch`: round-robins ICMP pings over the
    current linked peers and publishes results in `self.results` ({addr: 'Nms'|
    '—'}). The display reads it non-blocking, so latency fills in over the first
    few seconds instead of stalling the first frame — and pings run ONLY while
    someone is watching the live view (the caller stops it on exit)."""

    def __init__(self) -> None:
        self.results: dict = {}
        self._targets: list = []
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._t = threading.Thread(target=self._run, name="latency", daemon=True)

    def set_targets(self, addrs) -> None:
        with self._lock:
            self._targets = list(addrs)

    def _run(self) -> None:
        while not self._stop.is_set():
            with self._lock:
                tgts = list(self._targets)
            if not tgts:
                self._stop.wait(0.5)
                continue
            for addr in tgts:
                if self._stop.is_set():
                    break
                self.results[addr] = _ping_rtt(addr)

    def start(self) -> None:
        self._t.start()

    def stop(self) -> None:
        self._stop.set()


def _watch_live(cfg, own_id, interval: float = 2.0) -> int:
    """Live, redraw-in-place `gw watch`: link state + per-second throughput
    (from the sample delta between frames) + an async latency column. Root +
    a terminal required; Ctrl-C exits."""
    from .directory import Directory
    from . import wg as wgmod

    if not sys.stdout.isatty():
        sys.exit("gw watch needs a terminal to redraw into; "
                 "use 'gw watch --snapshot' for piped/one-shot output")
    if os.geteuid() != 0:
        # Root is for `wg show` (live link state) — the same gate the static
        # right-side columns have. Pinging itself is unprivileged on Linux.
        sys.exit("gw watch needs root — it reads live WireGuard state "
                 "(wg show). Try: sudo gw watch  (or gw watch --snapshot "
                 "for a no-root static view)")

    prober = _LatencyProber()
    prober.start()
    prev: dict = {}          # wg_pub_b64 -> (rx, tx, monotonic) for the rate delta
    sys.stdout.write("\033[?25l")   # hide cursor
    try:
        while True:
            records = sorted(Directory.load(cfg.dir_cache_path).all(),
                             key=lambda r: r.hostname)
            try:
                live = wgmod.get_peers(cfg.wg_interface)
            except Exception:
                live = {}
            now = dt.datetime.now(_UTC)
            now_epoch = int(now.timestamp())
            mono = time.monotonic()

            rates, targets = {}, []
            for r in records:
                if r.id_pub.hex() == own_id:
                    # Ping our own overlay address (~0ms) so the self row shows a
                    # latency too — makes a peer with NO latency (broken) visually
                    # distinct from the healthy rows.
                    targets.append(r.cred.addr)
                    continue
                pub = base64.b64encode(r.cred.wg_pub).decode()
                lp = live.get(pub)
                if not lp:
                    continue
                if lp.latest_handshake and (now_epoch - lp.latest_handshake) <= 180:
                    targets.append(r.cred.addr)
                    p = prev.get(pub)
                    if p and mono > p[2]:
                        dts = mono - p[2]
                        rates[r.cred.addr] = (
                            f"↓{_fmt_rate((lp.rx_bytes - p[0]) / dts)} "
                            f"↑{_fmt_rate((lp.tx_bytes - p[1]) / dts)}")
                prev[pub] = (lp.rx_bytes, lp.tx_bytes, mono)
            prober.set_targets(targets)

            body = _roster_lines(records, cfg, now, own_id, live, True,
                                 latency=prober.results, rates=rates)
            up = len(targets)
            fresh = _sync_freshness(cfg)
            frame = ["\033[H\033[J",
                     f"gw watch · {cfg.hostname}.{cfg.mesh_domain} · "
                     f"{now:%H:%M:%S}Z · {up} link{'' if up == 1 else 's'} up"
                     + (f" · {fresh}" if fresh else ""), ""]
            frame += body
            frame += ["", "(latency pings fill in live · throughput is per-second "
                      "· Ctrl-C to exit)"]
            sys.stdout.write("\n".join(frame))
            sys.stdout.flush()
            time.sleep(interval)
    except KeyboardInterrupt:
        pass
    finally:
        prober.stop()
        sys.stdout.write("\033[?25h\n")   # restore cursor
        sys.stdout.flush()
    return 0


def _sync_freshness(cfg) -> "str | None":
    """How fresh the local directory is — shown at the TOP of `gw watch` so the
    roster/segment view's staleness is obvious (it's only as current as the last
    sync). None on the anchor (it's the source of truth)."""
    if cfg.role == "anchor":
        return None
    from . import sync as syncmod
    last = syncmod.read_last_sync(cfg.data_dir)
    if last is None:
        return "never synced (is the daemon running / reaching the anchor?)"
    try:
        age = (dt.datetime.now(_UTC) - dt.datetime.fromisoformat(
            last.replace("Z", "+00:00"))).total_seconds()
    except (ValueError, AttributeError):
        age = 0.0
    if age > 120:
        return (f"⚠ directory synced {_fmt_ago(last)} — anchor unreachable? "
                f"this view may be stale")
    return f"directory synced {_fmt_ago(last)}"


def _fmt_ago(iso: str) -> str:
    """A coarse 'time since' for a timestamp: seconds, then minutes, then >1h."""
    try:
        t = dt.datetime.fromisoformat(iso.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return "?"
    s = (dt.datetime.now(_UTC) - t).total_seconds()
    if s < 0:
        return "just now"
    if s < 60:
        return f"{int(s)}s ago"
    if s < 3600:
        return f"{int(s // 60)}m ago"
    return ">1h ago"


def _fmt_until(iso: str) -> str:
    """Minutes until a future timestamp (for the open door's close time)."""
    try:
        t = dt.datetime.fromisoformat(iso.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return "?"
    s = (t - dt.datetime.now(_UTC)).total_seconds()
    if s <= 0:
        return "now"
    if s < 60:
        return "<1m"
    return f"{int(s // 60) + (1 if s % 60 else 0)}m"


def _door_status_lines(cfg) -> list:
    """The `door:` block for `gw watch` — anchor only. Shows whether the
    enrollment door is open (and time-to-close) or closed (and how long ago),
    plus failed attempts + source IPs and the last enrollment."""
    from . import door
    try:
        st = door.read_door_status(cfg.data_dir)
    except PermissionError:
        # door_status.json is 0600 root (it holds attempt source IPs). Degrade
        # honestly rather than dying — status is a no-root command.
        return ["door     : (state readable only with root — sudo gw watch)"]
    if st is None:
        return ["door     : closed (never opened)"]

    lines = []
    attempts = st.get("attempts") or []

    def _attempt_summary(prefix: str):
        if not attempts:
            return
        ips = ", ".join(f"{a.get('ip','?')} ({a.get('reason','?')})" for a in attempts)
        n = len(attempts)
        lines.append(f"           {prefix}{n} failed attempt{'s' if n != 1 else ''}: {ips}")

    if st.get("state") == "open" and st.get("standing"):
        n = int(st.get("enroll_count") or 0)
        head = f"door     : OPEN (standing) — {n} enrolled"
        enr = st.get("enrolled")
        if enr:
            head += f", last: {enr.get('hostname','?')} ({_fmt_ago(enr.get('ts',''))})"
        if st.get("opened_at"):
            head += f" (opened {_fmt_ago(st['opened_at'])})"
        lines.append(head)
        grants = ", ".join(st.get("caps") or []) or "(default)"
        lines.append(f"           grants: {grants} · closes only via: gw close-door")
        # The standing token, re-retrievable for baking into new images without
        # re-issuing. From the 0600-root window file — and this whole door block
        # only renders for a root `gw watch` (door_status.json is 0600 too), so
        # the token (which IS the enrollment credential) never shows non-root.
        w = door.read_window(cfg.data_dir)
        if w and w.get("token"):
            lines.append(f"           token: {w['token']}")
        _attempt_summary("")
    elif st.get("state") == "open":
        head = f"door     : OPEN — closes in {_fmt_until(st.get('expires',''))}"
        if st.get("opened_at"):
            head += f" (opened {_fmt_ago(st['opened_at'])})"
        lines.append(head)
        grants = ", ".join(st.get("caps") or []) or "(default)"
        pin = st.get("pinned_hostname")
        lines.append(f"           grants: {grants}"
                     + (f"; hostname pinned to {pin!r}" if pin else ""))
        _attempt_summary("")
        left = max(0, int(st.get("max_attempts", 3)) - len(attempts))
        lines.append(f"           {left} attempt{'s' if left != 1 else ''} remaining")
    else:
        reason = st.get("close_reason") or "closed"
        enr = st.get("enrolled")
        if reason == "enrolled" and enr:
            phrase = f"enrolled {enr.get('hostname','?')} from {enr.get('ip','?')}"
        else:
            phrase = {"expired": "window expired with no enrollment",
                      "attempts_exhausted": "too many failed attempts",
                      "superseded": "replaced by a newer invite / daemon stop",
                      }.get(reason, reason)
        when = _fmt_ago(st["closed_at"]) if st.get("closed_at") else "?"
        lines.append(f"door     : closed — last closed {when} ({phrase})")
        _attempt_summary("last window: ")
    return lines


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
        entries = [e for e in entries
                   if g in e.ctx.lower() or g in " ".join(e.argv).lower()
                   or g in N.describe(e.argv).lower()]

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


def _dur_short(seconds: float) -> str:
    """Compact future-duration: '45m', '18h', '2d 3h'."""
    s = int(seconds)
    if s < 3600:
        return f"{s // 60}m"
    if s < 86400:
        return f"{s // 3600}h"
    d, h = s // 86400, (s % 86400) // 3600
    return f"{d}d {h}h" if h else f"{d}d"


def _self_health_lines(cfg, directory, own_id) -> list:
    """The self/health block for `gw watch` — local facts about THIS node
    (version, own credential, reachability posture, trust anchors, and — for a
    plain node — how fresh the directory cache is). All local: no root, no
    network, so `status` stays instant. Live/reach-out checks (clock skew, live
    links) stay in `gw diagnose`."""
    from . import sync as syncmod
    lines = []
    lines.append(f"{'version':<9}: {_version()}")

    self_rec = directory.get(own_id) if own_id else None
    if self_rec is not None:
        left = (self_rec.cred.exp - dt.datetime.now(_UTC)).total_seconds()
        if left < 0:
            cred = f"⚠ EXPIRED {int(-left // 60)}m ago — renewal isn't keeping up"
        else:
            cred = (f"expires {self_rec.cred.exp:%Y-%m-%d %H:%M UTC} "
                    f"(in {_dur_short(left)})")
        lines.append(f"{'cred':<9}: {cred}")
    elif own_id:
        lines.append(f"{'cred':<9}: no self record yet (has the daemon published?)")

    reach = ("advertises an endpoint (dialable)" if cfg.endpoints
             else "no endpoint (outbound-only — you dial peers)")
    lines.append(f"{'reach':<9}: {reach}")

    n = len(cfg.ca_pubs)
    lines.append(f"{'trust':<9}: {n} trusted CA{'' if n == 1 else 's'} · "
                 f"anchor {cfg.root_url or '(none configured)'}")

    # (Sync freshness is shown prominently at the top of `gw watch` instead —
    # see _sync_freshness — so the segment/roster view's staleness is obvious.)

    # A pending mesh rename the daemon detected from the anchor — persisted so it
    # doesn't scroll past in the log. Needs an operator action, so it's loud.
    pend = cfg.data_dir / "pending_rename.json"
    if pend.exists():
        try:
            d = json.loads(pend.read_text())
            newk = membership_key(d["new_domain"])
            lines.append(f"{'rename':<9}: ⚠ the anchor renamed this mesh "
                         f"{d.get('old_domain','?')} → {d['new_domain']}. "
                         f"Migrate: sudo gw rename-mesh {newk}")
        except Exception:
            pass
    return lines


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


def cmd_firewall(args) -> int:
    """Print the recommended firewall ruleset for this mesh — a SUGGESTION only.
    greasewood NEVER touches your firewall; this command changes nothing. The
    same ruleset is recommended on every node (anchor or not), so promoting a
    node to anchor needs no firewall change. With root it also checks the live
    nftables ruleset and flags anything that looks blocked."""
    from .config import load_config
    from . import firewall as _fw
    cfg = load_config(Path(args.config))
    control_port = _control_port(cfg)

    bar = "─" * 72
    print(bar)
    print("  greasewood NEVER modifies your firewall.")
    print("  This is a SUGGESTION — nothing has been changed. Apply it yourself.")
    print(bar)
    print()
    _print_firewall_help(cfg.listen_port, control_port, cfg.wg_interface, header=False)
    print()
    print("The two UDP ports ride the underlay (WireGuard listens there). The two")
    print("TCP ports bind only to their interface, so they're scoped to it — and")
    print("harmless on a non-anchor node (nothing is bound, so the kernel refuses).")
    print()
    # Advisory check of the LIVE ruleset (read-only; needs root to see it).
    _fw.check(_fw.anchor_rules(cfg.listen_port, control_port, cfg.wg_interface), log)
    return 0


def cmd_watch(args) -> int:
    from .config import load_config
    from .directory import Directory

    cfg_path = Path(args.config)
    if not cfg_path.exists():
        print("not configured (no config file at %s)" % cfg_path)
        return 0

    cfg = load_config(cfg_path)

    # The snapshot (static) view is a no-root command: it reads only the public
    # files (id_pub.hex, directory.json). But on a legacy install with a 0700
    # data dir, those reads fail invisibly (exists() → False, Directory.load →
    # empty) and it would lie ("keys not generated", "directory is empty"). Say
    # the truth instead.
    if (cfg.data_dir.exists() and not os.access(cfg.data_dir, os.X_OK)) or (
            cfg.dir_cache_path.exists() and not os.access(cfg.dir_cache_path, os.R_OK)):
        sys.exit(f"can't read the public state under {cfg.data_dir} (a legacy "
                 f"install with a 0700 data dir?). Either run: sudo gw watch, "
                 f"or open the public files up: sudo chmod 755 {cfg.data_dir}")
    own_id, own_addr = _own_identity(cfg.data_dir)

    # Live is the default; a static one-shot is --snapshot (for piping/logging),
    # and we auto-fall-back to it when there's no terminal to redraw into.
    if not getattr(args, "snapshot", False) and sys.stdout.isatty():
        # Redraw-in-place live view: link state + per-second throughput + an
        # async latency column (pings run only while you're watching). Needs
        # root for live WireGuard state — that's why the default wants sudo.
        return _watch_live(cfg, own_id,
                            interval=max(1.0, getattr(args, "interval", 2.0) or 2.0))

    directory = Directory.load(cfg.dir_cache_path)

    print(f"role     : {cfg.role}")
    print(f"hostname : {cfg.hostname}")
    print(f"addr     : {own_addr or '(keys not generated)'}")
    fresh = _sync_freshness(cfg)
    if fresh:
        print(f"synced   : {fresh}")
    # Self/health — local facts about THIS node (fast, no root, no network).
    for line in _self_health_lines(cfg, directory, own_id):
        print(line)
    # The enrollment door only exists on the anchor — show its state there.
    if cfg.role == "anchor":
        for line in _door_status_lines(cfg):
            print(line)
    print()

    now = dt.datetime.now(_UTC)
    records = sorted(directory.all(), key=lambda r: r.hostname)

    if not records:
        print("directory is empty — run 'gw join <token>' then 'gw run'")
        return 0

    # Live data-plane state for the right-hand "this node" columns — only as
    # root (wg show needs it). None → the roster shows the policy 'peer?' answer
    # and a hint to re-run with sudo.
    is_root = os.geteuid() == 0
    live_peers = None
    if is_root:
        try:
            from . import wg as wgmod
            live_peers = wgmod.get_peers(cfg.wg_interface)
        except Exception:
            live_peers = None

    if getattr(args, "by_segment", False):
        # One table per named segment. A node appears under every segment it's in,
        # and a reach-all (segment:*) node appears under ALL of them — so many
        # nodes show up in more than one table.
        named = sorted({s for r in records for s in _record_segments(r) if s != "*"})
        shown: set[str] = set()
        for s in named:
            members = [r for r in records
                       if s in _record_segments(r) or "*" in _record_segments(r)]
            shown.update(r.id_pub.hex() for r in members)
            print(f"segment: {s}  ({len(members)} node{'' if len(members) == 1 else 's'})")
            _print_node_table(members, cfg, now, own_id, live_peers, is_root)
            _print_segment_health(members, cfg)
            print()
        # Anything not shown above — unsegmented nodes (can't peer), or reach-all
        # nodes with no named segment to fall under — so the grouped view drops
        # nobody.
        leftover = [r for r in records if r.id_pub.hex() not in shown]
        if leftover:
            print(f"(no segment)  ({len(leftover)} node{'' if len(leftover) == 1 else 's'}) "
                  f"— unsegmented, can't peer until given a segment")
            _print_node_table(leftover, cfg, now, own_id, live_peers, is_root)
            print()
    else:
        _print_node_table(records, cfg, now, own_id, live_peers, is_root)
        print()

    print(f"{len(records)} record(s) in local directory cache")
    return 0


# ---------------------------------------------------------------------------
# diagnose — pairwise link diagnosis (up to two nodes + the anchor)
# ---------------------------------------------------------------------------

def _anchor_clock_skew(root_url: str, timeout: float = 3.0) -> "float | None":
    """Local-minus-anchor clock difference in seconds via /health's 'now' stamp,
    or None if the anchor is unreachable or doesn't send one (older anchor)."""
    import urllib.request
    try:
        with urllib.request.urlopen(f"{root_url.rstrip('/')}/health",
                                    timeout=timeout) as resp:
            raw = json.loads(resp.read()).get("now")
        if not raw:
            return None
        anchor_now = dt.datetime.fromisoformat(raw.replace("Z", "+00:00"))
        return (dt.datetime.now(_UTC) - anchor_now).total_seconds()
    except Exception:
        return None


# IPv6 header (40) + ICMPv6 echo header (8): the fixed overhead an ICMP echo
# adds on top of its -s payload, so payload = iface_mtu - 48 fills exactly one
# interface-MTU packet.
_ICMP6_OVERHEAD = 48


def _iface_mtu(iface: str) -> "int | None":
    """The MTU of the WireGuard interface, or None if it can't be read."""
    r = subprocess.run(["ip", "-o", "link", "show", iface],
                       capture_output=True, text=True)
    if r.returncode != 0:
        return None
    parts = r.stdout.split()
    for i, tok in enumerate(parts):
        if tok == "mtu" and i + 1 < len(parts):
            try:
                return int(parts[i + 1])
            except ValueError:
                return None
    return None


def _ping6_df(addr: str, payload: int, timeout: int = 1) -> "bool | None":
    """Send one DF (don't-fragment) ICMPv6 echo of `payload` bytes across the
    overlay. True if a reply came back, False if not, None if ping is missing.
    -M do forbids fragmentation, so an oversized packet is dropped rather than
    split — which is exactly what a full-size tunnel packet does over a
    too-small underlay path."""
    ping = shutil.which("ping")
    if not ping:
        return None
    r = subprocess.run(
        [ping, "-6", "-M", "do", "-c", "1", "-W", str(timeout),
         "-s", str(payload), addr],
        capture_output=True, text=True)
    return r.returncode == 0


def _mtu_probe(iface: str, addr: str, iface_mtu: "int | None") -> "str | None":
    """Detect a path-MTU blackhole to a linked peer: a small DF ping succeeds
    but a full-interface-MTU one is dropped. Returns a warning string, or None
    if the path is clean, ping is unavailable, or the result is inconclusive
    (small ping already failing means the link is just down, not an MTU issue)."""
    if iface_mtu is None:
        return None
    small = _ping6_df(addr, 100)
    if not small:  # None (no ping) or False (link down) → don't cry wolf
        return None
    payload = iface_mtu - _ICMP6_OVERHEAD
    if _ping6_df(addr, payload):
        return None  # full-size packets pass → no blackhole
    return (f"PATH MTU BLACKHOLE: {payload}-byte (full {iface_mtu}-MTU) packets "
            f"to {addr} are dropped though small ones pass — TLS handshakes and "
            f"other large transfers will hang. Lower the tunnel MTU "
            f"(ip link set {iface} mtu 1280) or fix the underlay path MTU.")


def _self_firewall_port(port: int) -> str:
    """This host's own nftables verdict for a UDP port: 'OPEN', 'CLOSED' (a
    default-drop policy with no accept rule), 'open (no default-drop)', or
    '??? (nft unreadable)'. Only the local host is knowable — every other node's
    firewall is inferred from observed connectivity or left ???."""
    from . import firewall as fw
    rs = fw._load_ruleset()
    if rs is None:
        return "??? (nft unreadable)"
    if not fw.default_drop(rs):
        return "open (no default-drop)"
    missing = fw.missing_rules(rs, [fw.Rule("udp", port, None, "mesh")])
    return "CLOSED — blocked!" if missing else "OPEN"


def _diag_anchor_record(directory, cfg, own_rec):
    """The anchor's directory record. If this host IS the anchor, that's our own
    record; otherwise the node at the control-plane URL (root_url) address.
    None if unresolvable / not yet in cache."""
    if cfg.role == "anchor":
        return own_rec
    m = re.search(r"\[([0-9a-fA-F:]+)\]", cfg.root_url or "")
    if not m:
        return None
    addr = m.group(1)
    for r in directory.all():
        if r.cred.addr == addr:
            return r
    return None


class _DiagCol:
    """One column of the diagnose comparison — a node's resolved facts."""
    __slots__ = ("label", "is_self", "rec", "addr", "u6", "u4",
                 "caps", "segments", "cred", "has_ep", "ep_str", "hs", "fw")


def cmd_diagnose(args) -> int:
    """
    Pairwise link diagnosis. `gw diagnose [A [B]]` lays up to two named nodes
    plus the anchor side by side and explains, per pair, whether a WireGuard tunnel
    can form — and if not, WHICH factor blocks it, with the firewall/reachability
    directionality that's usually the real question.

      gw diagnose            this node ↔ the anchor
      gw diagnose A          this node ↔ A            (+ anchor as reference)
      gw diagnose A B        A ↔ B                    (+ anchor as reference)

    Only THIS host's firewall is directly knowable; a peer's is inferred OPEN
    from an observed handshake (packets flowing prove its whole inbound path —
    host firewall + any router/NAT + daemon) and otherwise shown ???. When the
    pair involves this host, the verdict localizes a failure: e.g. "our host
    firewall allows the port, so a peer that still can't reach us points at an
    upstream router/NAT not forwarding it."
    """
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from .config import load_config
    from .keys import derive_addr
    from .directory import Directory
    from .reconcile import default_policy
    from .wire import _canonical
    from . import wg as wgmod

    cfg_path = Path(args.config)
    if not cfg_path.exists():
        print(f"not configured (no config file at {cfg_path})")
        return 1
    cfg = load_config(cfg_path)
    port = cfg.listen_port

    own_id, own_addr = _own_identity(cfg.data_dir)
    if own_id is None:
        print("keys not generated yet — run 'gw join <token>' or 'gw create' first")
        return 1
    own_id_bytes = bytes.fromhex(own_id)

    for w in _key_file_warnings(_secret_key_paths(cfg)):
        print(f"  ⚠ {w}")

    ca_pubs = [bytes.fromhex(h) for h in cfg.ca_pubs]
    revoked: set = set()
    rev_path = cfg.data_dir / "revoked.json"
    if rev_path.exists():
        try:
            revoked = set(json.loads(rev_path.read_text()).get("revoked", []))
        except Exception:
            pass

    try:
        live_peers = wgmod.get_peers(cfg.wg_interface)
    except Exception:
        live_peers = {}
    directory = Directory.load(cfg.dir_cache_path)
    now = dt.datetime.now(_UTC)
    now_epoch = int(time.time())
    own_rec = directory.get(own_id)

    # ---- resolve the requested nodes → up to three columns (pair + anchor) ------
    def _find(name):
        from .hosts import sanitize
        want = sanitize(name)
        for r in directory.all():
            if sanitize(r.hostname) == want:
                return r
        return None

    requested = [n for n in (getattr(args, "nodes", None) or []) if n]
    picks = []                                  # list of (label, rec|None, is_self)
    for name in requested:
        r = _find(name)
        if r is None:
            sys.exit(f"no node named {name!r} in the directory cache (see gw watch)")
        picks.append((r.hostname, r, r.id_pub == own_id_bytes))

    if not requested:                           # 0 args: self ↔ anchor
        picks.append((cfg.hostname, own_rec, True))
    elif len(requested) == 1:                   # 1 arg: self ↔ A
        picks.insert(0, (cfg.hostname, own_rec, True))

    anchor_rec = _diag_anchor_record(directory, cfg, own_rec)  # always add the anchor as reference
    if anchor_rec is not None:
        picks.append((anchor_rec.hostname, anchor_rec, anchor_rec.id_pub == own_id_bytes))

    # Dedup by overlay address, cap at three, keep order.
    cols, seen = [], set()
    for label, rec, is_self in picks:
        key = rec.cred.addr if rec is not None else ("self" if is_self else label)
        if key in seen:
            continue
        seen.add(key)
        cols.append((label, rec, is_self))
    cols = cols[:3]

    def _verify(rec) -> str:
        if rec is None:
            return "(not in cache)"
        ok = False
        body = _canonical(rec.cred._body_dict())
        for raw in ca_pubs:
            try:
                Ed25519PublicKey.from_public_bytes(raw).verify(rec.cred.ca_sig, body)
                ok = True
                break
            except InvalidSignature:
                continue
        if not ok:
            return "✗ untrusted CA"
        if rec.id_pub.hex() in revoked:
            return "✗ REVOKED"
        left = (rec.cred.exp - now).total_seconds()
        if left < 0:
            return f"✗ EXPIRED {int(-left // 60)}m ago"
        return f"valid · {_dur_short(left)}"

    def _hs_age(rec):
        if rec is None:
            return None
        lp = live_peers.get(base64.b64encode(rec.cred.wg_pub).decode())
        if lp and lp.latest_handshake:
            age = now_epoch - lp.latest_handshake
            return age if age <= 180 else None
        return None

    # Build a column of facts per node.
    facts = []
    for label, rec, is_self in cols:
        c = _DiagCol()
        c.label = label
        c.is_self = is_self
        c.rec = rec
        c.addr = rec.cred.addr if rec else (own_addr or "?")
        eps = rec.endpoints if rec else cfg.endpoints
        c.u6, c.u4 = _underlay_addrs(eps)
        c.caps = list(rec.cred.caps) if rec else list(cfg.caps)
        c.segments = ",".join(_record_segments(rec)) if rec else \
            ",".join(s[len("segment:"):] for s in cfg.caps if s.startswith("segment:"))
        c.cred = _verify(rec)
        # Reachability is emergent: a node is dialable iff it advertises an
        # endpoint. No inbound flag anymore.
        c.has_ep = (c.u6 != "-" or c.u4 != "-")
        c.ep_str = c.u6 if c.u6 != "-" else (c.u4 if c.u4 != "-" else "—")
        c.hs = _hs_age(rec)
        if is_self:
            c.fw = _self_firewall_port(port)
        elif not c.has_ep:
            c.fw = "n/a (outbound-only)"
        elif c.hs is not None:
            c.fw = "OPEN (inferred: handshake)"
        else:
            c.fw = "??? unconfirmed"
        facts.append(c)

    # ---- header -------------------------------------------------------------
    print(f"diagnose · this host: {cfg.hostname} ({own_addr}) · "
          f"iface {cfg.wg_interface} · mesh UDP {port}")
    if not ca_pubs:
        print("  ⚠ no trusted CA keys — nothing will verify (check [ca] trusted_pubs)")
    if cfg.root_url:
        skew = _anchor_clock_skew(cfg.root_url)
        if skew is None:
            print("  clock: anchor unreachable — skew check skipped")
        elif abs(skew) >= 60:
            print(f"  ⚠ clock {skew:+.0f}s off the anchor — FIX NTP (past ±300s "
                  f"renewals refused; expiry checks misfire earlier)")
    if os.geteuid() != 0:
        print("  ⚠ not root — no live WireGuard state; link status & firewall "
              "inference unavailable (re-run with sudo)")
    print()

    # ---- comparison table (nodes as columns) --------------------------------
    heads = [f"{c.label}{' (self)' if c.is_self else ''}" for c in facts]
    rows = [("overlay", [c.addr for c in facts]),
            ("underlay v6", [c.u6 for c in facts]),
            ("underlay v4", [c.u4 for c in facts]),
            ("reachable", ["yes (advertises endpoint)" if c.has_ep
                           else "no (outbound-only)" for c in facts]),
            ("segments", [c.segments or "-" for c in facts]),
            ("credential", [c.cred for c in facts]),
            (f"firewall udp/{port}", [c.fw for c in facts])]
    lblw = max([len(r[0]) for r in rows] + [0])
    colw = [max(len(heads[i]), *(len(r[1][i]) for r in rows)) for i in range(len(facts))]
    print(" " * lblw + "  " + "  ".join(f"{heads[i]:<{colw[i]}}" for i in range(len(facts))))
    for name, cells in rows:
        print(f"{name:<{lblw}}  " +
              "  ".join(f"{cells[i]:<{colw[i]}}" for i in range(len(cells))))
    print()

    # ---- pairwise verdicts --------------------------------------------------
    print(f"link viability  (direct-or-fail; ??? firewalls assumed open)")
    import itertools
    for x, y in itertools.combinations(facts, 2):
        print(f"  {x.label} ↔ {y.label}")
        if not default_policy(x.caps, y.caps):
            print("    ✗ no shared segment — they won't peer by design "
                  "(give them a common segment to change this)")
            continue
        seg = "anchor is reach-all *" if ("*" in x.segments or "*" in y.segments) \
            else "share " + repr(",".join(sorted(
                set(x.segments.split(",")) & set(y.segments.split(",")))) or "?")
        print(f"    segment: ✓ {seg}")

        x_dials_y = y.has_ep       # x can dial y iff y listens with an endpoint
        y_dials_x = x.has_ep
        print(f"    {x.label} → {y.label}: " + (f"dial {y.ep_str}" if x_dials_y
              else f"can't — {y.label} is outbound-only / advertises no endpoint"))
        print(f"    {y.label} → {x.label}: " + (f"dial {x.ep_str}" if y_dials_x
              else f"can't — {x.label} is outbound-only / advertises no endpoint"))
        if not (x_dials_y or y_dials_x):
            print("    ✗ no dialable direction — the link can't form "
                  "(both outbound-only)")
            continue

        self_col = x if x.is_self else (y if y.is_self else None)
        other = y if x.is_self else (x if y.is_self else None)
        if self_col is None:
            print("    live: (neither is this host) — should link per the "
                  "directory; run 'gw diagnose' from either for live confirmation")
            continue
        if other.hs is not None:
            print(f"    live: ● LINKED (handshake {other.hs}s ago) — path open; "
                  f"{other.label}'s firewall/router inferred OPEN")
            # A LINKED peer can still silently blackhole full-size packets (a
            # WG-over-cloud MTU mismatch): small pings pass, TLS handshakes hang.
            if os.geteuid() == 0:
                warn = _mtu_probe(cfg.wg_interface, other.addr,
                                  _iface_mtu(cfg.wg_interface))
                if warn:
                    print(f"    ⚠ {warn}")
            continue
        print("    live: ○ no handshake yet")
        self_fw = self_col.fw
        if self_col.has_ep:
            if self_fw.startswith("OPEN") or self_fw.startswith("open"):
                print(f"    ⚠ our host firewall {self_fw} for udp/{port} — so the "
                      f"block is NOT this host. If {other.label} can't reach us, "
                      f"suspect an UPSTREAM router/NAT not forwarding udp/{port} to "
                      f"this host, or {other.label}'s outbound/daemon.")
            elif self_fw.startswith("CLOSED"):
                print(f"    ⚠ our host firewall {self_fw} for udp/{port} — OPEN it "
                      f"(create/join printed the exact rule).")
            else:
                print(f"    firewall udp/{port} here: {self_fw}")
        if other.has_ep:
            print(f"    ⚠ we can dial {other.label} at {other.ep_str} but it isn't "
                  f"answering — check {other.label}'s host firewall + any upstream "
                  f"port-forward for udp/{port}, and that its daemon is up "
                  f"('gw diagnose' on {other.label} shows its host firewall).")
    return 0


# ---------------------------------------------------------------------------
# renew  (force an immediate credential renewal for THIS node)
# ---------------------------------------------------------------------------

def cmd_renew(args) -> int:
    """
    Force an immediate credential renewal for THIS node. Normally the daemon
    renews on its own (~half the credential TTL); this fetches a fresh credential
    from the anchor right now, re-publishes the record so peers stop serving the old
    expiry, and adopts any caps/segments the anchor changed in the meantime (so
    `gw set-caps` / `gw set-segments` take effect immediately instead of at the
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

    # Re-publish our record with the fresh credential, keeping our current seq+1,
    # endpoints — highest-seq-wins means peers adopt this promptly.
    directory = Directory.load(cfg.dir_cache_path)
    existing = directory.get(keys.id_pub_hex)
    seq = (existing.seq + 1) if existing else 1
    endpoints = list(existing.endpoints) if existing else list(cfg.endpoints)
    aliases = list(existing.aliases) if existing else _config_aliases(cfg)
    record = NodeRecord(
        id_pub=keys.id_pub_bytes, seq=seq, endpoints=endpoints,
        cred=cred, aliases=aliases,
    ).sign(keys.id_priv)
    directory.put(record)
    directory.save(cfg.dir_cache_path)
    try:
        push_record(cfg.root_url, record)
    except Exception as e:
        log.warning("published locally but push to anchor failed (will sync): %s", e)

    print(f"renewed — credential now expires {cred.exp:%Y-%m-%d %H:%M UTC}")

    # Adopt caps/segments if the anchor changed them since we last renewed. Editing
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
          "sudo systemctl restart greasewood@<name>  (or re-run sudo gw run)")
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

    now = dt.datetime.now(_UTC).replace(microsecond=0)
    (cfg.data_dir / "renew_after").write_text(now.isoformat())
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

    out = Path(args.out) if args.out else \
        cfg.data_dir / f"greasewood-anchor-backup-{cfg.hostname}.gwbk"
    passphrase = _backup_passphrase(confirm=True)
    # This passphrase is the ONLY thing protecting the CA key (and anchor id_priv)
    # at rest — a weak one undoes the whole backup. Warn, but don't block.
    if len(passphrase) < 12:
        print(f"⚠ warning: backup passphrase is short ({len(passphrase)} chars). "
              "This one secret guards your entire fleet's root key — use a long, "
              "high-entropy passphrase (a diceware phrase is ideal).")
    blob = bak.pack(files, passphrase)

    from .keys import atomic_write
    atomic_write(Path(out), blob)          # 0600, atomic: the fleet's root key
    node_count = sum(1 for n in files if n.startswith("nodes/"))
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

    blob = Path(args.archive).read_bytes()
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


# ---------------------------------------------------------------------------
# purge  (decommission or start-over — removes all local greasewood state)
# ---------------------------------------------------------------------------

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
    unit = _unit_for_config(cfg_path)

    if not args.yes:
        last = not [k for k, p in _memberships() if p.resolve() != cfg_path.resolve()]
        print(f"This will permanently remove this mesh from the host:")
        print(f"  service instance    : {unit} (stop + disable)")
        print(f"  WireGuard interface : {iface}")
        print(f"  data directory      : {data_dir}  (keys, CA, credentials)")
        print(f"  config file         : {cfg_path}")
        if last:
            print(f"  systemd template    : greasewood@.service (last mesh → "
                  f"full reset)")
        answer = input("Proceed? [y/N] ").strip().lower()
        if answer != "y":
            print("Aborted.")
            return 1

    removed = []
    failed = []

    # Stop the daemon FIRST. A daemon left running through a purge haunts the
    # next mesh on this host: it keeps its stale CA and keys in memory, keeps
    # serving door enrollments, and its mesh interface is gone — so every join
    # against the re-created anchor fails with a peer-install error.
    systemctl = shutil.which("systemctl")
    if systemctl:
        r = subprocess.run([systemctl, "is-active", "--quiet", unit],
                           capture_output=True)
        if r.returncode == 0:
            subprocess.run([systemctl, "disable", "--now", unit],
                           capture_output=True)
            removed.append(f"stopped {unit}")
    # A manual `gw run` can't be stopped safely from here — but it MUST not
    # survive the purge, so at least say so loudly.
    r = subprocess.run(["pgrep", "-f", "gw run"], capture_output=True, text=True)
    stray = [p for p in (r.stdout or "").split()
             if p.isdigit() and int(p) != os.getpid()]
    if r.returncode == 0 and stray:
        print(f"⚠ a greasewood daemon still appears to be running (pid "
              f"{', '.join(stray)}) — kill it before re-creating a mesh on this "
              f"host, or it will serve enrollments with stale keys and no "
              f"interface.")

    # Tear down WireGuard interface
    r = subprocess.run(["ip", "link", "show", iface], capture_output=True)
    if r.returncode == 0:
        subprocess.run(["ip", "link", "set", iface, "down"], capture_output=True)
        subprocess.run(["ip", "link", "delete", iface], capture_output=True)
        removed.append(f"interface {iface}")

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
    if systemctl:
        remaining = _memberships()   # cfg_path is already unlinked above
        if not remaining:
            tmpl = _UNIT_DIR / "greasewood@.service"
            if tmpl.exists():
                subprocess.run([systemctl, "disable", unit], capture_output=True)
                tmpl.unlink()
                subprocess.run([systemctl, "daemon-reload"], capture_output=True)
                removed.append("systemd template greasewood@.service (last mesh)")
        elif (_UNIT_DIR / "greasewood@.service").exists():
            print(f"note: kept greasewood@.service — {len(remaining)} other mesh"
                  f"{'es' if len(remaining) != 1 else ''} still use it "
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

def _systemd_available() -> bool:
    """True only when this host is actually running systemd — `systemctl` on
    PATH AND /run/systemd/system present (the canonical sd_booted() check). A
    container with systemctl installed but `sleep` as PID 1 returns False, so
    create/join fall back to the manual `gw run` line instead of crashing on a
    systemctl that can't reach a manager."""
    return shutil.which("systemctl") is not None and Path("/run/systemd/system").is_dir()


def _write_service_template(exec_path: "str | None" = None) -> "str | None":
    """Write the greasewood@ template unit (idempotent) and daemon-reload.
    Returns the systemctl path (None if this host has no systemd). Shared by
    create/join (auto by default) and re-used across memberships."""
    gw_exec = exec_path or shutil.which("gw") or os.path.realpath(sys.argv[0])
    _UNIT_DIR.mkdir(parents=True, exist_ok=True)
    (_UNIT_DIR / "greasewood@.service").write_text(_SERVICE_UNIT.format(exec=gw_exec))
    systemctl = shutil.which("systemctl")
    if systemctl:
        subprocess.run([systemctl, "daemon-reload"], check=False)
    return systemctl


def _wait_service_settled(systemctl: str, unit: str, wait_secs: float = 6.0) -> str:
    """Wait for `unit` to reach 'active' and STAY there briefly; return the
    final is-active state ('active', 'activating', 'failed', ...). A unit that
    execs and crashes within a couple of seconds flaps active→activating
    (auto-restart) — the settle re-check catches exactly that."""
    def _state() -> str:
        r = subprocess.run([systemctl, "is-active", unit],
                           capture_output=True, text=True)
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


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main(argv=None) -> int:
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
            "  gw watch --snapshot · config · firewall · cert-status · cert-profiles\n"
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
    sub = p.add_subparsers(dest="cmd", required=True)

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
                         "segment:* to reach every segment), e.g. 'tls'")
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
    sp.add_argument("--segments", default=None, metavar="S1,S2",
                    help="segments the invited node belongs to (comma-sep). The "
                         "anchor decides this — the joiner cannot. A node peers only "
                         "with nodes sharing a segment. Omitted → the anchor's "
                         "[anchor] default_segments (ships as 'mesh', the flat default "
                         "pool). Naming other segments isolates the node; list "
                         "several to bridge them.")
    sp.add_argument("--caps", default=None,
                    help="ability caps granted to the invited node (comma-sep), "
                         "e.g. 'tls'. Omitted → the anchor's [anchor] default_caps "
                         "(ships as 'tls'). Segmentation is set with --segments.")
    sp.add_argument("--endpoint", default=None, metavar="ADDR",
                    help="underlay IPv6 address to embed in token (auto-detected if omitted)")
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
    sp.add_argument("--by-segment", action="store_true",
                    help="group into one table per segment (a node appears under "
                         "each of its segments; segment:* nodes appear under all)")
    sp.add_argument("--interval", type=float, default=2.0, metavar="SECS",
                    help="live refresh interval (default 2s; min 1s)")
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

    # firewall — print the recommended posture (a suggestion; nothing changes)
    sp = sub.add_parser("firewall",
                        help="print the recommended firewall ruleset (a SUGGESTION "
                             "— greasewood never changes your firewall). With sudo "
                             "also flags anything that looks blocked.")
    sp.set_defaults(fn=cmd_firewall)

    # diagnose
    sp = sub.add_parser(
        "diagnose",
        help="pairwise link diagnosis: compare up to two nodes + the anchor side "
             "by side and explain whether a tunnel can form (segments, "
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
                                 "'segment:prod,tls' (replaces the node's current caps)")
    sp.set_defaults(fn=cmd_set_caps)

    # set-segments (anchor) — change only a node's segments
    sp = sub.add_parser("set-segments",
                        help="[sudo, anchor] change an enrolled node's segments "
                             "(effective next renewal)")
    sp.add_argument("node", help="node hostname (or its 64-char id_pub hex)")
    sp.add_argument("segments", help="comma-separated segments, e.g. 'prod,web' "
                                     "(replaces segment tags; keeps tls; empty = mesh default)")
    sp.set_defaults(fn=cmd_set_segments)

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
                             "node (applies an anchor-side set-caps/set-segments now, "
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
                        help="[sudo, anchor] [anchor] write an encrypted backup of the CA key + "
                             "node registry + revoke list (passphrase via prompt "
                             "or $GW_BACKUP_PASSPHRASE)")
    sp.add_argument("--out", default=None, metavar="PATH",
                    help="output file (default: <data_dir>/greasewood-anchor-backup-"
                         "<hostname>.gwbk)")
    sp.set_defaults(fn=cmd_anchor_backup)

    # anchor-restore
    sp = sub.add_parser("anchor-restore",
                        help="[sudo] restore an anchor backup into a data dir (stand "
                             "up a replacement anchor on the same CA key — not a re-root)")
    sp.add_argument("archive", help="the .gwbk backup file")
    sp.add_argument("--data-dir", default="/var/lib/greasewood",
                    help="where to restore (default: /var/lib/greasewood)")
    sp.add_argument("--force", action="store_true",
                    help="overwrite an existing ca.key in the target dir")
    sp.set_defaults(fn=cmd_anchor_restore)

    args = p.parse_args(argv)
    _setup_logging(args.verbose)
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
