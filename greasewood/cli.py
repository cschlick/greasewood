"""
gw — CLI entry point.

Enrollment is door-based: a transient WireGuard tunnel, no SSH, no HTTP on the
underlay.

  On the hub:
    gw create          # one-shot: CA, door key, routing, self-credential
    gw run                # start the daemon (serves control plane + door)
    gw invite             # open a 15-min window, print a single-use join token

  On the new node:
    gw join <token>       # enroll over the door, then:
    gw run                # join the mesh

Other subcommands:
  revoke <id_pub>     Add a node to the revoke list (on the hub).
  status              Show local node and directory state.
  purge               Remove all local greasewood state.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import logging
import os
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

_UTC = dt.timezone.utc
log = logging.getLogger("greasewood")


def _setup_logging(verbose: bool) -> None:
    from .audit import _UTCFormatter
    level = logging.DEBUG if verbose else logging.INFO
    handler = logging.StreamHandler()
    # Full ISO-8601 UTC timestamps: a command trail spanning days must be
    # unambiguous (the old format was time-only).
    handler.setFormatter(_UTCFormatter(
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


# systemd units, embedded so `gw install-service` works from a pip-only install
# (no repo checkout needed). Kept in sync with systemd/ in the repo.
_SERVICE_UNIT = """\
[Unit]
Description=greasewood mesh daemon
Documentation=https://gitlab.com/cschlick/greasewood
After=network-online.target
Wants=network-online.target
# Only run once this node is configured (create / join writes the config);
# greasewood.path starts us the moment it appears.
ConditionPathExists=/etc/greasewood.toml

[Service]
Type=simple
# gw run creates WireGuard interfaces and edits routing → runs as root.
ExecStart={exec} run
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

_PATH_UNIT = """\
[Unit]
Description=Watch for greasewood configuration and start the daemon
Documentation=https://gitlab.com/cschlick/greasewood

[Path]
# Start greasewood.service once /etc/greasewood.toml exists. After a
# config-changing re-join: systemctl restart greasewood.
PathExists=/etc/greasewood.toml
Unit=greasewood.service

[Install]
WantedBy=paths.target
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
    import json as _json
    import re as _re
    have = set(cfg.aliases)
    new = [l for l in labels if l not in have]
    if not new:
        return []
    merged = _json.dumps(sorted(have | set(new)))
    text = cfg_path.read_text()
    line = f"aliases = {merged}"
    if _re.search(r"(?m)^\s*aliases\s*=", text):
        text = _re.sub(r"(?m)^\s*aliases\s*=.*$", line, text, count=1)
    elif _re.search(r"(?m)^\[network\]\s*$", text):
        text = _re.sub(r"(?m)^(\[network\]\s*)$", r"\1\n" + line, text, count=1)
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


def _print_firewall_help(listen_port: int = 51900, control_port: int = 51902) -> None:
    """
    Print (never apply) the recommended firewall posture. greasewood binds its
    control/enroll planes only to the overlay + loopback, so nothing it runs is
    exposed on the underlay regardless of firewall. On a default-drop host you
    still allow the few things below to *reach* those sockets.

    Recommended: apply the SAME rules on EVERY node, not just the current hub.
    Since any node can be promoted to hub (gw hub-promote), a uniform ruleset
    means a hub handover needs no firewall change anywhere. A rule allowing a
    port nothing is bound to is harmless — the kernel just refuses the
    connection until that node actually becomes a hub and binds it.
    """
    from .door import DOOR_PORT, DOOR_IFACE, ENROLL_PORT
    print("Firewall (greasewood never edits it). Recommended posture — the SAME")
    print("rules on every node, so any node can become the hub with no firewall")
    print("change. On a default-drop host, allow (nftables):")
    print(f"  udp dport {{ {listen_port}, {DOOR_PORT} }} accept            # WireGuard (underlay)")
    print(f"  iifname \"lo\" accept                          # hub talks to itself")
    print(f"  iifname \"gw-mesh\" tcp dport {control_port} accept        # control plane (when hub)")
    print(f"  iifname \"{DOOR_IFACE}\" tcp dport {ENROLL_PORT} accept    # enrollment (when hub)")


# ---------------------------------------------------------------------------
# create  (one-shot hub bootstrap: CA + door key + routing + self-credential)
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
    import ipaddress
    import subprocess

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
    import ipaddress
    import subprocess
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
    import subprocess
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
    import json as json_mod
    from .keys import CAKeys, NodeKeys
    from .ca import CA
    from .wire import NodeRecord
    from .directory import Directory
    from .config import _parse_duration
    from .door import load_or_generate_door_key, door_pub_bytes_from_key
    from . import wg as wgmod

    cfg_path = Path(args.config)
    data_dir = Path(args.data_dir)
    ca_key_path = data_dir / "ca.key"
    # The role is "hub"; the hostname is just this machine's name by default
    # (short form, no domain), overridable with --hostname.
    import socket
    from .keys import set_overlay_prefix, parse_overlay_prefix
    hostname = args.hostname or socket.gethostname().split(".")[0] or "hub"
    listen_port = args.listen_port
    control_port = args.control_port
    # The hub must reach every segment (it serves the control plane + door), so
    # it carries the reach-all wildcard segment. Plus any ability caps (--caps).
    caps = ["segment:*"]
    if args.caps:
        caps += [c.strip() for c in args.caps.split(",") if c.strip()]
    ttl = _parse_duration(args.credential_ttl)
    interface = args.interface
    overlay_prefix = args.overlay_prefix
    # The mesh's ONE name domain, everywhere, forever (changed only by a
    # deliberate fleet-wide set-domain). Rides in every join token.
    mesh_domain = args.mesh_domain or f"{args.name}.internal"
    # Activate this fleet's overlay /64 before we derive the hub's own address.
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
        # directory.json, *.pub) that root-free commands like `gw status` read;
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

    endpoint_line = f'\nendpoints = {json_mod.dumps(endpoints)}' if endpoints else ""
    hosts_sync = "true" if getattr(args, "hosts_sync", True) else "false"
    cfg_path.parent.mkdir(parents=True, exist_ok=True)
    cfg_path.write_text(f"""[node]
hostname = "{hostname}"
data_dir = "{data_dir}"
role = "hub"
inbound = "yes"
caps = {json_mod.dumps(caps)}{endpoint_line}

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

[hub]
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
        inbound="yes",
        cred=cred,
    ).sign(node_keys.id_priv)
    directory.put(record)
    directory.save(dir_cache)

    # The control plane binds the OVERLAY address (+loopback), so that's the URL
    # nodes use — not the underlay endpoint.
    control_url = f"http://[{node_keys.addr}]:{control_port}"

    print(f"\nHub setup complete.")
    print(f"  overlay addr : {node_keys.addr}")
    print(f"  CA pub key   : {ca_pub_hex}")
    print(f"  credential   : expires {cred.exp:%Y-%m-%d %H:%M UTC}")
    print()
    _print_daemon_guidance("then invite nodes to enroll them")
    print()
    print(f"Enroll a new node:")
    print(f"  TOKEN=$(sudo gw invite)          # on this machine")
    print(f"  sudo gw join \"$TOKEN\" --hostname <name>   # on the new machine")
    print()
    _print_firewall_help(listen_port, control_port)
    print()
    from . import firewall as _fw
    _fw.check(_fw.hub_rules(listen_port, control_port), log)
    return 0


# ---------------------------------------------------------------------------
# invite  (hub — generate a join token and open a door window)
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
    import datetime as dt_mod
    import json as json_mod
    from .config import load_config
    from .door import (
        generate_seed, derive_door_params, encode_token,
        load_or_generate_door_key, door_pub_bytes_from_key,
        active_window_expiry,
    )
    from . import wg as wgmod

    cfg = load_config(Path(args.config))
    if cfg.role != "hub":
        sys.exit("gw invite must be run on the hub node (role = hub)")
    if cfg.ca_key_file is None:
        sys.exit("invite requires ca_key_file in [hub]")

    # Preflight: a token is only redeemable if the daemon is up (it hosts the
    # enroll server) with its mesh interface present (it installs the joiner as
    # a peer). Catch both NOW, when the operator can act — not minutes later as
    # a cryptic rejection on the joining node.
    if not wgmod.interface_exists(cfg.wg_interface):
        sys.exit(f"the hub's mesh interface {cfg.wg_interface!r} doesn't exist — "
                 f"the daemon isn't running (or the interface was deleted under "
                 f"it). A joiner would be rejected at enrollment. Start the "
                 f"daemon first: sudo systemctl start greasewood   (or: sudo gw run)\n"
                 f"If you already started it and this persists, it's crashing on "
                 f"startup — look at: journalctl -u greasewood -n 20")
    import urllib.request as _url
    try:
        _url.urlopen(f"http://[::1]:{_control_port(cfg)}/directory", timeout=3)
    except Exception:
        sys.exit(f"the hub daemon isn't answering on loopback (port "
                 f"{_control_port(cfg)}) — it hosts the enroll server, so this "
                 f"token could never be redeemed. Start it first: "
                 f"sudo systemctl start greasewood   (or: sudo gw run)")

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
    hub_door_pub = door_pub_bytes_from_key(door_key_raw)
    import base64
    door_key_b64 = base64.b64encode(door_key_raw).decode()

    from .keys import CAKeys
    ca_keys = CAKeys.load(cfg.ca_key_file, _get_passphrase(cfg.ca_key_passphrase_env))

    # Hub underlay host(s) for the token (bare addresses; the joiner adds the
    # door port). Carry v6 and/or v4 so a joiner reaches the hub over whichever
    # family it has — stored comma-separated in the token's single host field
    # (a v6 literal has colons but never commas, so the split is unambiguous).
    if args.endpoint:
        hub_hosts = [args.endpoint]
    else:
        hub_hosts = []
        v6 = _detect_public_ipv6()
        if v6:
            hub_hosts.append(v6)
        v4 = _detect_public_ipv4()
        if v4:
            hub_hosts.append(v4)
        if not hub_hosts:
            sys.exit("could not detect a public address; use --endpoint <addr>")
    endpoint = ",".join(hub_hosts)

    window = cfg.door_window

    # The hub decides caps + segments HERE and issues them to whoever redeems the
    # token — the joiner does not choose (no self-assertion). They're stored in
    # the door window; the enroll server issues from them, ignoring the joiner's.
    #   segments (segment:<name>) control who-talks-to-whom.
    #   --caps grants abilities, e.g. tls.
    # When a flag is omitted, fall back to the hub's configured defaults for new
    # nodes ([hub] default_segments / default_caps, read fresh each invite — so
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
    # --hostname pins the name: the hub fixes it at enrollment (the joiner's
    # requested name is ignored) and marks the credential `hostname-pinned` so the
    # node can't rename itself afterward. Without it, the node names itself at
    # join and may `gw rename` later (today's behavior).
    pinned_hostname = args.hostname
    if pinned_hostname:
        # The hub is choosing the name, so it verifies uniqueness NOW — a pinned
        # name is guaranteed free before the token goes out, so it can't collide
        # at enrollment (the joiner can't fix a name it didn't pick). Unpinned
        # names are still checked at enroll, where the node can retry a new one.
        from .ca import CA as _CA
        owner = _CA(ca_keys, data_dir).hostname_owner(pinned_hostname)
        if owner is not None:
            sys.exit(
                f"hostname {pinned_hostname!r} is already in use (node {owner[:16]}…). "
                "Free it first (revoke + remove the old node on the hub) or pin a "
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

    # Bring up the hub's door WG interface on the configured door port
    door_key_path = data_dir / "door.key"
    from . import audit
    audit.attach_file(data_dir / "audit.log")   # one-shot door commands → the trail
    with audit.context("invite: bring up hub door interface"):
        wgmod.ensure_hub_door_interface(door_key_path, params.guest_pub_b64,
                                        params.psk_b64, cfg.door_port)

    # Write window file so the running gw-run daemon starts the enroll server.
    window_path = data_dir / "door_window.json"
    if getattr(args, "standing", False):
        # STANDING door: no expiry; serves any number of enrollments until
        # `gw close-door` (or a --supersede invite). The guest key + PSK are
        # persisted (0600, same posture as door.key) so the daemon can re-erect
        # the door interface after a reboot — the window outlives the kernel
        # state. Every join is still the full one-node ceremony: fresh identity,
        # CA-signed credential, blackhole isolation, audit trail.
        window_path.write_text(json_mod.dumps({
            "v": 1,
            "standing": True,
            "caps": caps,
            "hostname": None,          # standing doors can't pin one name
            "guest_pub": params.guest_pub_b64,
            "psk": params.psk_b64,
        }))
        os.chmod(window_path, 0o600)   # it now carries key material
        log.info("STANDING door opened — this token enrolls any number of "
                 "nodes until: sudo gw close-door")
    else:
        expires = dt_mod.datetime.now(dt_mod.timezone.utc) + window
        window_path.write_text(json_mod.dumps({
            "v": 1,
            "expires": expires.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "caps": caps,
            "hostname": pinned_hostname,   # None → joiner names itself (unpinned)
        }))

    token = encode_token(hub_door_pub, ca_keys.ca_pub_bytes, endpoint, seed,
                         cfg.door_port, mesh_domain=cfg.mesh_domain)
    print(token)
    return 0


def cmd_close_door(args) -> int:
    """[hub] Close the current door window — the issued token (standing or
    single-use) is permanently invalid from this moment: the guest key and PSK
    live only in the window, and seeds are never reused, so nothing can ever
    handshake against it again. Enrolled nodes are untouched (their credentials
    come from the CA, not the door). This is the revocation half of standing-
    token rotation; the next `gw invite --standing` mints the new epoch."""
    from .config import load_config
    from . import door as doormod
    from . import wg as wgmod

    _require_root("close-door", "it removes the hub's door window and interface")
    cfg = load_config(Path(args.config))
    if cfg.role != "hub":
        sys.exit("gw close-door must be run on the hub (role = hub)")

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

# Membership slots: the default mesh is slot 1 (unsuffixed: /etc/greasewood.toml,
# /var/lib/greasewood, gw-mesh, 51900, gw.internal); every further mesh this
# host joins auto-provisions the next slot N (greasewoodN.toml, greasewoodN,
# gw-meshN, 51900+10*(N-1), gwN.internal). All of it remains overridable with
# the explicit join flags — the slots are just the "I don't care what it's
# called" default.

def _slot_paths(n: int, etc: "Path" = Path("/etc"),
                var: "Path" = Path("/var/lib")) -> dict:
    """The derived names for membership slot `n` (1 = the unsuffixed default)."""
    suf = "" if n == 1 else str(n)
    return {
        "config": etc / f"greasewood{suf}.toml",
        "data_dir": var / f"greasewood{suf}",
        "interface": f"gw-mesh{suf}",
        "listen_port": 51900 + 10 * (n - 1),
        "mesh_domain": f"gw{suf}.internal",
    }


def _mesh_slots(etc: "Path" = Path("/etc")) -> "list[tuple[int, Path]]":
    """Existing membership configs on this host as (slot, config_path)."""
    import re as _re
    out = []
    if (etc / "greasewood.toml").exists():
        out.append((1, etc / "greasewood.toml"))
    for p in etc.glob("greasewood[0-9]*.toml"):
        m = _re.fullmatch(r"greasewood(\d+)\.toml", p.name)
        if m and int(m.group(1)) >= 2:
            out.append((int(m.group(1)), p))
    return sorted(out)


def _slot_for_ca(ca_pub_hex: str, etc: "Path" = Path("/etc")) -> "int | None":
    """The membership slot already trusting this CA, or None. This is how a
    token is routed: its CA pub identifies WHICH mesh it belongs to, so a token
    for a mesh we're already on refreshes that membership (even after a re-root
    — trusted_pubs carries old+new during migration), and an unknown CA means a
    genuinely new mesh."""
    from .config import load_config
    for n, p in _mesh_slots(etc):
        try:
            if ca_pub_hex in load_config(p).ca_pubs:
                return n
        except Exception:
            continue
    return None


def _next_free_slot(etc: "Path" = Path("/etc")) -> int:
    """First unused slot ≥ 2 (slot 1 is the default mesh; callers only allocate
    a new slot when slot 1 is already taken by a different mesh)."""
    used = {n for n, _ in _mesh_slots(etc)}
    n = 2
    while n in used:
        n += 1
    return n


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
    import ipaddress
    from .config import load_config
    try:
        mine = ipaddress.ip_network(f"{my_prefix}/64")
    except ValueError:
        return False
    for n, p in _mesh_slots(etc):
        if p.resolve() == Path(cfg_path).resolve():
            continue
        try:
            theirs = ipaddress.ip_network(f"{load_config(p).overlay_prefix}/64")
        except Exception:
            continue
        if theirs == mine:
            log.warning(
                "this mesh uses the SAME overlay /64 (%s) as membership #%d "
                "(%s). Everything still works — greasewood routes only "
                "identity-derived /128s, never the /64 — but the prefix no "
                "longer identifies a mesh on this host: any firewall rule or "
                "script scoped to %s now matches BOTH meshes, and addresses "
                "are indistinguishable by eye. For legibility, create meshes "
                "with distinct `create --overlay-prefix`.",
                mine, n, p, mine)
            return True
    return False


def _slot_service(cfg_path: "Path", slot: int) -> str:
    """Make membership slot N run as its own systemd service (greasewoodN),
    mirroring however slot 1 is managed: if the base greasewood.service is
    installed, write the same unit pinned to this slot's config and enable it
    now + at boot. Returns 'active' (already running), 'installed' (created and
    started), or 'manual' (no systemd management here — caller prints gw run)."""
    import shutil
    import subprocess
    unit = f"greasewood{slot}.service"
    systemctl = shutil.which("systemctl")
    if not systemctl or not (_UNIT_DIR / "greasewood.service").exists():
        return "manual"
    r = subprocess.run([systemctl, "is-active", "--quiet", unit],
                       capture_output=True)
    if r.returncode == 0:
        return "active"
    gw_exec = shutil.which("gw") or os.path.realpath(sys.argv[0])
    text = (_SERVICE_UNIT.format(exec=gw_exec)
            .replace("/etc/greasewood.toml", str(cfg_path))
            .replace(f"ExecStart={gw_exec} run",
                     f"ExecStart={gw_exec} -c {cfg_path} run")
            .replace("Description=greasewood mesh daemon",
                     f"Description=greasewood mesh daemon (membership #{slot})"))
    (_UNIT_DIR / unit).write_text(text)
    subprocess.run([systemctl, "daemon-reload"], check=True)
    subprocess.run([systemctl, "enable", "--now", unit], check=True)
    return "installed"


def cmd_join(args) -> int:
    _require_root("join")
    import json as json_mod
    import socket
    import struct
    import time
    from .keys import NodeKeys
    from .wire import Credential, NodeRecord
    from .directory import Directory
    from .door import decode_token, derive_door_params
    from .config import load_config
    from . import wg as wgmod
    import base64

    # Token comes from the positional arg, or from stdin when it's "-". Either
    # way we tolerantly extract the gw1.… line, so `gw invite | ssh B gw join -`
    # works even without `invite -q`.
    token = _extract_token(sys.stdin.read() if args.token == "-" else args.token)

    # Decode token → hub_door_pub, ca_pub, hub_host(s), seed, door_port.
    # Decoded FIRST because the CA pub routes the join (see below).
    try:
        (hub_door_pub_bytes, ca_pub_bytes, hub_host, seed, door_port,
         token_domain) = decode_token(token)
    except ValueError as e:
        sys.exit(f"invalid token: {e}")
    ca_pub_hex = ca_pub_bytes.hex()

    cfg_path = Path(args.config)
    data_dir = Path(args.data_dir)
    listen_port = args.listen_port

    # Auto-slotting: when every location knob is at its default, route the join
    # by the token's CA. A token for a mesh this host is already on refreshes
    # that membership; a token for a NEW mesh (unknown CA, default slot already
    # taken) auto-provisions the next slot — greasewood2.toml,
    # /var/lib/greasewood2, gw-mesh2, port 51910, names under gw2.internal — so
    # joining another mesh is just `gw join <token>`. Any explicit flag opts
    # out of the whole mechanism.
    slot_n = None            # ≥2 when this join targets a numbered membership
    auto = (args.config == "/etc/greasewood.toml"
            and args.data_dir == "/var/lib/greasewood"
            and args.listen_port == 51900
            and args.interface is None)
    if auto:
        known = _slot_for_ca(ca_pub_hex)
        if known is not None and known != 1:
            # Re-join of a mesh living in a numbered slot: use ITS config as-is
            # (the slot's real values — possibly customized — win, not the
            # naming formula; `prior` below then supplies interface/domain).
            cfg_path = _slot_paths(known)["config"]
            existing = load_config(cfg_path)
            data_dir, listen_port = existing.data_dir, existing.listen_port
            slot_n = known
            log.info("token's CA matches mesh membership #%d — refreshing it "
                     "(config %s)", known, cfg_path)
        elif known is None and cfg_path.exists():
            # Unknown CA and the default slot is taken: a genuinely new mesh.
            n = _next_free_slot()
            sp = _slot_paths(n)
            cfg_path, data_dir = sp["config"], sp["data_dir"]
            listen_port = sp["listen_port"]
            args.interface = sp["interface"]
            slot_n = n
            log.info(
                "token is for a mesh this host isn't on — auto-provisioning "
                "membership #%d: config %s, data %s, interface %s, UDP %d "
                "(every value overridable with join flags)",
                n, cfg_path, data_dir, args.interface, listen_port)

    # HARD domain-collision refusal, BEFORE the door dance (so a refusal never
    # burns the invite): a mesh has ONE domain everywhere, and a node cannot
    # bridge two meshes that share one — no alias, no flag, no exception. The
    # membership being refreshed (same config path) doesn't count against itself.
    if token_domain:
        for _n, _p in _mesh_slots():
            if _p.resolve() == cfg_path.resolve():
                continue
            try:
                if load_config(_p).mesh_domain == token_domain:
                    sys.exit(
                        f"this mesh's domain {token_domain!r} is already used by "
                        f"membership #{_n} ({_p}) — a node cannot bridge two "
                        f"meshes with the same domain. Rename one of them on its "
                        f"hub (gw set-domain <new-name>) and re-run this join. "
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

    # Caps/segments are NOT chosen here. The hub decides them at `gw invite` and
    # binds them into the credential issued over the door; we read them back
    # from that credential below and write them to config. (No self-assertion:
    # whatever a joiner might request is ignored by the hub.)
    caps: list[str] = []

    # inbound: "yes" (reachable, advertise endpoint) or "no" (outbound-only,
    # suppress endpoint — peers won't dial it; it dials them).
    if args.inbound is not None:
        node_inbound = args.inbound
    elif prior and getattr(prior, "inbound", None):
        node_inbound = prior.inbound
    else:
        node_inbound = "yes"

    # Endpoint(s) = where other nodes dial this one for a direct tunnel. If not
    # given, best-effort detect a public v6 and/or v4. A node with no endpoint
    # can still reach the hub (it initiates outbound), but peers can't dial it,
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
            "initiating outbound (e.g. to the hub); other nodes cannot dial it, "
            "so direct node-to-node links may not form. Pass --endpoint <addr> "
            "if this node is publicly reachable.")

    # (token was decoded up top — its CA pub routed the join to a slot)
    # The token may carry several hub underlay hosts (v4 and/or v6, comma-sep);
    # dial one this node can actually reach.
    hub_host = _pick_reachable_host(hub_host.split(","))

    hub_door_pub_b64 = base64.b64encode(hub_door_pub_bytes).decode()

    # Derive door params from seed (same derivation the hub ran at invite time)
    params = derive_door_params(seed)
    log.info("guest_pub: ...%s", params.guest_pub_b64[-8:])

    # Generate this node's permanent keypairs
    data_dir.mkdir(parents=True, exist_ok=True)
    try:
        # 0755, not 0700: the dir holds world-readable public files (id_pub.hex,
        # directory.json, *.pub) that root-free commands like `gw status` read;
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
            "hostname=%s; caps assigned by the hub)", node_keys.addr, hostname,
        )
    log.info("overlay addr: %s", node_keys.addr)

    # Bring up the local door interface (door port comes from the token)
    from . import audit
    audit.attach_file(data_dir / "audit.log")   # one-shot door commands → the trail
    with audit.context("join: bring up node door interface"):
        wgmod.ensure_node_door_interface(
            params.guest_priv_bytes, hub_door_pub_b64, params.psk_b64, hub_host,
            door_port,
        )

    # Connect to hub's enroll daemon via the door tunnel (retry for WG handshake)
    from .door import HUB_DOOR_IP, ENROLL_PORT
    log.info("connecting to enroll daemon at [%s]:%d ...", HUB_DOOR_IP, ENROLL_PORT)
    conn: socket.socket | None = None
    for attempt in range(15):
        try:
            s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((HUB_DOOR_IP, ENROLL_PORT))
            conn = s
            break
        except OSError:
            if attempt < 14:
                time.sleep(1)
    if conn is None:
        wgmod.destroy_interface("gw-door")
        sys.exit(f"could not connect to enroll daemon at [{HUB_DOOR_IP}]:{ENROLL_PORT} — is the hub daemon running and the token valid?")

    # The 5s above was only for *reaching* the daemon. The exchange itself (the
    # hub signs a credential, runs `wg set peer`, merges our record, and replies)
    # can take much longer when the hub is under load — e.g. enrolling a burst of
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
    req_body = json_mod.dumps(req, separators=(",", ":")).encode()

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
        return json_mod.loads(raw)

    def _send_framed(sock, obj):
        b = json_mod.dumps(obj, separators=(",", ":")).encode()
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
            # The hub keeps the door open for a few attempts — retry on the SAME
            # token (it rebuilds the door tunnel and reconnects).
            plural = "s" if left != 1 else ""
            msg += (f"\n{left} attempt{plural} left in this window — fix it and retry:\n"
                    f"  sudo gw join <token> --hostname <unique-name>")
        else:
            msg += ("\nNo attempts left — run 'sudo gw invite' on the hub for a "
                    "fresh token.")
        sys.exit(msg)

    # Verify and install the credential (gw-door still up — needed for door publish below)
    cred = Credential.from_dict(resp["credential"])
    try:
        cred.verify([ca_pub_bytes])
    except Exception as e:
        wgmod.destroy_interface("gw-door")
        sys.exit(f"credential verification failed: {e}")

    # The hub decided our name + caps; adopt them from the issued credential
    # (the authoritative record of what we were granted) so config matches. For
    # a hub-pinned hostname, cred.hostname differs from what we requested.
    caps = list(cred.caps)
    if cred.hostname != hostname:
        log.info("hub assigned hostname %r (requested %r)", cred.hostname, hostname)
    hostname = cred.hostname
    log.info("hub assigned caps=%s", caps)
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

    # Build directory with our record + hub's record
    dir_cache = data_dir / "directory.json"
    directory = Directory.load(dir_cache)

    # Hub's record — pre-seeds so the daemon knows the hub immediately. The hub
    # tells us its control port (it's configurable) so we build the right URL.
    hub_control_port = int(resp.get("control_port", 51902))
    hub_overlay_url = ""
    if resp.get("hub_record"):
        hub_rec = NodeRecord.from_dict(resp["hub_record"])
        try:
            hub_rec.verify([ca_pub_bytes], set())
            directory.put(hub_rec)
            log.info("pre-seeded hub record (hostname=%s)", hub_rec.hostname)
            hub_overlay_url = f"http://[{hub_rec.cred.addr}]:{hub_control_port}"
        except Exception as e:
            log.warning("hub record verify failed: %s", e)

    # Our own record. Outbound-only nodes don't advertise an endpoint, so peers
    # don't waste handshakes dialing an address they can't reach.
    existing = directory.get(node_keys.id_pub_hex)
    seq = (existing.seq + 1) if existing else 1
    adv_endpoints = list(node_endpoints) if node_inbound != "no" else []
    record = NodeRecord(
        id_pub=node_keys.id_pub_bytes,
        seq=seq,
        endpoints=adv_endpoints,
        inbound=node_inbound,
        cred=cred,
    ).sign(node_keys.id_priv)
    directory.put(record)
    directory.save(dir_cache)

    # Send our signed record back over the SAME door connection; the hub merges
    # it into its directory so the ReconcileLoop keeps the peer it just installed
    # (the bootstrap chicken-and-egg). Doing this on the door tunnel — rather
    # than a separate POST /publish — means the control plane never has to listen
    # on the door interface.
    try:
        _send_framed(conn, {"v": 1, "record": record.to_dict()})
        ack = _recv_framed(conn)
        if ack.get("ok"):
            log.info("published record to hub via door tunnel")
        else:
            log.warning("hub rejected door publish: %s", ack.get("error"))
    except Exception as e:
        log.warning("door publish failed (hub learns this node on next sync): %s", e)
    finally:
        try:
            conn.close()
        except Exception:
            pass

    # Tear down the door interface
    wgmod.destroy_interface("gw-door")

    endpoint_line = f'\nendpoints = {json_mod.dumps(node_endpoints)}' if node_endpoints else ""
    seeds_list = json_mod.dumps([hub_overlay_url]) if hub_overlay_url else "[]"
    root_url_val = json_mod.dumps(hub_overlay_url) if hub_overlay_url else '""'
    # hosts sync: on by default; --no-hosts-sync turns it off; a re-join keeps a
    # previously-disabled setting.
    if getattr(args, "hosts_sync", None) is False:      # --no-hosts-sync given
        hosts_sync = "false"
    elif prior is not None and not prior.hosts_sync:    # re-join kept disabled
        hosts_sync = "false"
    else:
        hosts_sync = "true"
    # Name domain: the mesh has exactly ONE, carried in the token (declared at
    # its hub's create / set-domain). The joiner adopts it, period — a collision
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
inbound = "{node_inbound}"
caps = {json_mod.dumps(caps)}{endpoint_line}

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
    if hub_overlay_url:
        print(f"  hub control  : {hub_overlay_url}")
    print()
    if slot_n and slot_n != 1:
        state = _slot_service(cfg_path, slot_n)
        if state == "installed":
            print(f"This membership runs as its own service: greasewood{slot_n} "
                  f"(started; also starts at boot).")
            print(f"  status: systemctl status greasewood{slot_n}   "
                  f"mesh view: gw -c {cfg_path} status")
        elif state == "active":
            print(f"greasewood{slot_n}.service is already running — restart it "
                  f"to pick up the refreshed config:")
            print(f"  sudo systemctl restart greasewood{slot_n}")
        else:
            print("Start this membership's daemon:")
            print(f"  sudo gw -c {cfg_path} run")
            print("  (tip: 'sudo gw install-service' + re-join makes memberships "
                  "manage themselves)")
    else:
        _print_daemon_guidance()
    print()
    from . import firewall as _fw
    if node_inbound == "no":
        log.warning(
            "firewall: inbound=no — outbound-only. No greasewood inbound ports "
            "are needed (it dials peers + the hub's door outbound); just keep "
            "your base 'ct state established,related accept' rule for replies. "
            "Note: this node can only pair with inbound-reachable nodes, not "
            "with other outbound-only nodes, and cannot be promoted to hub "
            "without switching to inbound (gw set-inbound yes)."
        )
    else:
        _print_firewall_help(listen_port)
        print()
        _fw.check(_fw.node_rules(listen_port, node_inbound), log)
    return 0



# ---------------------------------------------------------------------------
# revoke
# ---------------------------------------------------------------------------

def cmd_revoke(args) -> int:
    # Same hub-only guard as set-caps/set-segments: explicit role check first,
    # then ca_key_file + CA load — so a non-hub fails with one clear message and
    # never reaches a traceback.
    cfg, ca = _load_hub_ca(args, "revoke")

    try:
        id_pub_bytes = bytes.fromhex(args.id_pub_hex)
    except ValueError:
        sys.exit("id_pub_hex must be a 64-character hex string")

    freed = ca.add_revoke(id_pub_bytes)
    print(f"revoked: {args.id_pub_hex}")
    if freed:
        print("Its hostname is now free for reuse by a different node.")
    print("Takes effect live — the running daemon refuses its renew/publish and "
          "evicts it on the next reconcile; its credential also expires naturally.")
    return 0


# ---------------------------------------------------------------------------
# set-caps / set-segments — change an enrolled node's caps on the hub
# ---------------------------------------------------------------------------

def _load_hub_ca(args, cmd: str):
    """Shared setup for hub-side registry commands: load config + CA."""
    from .config import load_config
    from .keys import CAKeys
    from .ca import CA
    # Gate up front: the registry (nodes/*.json) and CA key are root-owned, and
    # these commands write them. Without this, a non-root run fails partway with
    # whatever file access breaks first — historically misread as the node not
    # existing at all.
    _require_root(cmd, "it reads and writes the hub's registry and CA key")
    cfg = load_config(Path(args.config))
    if cfg.role != "hub":
        sys.exit(f"gw {cmd} must be run on the hub (role = hub)")
    if cfg.ca_key_file is None:
        sys.exit(f"{cmd} requires ca_key_file in [hub]")
    ca_keys = CAKeys.load(cfg.ca_key_file, _get_passphrase(cfg.ca_key_passphrase_env))
    return cfg, CA(ca_keys, cfg.data_dir)


def _resolve_node(ca, cfg, handle: str):
    """Resolve a node handle — a hostname (with or without the `.<mesh_domain>`
    suffix) or a full 64-char id_pub hex — to (id_pub_bytes, hostname)."""
    s = handle.strip()
    if len(s) == 64 and all(c in "0123456789abcdefABCDEF" for c in s):
        info = ca.node_info(bytes.fromhex(s))
        if info is None:
            sys.exit(f"no enrolled node with id {s[:16]}…")
        return bytes.fromhex(s), info[0]
    suffix = "." + cfg.mesh_domain
    if s.endswith(suffix):
        s = s[: -len(suffix)]
    owner = ca.hostname_owner(s)
    if owner is None:
        sys.exit(f"no node named {handle!r} on this hub (see `gw status`)")
    return bytes.fromhex(owner), s


_NEXT_RENEWAL_NOTE = (
    "Takes effect at the node's next renewal (~half the credential TTL); no "
    "re-join needed. To apply immediately, run `sudo gw renew` on that node."
)


def cmd_set_caps(args) -> int:
    cfg, ca = _load_hub_ca(args, "set-caps")
    id_pub, name = _resolve_node(ca, cfg, args.node)
    caps = [c.strip() for c in args.caps.split(",") if c.strip()]
    if not any(c.startswith("segment:") for c in caps):
        log.warning("caps %s include no segment — %r will peer with no one "
                    "(add e.g. segment:mesh)", caps, name)
    ca.set_caps(id_pub, caps)
    print(f"caps for {name!r} → {caps}")
    print(_NEXT_RENEWAL_NOTE)
    return 0


def cmd_set_segments(args) -> int:
    cfg, ca = _load_hub_ca(args, "set-segments")
    id_pub, name = _resolve_node(ca, cfg, args.node)
    _, current = ca.node_info(id_pub)
    # Replace only the segment: tags; keep tls/hostname-pinned and anything else.
    kept = [c for c in current if not c.startswith("segment:")]
    segs = [s.strip() for s in args.segments.split(",") if s.strip()] or ["mesh"]
    segments = ["segment:" + s for s in segs]
    caps = kept + segments
    ca.set_caps(id_pub, caps)
    print(f"segments for {name!r} → {segs}  (caps now {caps})")
    print(_NEXT_RENEWAL_NOTE)
    return 0


# ---------------------------------------------------------------------------
# hub-promote — turn an enrolled node into a hub (generate a CA)
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


def _service_state() -> str:
    """How the greasewood daemon is managed on this host: 'active' (systemd
    unit installed and running), 'installed' (unit present, not yet running),
    or 'manual' (no unit). Used so create / join don't tell the user to run
    `gw run` when systemd already starts the daemon on its own."""
    if not (_UNIT_DIR / "greasewood.service").exists():
        return "manual"
    import shutil
    import subprocess
    systemctl = shutil.which("systemctl")
    if not systemctl:
        return "installed"
    r = subprocess.run([systemctl, "is-active", "greasewood.service"],
                       capture_output=True, text=True)
    return "active" if r.stdout.strip() == "active" else "installed"


def _print_daemon_guidance(then: str = "") -> None:
    """Tell the user how the daemon runs, correctly for service vs manual mode.
    `then` is an optional trailing clause (e.g. 'then invite nodes')."""
    state = _service_state()
    tail = f" — {then}" if then else ""
    if state == "active":
        print(f"The greasewood service is already running{tail}.")
        print("  status: systemctl status greasewood   logs: journalctl -u greasewood -f")
    elif state == "installed":
        print("The greasewood service is installed; it starts automatically now that")
        print("the config exists (and on every reboot). Check it in a moment with:")
        print("  systemctl status greasewood   (logs: journalctl -u greasewood -f)")
    else:
        print(f"Start the daemon{tail}:")
        print("  sudo gw run")
        print("  (tip: 'sudo gw install-service' makes it start on boot — no manual gw run)")


def cmd_hub_promote(args) -> int:
    """On a prospective new hub (currently a node): generate its own CA key and
    rewrite its config to role=hub, so a restart makes it serve as a hub.
    Prints the CA public key + control endpoint to add to the fleet's
    trusted_pubs (a manual re-root — see the printed steps)."""
    _require_root("hub-promote")
    import json as json_mod
    from .config import load_config
    from .keys import CAKeys, NodeKeys

    cfg_path = Path(args.config)
    if not cfg_path.exists():
        sys.exit(f"no config at {cfg_path} — this command runs on an enrolled node")
    cfg = load_config(cfg_path)

    # A hub must accept inbound connections (it serves the control plane + door).
    # An outbound-only node can't be one until it's reachable.
    if cfg.inbound == "no":
        sys.exit(
            "this node is outbound-only (inbound=no); a hub must accept inbound "
            "connections. Switch it first:\n"
            "  sudo gw set-inbound yes\n"
            "then re-run hub-promote."
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
    # Nodes reach the hub control plane over the overlay, so advertise the
    # overlay address (not the underlay).
    endpoint = f"http://[{keys.addr}]:{control_port}"

    # Trust our own CA as a root, in addition to whatever we already trust, so
    # this hub accepts the credentials it issues.
    trusted = list(dict.fromkeys([*cfg.ca_pubs, ca_pub_hex]))

    # A hub must reach every segment — ensure the wildcard segment. (Its own
    # credential picks this up on the next renewal under the new CA.)
    hub_caps = list(cfg.caps)
    if "segment:*" not in hub_caps:
        hub_caps.append("segment:*")

    endpoint_line = (
        f'\nendpoints = {json_mod.dumps(cfg.endpoints)}' if cfg.endpoints else ""
    )
    hosts_sync = "true" if cfg.hosts_sync else "false"
    cfg_path.write_text(f"""[node]
hostname = "{cfg.hostname}"
data_dir = "{cfg.data_dir}"
role = "hub"
inbound = "yes"
caps = {json_mod.dumps(hub_caps)}{endpoint_line}

[network]
interface = "{cfg.wg_interface}"
listen_port = {cfg.listen_port}
overlay_prefix = "{cfg.overlay_prefix}"
seeds = {json_mod.dumps(cfg.seeds)}
root_url = "{cfg.root_url}"
hosts_sync = {hosts_sync}
mesh_domain = "{cfg.mesh_domain}"

[ca]
trusted_pubs = {json_mod.dumps(trusted)}

[hub]
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
    log.info("promoted to hub role in %s", cfg_path)

    print("\nReady to become a hub. CA key generated; config set to role=hub.")
    print(f"  CA pub key   : {ca_pub_hex}")
    print(f"  hub endpoint : {endpoint}")
    print()
    print("To move the fleet to this hub (manual re-root — live tunnels stay up):")
    print("  1. Add this CA pub to [ca] trusted_pubs on EVERY node (keep the old")
    print("     one during the overlap), e.g. via Ansible, and restart their daemons:")
    print(f"       {ca_pub_hex}")
    print(f"  2. Repoint nodes' root_url + seeds to this hub: {endpoint}")
    print("  3. Once every node has renewed here, drop the old CA pub from")
    print("     trusted_pubs fleet-wide. Then decommission the old hub.")
    print("Start the daemon here:  sudo gw run")
    print()
    from . import firewall as _fw
    _fw.check(_fw.hub_rules(cfg.listen_port, control_port), log)
    return 0


# ---------------------------------------------------------------------------
# TLS service certificates (§12) — cert-request / cert-status
# ---------------------------------------------------------------------------

def _resolve_hub_url(cfg) -> str:
    """The control-plane URL to talk to: the configured hub."""
    return cfg.root_url


def cmd_cert_request(args) -> int:
    """Request an x509 TLS cert from the hub for a local service (e.g. Postgres).
    Generates the leaf key locally; only its public key is sent to the hub. Unless
    --no-auto-renew is given, the cert is recorded so the daemon renews it at
    ~half its TTL (and runs --reload-cmd afterward)."""
    import ipaddress
    from .config import load_config
    from .keys import NodeKeys
    from . import certs as certmod
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
        from .hosts import mesh_name
        dns = [mesh_name(cfg.hostname, cfg.mesh_domain)]
        ips = [keys.addr]

    # CN is not operator-settable: it's cosmetic under verify-full (the SAN is
    # what's checked) and the hub constrains it to an owned name anyway, so we
    # just derive it from the first SAN.
    cn = dns[0] if dns else (ips[0] if ips else keys.addr)
    name = args.name or (dns[0] if dns else "service")

    # Resolve the three destinations. Default is <out-dir>/<name>.{key,crt} +
    # <out-dir>/ca.crt; each can be overridden independently so the key, cert,
    # and CA cert may live in different directories.
    out_dir = Path(args.out_dir) if args.out_dir else (cfg.data_dir / "tls")
    key_path = Path(args.key_out) if args.key_out else out_dir / f"{name}.key"
    crt_path = Path(args.cert_out) if args.cert_out else out_dir / f"{name}.crt"
    ca_path = Path(args.ca_out) if args.ca_out else out_dir / "ca.crt"

    # Re-requesting an existing name RELOCATES it (record_managed keys on name).
    # Capture the prior destinations so we can flag any that are now orphaned.
    prior = [c for c in certmod.load_manifest(cfg.data_dir) if c.get("name") == name]
    old_paths = set(certmod.entry_paths(prior[0])) if prior else set()

    hub_url = args.hub or _resolve_hub_url(cfg)
    if not hub_url:
        sys.exit("no hub URL — set root_url in config or pass --hub")

    try:
        key_path, crt_path, ca_path = certmod.issue_cert(
            hub_url, keys, dns=dns, ips=ips, cn=cn,
            key_path=key_path, crt_path=crt_path, ca_path=ca_path)
    except certmod.CertRejected as e:
        sys.exit(f"cert request rejected: {e}")
    except RuntimeError as e:
        sys.exit(f"cert request to {hub_url} failed: {e}")

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
                  "sudo systemctl restart greasewood  (or re-run sudo gw run).")
    return 0


def cmd_cert_status(args) -> int:
    """Show the local TLS certs and their expiry."""
    from cryptography import x509
    from .config import load_config

    cfg = load_config(Path(args.config))
    out_dir = Path(args.out_dir) if args.out_dir else (cfg.data_dir / "tls")
    if not out_dir.exists():
        print(f"no TLS certs at {out_dir}")
        return 0

    now = dt.datetime.now(_UTC)
    found = False
    for crt in sorted(out_dir.glob("*.crt")):
        try:
            cert = x509.load_pem_x509_certificate(crt.read_bytes())
        except Exception:
            continue
        found = True
        exp = getattr(cert, "not_valid_after_utc", None) or \
            cert.not_valid_after.replace(tzinfo=_UTC)
        cn = ""
        try:
            cn = cert.subject.rfc4514_string()
        except Exception:
            pass
        sans = []
        try:
            ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            sans = [str(g.value) for g in ext.value]
        except x509.ExtensionNotFound:
            pass
        left = (exp - now).days
        print(f"{crt.name:<20} {cn:<30} expires {exp:%Y-%m-%d %H:%M} ({left}d)  "
              f"SAN={','.join(sans) if sans else '-'}")
    if not found:
        print(f"no TLS certs at {out_dir}")
    return 0


# ---------------------------------------------------------------------------
# set-inbound — flip a node between reachable and outbound-only
# ---------------------------------------------------------------------------

def cmd_set_inbound(args) -> int:
    """Change this node's reachability (yes/no). Switching to inbound
    means peers can dial it — so it can hold direct links to outbound-only nodes
    and be promoted to hub — but it must accept the WireGuard port (this checks
    and prints the rule; open it yourself). Restart the daemon to advertise."""
    _require_root("set-inbound")
    import re
    from .config import load_config

    cfg_path = Path(args.config)
    if not cfg_path.exists():
        sys.exit(f"no config at {cfg_path}")
    cfg = load_config(cfg_path)
    value = args.value

    text = cfg_path.read_text()
    new, n = re.subn(r'(?m)^\s*inbound\s*=\s*".*?"\s*$',
                     f'inbound = "{value}"', text, count=1)
    if n == 0:
        sys.exit("could not find an [node] inbound = \"...\" line to update")
    cfg_path.write_text(new)
    print(f"inbound = {value} (was {cfg.inbound})")

    from . import firewall as _fw
    if value == "no":
        print("Outbound-only: greasewood needs no inbound ports; keep your base "
              "'ct state established,related accept' for replies. (Open ports left "
              "in place are harmless; remove them yourself if you like.)")
    else:
        is_hub = cfg.role == "hub"
        rules = (_fw.hub_rules(cfg.listen_port, _control_port(cfg))
                 if is_hub else _fw.node_rules(cfg.listen_port, value))
        _fw.check(rules, log)
    print("Restart the daemon to advertise the change: sudo systemctl restart "
          "greasewood  (or re-run sudo gw run)")
    return 0


# ---------------------------------------------------------------------------
# rename — change this node's mesh hostname (hub-validated, no re-join)
# ---------------------------------------------------------------------------

def cmd_rename(args) -> int:
    """Rename this node in the mesh without re-joining. Asks the hub to re-issue
    the credential under the new name over the existing control plane; the hub
    enforces uniqueness (refused if taken) and frees the old name. Keys and the
    overlay address are unchanged. Requires the mesh to be up (the daemon
    running) so the hub is reachable."""
    _require_root("rename")
    import re
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
        sys.exit("provide a non-empty hostname: gw rename <newname>")
    if newname == cfg.hostname:
        print(f"already named {newname!r} — nothing to do")
        return 0

    # Hub-pinned nodes (enrolled via `gw invite --hostname`) can't rename. Fail
    # fast locally; the hub enforces this too (defense in depth).
    if "hostname-pinned" in cfg.caps:
        sys.exit("this node's hostname is hub-pinned; rename is disabled. "
                 "To change it, re-invite the node with a new --hostname on the hub.")

    try:
        keys = NodeKeys.load(cfg.data_dir)
    except FileNotFoundError:
        sys.exit("this node isn't enrolled yet (no keys) — run 'gw join' first")

    hub_url = cfg.root_url
    if not hub_url:
        sys.exit("no hub URL known — is this node enrolled and the mesh up?")

    # Ask the hub to re-issue under the new name (same authenticated path as
    # renewal; the hostname field turns it into a rename).
    req = RenewRequest(
        id_pub=keys.id_pub_bytes,
        wg_pub=keys.wg_pub_bytes,
        nonce=secrets.token_hex(16),
        ts=dt.datetime.now(_UTC).replace(microsecond=0),
        hostname=newname,
    ).sign(keys.id_priv)

    body = json.dumps(req.to_dict()).encode()
    url = f"{hub_url.rstrip('/')}/renew"
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
        sys.exit(f"could not reach the hub at {hub_url}: {e} — is the mesh up?")
    if "error" in data:
        sys.exit(f"rename rejected by hub: {data['error']}")

    cred = Credential.from_dict(data)

    # Re-sign our record with the new name + fresh credential and publish it, so
    # peers and /etc/hosts pick up the rename promptly.
    directory = Directory.load(cfg.dir_cache_path)
    existing = directory.get(keys.id_pub_hex)
    seq = (existing.seq + 1) if existing else 1
    endpoints = list(existing.endpoints) if existing else (
        [] if cfg.inbound == "no" else cfg.endpoints)
    inbound = existing.inbound if existing else cfg.inbound
    aliases = list(existing.aliases) if existing else _config_aliases(cfg)
    record = NodeRecord(
        id_pub=keys.id_pub_bytes, seq=seq, endpoints=endpoints,
        inbound=inbound, cred=cred, aliases=aliases,
    ).sign(keys.id_priv)
    directory.put(record)
    directory.save(cfg.dir_cache_path)
    from .sync import push_record
    try:
        push_record(hub_url, record)
    except Exception as e:
        log.warning("published locally but push to hub failed (will sync): %s", e)

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
          "sudo systemctl restart greasewood  (or re-run sudo gw run)")
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
    # pull the directory from, and the hub URL. (Moving the hub is a deliberate
    # re-root — a trusted_pubs/root_url config change — not a runtime event.)
    ca_pubs = [bytes.fromhex(h) for h in cfg.ca_pubs]
    def get_ca_pubs():
        return ca_pubs

    from . import audit
    with audit.context(f"startup: ensure interface {cfg.wg_interface} [{keys.addr}]"):
        wgmod.ensure_interface(
            cfg.wg_interface, keys.addr, cfg.listen_port, cfg.wg_key_path
        )

    ca: CA | None = None
    sync: SyncLoop | None = None
    renewal: RenewalLoop | None = None
    door_watcher = None

    # Revoke list is re-read live (not snapshotted) so `gw revoke` takes effect
    # without a daemon restart — both for control-plane refusal and local
    # eviction. Plain nodes have no revoke list (expiry-based revocation).
    get_revoked: "callable" = set
    is_hub = cfg.role == "hub"

    if is_hub:
        if not cfg.ca_key_file:
            sys.exit("hub role requires ca_key_file in [hub]")
        ca_keys = CAKeys.load(cfg.ca_key_file, _get_passphrase(cfg.ca_key_passphrase_env))
        ca = CA(ca_keys, cfg.data_dir, cfg.credential_ttl)
        get_revoked = ca.load_revoked_set
        log.info("CA loaded, pub=%s...", ca_keys.ca_pub_bytes.hex()[:16])
        # Re-apply door routing in case the machine rebooted since create
        wgmod.setup_door_routing()

        # Bind the control plane to the overlay address (reachable only through
        # the mesh) and loopback (for the hub talking to itself) — NOT "::".
        # This keeps it off the underlay structurally, no firewall rule needed.
        port = _control_port(cfg)
        listen_addrs = [f"[{keys.addr}]:{port}", f"[::1]:{port}"]

        # Fleet-wide renew hint (gw renew-all): served in /directory, re-read
        # per request so a bump takes effect without restarting the hub.
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

    # Directory sync — pull from the configured seeds (the hub). The renewal loop
    # is built below; the callback reads it lazily (the first pull is one interval
    # out), so acting on the hub's fleet renew hint needs no reordering.
    sync = SyncLoop(
        directory, lambda: cfg.seeds, cfg.dir_cache_path,
        on_renew_after=lambda ts: renewal.maybe_renew_after(ts) if renewal else None,
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
    )
    recon.start()

    # Effective advertised endpoints: outbound-only nodes (inbound=no) suppress
    # their endpoint so peers don't waste handshakes dialing an unreachable addr.
    eff_endpoints = [] if cfg.inbound == "no" else cfg.endpoints

    # Honor config changes on (re)start: if our record's inbound/endpoints/
    # aliases no longer match config (e.g. after `gw set-inbound` or a
    # `gw cert-request` that added a service name), re-sign it so what we
    # advertise is current — the daemon reads config only at startup.
    want_aliases = _config_aliases(cfg)
    own_record = directory.get(keys.id_pub_hex)
    if own_record and (own_record.inbound != cfg.inbound
                       or list(own_record.endpoints) != list(eff_endpoints)
                       or sorted(own_record.aliases) != sorted(want_aliases)):
        from .wire import NodeRecord
        own_record = NodeRecord(
            id_pub=keys.id_pub_bytes,
            seq=own_record.seq + 1,
            endpoints=eff_endpoints,
            inbound=cfg.inbound,
            cred=own_record.cred,
            aliases=want_aliases,
        ).sign(keys.id_priv)
        directory.put(own_record)
        directory.save(cfg.dir_cache_path)
        log.info("updated own record (inbound=%s, endpoints=%s, aliases=%s)",
                 cfg.inbound, eff_endpoints, want_aliases)

    # Push our own record so the rest of the mesh knows about us. This gets a
    # newly enrolled node into the hub's directory; it is also how endpoint
    # changes propagate without waiting for the next renewal cycle.
    if own_record:
        for seed in cfg.seeds:
            try:
                push_record(seed, own_record)
                log.info("pushed own record to %s", seed)
            except Exception as e:
                log.warning("push to %s failed (will retry on next sync): %s", seed, e)

    # Renewal loop — targets the configured hub.
    if own_record:
        renewal = RenewalLoop(
            node_keys=keys,
            directory=directory,
            get_root_url=lambda: cfg.root_url,
            current_cred=own_record.cred,
            inbound=cfg.inbound,
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
        cert_renewal = CertRenewalLoop(keys, lambda: _resolve_hub_url(cfg), cfg.data_dir)
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
# nodes
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


def _print_node_table(records, cfg, now, own_id, live_peers, is_root) -> None:
    """The split roster: LEFT is the mesh (fleet-wide, same on every node — name,
    addr, inbound, segments, credential); RIGHT is THIS node's view (do I peer
    with them, and — with root + live WireGuard state — the live data link and
    its traffic). The right side degrades gracefully: without root it shows only
    the policy 'would I peer' answer."""
    import base64
    from .hosts import mesh_name
    from .reconcile import default_policy

    have_live = live_peers is not None
    now_epoch = int(now.timestamp())

    def _exp(r):
        left = (r.cred.exp - now).total_seconds()
        if left < 0:
            return "EXPIRED"
        if left < 3600:
            return "<1h!"
        h = int(left // 3600)
        return f"{h // 24}d" if h >= 48 else f"{h}h"

    # LEFT (mesh) cells + RIGHT (this node) cells, row-aligned.
    left_hdr = ("name", "addr", "in", "segments", "exp")
    left_rows, right_rows = [], []
    for r in records:
        left_rows.append((
            mesh_name(r.hostname, cfg.mesh_domain), r.cred.addr,
            "yes" if r.inbound != "no" else "no",
            ",".join(_record_segments(r)) or "-", _exp(r),
        ))
        is_self = r.id_pub.hex() == own_id
        peers = default_policy(cfg.caps, r.cred.caps)
        if not have_live:                       # no live data — show policy only
            right_rows.append(("self" if is_self else ("yes" if peers else "no"),))
        elif is_self:
            right_rows.append(("(self)", ""))
        elif not peers:
            right_rows.append(("— not a peer", ""))
        else:
            lp = live_peers.get(base64.b64encode(r.cred.wg_pub).decode())
            if lp is None:
                right_rows.append(("not installed", ""))
            elif lp.latest_handshake and (now_epoch - lp.latest_handshake) <= 180:
                right_rows.append((f"● up, {_fmt_hs_age(now_epoch - lp.latest_handshake)} ago",
                                   f"↓{_fmt_bytes(lp.rx_bytes)} ↑{_fmt_bytes(lp.tx_bytes)}"))
            else:
                right_rows.append(("○ no handshake", ""))
    right_hdr = ("link", "traffic") if have_live else ("peer?",)

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
    print(f"{'mesh — the fleet (same on every node)':<{lwidth}} │ this node")
    print(_fl(left_hdr) + " │ " + _fr(right_hdr))
    print("-" * lwidth + "-+-" + "-" * max(len(_fr(right_hdr)), 9))
    for lr, rr in zip(left_rows, right_rows):
        print(_fl(lr) + " │ " + _fr(rr))
    if not have_live:
        note = ("run 'sudo gw status' to see live data links + traffic" if not is_root
                else "no live WireGuard state — is the daemon running?")
        print(f"({note})")


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
    """The `door:` block for `gw status` — hub only. Shows whether the
    enrollment door is open (and time-to-close) or closed (and how long ago),
    plus failed attempts + source IPs and the last enrollment."""
    from . import door
    try:
        st = door.read_door_status(cfg.data_dir)
    except PermissionError:
        # door_status.json is 0600 root (it holds attempt source IPs). Degrade
        # honestly rather than dying — status is a no-root command.
        return ["door     : (state readable only with root — sudo gw status)"]
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
    import sys as _sys
    from .config import load_config
    from . import narrate as N

    # Where to read from.
    src = getattr(args, "source", None)
    if src == "-":
        lines = _sys.stdin.read().splitlines()
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

    color = _sys.stdout.isatty() and not getattr(args, "no_color", False)
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
    """The self/health block for `gw status` — local facts about THIS node
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

    inb = "yes (accepts inbound)" if cfg.inbound != "no" else "no (outbound-only)"
    lines.append(f"{'inbound':<9}: {inb}")

    n = len(cfg.ca_pubs)
    lines.append(f"{'trust':<9}: {n} trusted CA{'' if n == 1 else 's'} · "
                 f"hub {cfg.root_url or '(none configured)'}")

    # Sync freshness — nodes read a *cache*, so a stale roster is worth flagging.
    # The hub is the source of truth, so it has nothing to be 'stale' against.
    if cfg.role != "hub":
        last = syncmod.read_last_sync(cfg.data_dir)
        if last is None:
            lines.append(f"{'sync':<9}: never (is the daemon running / reaching the hub?)")
        else:
            try:
                age = (dt.datetime.now(_UTC)
                       - dt.datetime.fromisoformat(last.replace("Z", "+00:00"))
                       ).total_seconds()
            except (ValueError, AttributeError):
                age = 0
            flag = "⚠ " if age > 120 else ""
            tail = " — hub unreachable?" if age > 120 else ""
            lines.append(f"{'sync':<9}: {flag}directory synced {_fmt_ago(last)}{tail}")
    return lines


def cmd_status(args) -> int:
    from .config import load_config
    from .directory import Directory

    cfg_path = Path(args.config)
    if not cfg_path.exists():
        print("not configured (no config file at %s)" % cfg_path)
        return 0

    cfg = load_config(cfg_path)

    # status is a no-root command: it reads only the public files (id_pub.hex,
    # directory.json). But on a legacy install with a 0700 data dir, those reads
    # fail invisibly (exists() → False, Directory.load → empty) and status would
    # lie ("keys not generated", "directory is empty"). Say the truth instead.
    if (cfg.data_dir.exists() and not os.access(cfg.data_dir, os.X_OK)) or (
            cfg.dir_cache_path.exists() and not os.access(cfg.dir_cache_path, os.R_OK)):
        sys.exit(f"can't read the public state under {cfg.data_dir} (a legacy "
                 f"install with a 0700 data dir?). Either run: sudo gw status, "
                 f"or open the public files up: sudo chmod 755 {cfg.data_dir}")
    own_id, own_addr = _own_identity(cfg.data_dir)
    directory = Directory.load(cfg.dir_cache_path)

    print(f"role     : {cfg.role}")
    print(f"hostname : {cfg.hostname}")
    print(f"addr     : {own_addr or '(keys not generated)'}")
    # Self/health — local facts about THIS node (fast, no root, no network).
    for line in _self_health_lines(cfg, directory, own_id):
        print(line)
    # The enrollment door only exists on the hub — show its state there.
    if cfg.role == "hub":
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
# diagnose — explain why a peer link is or isn't forming
# ---------------------------------------------------------------------------

def _handshake_phrase(live, now_epoch: int) -> str:
    """Human phrase for a live peer's last-handshake age."""
    if live is None:
        return "not installed"
    if live.latest_handshake == 0:
        return "no handshake yet"
    age = now_epoch - live.latest_handshake
    if age < 0:
        age = 0
    if age <= 180:
        return f"handshook {age}s ago"
    if age < 3600:
        return f"stale ({age // 60}m ago)"
    return f"stale ({age // 3600}h ago)"


def _hub_clock_skew(root_url: str, timeout: float = 3.0) -> "float | None":
    """Local-minus-hub clock difference in seconds via /health's 'now' stamp,
    or None if the hub is unreachable or doesn't send one (older hub)."""
    import urllib.request
    try:
        with urllib.request.urlopen(f"{root_url.rstrip('/')}/health",
                                    timeout=timeout) as resp:
            raw = json.loads(resp.read()).get("now")
        if not raw:
            return None
        hub_now = dt.datetime.fromisoformat(raw.replace("Z", "+00:00"))
        return (dt.datetime.now(_UTC) - hub_now).total_seconds()
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


def cmd_diagnose(args) -> int:
    """
    Per-peer connectivity diagnosis, **from THIS node's point of view — not a
    global fleet dashboard.** It reads only this node's own directory cache,
    trusted-CA set, and live WireGuard state, and reports, for each peer this node
    knows about, whether *this* node can form a link to it. Every verdict is about
    a link *from here* (e.g. "REJECTED" = this node won't install that peer under
    its trust set; "LINKED" = this node has a live tunnel to it) — not the peer's
    health elsewhere. So run it on the node that's actually having trouble, and
    it only sees peers already in its local directory cache.

    Runs the same 7-step reconcile checks the daemon uses and prints, per peer,
    exactly which step it fails — turning a silent direct-or-fail link into an
    actionable reason. Then overlays live WireGuard handshake state to separate
    "rejected by verification" from "configured but never handshook" (an
    endpoint/firewall problem).
    """
    import base64
    import time as _time
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

    # Read-only: use the public id (never the private key) so non-root works;
    # live WireGuard state still needs root, but it degrades gracefully below.
    own_id, own_addr = _own_identity(cfg.data_dir)
    if own_id is None:
        print("keys not generated yet — run 'gw join <token>' or 'gw create' first")
        return 1
    own_id_bytes = bytes.fromhex(own_id)

    # Key hygiene — stat() needs no read permission, so this works non-root too.
    for w in _key_file_warnings(_secret_key_paths(cfg)):
        print(f"  ⚠ {w}")

    ca_pubs = [bytes.fromhex(h) for h in cfg.ca_pubs]

    # Revoke list: only the hub maintains one (nodes are expiry-based).
    revoked: set[str] = set()
    rev_path = cfg.data_dir / "revoked.json"
    if rev_path.exists():
        try:
            revoked = set(json.loads(rev_path.read_text()).get("revoked", []))
        except Exception:
            pass

    # Live WireGuard state (best effort — needs root + the daemon running).
    try:
        live_peers = wgmod.get_peers(cfg.wg_interface)
        wg_available = True
    except Exception:
        live_peers, wg_available = {}, False

    directory = Directory.load(cfg.dir_cache_path)
    now = dt.datetime.now(_UTC)
    now_epoch = int(_time.time())

    # MTU blackhole probe for LINKED peers: on by default when we have live WG
    # state (needs root anyway), off with --no-mtu-probe. Reads the tunnel MTU
    # once; the per-peer DF pings happen in the loop below.
    do_mtu_probe = wg_available and not getattr(args, "no_mtu_probe", False)
    iface_mtu = _iface_mtu(cfg.wg_interface) if do_mtu_probe else None

    print(f"self     : {cfg.hostname}  ({own_addr})")
    print(f"role     : {cfg.role}   inbound={cfg.inbound}   iface={cfg.wg_interface}")
    print(f"trusted CAs: {len(ca_pubs)}   hub: {cfg.root_url or '(none configured)'}")
    if not ca_pubs:
        print("  ⚠ no trusted CA keys — check [ca] trusted_pubs; nothing will verify")

    # Clock skew vs the hub — the failure mode that masquerades as everything
    # else (creds "expired", renewals refused for skew). /health carries the
    # hub's time; compare and say it plainly. Best-effort: hub may be down.
    if cfg.root_url:
        skew = _hub_clock_skew(cfg.root_url)
        if skew is None:
            print("clock    : hub unreachable — skew check skipped")
        elif abs(skew) >= 60:
            print(f"  ⚠ local clock is {skew:+.0f}s off the hub — FIX NTP. "
                  f"Past ±300s renewals are refused; expiry checks misfire "
                  f"before that.")
        else:
            print(f"clock    : within {abs(skew):.0f}s of the hub (ok)")
    if os.geteuid() != 0:
        print("  ⚠ not root — live WireGuard handshake state is unavailable; "
              "re-run with sudo for link health")
    elif not live_peers:
        print(f"WireGuard: 0 live peer(s) on {cfg.wg_interface} "
              f"(is the daemon running?)")
    print()

    records = sorted((r for r in directory.all() if r.id_pub != own_id_bytes),
                     key=lambda r: r.hostname)
    if not records:
        print("no peer records in the directory cache yet — is sync reaching the hub?")
        return 0

    own_rec = directory.get(own_id)  # our own published record (endpoint check)
    want = getattr(args, "hostname", None)
    counts = {"linked": 0, "no-handshake": 0, "rejected": 0, "policy": 0}
    # Set if an outbound-only peer has a live link to us: since it advertises no
    # endpoint, it could only have reached us by dialing OURS — proof we're
    # actually inbound-reachable (a fact a node otherwise can't observe itself).
    proved_inbound = False

    for r in records:
        if want and r.hostname != want:
            continue
        wg_b64 = base64.b64encode(r.cred.wg_pub).decode()
        live = live_peers.get(wg_b64)
        problems: list[str] = []

        # Step 1: CA signature against the trusted set
        body = _canonical(r.cred._body_dict())
        ca_ok = False
        for raw in ca_pubs:
            try:
                Ed25519PublicKey.from_public_bytes(raw).verify(r.cred.ca_sig, body)
                ca_ok = True
                break
            except InvalidSignature:
                continue
        if not ca_ok:
            problems.append("CA signature not from a trusted CA (wrong fleet? trusted_pubs not updated after a re-root?)")

        # Step 2: expiry
        left = (r.cred.exp - now).total_seconds()
        if left < 0:
            problems.append(f"credential EXPIRED {int(-left // 60)}m ago (renewal not propagating?)")

        # Step 3: self-signature
        try:
            Ed25519PublicKey.from_public_bytes(r.id_pub).verify(
                r.sig, _canonical(r._body_dict()))
        except InvalidSignature:
            problems.append("invalid self-signature (record tampered/corrupt)")

        # Step 4: addr derivation + id/cred consistency
        if r.cred.addr != derive_addr(r.id_pub) or r.id_pub != r.cred.id_pub:
            problems.append("addr does not derive from id_pub (forged record)")

        # Step 5: revoke list
        if r.id_pub.hex() in revoked:
            problems.append("node is REVOKED")

        # Step 6: authorization policy
        policy_ok = default_policy(cfg.caps, r.cred.caps)
        if not policy_ok:
            problems.append(f"policy denies link (local caps={cfg.caps}, peer caps={r.cred.caps})")

        # Classify. Verification/policy failures (steps 1-6) come first; only if
        # the record is acceptable do we look at the data plane (step 7).
        only_policy = problems == [problems[-1]] if problems else False
        if problems and not policy_ok and only_policy:
            status, bucket = "policy-denied", "policy"
        elif problems:
            status, bucket = "REJECTED (won't be installed)", "rejected"
        elif live is None:
            status, bucket = "verified but NOT installed (reconcile not run / not root?)", "no-handshake"
        elif live.latest_handshake and (now_epoch - live.latest_handshake) <= 180:
            status, bucket = f"LINKED ({_handshake_phrase(live, now_epoch)})", "linked"
            if r.inbound == "no" or not r.endpoints:
                proved_inbound = True
            # A LINKED peer can still silently blackhole large packets (WG-over-
            # cloud MTU mismatch): small traffic works, TLS handshakes hang.
            if do_mtu_probe:
                warn = _mtu_probe(cfg.wg_interface, r.cred.addr, iface_mtu)
                if warn:
                    problems.append(warn)
        else:
            status, bucket = f"installed, {_handshake_phrase(live, now_epoch)}", "no-handshake"
            # Why no handshake? Endpoint / inbound-asymmetry hints.
            no_self_ep = cfg.inbound == "no"
            no_peer_ep = (r.inbound == "no") or (not r.endpoints)
            if no_self_ep and no_peer_ep:
                problems.append("both sides are outbound-only (inbound=no / no endpoint) "
                                "— direct-or-fail can't form this link")
            elif not live.endpoint and no_peer_ep:
                problems.append("no endpoint to dial and the peer advertises none "
                                "(peer is outbound-only); this side must be reachable")
            elif live.endpoint:
                problems.append(f"dialing {live.endpoint} but no handshake — check the peer's "
                                "firewall (mesh UDP port open?) and that its daemon is running")
        counts[bucket] += 1

        u6, u4 = _underlay_addrs(r.endpoints)
        print(f"● {r.hostname}  [{r.cred.addr}]  inbound={r.inbound}")
        print(f"    underlay  v6={u6}  v4={u4}")
        print(f"    expires   {r.cred.exp:%Y-%m-%d %H:%M UTC}")
        print(f"    {status}")
        for p in problems:
            print(f"    - {p}")

    print()
    print(f"summary: {counts['linked']} linked, {counts['no-handshake']} configured/no-handshake, "
          f"{counts['rejected']} rejected, {counts['policy']} policy-denied")

    # Self inbound-reachability advisory (best-effort, from live handshakes only —
    # never auto-changes the declared value; just surfaces evidence for/against).
    if os.geteuid() == 0 and live_peers:
        if cfg.inbound == "no":
            print("reachability: inbound=no (outbound-only) — you advertise no "
                  "endpoint; links form only when you initiate to a reachable peer.")
        elif proved_inbound:
            print("reachability: inbound=yes CONFIRMED — an outbound-only peer "
                  "reached you, so your endpoint is dialable from the mesh.")
        elif own_rec is not None and not own_rec.endpoints:
            print("reachability: inbound=yes but you advertise NO endpoint — peers "
                  "have nothing to dial; set [network] endpoints, or you'll only "
                  "link when you're the initiator.")
        elif counts["linked"] == 0:
            print("reachability: inbound=yes but no peer has handshaked — if this "
                  "persists, your advertised endpoint may be blocked inbound "
                  "(firewall/NAT); verify the mesh UDP port is open. (Normal right "
                  "after startup.)")
        else:
            print("reachability: inbound=yes — reachable-looking, but unconfirmed "
                  "(no outbound-only peer has dialed in to prove it).")
    return 0


# ---------------------------------------------------------------------------
# renew  (force an immediate credential renewal for THIS node)
# ---------------------------------------------------------------------------

def cmd_renew(args) -> int:
    """
    Force an immediate credential renewal for THIS node. Normally the daemon
    renews on its own (~half the credential TTL); this fetches a fresh credential
    from the hub right now, re-publishes the record so peers stop serving the old
    expiry, and adopts any caps/segments the hub changed in the meantime (so
    `gw set-caps` / `gw set-segments` take effect immediately instead of at the
    next scheduled renewal).

    Run it ON THE NODE: renewal is self-signed by the node's id_priv, so the hub
    cannot renew a node on its behalf — there is no "renew everyone from the hub".
    """
    _require_root("renew")
    from .config import load_config
    from .keys import NodeKeys
    from .directory import Directory
    from .wire import NodeRecord
    from .renewal import _do_renew
    from .sync import push_record
    import json as json_mod
    import re

    cfg_path = Path(args.config)
    if not cfg_path.exists():
        sys.exit(f"not configured (no config file at {cfg_path})")
    cfg = load_config(cfg_path)
    try:
        keys = NodeKeys.load(cfg.data_dir)
    except Exception:
        sys.exit("this node isn't enrolled yet (no keys) — run 'gw join <token>' first")
    if not cfg.root_url:
        sys.exit("no hub URL configured (root_url) — is this node enrolled?")

    try:
        cred = _do_renew(cfg.root_url, keys)
    except Exception as e:
        sys.exit(f"renew failed: {e}\n(is the mesh up and the hub reachable? "
                 f"renewal goes over the overlay)")

    # Re-publish our record with the fresh credential, keeping our current seq+1,
    # endpoints, and inbound — highest-seq-wins means peers adopt this promptly.
    directory = Directory.load(cfg.dir_cache_path)
    existing = directory.get(keys.id_pub_hex)
    seq = (existing.seq + 1) if existing else 1
    endpoints = list(existing.endpoints) if existing else (
        [] if cfg.inbound == "no" else cfg.endpoints)
    inbound = existing.inbound if existing else cfg.inbound
    aliases = list(existing.aliases) if existing else _config_aliases(cfg)
    record = NodeRecord(
        id_pub=keys.id_pub_bytes, seq=seq, endpoints=endpoints,
        inbound=inbound, cred=cred, aliases=aliases,
    ).sign(keys.id_priv)
    directory.put(record)
    directory.save(cfg.dir_cache_path)
    try:
        push_record(cfg.root_url, record)
    except Exception as e:
        log.warning("published locally but push to hub failed (will sync): %s", e)

    print(f"renewed — credential now expires {cred.exp:%Y-%m-%d %H:%M UTC}")

    # Adopt caps/segments if the hub changed them since we last renewed. Editing
    # this line grants nothing on its own (peers enforce against the credential),
    # but the daemon reads its LOCAL side of the peering policy from here, so we
    # keep it in sync with what the CA just issued.
    if list(cred.caps) != list(cfg.caps):
        text = cfg_path.read_text()
        new, n = re.subn(r'(?m)^\s*caps\s*=\s*\[.*\]\s*$',
                         f'caps = {json_mod.dumps(list(cred.caps))}', text, count=1)
        if n:
            cfg_path.write_text(new)
            print(f"caps updated by the hub: {list(cfg.caps)} -> {list(cred.caps)}")
        else:
            log.warning("hub changed caps to %s but couldn't update %s — edit by hand",
                        list(cred.caps), cfg_path)

    print("Restart the daemon to fully adopt it: "
          "sudo systemctl restart greasewood  (or re-run sudo gw run)")
    return 0


# ---------------------------------------------------------------------------
# renew-all  (hub: advertise a fleet-wide "renew asap" hint)
# ---------------------------------------------------------------------------

def cmd_renew_all(args) -> int:
    """
    [hub] Request a fleet-wide credential renewal. Writes renew_after = now, which
    the hub advertises in GET /directory; every cooperating node whose credential
    was issued before that timestamp renews after a jittered delay. The jitter
    window scales with the mesh size (window = N * spread), so the hub's
    renewals/sec stays roughly constant no matter how big the fleet is.

    Pull-based, not a push: nodes act on their next directory poll, and a node
    that's offline now renews when it returns — renew_after is a level, not an
    edge. Handy after a re-root (pull the fleet onto the new CA before the overlap
    window closes) or any fleet-wide policy change.
    """
    from .config import load_config
    _require_root("renew-all", "it writes the hub's root-owned renewal state")
    cfg = load_config(Path(args.config))
    if cfg.role != "hub":
        sys.exit("gw renew-all must be run on the hub (role = hub)")

    now = dt.datetime.now(_UTC).replace(microsecond=0)
    (cfg.data_dir / "renew_after").write_text(now.isoformat())
    print(f"fleet renewal requested: renew_after = {now:%Y-%m-%d %H:%M UTC}")
    print("Cooperating nodes whose credential predates this will renew within a "
          "poll interval + jitter; offline nodes renew when they return.")
    print(f"(To stop advertising it later, delete {cfg.data_dir / 'renew_after'}.)")
    return 0


# ---------------------------------------------------------------------------
# hub-backup / hub-restore  (encrypted CA + registry snapshot)
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


def cmd_hub_backup(args) -> int:
    """Write a single encrypted archive of this hub's trust state (CA key, the
    nodes/ registry, revoke list, door key). Restoring the same key onto a new
    host is a restore, not a re-root — no fleet-wide trust change."""
    from .config import load_config
    from . import backup as bak

    _require_root("hub-backup", "it reads the CA key and the hub registry")
    cfg = load_config(Path(args.config))
    if cfg.role != "hub":
        sys.exit("gw hub-backup must be run on the hub (role = hub)")
    if cfg.ca_key_file is None:
        sys.exit("hub-backup requires ca_key_file in [hub]")

    files = bak.collect_hub_state(cfg.data_dir, cfg.ca_key_file)
    if "ca.key" not in files:
        sys.exit(f"CA key not found at {cfg.ca_key_file} — nothing to back up")

    out = Path(args.out) if args.out else \
        cfg.data_dir / f"greasewood-hub-backup-{cfg.hostname}.gwbk"
    passphrase = _backup_passphrase(confirm=True)
    # This passphrase is the ONLY thing protecting the CA key (and hub id_priv)
    # at rest — a weak one undoes the whole backup. Warn, but don't block.
    if len(passphrase) < 12:
        print(f"⚠ warning: backup passphrase is short ({len(passphrase)} chars). "
              "This one secret guards your entire fleet's root key — use a long, "
              "high-entropy passphrase (a diceware phrase is ideal).")
    blob = bak.pack(files, passphrase)

    fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, blob)
    finally:
        os.close(fd)
    node_count = sum(1 for n in files if n.startswith("nodes/"))
    print(f"wrote encrypted hub backup → {out}")
    print(f"  CA key + {node_count} enrolled node(s) + revoke list + door key")
    print("Store it OFFLINE. Anyone with this file AND the passphrase can "
          "impersonate your CA. Test-restore it before you rely on it.")
    return 0


def cmd_hub_restore(args) -> int:
    """Decrypt a hub backup into a data dir. For standing up a replacement hub
    on the same CA key (see RUNBOOK 'destroyed hub')."""
    _require_root("hub-restore")
    from . import backup as bak

    blob = Path(args.archive).read_bytes()
    data_dir = Path(args.data_dir).expanduser()

    # Guard against clobbering a live hub's CA key by accident.
    if (data_dir / "ca.key").exists() and not args.force:
        sys.exit(f"{data_dir / 'ca.key'} already exists — refusing to overwrite "
                 f"a live hub. Pass --force if you really mean to restore over it.")

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
          f"{data_dir / 'ca.key'} (role = hub), then `sudo gw run`. Because the "
          "CA key is unchanged, existing nodes keep trusting it — no re-root.")
    return 0


# ---------------------------------------------------------------------------
# purge  (decommission or start-over — removes all local greasewood state)
# ---------------------------------------------------------------------------

def cmd_purge(args) -> int:
    _require_root("purge")
    import shutil
    import subprocess

    cfg_path = Path(args.config)

    # Determine interface name, data_dir, and mesh domain from config if available
    iface = "gw-mesh"
    data_dir = Path("/var/lib/greasewood")
    mesh_domain = "gw.internal"
    if cfg_path.exists():
        try:
            from .config import load_config
            cfg = load_config(cfg_path)
            iface = cfg.wg_interface
            data_dir = cfg.data_dir
            mesh_domain = cfg.mesh_domain
        except Exception:
            pass

    if not args.yes:
        print(f"This will permanently remove:")
        print(f"  WireGuard interface : {iface}")
        print(f"  data directory      : {data_dir}")
        print(f"  config file         : {cfg_path}")
        answer = input("Proceed? [y/N] ").strip().lower()
        if answer != "y":
            print("Aborted.")
            return 1

    removed = []
    failed = []

    # Stop the daemon FIRST. A daemon left running through a purge haunts the
    # next mesh on this host: it keeps its stale CA and keys in memory, keeps
    # serving door enrollments, and its mesh interface is gone — so every join
    # against the re-created hub fails with a peer-install error.
    systemctl = shutil.which("systemctl")
    if systemctl:
        r = subprocess.run([systemctl, "is-active", "--quiet", "greasewood"],
                           capture_output=True)
        if r.returncode == 0:
            subprocess.run([systemctl, "stop", "greasewood"], capture_output=True)
            removed.append("stopped greasewood.service")
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

    for item in removed:
        print(f"removed: {item}")
    for item in failed:
        print(f"failed:  {item}")

    if failed:
        return 1
    print("purge complete")
    return 0


# ---------------------------------------------------------------------------
# service management — install-service / uninstall-service (no Ansible needed)
# ---------------------------------------------------------------------------

def cmd_install_service(args) -> int:
    """Install + enable the systemd units so the daemon runs as a managed
    service. After this, create / join is all you need — the service starts
    itself when the config appears. Pip-only; no Ansible required."""
    import shutil
    import subprocess

    if os.geteuid() != 0:
        sys.exit("install-service must run as root (sudo gw install-service)")

    gw_exec = args.exec or shutil.which("gw") or os.path.realpath(sys.argv[0])
    units = {
        "greasewood.service": _SERVICE_UNIT.format(exec=gw_exec),
        "greasewood.path": _PATH_UNIT,
    }
    _UNIT_DIR.mkdir(parents=True, exist_ok=True)
    for name, body in units.items():
        path = _UNIT_DIR / name
        path.write_text(body)
        print(f"wrote {path}")

    systemctl = shutil.which("systemctl")
    if not systemctl:
        print("\nsystemctl not found — on a systemd host, enable once with:")
        print("  systemctl daemon-reload")
        print("  systemctl enable --now greasewood.path")
        print("  systemctl enable greasewood.service")
        return 0

    subprocess.run([systemctl, "daemon-reload"], check=True)
    if not args.no_enable:
        # The path unit (always armed) starts the daemon when config appears;
        # enabling the service makes it also come up at boot once configured.
        subprocess.run([systemctl, "enable", "--now", "greasewood.path"], check=True)
        subprocess.run([systemctl, "enable", "greasewood.service"], check=True)
        print("\nenabled: greasewood.path (armed) + greasewood.service (boot).")
        if Path(getattr(args, "config", "/etc/greasewood.toml")).exists():
            # Config already exists (install-service ran AFTER create/join), so
            # the path unit fires the service right now — verify it actually
            # comes up and STAYS up. `systemctl start` reports success the
            # moment the process execs (Type=simple); a daemon that crashes a
            # second later looks "started" while it silently restart-loops.
            state = _wait_service_settled(systemctl, "greasewood")
            if state == "active":
                print("config present → greasewood.service is up and running.")
            else:
                print(f"⚠ config present but greasewood.service is "
                      f"{state or 'not running'} — it is likely crashing at "
                      f"startup. Look at: journalctl -u greasewood -n 20")
        else:
            print("Run create or join — the daemon starts on its own; no `gw run`.")
        print("Logs: journalctl -u greasewood -f")
        print("Opt out: sudo gw uninstall-service "
              "(or systemctl disable --now greasewood.path greasewood.service)")
    else:
        print("\nunits written (not enabled). Enable with:")
        print("  systemctl enable --now greasewood.path && systemctl enable greasewood.service")
    return 0


def _wait_service_settled(systemctl: str, unit: str, wait_secs: float = 6.0) -> str:
    """Wait for `unit` to reach 'active' and STAY there briefly; return the
    final is-active state ('active', 'activating', 'failed', ...). A unit that
    execs and crashes within a couple of seconds flaps active→activating
    (auto-restart) — the settle re-check catches exactly that."""
    import subprocess
    import time

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


def cmd_uninstall_service(args) -> int:
    """Disable and remove the systemd units (the daemon keeps running until the
    next stop/reboot; this just stops it from auto-starting)."""
    import shutil
    import subprocess

    if os.geteuid() != 0:
        sys.exit("uninstall-service must run as root (sudo gw uninstall-service)")

    systemctl = shutil.which("systemctl")
    if systemctl:
        subprocess.run([systemctl, "disable", "--now",
                        "greasewood.path", "greasewood.service"], check=False)
    for name in ("greasewood.path", "greasewood.service"):
        p = _UNIT_DIR / name
        if p.exists():
            p.unlink()
            print(f"removed {p}")
    if systemctl:
        subprocess.run([systemctl, "daemon-reload"], check=False)
    print("greasewood service removed. (Run `gw run` manually, or reinstall with "
          "`gw install-service`.)")
    return 0


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        prog="gw",
        description="Minimal WireGuard mesh overlay — direct-or-fail, IPv6-only",
        epilog=(
            "sudo requirements:\n"
            "  sudo gw create            -- one-shot hub bootstrap\n"
            "  sudo gw invite                 -- open a door window, print join token\n"
            "  sudo gw join <token> ...     -- enroll this machine (creates WG interfaces)\n"
            "  sudo gw run                  -- start the daemon\n"
            "  sudo gw purge                -- remove all local state\n"
            "\n"
            "no sudo needed (read-only):\n"
            "  gw status\n"
            "  gw diagnose   (add sudo to also see live WireGuard handshake state)\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("-c", "--config", default="/etc/greasewood.toml", metavar="FILE")
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("--version", action="version", version=f"greasewood {_version()}")
    sub = p.add_subparsers(dest="cmd", required=True)

    # create
    sp = sub.add_parser("create",
                        help="[sudo] one-shot hub bootstrap: CA + door key + routing + self-credential")
    sp.add_argument("name",
                    help="the mesh's name (a DNS label, e.g. 'prod-fleet') — "
                         "members resolve as <hostname>.<name>.internal. "
                         "Required so no two meshes sit on the same default: "
                         "a node can never bridge two meshes with one domain.")
    sp.add_argument("--hostname", default=None,
                    help="this hub's hostname in the mesh "
                         "(default: the machine's hostname)")
    sp.add_argument("--data-dir", dest="data_dir", default="/var/lib/greasewood")
    sp.add_argument("--listen-port", dest="listen_port", type=int, default=51900)
    sp.add_argument("--control-port", dest="control_port", type=int, default=51902)
    sp.add_argument("--door-port", dest="door_port", type=int, default=51901,
                    help="UDP port for the enrollment door (carried in tokens)")
    sp.add_argument("--endpoint", default=None, metavar="ADDR",
                    help="underlay IPv6 address (auto-detected if omitted)")
    sp.add_argument("--interface", default="gw-mesh",
                    help="WireGuard interface name (default: gw-mesh; use a "
                         "distinct name per mesh on a multi-homed host)")
    sp.add_argument("--overlay-prefix", dest="overlay_prefix",
                    default="fd8d:e5c1:db1a:7::",
                    help="the fleet's overlay /64 ULA (default: fd8d:e5c1:db1a:7::)")
    sp.add_argument("--mesh-domain", dest="mesh_domain", default=None,
                    help="full domain override (default: <name>.internal)")
    sp.add_argument("--caps", default="",
                    help="extra ability caps for the hub (it always carries "
                         "segment:* to reach every segment), e.g. 'tls'")
    sp.add_argument("--credential-ttl", dest="credential_ttl", default="24h")
    sp.add_argument("--force", action="store_true", help="overwrite existing CA key")
    sp.add_argument("--no-hosts-sync", dest="hosts_sync", action="store_false",
                    help="don't maintain the managed /etc/hosts block "
                         "(<name>.gw.internal -> overlay addr); it's on by default")
    sp.set_defaults(fn=cmd_create, hosts_sync=True)

    # invite
    sp = sub.add_parser("invite",
                        help="[sudo] open a 15-min door window and print a single-use join token")
    sp.add_argument("--hostname", default=None,
                    help="pin the invited node's mesh hostname (the hub fixes it; "
                         "the joiner can't choose or later `gw rename` it). Omit "
                         "to let the node name itself at join.")
    sp.add_argument("--segments", default=None, metavar="S1,S2",
                    help="segments the invited node belongs to (comma-sep). The "
                         "hub decides this — the joiner cannot. A node peers only "
                         "with nodes sharing a segment. Omitted → the hub's "
                         "[hub] default_segments (ships as 'mesh', the flat default "
                         "pool). Naming other segments isolates the node; list "
                         "several to bridge them.")
    sp.add_argument("--caps", default=None,
                    help="ability caps granted to the invited node (comma-sep), "
                         "e.g. 'tls'. Omitted → the hub's [hub] default_caps "
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
                        help="[sudo, hub] close the current door window — "
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
    sp.add_argument("--data-dir", dest="data_dir", default="/var/lib/greasewood")
    sp.add_argument("--listen-port", dest="listen_port", type=int, default=51900)
    sp.add_argument("--interface", default=None,
                    help="WireGuard interface name (default: keep existing, else "
                         "gw-mesh; use a distinct name per mesh on one host)")
    sp.add_argument("--endpoint", default=None, metavar="[ADDR]:PORT",
                    help="this node's underlay endpoint (auto-detected if omitted)")
    sp.add_argument("--no-hosts-sync", dest="hosts_sync", action="store_const",
                    const=False, default=None,
                    help="don't maintain the managed /etc/hosts block "
                         "(<name>.gw.internal -> overlay addr); on by default")
    sp.add_argument("--inbound", choices=["yes", "no"], default=None,
                    help="can peers dial this node? 'no' = outbound-only "
                         "(suppress endpoint, no inbound ports). Default: keep "
                         "existing, else yes.")
    sp.set_defaults(fn=cmd_join)

    # purge
    sp = sub.add_parser("purge",
                        help="[sudo] remove all greasewood state from this machine (decommission or start over)")
    sp.add_argument("--yes", "-y", action="store_true", help="skip confirmation prompt")
    sp.set_defaults(fn=cmd_purge)

    # install-service / uninstall-service
    sp = sub.add_parser("install-service",
                        help="[sudo] install + enable the systemd units (run as a background service)")
    sp.add_argument("--exec", default=None,
                    help="path to the gw executable for ExecStart (default: auto-detect)")
    sp.add_argument("--no-enable", dest="no_enable", action="store_true",
                    help="write the unit files but don't enable/start them")
    sp.set_defaults(fn=cmd_install_service)

    sp = sub.add_parser("uninstall-service",
                        help="[sudo] disable + remove the systemd units")
    sp.set_defaults(fn=cmd_uninstall_service)

    # run
    sp = sub.add_parser("run", help="[sudo] start the daemon (creates WireGuard interface)")
    sp.set_defaults(fn=cmd_run)

    # nodes
    sp = sub.add_parser("status",
                        help="list the mesh nodes in this node's directory (name, "
                             "addr, expiry, state, segments) + who you are")
    sp.add_argument("--by-segment", action="store_true",
                    help="group into one table per segment (a node appears under "
                         "each of its segments; segment:* nodes appear under all)")
    sp.set_defaults(fn=cmd_status)

    # diagnose
    sp = sub.add_parser(
        "diagnose",
        help="explain why THIS node's links to its peers are/aren't forming "
             "(per-peer checks + live handshake, from this node's view — not a fleet dashboard)")
    sp.add_argument("hostname", nargs="?", default=None,
                    help="diagnose only this peer (default: every peer in this "
                         "node's directory cache)")
    sp.add_argument("--no-mtu-probe", dest="no_mtu_probe", action="store_true",
                    help="skip the DF-ping path-MTU check on linked peers "
                         "(which sends a couple of pings per linked peer)")
    sp.set_defaults(fn=cmd_diagnose)

    # revoke
    sp = sub.add_parser("revoke", help="add a node to the revoke list (run on the hub)")
    sp.add_argument("id_pub_hex", help="64-char hex identity public key")
    sp.set_defaults(fn=cmd_revoke)

    # set-caps (hub) — change an enrolled node's full tag set
    sp = sub.add_parser("set-caps",
                        help="[hub] change an enrolled node's caps (effective next renewal)")
    sp.add_argument("node", help="node hostname (or its 64-char id_pub hex)")
    sp.add_argument("caps", help="comma-separated full tag set, e.g. "
                                 "'segment:prod,tls' (replaces the node's current caps)")
    sp.set_defaults(fn=cmd_set_caps)

    # set-segments (hub) — change only a node's segments
    sp = sub.add_parser("set-segments",
                        help="[hub] change an enrolled node's segments "
                             "(effective next renewal)")
    sp.add_argument("node", help="node hostname (or its 64-char id_pub hex)")
    sp.add_argument("segments", help="comma-separated segments, e.g. 'prod,web' "
                                     "(replaces segment tags; keeps tls; empty = mesh default)")
    sp.set_defaults(fn=cmd_set_segments)

    # hub-promote (on the prospective new hub)
    sp = sub.add_parser("hub-promote",
                        help="[sudo] turn this enrolled node into a hub (generate CA key, set role=hub)")
    sp.add_argument("--control-port", dest="control_port", type=int, default=51902)
    sp.add_argument("--credential-ttl", dest="credential_ttl", default="24h")
    sp.set_defaults(fn=cmd_hub_promote)

    # cert-request (on a node with the 'tls' capability)
    sp = sub.add_parser("cert-request",
                        help="request an x509 TLS cert from the hub for a local service")
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
    sp.add_argument("--hub", default=None, help="override the hub control-plane URL")
    sp.add_argument("--reload-cmd", dest="reload_cmd", default=None, metavar="CMD",
                    help="command the daemon runs after auto-renewing this cert, "
                         "e.g. 'systemctl reload postgresql'. Run as an argv, not "
                         "through a shell — for pipes/redirects wrap it: "
                         "\"sh -c '...'\"")
    sp.add_argument("--no-auto-renew", dest="no_auto_renew", action="store_true",
                    help="do not auto-renew this cert in the daemon (one-shot; "
                         "re-run manually before expiry)")
    sp.set_defaults(fn=cmd_cert_request)

    # cert-status
    sp = sub.add_parser("cert-status", help="show local TLS certs and expiry")
    sp.add_argument("--out-dir", dest="out_dir", default=None)
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

    # set-inbound
    sp = sub.add_parser("set-inbound",
                        help="change reachability: yes (dialable) / no (outbound-only)")
    sp.add_argument("value", choices=["yes", "no"])
    sp.set_defaults(fn=cmd_set_inbound)

    # rename
    sp = sub.add_parser("rename",
                        help="[sudo] change this node's mesh hostname (hub-validated, no re-join)")
    sp.add_argument("hostname", help="the new hostname")
    sp.set_defaults(fn=cmd_rename)

    # renew
    sp = sub.add_parser("renew",
                        help="[sudo] force an immediate credential renewal for THIS "
                             "node (applies a hub-side set-caps/set-segments now, "
                             "instead of waiting ~half the TTL)")
    sp.set_defaults(fn=cmd_renew)

    # renew-all
    sp = sub.add_parser("renew-all",
                        help="[hub] request a fleet-wide renewal — advertise "
                             "renew_after=now so cooperating nodes renew (jittered, "
                             "rate ~constant with mesh size)")
    sp.set_defaults(fn=cmd_renew_all)

    # hub-backup
    sp = sub.add_parser("hub-backup",
                        help="[hub] write an encrypted backup of the CA key + "
                             "node registry + revoke list (passphrase via prompt "
                             "or $GW_BACKUP_PASSPHRASE)")
    sp.add_argument("--out", default=None, metavar="PATH",
                    help="output file (default: <data_dir>/greasewood-hub-backup-"
                         "<hostname>.gwbk)")
    sp.set_defaults(fn=cmd_hub_backup)

    # hub-restore
    sp = sub.add_parser("hub-restore",
                        help="[sudo] restore a hub backup into a data dir (stand "
                             "up a replacement hub on the same CA key — not a re-root)")
    sp.add_argument("archive", help="the .gwbk backup file")
    sp.add_argument("--data-dir", default="/var/lib/greasewood",
                    help="where to restore (default: /var/lib/greasewood)")
    sp.add_argument("--force", action="store_true",
                    help="overwrite an existing ca.key in the target dir")
    sp.set_defaults(fn=cmd_hub_restore)

    args = p.parse_args(argv)
    _setup_logging(args.verbose)
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
