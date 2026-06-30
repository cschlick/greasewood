"""
gw — CLI entry point.

Enrollment is door-based: a transient WireGuard tunnel, no SSH, no HTTP on the
underlay.

  On the hub:
    gw setup-hub          # one-shot: CA, door key, routing, self-credential
    gw run                # start the daemon (serves control plane + door)
    gw mint               # open a 15-min window, print a single-use join token

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
import getpass
import json
import logging
import os
import signal
import socket
import sys
import threading
import time
from pathlib import Path

_UTC = dt.timezone.utc
log = logging.getLogger("greasewood")


def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
        level=level,
    )


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
# Only run once this node is configured (setup-hub / join writes the config);
# greasewood.path starts us the moment it appears.
ConditionPathExists=/etc/greasewood.toml

[Service]
Type=simple
# gw run creates WireGuard interfaces and edits routing → runs as root.
ExecStart={exec} run
Restart=on-failure
RestartSec=5

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
# setup-hub  (one-shot hub bootstrap: CA + door key + routing + self-credential)
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


def cmd_setup_hub(args) -> int:
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
    hostname = args.hostname
    listen_port = args.listen_port
    control_port = args.control_port
    caps = [c.strip() for c in args.caps.split(",")]
    ttl = _parse_duration(args.credential_ttl)

    endpoint = args.endpoint
    if not endpoint:
        ip = _detect_public_ipv6()
        if ip:
            endpoint = f"[{ip}]:{listen_port}"
            log.info("detected public IPv6 endpoint: %s", endpoint)

    data_dir.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(data_dir, 0o700)
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

    # Door keypair (persistent across mints)
    load_or_generate_door_key(data_dir)
    log.info("door key ready → %s/door.key", data_dir)

    # Set up door routing (idempotent — also called in gw run for reboots)
    wgmod.setup_door_routing()

    # If run via sudo, give data_dir to the real operator so they can
    # run gw mint without sudo.
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user:
        import pwd
        try:
            pw = pwd.getpwnam(sudo_user)
            for path in [data_dir, *data_dir.rglob("*")]:
                try:
                    os.chown(path, pw.pw_uid, -1)
                except OSError:
                    pass
            log.info("data_dir ownership → %s", sudo_user)
        except KeyError:
            pass

    ca_pub_hex = ca_keys.ca_pub_bytes.hex()

    node_keys = NodeKeys.load_or_generate(data_dir)
    log.info("overlay addr: %s", node_keys.addr)

    endpoint_line = f'\nendpoints = ["{endpoint}"]' if endpoint else ""
    hosts_sync = "true" if getattr(args, "hosts_sync", False) else "false"
    cfg_path.parent.mkdir(parents=True, exist_ok=True)
    cfg_path.write_text(f"""[node]
hostname = "{hostname}"
data_dir = "{data_dir}"
role = "hub"
inbound = "yes"
caps = {json_mod.dumps(caps)}{endpoint_line}

[network]
interface = "gw-mesh"
listen_port = {listen_port}
seeds = []
root_url = "http://[::1]:{control_port}"
hosts_sync = {hosts_sync}
mesh_domain = "internal"

[ca]
trusted_pubs = ["{ca_pub_hex}"]

[hub]
ca_key_file = "{ca_key_path}"
control_listen = ":{control_port}"
credential_ttl = "{args.credential_ttl}"
renew_before = "12h"
door_window = "15m"
door_port = {args.door_port}
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
        endpoints=[endpoint] if endpoint else [],
        inbound="yes",
        hostname=hostname,
        cred=cred,
    ).sign(node_keys.id_priv)
    directory.put(record)
    directory.save(dir_cache)

    ep_host = endpoint.rsplit(":", 1)[0] if endpoint else None
    control_url = (
        f"http://{ep_host}:{control_port}" if ep_host
        else f"http://[{node_keys.addr}]:{control_port}"
    )

    print(f"\nHub setup complete.")
    print(f"  overlay addr : {node_keys.addr}")
    print(f"  CA pub key   : {ca_pub_hex}")
    print(f"  credential   : expires {cred.exp:%Y-%m-%d %H:%M UTC}")
    print()
    print(f"Start the daemon (then mint tokens to enroll nodes):")
    print(f"  sudo gw run")
    print()
    print(f"Enroll a new node:")
    print(f"  TOKEN=$(sudo gw mint)          # on this machine")
    print(f"  sudo gw join \"$TOKEN\" --hostname <name>   # on the new machine")
    print()
    _print_firewall_help(listen_port, control_port)
    print()
    from . import firewall as _fw
    _rules = _fw.hub_rules(listen_port, control_port)
    if getattr(args, "open_firewall", False):
        _fw.apply(_rules, log)
    else:
        _fw.check(_rules, log)
    return 0


# ---------------------------------------------------------------------------
# mint  (hub — generate a join token and open a door window)
# ---------------------------------------------------------------------------

def cmd_mint(args) -> int:
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
    if cfg.role not in ("hub", "root"):
        sys.exit("gw mint must be run on the hub node (role = hub)")
    if cfg.ca_key_file is None:
        sys.exit("mint requires ca_key_file in [hub]")

    data_dir = cfg.data_dir

    # The door is a single slot: a new mint regenerates the guest key and
    # overwrites the one window, so any previously minted-but-unused token
    # stops working. Warn (don't fail) if we're clobbering a still-open
    # window — for orderly provisioning, mint the next token only after the
    # current node has joined (the window clears automatically on success).
    open_exp = active_window_expiry(data_dir)
    if open_exp:
        log.warning(
            "superseding an open door window (expires %s) — the previously "
            "minted token is now INVALID. The door enrolls one node at a time; "
            "mint the next token only after the current node has joined.",
            open_exp,
        )

    door_key_raw = load_or_generate_door_key(data_dir)
    hub_door_pub = door_pub_bytes_from_key(door_key_raw)
    import base64
    door_key_b64 = base64.b64encode(door_key_raw).decode()

    from .keys import CAKeys
    ca_keys = CAKeys.load(cfg.ca_key_file, _get_passphrase(cfg.ca_key_passphrase_env))

    # Detect hub's underlay endpoint for the token (nodes need it to reach gw-door)
    endpoint = args.endpoint
    if not endpoint:
        ip = _detect_public_ipv6()
        if not ip:
            sys.exit("could not detect a public IPv6 address; use --endpoint")
        endpoint = ip

    window = cfg.door_window

    seed = generate_seed()
    params = derive_door_params(seed)

    # Set up door routing (idempotent — survives reboots if called here too)
    wgmod.setup_door_routing()

    # Bring up the hub's door WG interface on the configured door port
    door_key_path = data_dir / "door.key"
    wgmod.ensure_hub_door_interface(door_key_path, params.guest_pub_b64,
                                    params.psk_b64, cfg.door_port)

    # Write window file so the running gw-run daemon starts the enroll server
    expires = dt_mod.datetime.now(dt_mod.timezone.utc) + window
    window_path = data_dir / "door_window.json"
    window_path.write_text(json_mod.dumps({
        "v": 1,
        "expires": expires.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }))

    token = encode_token(hub_door_pub, ca_keys.ca_pub_bytes, endpoint, seed,
                         cfg.door_port)
    print(token)
    return 0


# ---------------------------------------------------------------------------
# join  (new node — door-based enrollment, no SSH)
# ---------------------------------------------------------------------------

def cmd_join(args) -> int:
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

    token = args.token
    cfg_path = Path(args.config)
    data_dir = Path(args.data_dir)
    listen_port = args.listen_port

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
        hostname = f"{getpass.getuser()}@{socket.gethostname()}"

    if args.caps is not None:
        caps = [c.strip() for c in args.caps.split(",")]
    elif prior and prior.caps:
        caps = list(prior.caps)
    else:
        caps = ["mesh"]

    # inbound: "yes" (reachable, advertise endpoint), "no" (outbound-only,
    # suppress endpoint — peers won't dial it; it dials them), or "unknown".
    if args.inbound is not None:
        node_inbound = args.inbound
    elif prior and getattr(prior, "inbound", None):
        node_inbound = prior.inbound
    else:
        node_inbound = "yes"

    # Endpoint = where other nodes dial this one for a direct tunnel. If not
    # given, try to auto-detect a public IPv6. A node with no endpoint can
    # still reach the hub (it initiates outbound), but peers can't dial it, so
    # node<->node links won't form unless the other side is reachable.
    endpoint = args.endpoint
    if not endpoint:
        ip = _detect_public_ipv6()
        if ip:
            endpoint = f"[{ip}]:{listen_port}"
            log.info("detected public IPv6 endpoint: %s", endpoint)
        elif prior and prior.endpoints:
            endpoint = prior.endpoints[0]
            log.info("keeping existing endpoint: %s", endpoint)
        else:
            log.warning(
                "no public IPv6 endpoint detected — this node will be reachable "
                "only by initiating outbound (e.g. to the hub); other nodes "
                "cannot dial it, so direct node-to-node links may not form. "
                "Pass --endpoint '[ADDR]:%d' if this node is publicly reachable.",
                listen_port,
            )

    # Decode token → hub_door_pub, ca_pub, hub_host, seed, door_port
    try:
        hub_door_pub_bytes, ca_pub_bytes, hub_host, seed, door_port = decode_token(token)
    except ValueError as e:
        sys.exit(f"invalid token: {e}")

    hub_door_pub_b64 = base64.b64encode(hub_door_pub_bytes).decode()
    ca_pub_hex = ca_pub_bytes.hex()

    # Derive door params from seed (same derivation the hub ran at mint time)
    params = derive_door_params(seed)
    log.info("guest_pub: ...%s", params.guest_pub_b64[-8:])

    # Generate this node's permanent keypairs
    data_dir.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(data_dir, 0o700)
    except PermissionError:
        pass
    node_keys = NodeKeys.load_or_generate(data_dir)
    if already_enrolled:
        log.info(
            "re-enrolling existing node %s (keys reused; refreshing credential, "
            "hostname=%s, caps=%s)", node_keys.addr, hostname, caps,
        )
    log.info("overlay addr: %s", node_keys.addr)

    # Bring up the local door interface (door port comes from the token)
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

    # Send enroll request
    req = {
        "v": 1,
        "id_pub": node_keys.id_pub_hex,
        "wg_pub": node_keys.wg_pub_b64,
        "hostname": hostname,
        "caps": caps,
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
        sys.exit(f"enrollment rejected: {resp.get('error')} — {resp.get('reason')}")

    # Verify and install the credential (gw-door still up — needed for door publish below)
    cred = Credential.from_dict(resp["credential"])
    try:
        cred.verify([ca_pub_bytes])
    except Exception as e:
        wgmod.destroy_interface("gw-door")
        sys.exit(f"credential verification failed: {e}")
    if cred.id_pub != node_keys.id_pub_bytes:
        wgmod.destroy_interface("gw-door")
        sys.exit("credential id_pub mismatch — something went wrong")
    log.info("credential verified, expires %s", cred.exp.strftime("%Y-%m-%d %H:%M UTC"))

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
    adv_endpoints = [endpoint] if (endpoint and node_inbound != "no") else []
    record = NodeRecord(
        id_pub=node_keys.id_pub_bytes,
        seq=seq,
        endpoints=adv_endpoints,
        inbound=node_inbound,
        hostname=hostname,
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

    endpoint_line = f'\nendpoints = ["{endpoint}"]' if endpoint else ""
    seeds_list = json_mod.dumps([hub_overlay_url]) if hub_overlay_url else "[]"
    root_url_val = json_mod.dumps(hub_overlay_url) if hub_overlay_url else '""'
    # hosts sync: explicit flag wins, else keep prior setting, else off.
    if getattr(args, "hosts_sync", False):
        hosts_sync = "true"
    elif prior and getattr(prior, "hosts_sync", False):
        hosts_sync = "true"
    else:
        hosts_sync = "false"
    mesh_domain = (prior.mesh_domain if prior and getattr(prior, "mesh_domain", None)
                   else "internal")

    cfg_path.parent.mkdir(parents=True, exist_ok=True)
    cfg_path.write_text(f"""[node]
hostname = "{hostname}"
data_dir = "{data_dir}"
role = "node"
inbound = "{node_inbound}"
caps = {json_mod.dumps(caps)}{endpoint_line}

[network]
interface = "gw-mesh"
listen_port = {listen_port}
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
    print(f"Start the daemon:")
    print(f"  sudo gw run")
    print()
    print()
    from . import firewall as _fw
    if node_inbound == "no":
        log.warning(
            "firewall: inbound=no — outbound-only. No greasewood inbound ports "
            "are needed (it dials peers + the hub's door outbound); just keep "
            "your base 'ct state established,related accept' rule for replies. "
            "Note: this node can only pair with inbound-reachable nodes, not "
            "with other outbound-only nodes, and cannot be promoted to hub "
            "without switching to inbound (gw set-inbound yes --open-firewall)."
        )
    else:
        _print_firewall_help(listen_port)
        print()
        _rules = _fw.node_rules(listen_port, node_inbound)
        if getattr(args, "open_firewall", False):
            _fw.apply(_rules, log)
        else:
            _fw.check(_rules, log)
    return 0



# ---------------------------------------------------------------------------
# revoke
# ---------------------------------------------------------------------------

def cmd_revoke(args) -> int:
    from .config import load_config
    from .keys import CAKeys
    from .ca import CA

    cfg = load_config(Path(args.config))
    if cfg.ca_key_file is None:
        sys.exit("ca_key_file must be set in [root]")

    ca_keys = CAKeys.load(cfg.ca_key_file, _get_passphrase(cfg.ca_key_passphrase_env))
    ca = CA(ca_keys, cfg.data_dir)

    try:
        id_pub_bytes = bytes.fromhex(args.id_pub_hex)
    except ValueError:
        sys.exit("id_pub_hex must be a 64-character hex string")

    ca.add_revoke(id_pub_bytes)
    print(f"revoked: {args.id_pub_hex}")
    print("The node's existing credential will expire naturally.")
    print("Restart the daemon to reload the revoke list into the reconcile loop.")
    return 0


# ---------------------------------------------------------------------------
# hub succession (§11) — hub-promote / hub-endorse / hub-retire
# ---------------------------------------------------------------------------

def _control_port(cfg) -> int:
    """The control-plane port from cfg.control_listen (':51902' -> 51902)."""
    try:
        return int(cfg.control_listen.rsplit(":", 1)[1])
    except (ValueError, IndexError):
        return 51902


def cmd_hub_promote(args) -> int:
    """On a prospective new hub (currently a node): mint its own CA key and
    rewrite its config to role=hub, so a restart makes it serve as a hub.
    Prints the CA public key + control endpoint to hand to `gw hub-endorse`."""
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
            "  sudo gw set-inbound yes --open-firewall\n"
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
    # we accept credentials we issue even before the bundle has propagated.
    trusted = list(dict.fromkeys([*cfg.ca_pubs, ca_pub_hex]))

    endpoint_line = (
        f'\nendpoints = {json_mod.dumps(cfg.endpoints)}' if cfg.endpoints else ""
    )
    hosts_sync = "true" if cfg.hosts_sync else "false"
    cfg_path.write_text(f"""[node]
hostname = "{cfg.hostname}"
data_dir = "{cfg.data_dir}"
role = "hub"
inbound = "yes"
caps = {json_mod.dumps(cfg.caps)}{endpoint_line}

[network]
interface = "{cfg.wg_interface}"
listen_port = {cfg.listen_port}
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
""")
    log.info("promoted to hub role in %s", cfg_path)

    print("\nReady to become a hub. CA key generated; config set to role=hub.")
    print(f"  CA pub key   : {ca_pub_hex}")
    print(f"  hub endpoint : {endpoint}")
    print()
    print("Next, on the CURRENT hub, endorse this one:")
    print(f"  gw hub-endorse --ca-pub {ca_pub_hex} \\")
    print(f"                 --endpoint {endpoint}")
    print("Then restart the daemon here:  sudo gw run")
    print()
    from . import firewall as _fw
    _rules = _fw.hub_rules(cfg.listen_port, control_port)
    if getattr(args, "open_firewall", False):
        _fw.apply(_rules, log)
    else:
        _fw.check(_rules, log)
    return 0


def _load_ca_for_succession(cfg):
    from .keys import CAKeys
    from .ca import CA
    if cfg.ca_key_file is None:
        sys.exit("this command must run on a hub (no ca_key_file in config)")
    ca_keys = CAKeys.load(cfg.ca_key_file, _get_passphrase(cfg.ca_key_passphrase_env))
    return CA(ca_keys, cfg.data_dir, cfg.credential_ttl)


def _append_to_bundle(cfg, stmt) -> None:
    from .trust import CABundle
    bundle = CABundle.load(cfg.ca_bundle_path)
    bundle.merge([stmt])
    bundle.save(cfg.ca_bundle_path)


def cmd_hub_endorse(args) -> int:
    """On the current hub: endorse another CA as a successor and advertise its
    endpoint. The endorsement enters the bundle and propagates to the fleet."""
    from .config import load_config, _parse_duration

    cfg = load_config(Path(args.config))
    ca = _load_ca_for_succession(cfg)
    try:
        subject_pub = bytes.fromhex(args.ca_pub)
        if len(subject_pub) != 32:
            raise ValueError
    except ValueError:
        sys.exit("--ca-pub must be a 64-character hex Ed25519 public key")

    ttl = _parse_duration(args.ttl)
    stmt = ca.endorse(subject_pub, args.endpoint, ttl)
    _append_to_bundle(cfg, stmt)

    print(f"endorsed CA {args.ca_pub[:16]}… as successor")
    print(f"  endpoint : {args.endpoint}")
    print(f"  valid    : {stmt.exp:%Y-%m-%d %H:%M UTC}")
    print()
    print("The fleet will trust the new CA within one sync cycle. Start the new")
    print("hub (sudo gw run there); nodes repoint to it and renew under it.")
    print("After the overlap, run 'gw hub-retire' for the old CA.")
    return 0


def cmd_hub_retire(args) -> int:
    """On a hub: retire a CA (typically the predecessor) so the fleet stops
    accepting its signatures. Run after the successor has taken over."""
    from .config import load_config, _parse_duration

    cfg = load_config(Path(args.config))
    ca = _load_ca_for_succession(cfg)
    try:
        subject_pub = bytes.fromhex(args.ca_pub)
        if len(subject_pub) != 32:
            raise ValueError
    except ValueError:
        sys.exit("--ca-pub must be a 64-character hex Ed25519 public key")

    ttl = _parse_duration(args.ttl)
    # Grace = how long the old CA stays trusted before the retirement bites, so
    # every node migrates to the new CA first. Defaults to one credential TTL.
    grace = _parse_duration(args.grace) if args.grace else cfg.credential_ttl
    stmt = ca.retire(subject_pub, ttl, grace)
    _append_to_bundle(cfg, stmt)

    print(f"retired CA {args.ca_pub[:16]}… effective {stmt.iat:%Y-%m-%d %H:%M UTC}")
    print(f"  grace    : {grace} (nodes must renew under the new CA before then)")
    print("Until the effective time the old CA stays trusted, so the migration")
    print("is non-disruptive. Decommission the old hub after the effective time.")
    return 0


# ---------------------------------------------------------------------------
# TLS service certificates (§12) — cert-request / cert-status
# ---------------------------------------------------------------------------

def _resolve_hub_url(cfg) -> str:
    """The control-plane URL to talk to: the current active hub (per the CA
    bundle), falling back to the configured root_url."""
    from .trust import CABundle, active_hub_endpoint
    roots = {bytes.fromhex(h) for h in cfg.ca_pubs}
    bundle = CABundle.load(cfg.ca_bundle_path)
    return active_hub_endpoint(roots, bundle) or cfg.root_url


def cmd_cert_request(args) -> int:
    """Request an x509 TLS cert from the hub for a local service (e.g. Postgres).
    Generates the leaf key locally; only its public key is sent to the hub."""
    import json as json_mod
    import ipaddress
    import secrets
    import urllib.error
    import urllib.request
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from .config import load_config
    from .keys import NodeKeys
    from .wire import CertRequest

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
    # valid for exactly the name peers resolve it by (the /etc/hosts block and
    # the cert SAN use the same <hostname>.<mesh_domain>) plus its raw address.
    if not dns and not ips:
        from .hosts import mesh_name
        dns = [mesh_name(cfg.hostname, cfg.mesh_domain)]
        ips = [keys.addr]

    cn = args.cn or (dns[0] if dns else (ips[0] if ips else keys.addr))
    name = args.name or (dns[0] if dns else "service")
    out_dir = Path(args.out_dir) if args.out_dir else (cfg.data_dir / "tls")

    hub_url = _resolve_hub_url(cfg)
    if not hub_url:
        sys.exit("no hub URL — set root_url in config or pass --hub")
    if args.hub:
        hub_url = args.hub

    # Generate the leaf (service) keypair locally; the private key never leaves.
    leaf = Ed25519PrivateKey.generate()
    leaf_pub = leaf.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )

    req = CertRequest(
        id_pub=keys.id_pub_bytes,
        leaf_pub=leaf_pub,
        cn=cn,
        dns=dns,
        ips=ips,
        nonce=secrets.token_hex(16),
        ts=dt.datetime.now(_UTC).replace(microsecond=0),
    ).sign(keys.id_priv)

    body = json_mod.dumps(req.to_dict()).encode()
    url = f"{hub_url.rstrip('/')}/cert"
    # Retry a few times — the overlay tunnel to the hub may still be settling
    # right after the node starts.
    import time as _t
    data = None
    last_err = None
    for attempt in range(5):
        http_req = urllib.request.Request(
            url, data=body, headers={"Content-Type": "application/json"}
        )
        try:
            with urllib.request.urlopen(http_req, timeout=10) as resp:
                data = json_mod.loads(resp.read())
            break
        except urllib.error.HTTPError as e:
            # The hub answered with an error — surface its reason. 4xx (e.g. no
            # tls capability, bad request) won't change on retry; fail fast.
            try:
                msg = json_mod.loads(e.read()).get("error", str(e))
            except Exception:
                msg = str(e)
            if 400 <= e.code < 500:
                sys.exit(f"cert request rejected: {msg}")
            last_err = msg
            if attempt < 4:
                _t.sleep(3)
        except urllib.error.URLError as e:
            last_err = e
            if attempt < 4:
                _t.sleep(3)
    if data is None:
        sys.exit(f"cert request to {hub_url} failed: {last_err}")
    if "error" in data:
        sys.exit(f"cert request rejected: {data['error']}")

    leaf_key_pem = leaf.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    out_dir.mkdir(parents=True, exist_ok=True)
    key_path = out_dir / f"{name}.key"
    crt_path = out_dir / f"{name}.crt"
    ca_path = out_dir / "ca.crt"
    # Private key 0600; certs world-readable.
    fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, leaf_key_pem)
    finally:
        os.close(fd)
    crt_path.write_text(data["cert"])
    ca_path.write_text(data["ca_cert"])

    print("TLS certificate issued.")
    print(f"  cn       : {cn}")
    if dns:
        print(f"  dns SANs : {', '.join(dns)}")
    if ips:
        print(f"  ip SANs  : {', '.join(ips)}")
    print(f"  key      : {key_path}")
    print(f"  cert     : {crt_path}")
    print(f"  ca cert  : {ca_path}")
    print()
    print("Point your service at these (e.g. Postgres ssl_cert_file / ssl_key_file,")
    print("clients ssl_ca_file = ca.crt). Re-run before expiry to renew.")
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
    """Change this node's reachability (yes/no/unknown). Switching to inbound
    means peers can dial it — so it can hold direct links to outbound-only nodes
    and be promoted to hub — but it must accept the WireGuard port; pair with
    --open-firewall to open it. Restart the daemon to advertise the change."""
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
        is_hub = cfg.role in ("hub", "root")
        rules = (_fw.hub_rules(cfg.listen_port, _control_port(cfg))
                 if is_hub else _fw.node_rules(cfg.listen_port, value))
        if getattr(args, "open_firewall", False):
            _fw.apply(rules, log)
        else:
            _fw.check(rules, log)
    print("Restart the daemon to advertise the change: sudo systemctl restart "
          "greasewood  (or re-run sudo gw run)")
    return 0


# ---------------------------------------------------------------------------
# run
# ---------------------------------------------------------------------------

def cmd_run(args) -> int:
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
    log.info("starting — role=%s hostname=%s", cfg.role, cfg.hostname)

    keys = NodeKeys.load_or_generate(cfg.data_dir)
    log.info("overlay addr: %s", keys.addr)

    directory = Directory.load(cfg.dir_cache_path)

    # Live trust state: static roots + the CA-succession bundle. Everything that
    # asks "who do I trust?" / "where is the hub?" reads from here, so trust and
    # the active hub can change at runtime as the bundle syncs (§11).
    from .trust import CABundle, TrustStore, TrustSyncLoop
    trust = TrustStore(
        roots=[bytes.fromhex(h) for h in cfg.ca_pubs],
        bundle=CABundle.load(cfg.ca_bundle_path),
        bundle_path=cfg.ca_bundle_path,
        static_seeds=cfg.seeds,
        fallback_hub_url=cfg.root_url,
    )

    wgmod.ensure_interface(
        cfg.wg_interface, keys.addr, cfg.listen_port, cfg.wg_key_path
    )

    ca: CA | None = None
    sync: SyncLoop | None = None
    renewal: RenewalLoop | None = None
    door_watcher = None
    trust_sync = None

    # Revoke list is re-read live (not snapshotted) so `gw revoke` takes effect
    # without a daemon restart — both for control-plane refusal and local
    # eviction. Plain nodes have no revoke list (expiry-based revocation).
    get_revoked: "callable" = set
    is_hub = cfg.role in ("hub", "root")

    if is_hub:
        if not cfg.ca_key_file:
            sys.exit("hub role requires ca_key_file in [hub]")
        ca_keys = CAKeys.load(cfg.ca_key_file, _get_passphrase(cfg.ca_key_passphrase_env))
        ca = CA(ca_keys, cfg.data_dir, cfg.credential_ttl)
        get_revoked = ca.load_revoked_set
        log.info("CA loaded, pub=%s...", ca_keys.ca_pub_bytes.hex()[:16])
        # Re-apply door routing in case the machine rebooted since setup-hub
        wgmod.setup_door_routing()

        # Bind the control plane to the overlay address (reachable only through
        # the mesh) and loopback (for the hub talking to itself) — NOT "::".
        # This keeps it off the underlay structurally, no firewall rule needed.
        port = _control_port(cfg)
        listen_addrs = [f"[{keys.addr}]:{port}", f"[::1]:{port}"]
        srv = ControlServer(
            listen_addrs,
            directory,
            get_ca_pubs=trust.trusted_pubs,
            get_revoked=get_revoked,
            ca=ca,
            cache_path=cfg.dir_cache_path,
            get_bundle=trust.bundle_dict,
            tls_cert_ttl=cfg.tls_cert_ttl,
        )
        srv.start()

        from .enroll import DoorWatcher
        door_watcher = DoorWatcher(
            data_dir=cfg.data_dir,
            ca=ca,
            directory=directory,
            node_keys=keys,
            wg_iface=cfg.wg_interface,
            get_ca_pubs=trust.trusted_pubs,
            get_revoked=get_revoked,
            cache_path=cfg.dir_cache_path,
            control_port=_control_port(cfg),
        )
        door_watcher.start()
        log.info("door watcher started")

    # Keep the trusted-CA set current (picks up succession bundle + local
    # hub-endorse/retire writes). Runs on every role.
    trust_sync = TrustSyncLoop(trust)
    trust_sync.start()

    # Directory sync — seeds follow the active hub via the TrustStore.
    sync = SyncLoop(directory, trust.seeds, cfg.dir_cache_path)
    sync.start()

    # Name resolution via a managed /etc/hosts block (opt-in). When off, remove
    # any block we left behind before (clean opt-out).
    from . import hosts as _hosts
    if cfg.hosts_sync:
        log.info("hosts: maintaining /etc/hosts mesh block under .%s", cfg.mesh_domain)
    else:
        try:
            if _hosts.remove_block():
                log.info("hosts: removed managed /etc/hosts block (sync disabled)")
        except Exception as e:
            log.warning("hosts: could not clean /etc/hosts: %s", e)

    recon = ReconcileLoop(
        iface=cfg.wg_interface,
        directory=directory,
        local_id_pub=keys.id_pub_bytes,
        local_caps=cfg.caps,
        get_ca_pubs=trust.trusted_pubs,
        get_revoked=get_revoked,
        hosts_domain=cfg.mesh_domain if cfg.hosts_sync else None,
    )
    recon.start()

    # Effective advertised endpoints: outbound-only nodes (inbound=no) suppress
    # their endpoint so peers don't waste handshakes dialing an unreachable addr.
    eff_endpoints = [] if cfg.inbound == "no" else cfg.endpoints

    # Honor config changes on (re)start: if our record's inbound/endpoints no
    # longer match config (e.g. after `gw set-inbound`), re-sign it so what we
    # advertise is current — the daemon reads config only at startup.
    own_record = directory.get(keys.id_pub_hex)
    if own_record and (own_record.inbound != cfg.inbound
                       or list(own_record.endpoints) != list(eff_endpoints)):
        from .wire import NodeRecord
        own_record = NodeRecord(
            id_pub=keys.id_pub_bytes,
            seq=own_record.seq + 1,
            endpoints=eff_endpoints,
            inbound=cfg.inbound,
            hostname=cfg.hostname,
            cred=own_record.cred,
        ).sign(keys.id_priv)
        directory.put(own_record)
        directory.save(cfg.dir_cache_path)
        log.info("updated own record (inbound=%s, endpoints=%s)",
                 cfg.inbound, eff_endpoints)

    # Push our own record so the rest of the mesh knows about us. This gets a
    # newly enrolled node into the hub's directory; it is also how endpoint
    # changes propagate without waiting for the next renewal cycle.
    if own_record:
        for seed in trust.seeds():
            try:
                push_record(seed, own_record)
                log.info("pushed own record to %s", seed)
            except Exception as e:
                log.warning("push to %s failed (will retry on next sync): %s", seed, e)

    # Renewal loop — targets the active hub (follows succession).
    if own_record:
        renewal = RenewalLoop(
            node_keys=keys,
            directory=directory,
            get_root_url=trust.hub_url,
            current_cred=own_record.cred,
            inbound=cfg.inbound,
            hostname=cfg.hostname,
            endpoints=eff_endpoints,
            cache_path=cfg.dir_cache_path,
        )
        renewal.start()
    else:
        log.warning("no credential in directory — run 'gw join <token>' first")

    # Block until SIGTERM / SIGINT
    stop_flag = threading.Event()

    def _handle_signal(signum, frame):
        log.info("caught signal %d, shutting down", signum)
        stop_flag.set()

    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    stop_flag.wait()

    recon.stop()
    if trust_sync:
        trust_sync.stop()
    if sync:
        sync.stop()
    if renewal:
        renewal.stop()
    if door_watcher:
        door_watcher.stop()
    log.info("shutdown complete")
    return 0


# ---------------------------------------------------------------------------
# status
# ---------------------------------------------------------------------------

def cmd_status(args) -> int:
    from .config import load_config
    from .keys import NodeKeys
    from .directory import Directory

    cfg_path = Path(args.config)
    if not cfg_path.exists():
        print("not configured (no config file at %s)" % cfg_path)
        return 0

    cfg = load_config(cfg_path)

    try:
        keys = NodeKeys.load(cfg.data_dir)
        own_id = keys.id_pub_hex
        own_addr = keys.addr
    except FileNotFoundError:
        own_id = None
        own_addr = None

    print(f"role     : {cfg.role}")
    print(f"hostname : {cfg.hostname}")
    print(f"addr     : {own_addr or '(keys not generated)'}")
    print()

    directory = Directory.load(cfg.dir_cache_path)
    now = dt.datetime.now(_UTC)
    records = sorted(directory.all(), key=lambda r: r.hostname)

    if not records:
        print("directory is empty — run 'gw join <token>' then 'gw run'")
        return 0

    fmt = "{:<20} {:<44} {:<22} {}"
    print(fmt.format("hostname", "addr", "expires", "state"))
    print("-" * 92)
    for r in records:
        exp = r.cred.exp
        left = (exp - now).total_seconds()
        if left < 0:
            state = "EXPIRED"
        elif left < 3600:
            state = f"expiring ({int(left / 60)}m)"
        else:
            state = "ok"
        marker = " ← self" if r.id_pub.hex() == own_id else ""
        print(fmt.format(
            r.hostname, r.cred.addr, exp.strftime("%Y-%m-%d %H:%M UTC"), state + marker
        ))

    print(f"\n{len(records)} record(s) in local directory cache")
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


def cmd_diagnose(args) -> int:
    """
    Per-peer connectivity diagnosis. Runs the same 7-step reconcile checks the
    daemon uses and prints, for each peer, exactly which step it fails — turning
    a silent direct-or-fail link into an actionable reason. Then overlays live
    WireGuard handshake state to separate "rejected by verification" from
    "configured but never handshook" (an endpoint/firewall problem).
    """
    import base64
    import time as _time
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from .config import load_config
    from .keys import NodeKeys, derive_addr
    from .directory import Directory
    from .trust import CABundle, TrustStore
    from .reconcile import default_policy
    from .wire import _canonical
    from . import wg as wgmod

    cfg_path = Path(args.config)
    if not cfg_path.exists():
        print(f"not configured (no config file at {cfg_path})")
        return 1
    cfg = load_config(cfg_path)

    try:
        keys = NodeKeys.load(cfg.data_dir)
    except FileNotFoundError:
        print("keys not generated yet — run 'gw join <token>' or 'gw setup-hub' first")
        return 1

    trust = TrustStore(
        roots=[bytes.fromhex(h) for h in cfg.ca_pubs],
        bundle=CABundle.load(cfg.ca_bundle_path),
        bundle_path=cfg.ca_bundle_path,
        static_seeds=cfg.seeds,
        fallback_hub_url=cfg.root_url,
    )
    ca_pubs = trust.trusted_pubs()

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

    print(f"self     : {cfg.hostname}  ({keys.addr})")
    print(f"role     : {cfg.role}   inbound={cfg.inbound}   iface={cfg.wg_interface}")
    print(f"trusted CAs: {len(ca_pubs)}   hub: {trust.hub_url() or '(none configured)'}")
    if not ca_pubs:
        print("  ⚠ no trusted CA keys — check [ca] trusted_pubs; nothing will verify")
    if not wg_available or not live_peers:
        hint = "" if wg_available else "  (need root, or the daemon isn't running)"
        print(f"WireGuard: {len(live_peers)} live peer(s) on {cfg.wg_interface}{hint}")
    print()

    records = sorted((r for r in directory.all() if r.id_pub != keys.id_pub_bytes),
                     key=lambda r: r.hostname)
    if not records:
        print("no peer records in the directory cache yet — is sync reaching the hub?")
        return 0

    want = getattr(args, "hostname", None)
    counts = {"linked": 0, "no-handshake": 0, "rejected": 0, "policy": 0}

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
            problems.append("CA signature not from a trusted CA (succession not synced? wrong fleet?)")

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

        print(f"● {r.hostname}  [{r.cred.addr}]  inbound={r.inbound}")
        print(f"    {status}")
        for p in problems:
            print(f"    - {p}")

    print()
    print(f"summary: {counts['linked']} linked, {counts['no-handshake']} configured/no-handshake, "
          f"{counts['rejected']} rejected, {counts['policy']} policy-denied")
    return 0


# ---------------------------------------------------------------------------
# purge  (decommission or start-over — removes all local greasewood state)
# ---------------------------------------------------------------------------

def cmd_purge(args) -> int:
    import shutil
    import subprocess

    cfg_path = Path(args.config)

    # Determine interface name and data_dir from config if available
    iface = "gw-mesh"
    data_dir = Path("/var/lib/greasewood")
    if cfg_path.exists():
        try:
            from .config import load_config
            cfg = load_config(cfg_path)
            iface = cfg.wg_interface
            data_dir = cfg.data_dir
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
        if hosts.remove_block():
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
    service. After this, setup-hub / join is all you need — the service starts
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
    for name, body in units.items():
        path = Path("/etc/systemd/system") / name
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
        print("Run setup-hub or join — the daemon starts on its own; no `gw run`.")
        print("Logs: journalctl -u greasewood -f")
        print("Opt out: sudo gw uninstall-service "
              "(or systemctl disable --now greasewood.path greasewood.service)")
    else:
        print("\nunits written (not enabled). Enable with:")
        print("  systemctl enable --now greasewood.path && systemctl enable greasewood.service")
    return 0


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
        p = Path("/etc/systemd/system") / name
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
            "  sudo gw setup-hub            -- one-shot hub bootstrap\n"
            "  sudo gw mint                 -- open a door window, print join token\n"
            "  sudo gw join <token> ...     -- enroll this machine (creates WG interfaces)\n"
            "  sudo gw run                  -- start the daemon\n"
            "  sudo gw purge                -- remove all local state\n"
            "\n"
            "no sudo needed:\n"
            "  gw status\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("-c", "--config", default="/etc/greasewood.toml", metavar="FILE")
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("--version", action="version", version=f"greasewood {_version()}")
    sub = p.add_subparsers(dest="cmd", required=True)

    # setup-hub
    sp = sub.add_parser("setup-hub",
                        help="[sudo] one-shot hub bootstrap: CA + door key + routing + self-credential")
    sp.add_argument("--hostname", default="hub")
    sp.add_argument("--data-dir", dest="data_dir", default="/var/lib/greasewood")
    sp.add_argument("--config", default="/etc/greasewood.toml", dest="config")
    sp.add_argument("--listen-port", dest="listen_port", type=int, default=51900)
    sp.add_argument("--control-port", dest="control_port", type=int, default=51902)
    sp.add_argument("--door-port", dest="door_port", type=int, default=51901,
                    help="UDP port for the enrollment door (carried in tokens)")
    sp.add_argument("--endpoint", default=None, metavar="ADDR",
                    help="underlay IPv6 address (auto-detected if omitted)")
    sp.add_argument("--caps", default="mesh")
    sp.add_argument("--credential-ttl", dest="credential_ttl", default="24h")
    sp.add_argument("--force", action="store_true", help="overwrite existing CA key")
    sp.add_argument("--open-firewall", dest="open_firewall", action="store_true",
                    help="insert the needed nftables accept rules (opt-in; tagged "
                         "\"greasewood\"). Default: only check and warn.")
    sp.add_argument("--hosts-sync", dest="hosts_sync", action="store_true",
                    help="maintain a managed /etc/hosts block (<name>.internal "
                         "-> overlay addr) from the directory")
    sp.set_defaults(fn=cmd_setup_hub)

    # mint
    sp = sub.add_parser("mint",
                        help="[sudo] open a 15-min door window and print a single-use join token")
    sp.add_argument("--endpoint", default=None, metavar="ADDR",
                    help="underlay IPv6 address to embed in token (auto-detected if omitted)")
    sp.set_defaults(fn=cmd_mint)

    # join
    sp = sub.add_parser("join",
                        help="[sudo] enroll this machine using a token from 'gw mint'")
    sp.add_argument("token", help="join token printed by 'gw mint' on the hub")
    sp.add_argument("--hostname", default=None,
                    help="this node's hostname in the mesh "
                         "(default: keep existing, else user@hostname)")
    sp.add_argument("--data-dir", dest="data_dir", default="/var/lib/greasewood")
    sp.add_argument("--config", default="/etc/greasewood.toml", dest="config")
    sp.add_argument("--listen-port", dest="listen_port", type=int, default=51900)
    sp.add_argument("--caps", default=None,
                    help="comma-separated caps (default: keep existing, else mesh)")
    sp.add_argument("--endpoint", default=None, metavar="[ADDR]:PORT",
                    help="this node's underlay endpoint (auto-detected if omitted)")
    sp.add_argument("--open-firewall", dest="open_firewall", action="store_true",
                    help="insert the needed nftables accept rules (opt-in; tagged "
                         "\"greasewood\"). Default: only check and warn.")
    sp.add_argument("--hosts-sync", dest="hosts_sync", action="store_true",
                    help="maintain a managed /etc/hosts block (<name>.internal "
                         "-> overlay addr) from the directory")
    sp.add_argument("--inbound", choices=["yes", "no", "unknown"], default=None,
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

    # status
    sp = sub.add_parser("status", help="show local node and directory state")
    sp.set_defaults(fn=cmd_status)

    # diagnose
    sp = sub.add_parser(
        "diagnose",
        help="explain why peer links are or aren't forming (per-peer checks + handshake state)")
    sp.add_argument("hostname", nargs="?", default=None,
                    help="diagnose only this peer (default: all peers)")
    sp.set_defaults(fn=cmd_diagnose)

    # revoke
    sp = sub.add_parser("revoke", help="add a node to the revoke list (run on the hub)")
    sp.add_argument("id_pub_hex", help="64-char hex identity public key")
    sp.set_defaults(fn=cmd_revoke)

    # hub-promote (on the prospective new hub)
    sp = sub.add_parser("hub-promote",
                        help="[sudo] turn this enrolled node into a hub (mint CA key, set role=hub)")
    sp.add_argument("--config", default="/etc/greasewood.toml", dest="config")
    sp.add_argument("--control-port", dest="control_port", type=int, default=51902)
    sp.add_argument("--credential-ttl", dest="credential_ttl", default="24h")
    sp.add_argument("--open-firewall", dest="open_firewall", action="store_true",
                    help="insert the needed nftables accept rules (opt-in)")
    sp.set_defaults(fn=cmd_hub_promote)

    # hub-endorse (on the current hub)
    sp = sub.add_parser("hub-endorse",
                        help="endorse another CA as a successor hub (run on the current hub)")
    sp.add_argument("--ca-pub", dest="ca_pub", required=True, metavar="HEX",
                    help="successor CA public key (from 'gw hub-promote')")
    sp.add_argument("--endpoint", required=True, metavar="URL",
                    help="successor's control-plane URL (from 'gw hub-promote')")
    sp.add_argument("--ttl", default="3650d",
                    help="how long the endorsement stays valid (default: 3650d)")
    sp.set_defaults(fn=cmd_hub_endorse)

    # hub-retire (on a hub, after the successor has taken over)
    sp = sub.add_parser("hub-retire",
                        help="retire a CA so the fleet stops accepting its signatures")
    sp.add_argument("--ca-pub", dest="ca_pub", required=True, metavar="HEX",
                    help="CA public key to retire")
    sp.add_argument("--ttl", default="3650d",
                    help="how long the retirement stays in effect (default: 3650d)")
    sp.add_argument("--grace", default=None,
                    help="delay before the retirement takes effect, for nodes to "
                         "migrate first (default: the hub's credential TTL)")
    sp.set_defaults(fn=cmd_hub_retire)

    # cert-request (on a node with the 'tls' capability)
    sp = sub.add_parser("cert-request",
                        help="request an x509 TLS cert from the hub for a local service")
    sp.add_argument("--san", action="append", default=[], metavar="NAME|IP",
                    help="subject alternative name (repeatable; DNS or IP). "
                         "Defaults to the node's overlay address if omitted.")
    sp.add_argument("--cn", default=None, help="subject common name")
    sp.add_argument("--name", default=None,
                    help="basename for the written .key/.crt (default: first SAN)")
    sp.add_argument("--out-dir", dest="out_dir", default=None,
                    help="where to write key/cert/ca (default: <data_dir>/tls)")
    sp.add_argument("--hub", default=None, help="override the hub control-plane URL")
    sp.add_argument("--config", default="/etc/greasewood.toml", dest="config")
    sp.set_defaults(fn=cmd_cert_request)

    # cert-status
    sp = sub.add_parser("cert-status", help="show local TLS certs and expiry")
    sp.add_argument("--out-dir", dest="out_dir", default=None)
    sp.add_argument("--config", default="/etc/greasewood.toml", dest="config")
    sp.set_defaults(fn=cmd_cert_status)

    # set-inbound
    sp = sub.add_parser("set-inbound",
                        help="change reachability: yes (dialable) / no (outbound-only) / unknown")
    sp.add_argument("value", choices=["yes", "no", "unknown"])
    sp.add_argument("--open-firewall", dest="open_firewall", action="store_true",
                    help="when switching to inbound, open the WireGuard port (opt-in)")
    sp.add_argument("--config", default="/etc/greasewood.toml", dest="config")
    sp.set_defaults(fn=cmd_set_inbound)

    args = p.parse_args(argv)
    _setup_logging(args.verbose)
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
