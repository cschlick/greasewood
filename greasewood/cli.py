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


def _get_passphrase(env_var: str | None) -> bytes | None:
    if not env_var:
        return None
    val = os.environ.get(env_var)
    if not val:
        sys.exit(f"{env_var} is set in config but that environment variable is empty")
    return val.encode()


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
    cfg_path.parent.mkdir(parents=True, exist_ok=True)
    cfg_path.write_text(f"""[node]
hostname = "{hostname}"
data_dir = "{data_dir}"
role = "hub"
inbound = "yes"
caps = {json_mod.dumps(caps)}{endpoint_line}

[network]
interface = "gw0"
listen_port = {listen_port}
seeds = []
root_url = "http://[::1]:{control_port}"

[ca]
trusted_pubs = ["{ca_pub_hex}"]

[hub]
ca_key_file = "{ca_key_path}"
control_listen = ":{control_port}"
credential_ttl = "{args.credential_ttl}"
renew_before = "12h"
door_window = "15m"
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

    # Bring up the hub's door WG interface
    door_key_path = data_dir / "door.key"
    wgmod.ensure_hub_door_interface(door_key_path, params.guest_pub_b64, params.psk_b64)

    # Write window file so the running gw-run daemon starts the enroll server
    expires = dt_mod.datetime.now(dt_mod.timezone.utc) + window
    window_path = data_dir / "door_window.json"
    window_path.write_text(json_mod.dumps({
        "v": 1,
        "expires": expires.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }))

    token = encode_token(hub_door_pub, ca_keys.ca_pub_bytes, endpoint, seed)
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

    # Decode token → hub_door_pub, ca_pub, hub_host, seed
    try:
        hub_door_pub_bytes, ca_pub_bytes, hub_host, seed = decode_token(token)
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

    # Bring up the local door interface
    wgmod.ensure_node_door_interface(
        params.guest_priv_bytes, hub_door_pub_b64, params.psk_b64, hub_host,
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
    try:
        conn.sendall(struct.pack(">I", len(req_body)) + req_body)

        # Receive response
        hdr = b""
        while len(hdr) < 4:
            chunk = conn.recv(4 - len(hdr))
            if not chunk:
                raise ConnectionError("connection closed")
            hdr += chunk
        length = struct.unpack(">I", hdr)[0]
        raw = b""
        while len(raw) < length:
            chunk = conn.recv(length - len(raw))
            if not chunk:
                raise ConnectionError("connection closed")
            raw += chunk
        resp = json_mod.loads(raw)
    except Exception as e:
        conn.close()
        wgmod.destroy_interface("gw-door")
        sys.exit(f"enroll RPC failed: {e}")
    finally:
        try:
            conn.close()
        except Exception:
            pass

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

    # Hub's record — pre-seeds so the daemon knows the hub immediately
    hub_overlay_url = ""
    if resp.get("hub_record"):
        hub_rec = NodeRecord.from_dict(resp["hub_record"])
        try:
            hub_rec.verify([ca_pub_bytes], set())
            directory.put(hub_rec)
            log.info("pre-seeded hub record (hostname=%s)", hub_rec.hostname)
            hub_overlay_url = f"http://[{hub_rec.cred.addr}]:7946"
        except Exception as e:
            log.warning("hub record verify failed: %s", e)

    # Our own record
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

    # Push our record to the hub via the door tunnel before tearing it down.
    # This bootstraps the hub's directory so the ReconcileLoop installs our
    # WG peer immediately — without this, the node can't reach the hub overlay
    # address to publish, and the hub never adds the peer (chicken-and-egg).
    from .door import HUB_DOOR_IP as _HUB_DOOR_IP
    from .sync import push_record as _push_record
    try:
        _push_record(f"http://[{_HUB_DOOR_IP}]:7946", record, timeout=5.0)
        log.info("pre-published record to hub via door tunnel")
    except Exception as e:
        log.warning("door pre-publish failed (hub learns this node on next sync): %s", e)

    # Tear down the door interface
    wgmod.destroy_interface("gw-door")

    endpoint_line = f'\nendpoints = ["{endpoint}"]' if endpoint else ""
    seeds_list = json_mod.dumps([hub_overlay_url]) if hub_overlay_url else "[]"
    root_url_val = json_mod.dumps(hub_overlay_url) if hub_overlay_url else '""'

    cfg_path.parent.mkdir(parents=True, exist_ok=True)
    cfg_path.write_text(f"""[node]
hostname = "{hostname}"
data_dir = "{data_dir}"
role = "node"
inbound = "yes"
caps = {json_mod.dumps(caps)}{endpoint_line}

[network]
interface = "gw0"
listen_port = {listen_port}
seeds = {seeds_list}
root_url = {root_url_val}

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
    """The control-plane port from cfg.control_listen (':7946' -> 7946)."""
    try:
        return int(cfg.control_listen.rsplit(":", 1)[1])
    except (ValueError, IndexError):
        return 7946


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
    cfg_path.write_text(f"""[node]
hostname = "{cfg.hostname}"
data_dir = "{cfg.data_dir}"
role = "hub"
inbound = "{cfg.inbound}"
caps = {json_mod.dumps(cfg.caps)}{endpoint_line}

[network]
interface = "{cfg.wg_interface}"
listen_port = {cfg.listen_port}
seeds = {json_mod.dumps(cfg.seeds)}
root_url = "{cfg.root_url}"

[ca]
trusted_pubs = {json_mod.dumps(trusted)}

[hub]
ca_key_file = "{ca_key_path}"
control_listen = ":{control_port}"
credential_ttl = "{args.credential_ttl}"
renew_before = "12h"
door_window = "15m"
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
    stmt = ca.retire(subject_pub, ttl)
    _append_to_bundle(cfg, stmt)

    print(f"retired CA {args.ca_pub[:16]}…")
    print("Once this propagates, the fleet no longer accepts its credentials.")
    print("Ensure every node has renewed under the new CA before decommissioning.")
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

    revoked: set[str] = set()
    is_hub = cfg.role in ("hub", "root")

    if is_hub:
        if not cfg.ca_key_file:
            sys.exit("hub role requires ca_key_file in [hub]")
        ca_keys = CAKeys.load(cfg.ca_key_file, _get_passphrase(cfg.ca_key_passphrase_env))
        ca = CA(ca_keys, cfg.data_dir, cfg.credential_ttl)
        revoked = ca.load_revoked_set()
        log.info("CA loaded, pub=%s...", ca_keys.ca_pub_bytes.hex()[:16])
        # Re-apply door routing in case the machine rebooted since setup-hub
        wgmod.setup_door_routing()

        srv = ControlServer(
            cfg.control_listen,
            directory,
            get_ca_pubs=trust.trusted_pubs,
            get_revoked=lambda: revoked,
            ca=ca,
            cache_path=cfg.dir_cache_path,
            get_bundle=trust.bundle_dict,
        )
        srv.start()

        from .enroll import DoorWatcher
        door_watcher = DoorWatcher(
            data_dir=cfg.data_dir,
            ca=ca,
            directory=directory,
            node_keys=keys,
            wg_iface=cfg.wg_interface,
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

    recon = ReconcileLoop(
        iface=cfg.wg_interface,
        directory=directory,
        local_id_pub=keys.id_pub_bytes,
        local_caps=cfg.caps,
        get_ca_pubs=trust.trusted_pubs,
        revoked=revoked,
    )
    recon.start()

    # Push our own record so the rest of the mesh knows about us. This gets a
    # newly enrolled node into the hub's directory; it is also how endpoint
    # changes propagate without waiting for the next renewal cycle.
    own_record = directory.get(keys.id_pub_hex)
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
            endpoints=cfg.endpoints,
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
# purge  (decommission or start-over — removes all local greasewood state)
# ---------------------------------------------------------------------------

def cmd_purge(args) -> int:
    import shutil
    import subprocess

    cfg_path = Path(args.config)

    # Determine interface name and data_dir from config if available
    iface = "gw0"
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

    for item in removed:
        print(f"removed: {item}")
    for item in failed:
        print(f"failed:  {item}")

    if failed:
        return 1
    print("purge complete")
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
    sub = p.add_subparsers(dest="cmd", required=True)

    # setup-hub
    sp = sub.add_parser("setup-hub",
                        help="[sudo] one-shot hub bootstrap: CA + door key + routing + self-credential")
    sp.add_argument("--hostname", default="hub")
    sp.add_argument("--data-dir", dest="data_dir", default="/var/lib/greasewood")
    sp.add_argument("--config", default="/etc/greasewood.toml", dest="config")
    sp.add_argument("--listen-port", dest="listen_port", type=int, default=51820)
    sp.add_argument("--control-port", dest="control_port", type=int, default=7946)
    sp.add_argument("--endpoint", default=None, metavar="ADDR",
                    help="underlay IPv6 address (auto-detected if omitted)")
    sp.add_argument("--caps", default="mesh")
    sp.add_argument("--credential-ttl", dest="credential_ttl", default="24h")
    sp.add_argument("--force", action="store_true", help="overwrite existing CA key")
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
    sp.add_argument("--listen-port", dest="listen_port", type=int, default=51820)
    sp.add_argument("--caps", default=None,
                    help="comma-separated caps (default: keep existing, else mesh)")
    sp.add_argument("--endpoint", default=None, metavar="[ADDR]:PORT",
                    help="this node's underlay endpoint (auto-detected if omitted)")
    sp.set_defaults(fn=cmd_join)

    # purge
    sp = sub.add_parser("purge",
                        help="[sudo] remove all greasewood state from this machine (decommission or start over)")
    sp.add_argument("--yes", "-y", action="store_true", help="skip confirmation prompt")
    sp.set_defaults(fn=cmd_purge)

    # run
    sp = sub.add_parser("run", help="[sudo] start the daemon (creates WireGuard interface)")
    sp.set_defaults(fn=cmd_run)

    # status
    sp = sub.add_parser("status", help="show local node and directory state")
    sp.set_defaults(fn=cmd_status)

    # revoke
    sp = sub.add_parser("revoke", help="add a node to the revoke list (run on the hub)")
    sp.add_argument("id_pub_hex", help="64-char hex identity public key")
    sp.set_defaults(fn=cmd_revoke)

    # hub-promote (on the prospective new hub)
    sp = sub.add_parser("hub-promote",
                        help="[sudo] turn this enrolled node into a hub (mint CA key, set role=hub)")
    sp.add_argument("--config", default="/etc/greasewood.toml", dest="config")
    sp.add_argument("--control-port", dest="control_port", type=int, default=7946)
    sp.add_argument("--credential-ttl", dest="credential_ttl", default="24h")
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
    sp.set_defaults(fn=cmd_hub_retire)

    args = p.parse_args(argv)
    _setup_logging(args.verbose)
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
