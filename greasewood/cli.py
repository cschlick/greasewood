"""
gw — CLI entry point.

Enrollment flow (§10.1) — entirely over SSH, no HTTP:

  On the new node:
    gw init-node          # generate keypairs, print public material

  On the root (operator SSHes in):
    gw issue \\
        --id-pub <hex> --wg-pub <hex> --hostname <name> --caps mesh \\
        [--endpoint [addr]:port]  # sign + output credential JSON, update directory

  Back on the new node:
    gw install-cred cred.json   # create signed NodeRecord, seed directory
    gw run                      # start daemon (pushes record to seeds on start)

Other subcommands:
  init-ca             Generate CA keypair (root, run once at genesis).
  revoke <id_pub>     Add a node to the revoke list.
  run                 Run the daemon (all roles).
  status              Show local directory state.
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
# setup-root  (one-shot root bootstrap — replaces init-ca + init-node + issue + install-cred)
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
    # run gw issue / gw mint without sudo.
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
    from . import wg as wgmod
    import base64

    token = args.token
    hostname = args.hostname or f"{getpass.getuser()}@{socket.gethostname()}"
    caps = [c.strip() for c in args.caps.split(",")]
    cfg_path = Path(args.config)
    data_dir = Path(args.data_dir)
    listen_port = args.listen_port
    endpoint = args.endpoint

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
# init-ca  (genesis — run once on the root node)
# ---------------------------------------------------------------------------

def cmd_init_ca(args) -> int:
    from .keys import CAKeys

    key_path = Path(args.key_path)
    if key_path.exists() and not args.force:
        sys.exit(f"CA key already exists at {key_path} (use --force to overwrite)")

    passphrase = None
    if args.passphrase_env:
        val = os.environ.get(args.passphrase_env)
        if not val:
            sys.exit(f"--passphrase-env={args.passphrase_env} is set but that env var is empty")
        passphrase = val.encode()

    ca = CAKeys.generate()
    ca.save(key_path, passphrase)
    print(f"CA private key : {key_path}")
    print(f"CA public key  : {key_path.with_suffix('.pub')}")
    print()
    print("Add this to [ca] trusted_pubs in every node's greasewood.toml:")
    print(f"  {ca.ca_pub_bytes.hex()}")
    return 0


# ---------------------------------------------------------------------------
# init-node  (run on the new node before calling `issue` on the root)
# ---------------------------------------------------------------------------

def cmd_init_node(args) -> int:
    from .config import load_config
    from .keys import NodeKeys

    cfg = load_config(Path(args.config))
    keys = NodeKeys.load_or_generate(cfg.data_dir)

    print(f"id_pub  : {keys.id_pub_hex}")
    print(f"wg_pub  : {keys.wg_pub_b64}")
    print(f"addr    : {keys.addr}")
    if cfg.endpoints:
        print(f"endpoint: {cfg.endpoints[0]}")
    else:
        print("endpoint: (not configured — set [node] endpoints in greasewood.toml)")
    print()
    print("Pass id_pub and wg_pub to `gw issue` on the root node.")
    return 0


# ---------------------------------------------------------------------------
# issue  (run on the root node over SSH — signs and outputs a credential)
# ---------------------------------------------------------------------------

def cmd_issue(args) -> int:
    from .config import load_config
    from .keys import CAKeys
    from .ca import CA
    from .directory import Directory
    from .wire import NodeRecord

    cfg = load_config(Path(args.config))
    if cfg.ca_key_file is None:
        sys.exit("ca_key_file must be set in [root]")

    ca_keys = CAKeys.load(cfg.ca_key_file, _get_passphrase(cfg.ca_key_passphrase_env))
    ca = CA(ca_keys, cfg.data_dir, cfg.credential_ttl)

    try:
        id_pub = bytes.fromhex(args.id_pub)
    except ValueError:
        sys.exit("--id-pub must be a 64-character hex string")

    import base64
    try:
        wg_pub = base64.b64decode(args.wg_pub)
        if len(wg_pub) != 32:
            raise ValueError
    except Exception:
        sys.exit("--wg-pub must be the base64 WireGuard public key (32 bytes)")

    caps = [c.strip() for c in args.caps.split(",")]
    cred = ca.issue(id_pub, wg_pub, args.hostname, caps)

    # The credential is output here; the new node wraps it in a NodeRecord
    # (signed with its own id_priv) and pushes that record to the root via
    # POST /publish on first daemon startup. Nothing is written to the root's
    # directory here — a NodeRecord must be signed by the node's own id_priv,
    # which only the node itself holds.
    cred_json = json.dumps(cred.to_dict(), indent=2)

    if args.output:
        Path(args.output).write_text(cred_json)
        print(f"credential written to {args.output}")
    else:
        print(cred_json)

    # Print the next step for the operator
    print(
        f"\n# Next: copy the credential to {args.hostname} and run:\n"
        f"#   gw install-cred <cred-file>",
        file=sys.stderr,
    )
    return 0


# ---------------------------------------------------------------------------
# install-cred  (run on the new node after receiving the credential from root)
# ---------------------------------------------------------------------------

def cmd_install_cred(args) -> int:
    from .config import load_config
    from .keys import NodeKeys
    from .wire import Credential, NodeRecord
    from .directory import Directory

    cfg = load_config(Path(args.config))
    ca_pubs = [bytes.fromhex(h) for h in cfg.ca_pubs]
    if not ca_pubs:
        sys.exit("ca.trusted_pubs is empty — add the CA public key to greasewood.toml")

    cred_path = Path(args.cred_file)
    if not cred_path.exists():
        sys.exit(f"credential file not found: {cred_path}")

    cred = Credential.from_dict(json.loads(cred_path.read_text()))

    # Verify the CA signature locally before trusting the credential
    cred.verify(ca_pubs)

    keys = NodeKeys.load_or_generate(cfg.data_dir)

    # Verify the credential was actually issued for this node
    if cred.id_pub != keys.id_pub_bytes:
        sys.exit(
            "credential id_pub does not match this node's id_pub — wrong credential file?"
        )

    directory = Directory.load(cfg.dir_cache_path)
    existing = directory.get(keys.id_pub_hex)
    seq = (existing.seq + 1) if existing else 1

    record = NodeRecord(
        id_pub=keys.id_pub_bytes,
        seq=seq,
        endpoints=cfg.endpoints,
        inbound=cfg.inbound,
        hostname=cfg.hostname,
        cred=cred,
    ).sign(keys.id_priv)

    directory.put(record)
    directory.save(cfg.dir_cache_path)

    print(f"credential installed for {cfg.hostname}")
    print(f"  addr    : {cred.addr}")
    print(f"  caps    : {cred.caps}")
    print(f"  expires : {cred.exp:%Y-%m-%d %H:%M UTC}")
    print()
    print("Run 'gw run' to start the daemon.")
    print("The daemon will push this node's record to seeds on startup.")
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
    ca_pubs = [bytes.fromhex(h) for h in cfg.ca_pubs]

    wgmod.ensure_interface(
        cfg.wg_interface, keys.addr, cfg.listen_port, cfg.wg_key_path
    )

    ca: CA | None = None
    sync: SyncLoop | None = None
    renewal: RenewalLoop | None = None
    door_watcher = None

    revoked: set[str] = set()
    is_hub = cfg.role in ("hub", "root")

    if is_hub or cfg.role == "seed":
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
            ca_pubs=ca_pubs,
            get_revoked=lambda: revoked,
            ca=ca,
            cache_path=cfg.dir_cache_path,
        )
        srv.start()

        if is_hub and ca is not None:
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

    if cfg.seeds:
        sync = SyncLoop(directory, cfg.seeds, cfg.dir_cache_path)
        sync.start()

    recon = ReconcileLoop(
        iface=cfg.wg_interface,
        directory=directory,
        local_id_pub=keys.id_pub_bytes,
        local_caps=cfg.caps,
        ca_pubs=ca_pubs,
        revoked=revoked,
    )
    recon.start()

    # Push our own record to all seeds so the rest of the mesh knows about us.
    # This is the step that gets a newly enrolled node into the directory on the
    # root/seeds; it is also how endpoint changes propagate without waiting for
    # the next renewal cycle.
    own_record = directory.get(keys.id_pub_hex)
    if own_record and cfg.seeds:
        for seed in cfg.seeds:
            try:
                push_record(seed, own_record)
                log.info("pushed own record to %s", seed)
            except Exception as e:
                log.warning("push to %s failed (will retry on next sync): %s", seed, e)

    # Renewal loop
    if cfg.root_url and own_record:
        renewal = RenewalLoop(
            node_keys=keys,
            directory=directory,
            root_url=cfg.root_url,
            current_cred=own_record.cred,
            inbound=cfg.inbound,
            hostname=cfg.hostname,
            endpoints=cfg.endpoints,
            cache_path=cfg.dir_cache_path,
        )
        renewal.start()
    elif not own_record:
        log.warning("no credential in directory — run 'gw install-cred' first")
    elif not cfg.root_url:
        log.warning("root_url not set — automatic renewal disabled")

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
        print("directory is empty — run 'gw install-cred' then 'gw run'")
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
            "  gw issue   (ca.key owned by you after setup-hub)\n"
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
    sp.add_argument("--hostname", default=None, help="this node's hostname in the mesh (default: user@hostname)")
    sp.add_argument("--data-dir", dest="data_dir", default="/var/lib/greasewood")
    sp.add_argument("--config", default="/etc/greasewood.toml", dest="config")
    sp.add_argument("--listen-port", dest="listen_port", type=int, default=51820)
    sp.add_argument("--caps", default="mesh")
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

    # issue  (root-side, run over SSH)
    sp = sub.add_parser("issue", help="sign a credential for a new node (run on root via SSH, no sudo needed)")
    sp.add_argument("--id-pub", required=True, metavar="HEX",
                    help="node identity public key (hex)")
    sp.add_argument("--wg-pub", required=True, metavar="B64",
                    help="node WireGuard public key (base64)")
    sp.add_argument("--hostname", required=True, help="node hostname")
    sp.add_argument("--caps", default="mesh", metavar="CAPS",
                    help="comma-separated capability list (default: mesh)")
    sp.add_argument("--output", "-o", metavar="FILE",
                    help="write credential JSON to file instead of stdout")
    sp.set_defaults(fn=cmd_issue)

    # install-cred  (node-side)
    sp = sub.add_parser("install-cred",
                        help="install a credential received from root (called automatically by join)")
    sp.add_argument("cred_file", help="path to credential JSON file")
    sp.set_defaults(fn=cmd_install_cred)

    # revoke
    sp = sub.add_parser("revoke", help="add a node to the revoke list (run on root)")
    sp.add_argument("id_pub_hex", help="64-char hex identity public key")
    sp.set_defaults(fn=cmd_revoke)

    # init-ca
    sp = sub.add_parser("init-ca", help="generate CA keypair (called automatically by setup-root)")
    sp.add_argument("key_path", help="path to write the CA private key")
    sp.add_argument("--force", action="store_true", help="overwrite existing key")
    sp.add_argument("--passphrase-env", dest="passphrase_env", metavar="ENV",
                    help="env var containing CA key passphrase")
    sp.set_defaults(fn=cmd_init_ca)

    # init-node
    sp = sub.add_parser("init-node", help="generate node keypairs (called automatically by join)")
    sp.set_defaults(fn=cmd_init_node)

    args = p.parse_args(argv)
    _setup_logging(args.verbose)
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
