"""
greasewood — CLI entry point.

Subcommands:
  init-ca             Generate CA keypair (root node, run once at genesis).
  token add           Generate a one-time enrollment token.
  revoke <id_pub>     Add a node to the revoke list.
  enroll              Enroll this node with the root (run once per node).
  run                 Run the daemon.
  status              Show local directory state.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import logging
import os
import signal
import sys
import time
import urllib.error
import urllib.request
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
# init-ca
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
    print(f"CA private key: {key_path}")
    print(f"CA public key : {key_path.with_suffix('.pub')}")
    print()
    print("Add this to [ca] trusted_pubs in every node's config:")
    print(f"  {ca.ca_pub_bytes.hex()}")
    return 0


# ---------------------------------------------------------------------------
# token add
# ---------------------------------------------------------------------------

def cmd_token_add(args) -> int:
    from .config import load_config
    from .keys import CAKeys
    from .ca import CA

    cfg = load_config(Path(args.config))
    if cfg.ca_key_file is None:
        sys.exit("ca_key_file must be set in [root] for token management")

    ca_keys = CAKeys.load(cfg.ca_key_file, _get_passphrase(cfg.ca_key_passphrase_env))
    ca = CA(ca_keys, cfg.data_dir)
    token = ca.generate_token()
    print(token)
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
    print("Existing credential will expire naturally; for emergency eviction")
    print("restart the daemon so the reconcile loop reloads the revoke list.")
    return 0


# ---------------------------------------------------------------------------
# enroll
# ---------------------------------------------------------------------------

def cmd_enroll(args) -> int:
    from .config import load_config
    from .keys import NodeKeys
    from .wire import EnrollRequest, Credential, NodeRecord
    from .directory import Directory

    cfg = load_config(Path(args.config))
    keys = NodeKeys.load_or_generate(cfg.data_dir)

    print(f"node id_pub : {keys.id_pub_hex}")
    print(f"node addr   : {keys.addr}")

    req = EnrollRequest(
        id_pub=keys.id_pub_bytes,
        wg_pub=keys.wg_pub_bytes,
        addr=keys.addr,
        hostname=cfg.hostname,
        req_caps=cfg.caps,
        token=args.token,
    ).sign(keys.id_priv)

    root_url = args.root_url or cfg.root_url
    if not root_url:
        sys.exit("root_url must be set in [network] or passed via --root-url")

    url = f"{root_url.rstrip('/')}/enroll"
    body = json.dumps(req.to_dict()).encode()
    http_req = urllib.request.Request(
        url, data=body, headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(http_req, timeout=15) as resp:
            data = json.loads(resp.read())
    except urllib.error.URLError as e:
        sys.exit(f"enrollment request failed: {e}")

    if "error" in data:
        sys.exit(f"enrollment rejected: {data['error']}")

    cred = Credential.from_dict(data)
    print(f"enrolled — credential expires {cred.exp:%Y-%m-%d %H:%M UTC}")
    print(f"caps: {cred.caps}")

    # Wrap in a NodeRecord and seed the local directory cache
    record = NodeRecord(
        id_pub=keys.id_pub_bytes,
        seq=1,
        endpoints=cfg.endpoints,
        inbound=cfg.inbound,
        hostname=cfg.hostname,
        cred=cred,
    ).sign(keys.id_priv)

    directory = Directory.load(cfg.dir_cache_path)
    directory.put(record)
    directory.save(cfg.dir_cache_path)
    print("local directory seeded — run 'greasewood run' to start the daemon")
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
    from .sync import SyncLoop
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
    threads = []
    sync: SyncLoop | None = None
    renewal: RenewalLoop | None = None

    # Control plane HTTP server (root and seed)
    if cfg.role in ("root", "seed"):
        if cfg.role == "root":
            if not cfg.ca_key_file:
                sys.exit("role=root requires ca_key_file in [root]")
            ca_keys = CAKeys.load(cfg.ca_key_file, _get_passphrase(cfg.ca_key_passphrase_env))
            ca = CA(ca_keys, cfg.data_dir, cfg.credential_ttl)
            log.info("CA loaded, pub=%s...", ca_keys.ca_pub_bytes.hex()[:16])
        srv = ControlServer(cfg.control_listen, directory, ca)
        threads.append(srv.start())

    # Directory sync loop
    if cfg.seeds:
        sync = SyncLoop(directory, cfg.seeds, cfg.dir_cache_path)
        threads.append(sync.start())

    # Load revoke list (root reads from disk; others start empty and rely on
    # credential expiry for routine revocation)
    revoked: set[str] = set()
    if ca is not None:
        revoked = ca.load_revoked_set()

    # Reconcile loop
    recon = ReconcileLoop(
        iface=cfg.wg_interface,
        directory=directory,
        local_id_pub=keys.id_pub_bytes,
        local_caps=cfg.caps,
        ca_pubs=ca_pubs,
        revoked=revoked,
    )
    threads.append(recon.start())

    # Renewal loop (only if we have an existing credential)
    if cfg.root_url:
        own_record = directory.get(keys.id_pub_hex)
        if own_record:
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
            threads.append(renewal.start())
        else:
            log.warning("no credential in directory — run 'greasewood enroll' first")
    else:
        log.warning("root_url not set — renewal disabled")

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
    log.info("shutdown complete")
    return 0


# ---------------------------------------------------------------------------
# status
# ---------------------------------------------------------------------------

def cmd_status(args) -> int:
    from .config import load_config
    from .keys import NodeKeys
    from .directory import Directory

    cfg = load_config(Path(args.config))
    directory = Directory.load(cfg.dir_cache_path)

    try:
        keys = NodeKeys.load(cfg.data_dir)
        own_id = keys.id_pub_hex
    except FileNotFoundError:
        own_id = None

    now = dt.datetime.now(_UTC)
    records = sorted(directory.all(), key=lambda r: r.hostname)

    if not records:
        print("directory is empty — run 'greasewood enroll' then 'greasewood run'")
        return 0

    fmt = "{:<20} {:<44} {:<22} {}"
    print(fmt.format("hostname", "addr", "expires", "state"))
    print("-" * 90)
    for r in records:
        exp = r.cred.exp
        left = (exp - now).total_seconds()
        if left < 0:
            state = "EXPIRED"
        elif left < 3600:
            state = f"expiring ({int(left/60)}m)"
        else:
            state = "ok"
        marker = " ← self" if r.id_pub.hex() == own_id else ""
        print(fmt.format(r.hostname, r.cred.addr, exp.strftime("%Y-%m-%d %H:%M UTC"), state + marker))

    print(f"\n{len(records)} record(s) in local directory cache")
    return 0


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

import threading  # noqa: E402 (needed for cmd_run)


def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        prog="greasewood",
        description="Minimal WireGuard mesh overlay — direct-or-fail, IPv6-only",
    )
    p.add_argument("-c", "--config", default="greasewood.toml", metavar="FILE")
    p.add_argument("-v", "--verbose", action="store_true")
    sub = p.add_subparsers(dest="cmd", required=True)

    # init-ca
    sp = sub.add_parser("init-ca", help="generate CA keypair (root, run once)")
    sp.add_argument("key_path", help="path to write the CA private key")
    sp.add_argument("--force", action="store_true", help="overwrite existing key")
    sp.add_argument("--passphrase-env", dest="passphrase_env", metavar="ENV",
                    help="env var containing CA key passphrase")
    sp.set_defaults(fn=cmd_init_ca)

    # token
    sp = sub.add_parser("token", help="manage enrollment tokens")
    tsub = sp.add_subparsers(dest="token_cmd", required=True)
    ts = tsub.add_parser("add", help="generate a one-time enrollment token")
    ts.set_defaults(fn=cmd_token_add)

    # revoke
    sp = sub.add_parser("revoke", help="add a node to the revoke list")
    sp.add_argument("id_pub_hex", help="64-char hex identity public key")
    sp.set_defaults(fn=cmd_revoke)

    # enroll
    sp = sub.add_parser("enroll", help="enroll this node with the root (run once)")
    sp.add_argument("--token", required=True, help="one-time enrollment token")
    sp.add_argument("--root-url", dest="root_url", metavar="URL",
                    help="override root_url from config")
    sp.set_defaults(fn=cmd_enroll)

    # run
    sp = sub.add_parser("run", help="run the daemon")
    sp.set_defaults(fn=cmd_run)

    # status
    sp = sub.add_parser("status", help="show directory state")
    sp.set_defaults(fn=cmd_status)

    args = p.parse_args(argv)
    _setup_logging(args.verbose)

    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
