"""
greasewood — CLI entry point.

Enrollment flow (§10.1) — entirely over SSH, no HTTP:

  On the new node:
    greasewood init-node          # generate keypairs, print public material

  On the root (operator SSHes in):
    greasewood issue \\
        --id-pub <hex> --wg-pub <hex> --hostname <name> --caps mesh \\
        [--endpoint [addr]:port]  # sign + output credential JSON, update directory

  Back on the new node:
    greasewood install-cred cred.json   # create signed NodeRecord, seed directory
    greasewood run                      # start daemon (pushes record to seeds on start)

Other subcommands:
  init-ca             Generate CA keypair (root, run once at genesis).
  revoke <id_pub>     Add a node to the revoke list.
  run                 Run the daemon (all roles).
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
    print("Pass id_pub and wg_pub to `greasewood issue` on the root node.")
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

    # Write a signed NodeRecord into the root's directory so the root's
    # reconcile loop can configure a WireGuard peer for the new node.
    # We sign this record with the root's id_priv (using its own node keys),
    # which is wrong — a NodeRecord must be signed by the node's own id_priv.
    # Instead, we write a bare credential entry and let the new node push
    # its own record via /publish on first startup. The root writes nothing to
    # the directory here; that's the new node's job.

    cred_json = json.dumps(cred.to_dict(), indent=2)

    if args.output:
        Path(args.output).write_text(cred_json)
        print(f"credential written to {args.output}")
    else:
        print(cred_json)

    # Print the next step for the operator
    print(
        f"\n# Next: copy the credential to {args.hostname} and run:\n"
        f"#   greasewood install-cred <cred-file>",
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
    print("Run 'greasewood run' to start the daemon.")
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

    # Revoke list — root reads from disk; others start empty and rely on
    # credential expiry for routine revocation.
    revoked: set[str] = set()

    if cfg.role in ("root", "seed"):
        if cfg.role == "root":
            if not cfg.ca_key_file:
                sys.exit("role=root requires ca_key_file in [root]")
            ca_keys = CAKeys.load(cfg.ca_key_file, _get_passphrase(cfg.ca_key_passphrase_env))
            ca = CA(ca_keys, cfg.data_dir, cfg.credential_ttl)
            revoked = ca.load_revoked_set()
            log.info("CA loaded, pub=%s...", ca_keys.ca_pub_bytes.hex()[:16])

        srv = ControlServer(
            cfg.control_listen,
            directory,
            ca_pubs=ca_pubs,
            get_revoked=lambda: revoked,
            ca=ca,
        )
        srv.start()

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
        log.warning("no credential in directory — run 'greasewood install-cred' first")
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
        print("directory is empty — run 'greasewood install-cred' then 'greasewood run'")
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
# main
# ---------------------------------------------------------------------------

def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        prog="greasewood",
        description="Minimal WireGuard mesh overlay — direct-or-fail, IPv6-only",
    )
    p.add_argument("-c", "--config", default="greasewood.toml", metavar="FILE")
    p.add_argument("-v", "--verbose", action="store_true")
    sub = p.add_subparsers(dest="cmd", required=True)

    # init-ca
    sp = sub.add_parser("init-ca", help="generate CA keypair (root, run once at genesis)")
    sp.add_argument("key_path", help="path to write the CA private key")
    sp.add_argument("--force", action="store_true", help="overwrite existing key")
    sp.add_argument("--passphrase-env", dest="passphrase_env", metavar="ENV",
                    help="env var containing CA key passphrase")
    sp.set_defaults(fn=cmd_init_ca)

    # init-node
    sp = sub.add_parser("init-node", help="generate node keypairs and print public material")
    sp.set_defaults(fn=cmd_init_node)

    # issue  (root-side, run over SSH)
    sp = sub.add_parser("issue", help="sign a credential for a new node (run on root via SSH)")
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
                        help="install a credential received from the root (run on new node)")
    sp.add_argument("cred_file", help="path to credential JSON file")
    sp.set_defaults(fn=cmd_install_cred)

    # revoke
    sp = sub.add_parser("revoke", help="add a node to the revoke list (run on root)")
    sp.add_argument("id_pub_hex", help="64-char hex identity public key")
    sp.set_defaults(fn=cmd_revoke)

    # run
    sp = sub.add_parser("run", help="run the daemon")
    sp.set_defaults(fn=cmd_run)

    # status
    sp = sub.add_parser("status", help="show local directory state")
    sp.set_defaults(fn=cmd_status)

    args = p.parse_args(argv)
    _setup_logging(args.verbose)
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
