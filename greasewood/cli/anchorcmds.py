"""greasewood.cli.anchorcmds — Anchor authority: the gw anchor family (status/init/offer/adopt/export/drop), promote, renew-all, backup/restore, and the legacy standby/activate/transfer flows."""
import datetime as dt
import json
import logging
import os
import subprocess
import sys
from pathlib import Path

from ..config import membership_key, render_config

# The package namespace is the late-binding seam: cross-module helpers are
# called as cli.<name> so a monkeypatch on the package (the tests' historic
# patch point) reaches every caller, exactly as it did when this was one file.
import greasewood.cli as cli

_UTC = dt.timezone.utc
log = logging.getLogger("greasewood")




def cmd_anchor_promote(args) -> int:
    """On a prospective new anchor (currently a node): generate its own CA key and
    rewrite its config to role=anchor, so a restart makes it serve as an anchor.
    Prints the CA public key + control endpoint to add to the fleet's
    trusted_pubs (a manual re-root — see the printed steps)."""
    cli._require_root("anchor-promote")
    from ..config import load_config
    from ..keys import CAKeys, NodeKeys

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
        endpoint_auto=cfg.endpoint_auto,          # preserve the operator's choice
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
    if not cli._service_restart(membership_key(cfg.mesh_domain),
                          why="to begin serving as anchor"):
        print("Start the daemon here:  sudo gw run")
    print()
    from .. import firewall as _fw
    _fw.check(_fw.anchor_rules(cfg.listen_port, control_port, cfg.wg_interface), log)
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
    from ..config import load_config
    cli._require_root("renew-all", "it writes the anchor's root-owned renewal state")
    cfg = load_config(Path(args.config))
    if not cli._holds_anchor(cfg):
        sys.exit(f"gw renew-all needs anchor authority. {cli.NOT_A_HOLDER_MSG}")

    now = cli._request_fleet_renewal(cfg)
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




def _failover_passphrase(confirm: bool) -> bytes:
    """Passphrase for the encrypted failover blob. From $GW_FAILOVER_PASSPHRASE
    if set, else prompted — confirmed when packing at invite time."""
    import getpass
    env = os.environ.get("GW_FAILOVER_PASSPHRASE")
    if env:
        return env.encode()
    pw = getpass.getpass("Failover passphrase: ")
    if not pw:
        sys.exit("empty passphrase — aborting")
    if confirm and getpass.getpass("Confirm passphrase: ") != pw:
        sys.exit("passphrases did not match — aborting")
    return pw.encode()




def _claim_anchor_offer(cfg) -> bytes:
    """`gw anchor adopt` with no path: collect the offer a holder minted for
    this node (`gw anchor offer <name>` there) over the control plane, and
    open it with this node's own WireGuard key. Tries every holder in the
    anchor set — the offer lives on whichever one minted it. Exits with the
    story on failure; returns the anchor file's bytes on success."""
    import secrets as _secrets
    import urllib.error
    import urllib.request
    from .. import anchorfile
    from ..directory import Directory as _Dir
    from ..keys import NodeKeys
    from ..wire import AnchorClaimRequest
    keys = NodeKeys.load_or_generate(cfg.data_dir)
    req = AnchorClaimRequest(
        id_pub=keys.id_pub_bytes,
        nonce=_secrets.token_hex(16),
        ts=dt.datetime.now(_UTC).replace(microsecond=0),
    ).sign(keys.id_priv)
    targets = cli._anchor_urls(cfg, _Dir.load(cfg.dir_cache_path),
                           own_addr=keys.addr)
    if not targets:
        sys.exit("no anchor holders known (root_url/seeds empty and none in "
                 "the directory) — is this node enrolled and synced?")
    refusals: "list[str]" = []
    for base in targets:
        url = f"{base.rstrip('/')}/anchor-claim"
        http_req = urllib.request.Request(
            url, data=json.dumps(req.to_dict()).encode(),
            headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(http_req, timeout=15) as resp:
                data = json.loads(resp.read())
        except urllib.error.HTTPError as e:
            try:
                why = json.loads(e.read()).get("error", str(e))
            except Exception:
                why = str(e)
            refusals.append(f"{base}: {why}")
            continue
        except (urllib.error.URLError, OSError) as e:
            refusals.append(f"{base}: {e}")
            continue
        if "sealed" not in data:
            refusals.append(f"{base}: malformed response")
            continue
        try:
            return anchorfile.unseal_with_wg(data["sealed"], keys.wg_priv)
        except ValueError as e:
            sys.exit(str(e))
    detail = "\n".join(f"  {r}" for r in refusals)
    sys.exit("no holder had an offer for this node:\n" + detail + "\n"
             "Mint one first — on any holder:  sudo gw anchor offer "
             f"{cfg.hostname}   (offers are single-use and expire in "
             f"{int(anchorfile.OFFER_TTL.total_seconds() // 60)}m)")




def cmd_anchor(args) -> int:
    """`gw anchor <action>` — manage the ANCHOR FILE, the mesh's portable
    authority: any node whose data dir holds anchor.gwa performs anchor
    duties (several at once — every decision is a replicated CA-signed
    statement, and issuance reads the replicated directory)."""
    from ..config import load_config
    from .. import anchorfile

    if args.action == "status":
        cfg = load_config(Path(args.config))
        p = anchorfile.anchor_path(cfg.data_dir)
        try:
            af = anchorfile.load(cfg.data_dir)
        except PermissionError:
            print(f"anchor file : present at {p} (run as root to inspect)")
            af = None
        except ValueError as e:
            print(f"anchor file : ⚠ CORRUPT at {p}: {e}")
            print("  restore it from another holder (gw anchor export → "
                  "gw anchor adopt) or from a gw anchor-backup archive")
            return 1
        else:
            if af is not None:
                print(f"anchor file : present — this node is a HOLDER ({p})")
                print(f"  CA pub    : {af.ca_keys().ca_pub_hex}")
                if af.created:
                    print(f"  created   : {af.created}")
            elif cfg.role == "anchor" and cfg.ca_key_file:
                print("anchor file : none — LEGACY anchor (role=anchor + "
                      "ca_key_file). Fold it into the file: sudo gw anchor init")
            else:
                print("anchor file : none — this node holds no anchor authority")
        # The fleet's holders, from the replicated directory (roles ride in
        # CA-attested credentials, so this view needs no privileged state).
        from ..directory import Directory
        d = Directory.load(cfg.dir_cache_path)
        import datetime as _dt
        now = _dt.datetime.now(_dt.timezone.utc)
        holders = [r for r in d.all()
                   if any(c in ("role:*", "role:anchor") for c in r.cred.caps)]
        if holders:
            print("holders (from the directory):")
            for r in sorted(holders, key=lambda r: r.hostname):
                left = (r.cred.exp - now).total_seconds()
                state = ("cred EXPIRED" if left < 0
                         else f"cred expires in {int(left // 3600)}h")
                print(f"  {r.hostname:<12} {r.cred.addr}  ({state})")
        return 0

    cli._require_root(f"anchor {args.action}", "it handles the mesh's root keys")
    cfg = load_config(Path(args.config))

    if args.action == "init":
        if anchorfile.load(cfg.data_dir) is not None:
            print(f"anchor file already present at "
                  f"{anchorfile.anchor_path(cfg.data_dir)} — nothing to do")
            return 0
        if not (cfg.role == "anchor" and cfg.ca_key_file):
            sys.exit("gw anchor init folds a LEGACY anchor's ca.key + door.key "
                     "into the anchor file — run it on the anchor. (A node "
                     "becomes a holder with `gw anchor adopt`, not init.)")
        from ..keys import CAKeys
        from ..door import load_or_generate_door_key
        ca_keys = CAKeys.load(Path(cfg.ca_key_file),
                              cli._get_passphrase(cfg.ca_key_passphrase_env))
        door_raw = load_or_generate_door_key(cfg.data_dir)
        af = anchorfile.AnchorFile.build(cfg.mesh_domain, ca_keys, door_raw)
        p = af.save(cfg.data_dir)
        print(f"anchor file written → {p}")
        print("This ONE file is now the anchor authority: copy it to another "
              "node (over ssh/scp — never the mesh) and `sudo gw anchor adopt` "
              "there to run active/active; delete it (`sudo gw anchor drop`) "
              "to de-anchor a machine. The legacy ca.key/door.key remain "
              "beside it untouched.")
        return 0

    if args.action == "export":
        from ..keys import atomic_write
        if not args.path:
            sys.exit("export needs a destination: gw anchor export <path> "
                     "(or '-' to stream for a pipe)")
        af = anchorfile.load(cfg.data_dir)
        if af is None:
            sys.exit("no anchor file here — on a legacy anchor run "
                     "`sudo gw anchor init` first")
        blob = af.to_bytes()
        if args.path == "-":
            sys.stdout.buffer.write(blob)
            print("\n⚠ that was the mesh's ROOT KEY — whoever holds it IS an "
                  "anchor. Move it over your own channel (ssh), then shred "
                  "intermediate copies.", file=sys.stderr)
        else:
            out = Path(args.path)
            if out.exists():
                sys.exit(f"{out} already exists — refusing to overwrite")
            atomic_write(out, blob, mode=0o600)
            print(f"exported → {out}")
            print("⚠ this file IS the mesh's root authority. Copy it to the "
                  "new holder over ssh/scp, `sudo gw anchor adopt` there, "
                  "then delete this copy.")
        return 0

    if args.action == "offer":
        if not args.path:
            sys.exit("offer needs a target: gw anchor offer <node> — the "
                     "hostname (or id hex) of the enrolled node that should "
                     "become a holder")
        af = anchorfile.load(cfg.data_dir)
        if af is None:
            sys.exit("no anchor file here — on a legacy anchor run "
                     "`sudo gw anchor init` first")
        from ..ca import CA
        from ..keys import NodeKeys
        _pubs = [bytes.fromhex(h) for h in cfg.ca_pubs_hex]
        ca = CA(af.ca_keys(), cfg.data_dir, dir_cache_path=cfg.dir_cache_path,
                get_ca_pubs=(lambda: _pubs) if _pubs else None)
        target_id, target_name = cli._resolve_node(ca, cfg, args.path)
        own = NodeKeys.load_or_generate(cfg.data_dir)
        if target_id == own.id_pub_bytes:
            sys.exit("that's this node — it already holds the anchor file")
        # The wg key to seal to comes from the target's CA-attested record:
        # the CA says this key belongs to that name, so the offer can only be
        # opened by the machine the operator named.
        from ..directory import Directory as _Dir
        rec = _Dir.load(cfg.dir_cache_path).get(target_id.hex())
        if rec is None:
            sys.exit(f"no record for {target_name!r} in the directory — the "
                     f"node must be enrolled and have published (is its "
                     f"daemon running?)")
        try:
            rec.cred.verify(_pubs or [af.ca_keys().ca_pub_bytes],
                            allow_expired=True)
        except ValueError as e:
            sys.exit(f"{target_name!r}'s record isn't trusted ({e}) — "
                     f"refusing to seal the root key to it")
        sealed = anchorfile.seal_to_wg(rec.cred.wg_pub, af.to_bytes())
        anchorfile.write_offer(cfg.data_dir, target_id.hex(), target_name,
                               sealed)
        from .. import audit as _audit
        if cfg.audit_log is not None:
            _audit.attach_file(cfg.audit_log)
        _audit.event("anchor-offer", node=target_name, id=target_id.hex()[:16])
        mins = int(anchorfile.OFFER_TTL.total_seconds() // 60)
        print(f"offer minted for {target_name} — sealed to its WireGuard key, "
              f"single-use, expires in {mins}m.")
        print(f"On {target_name}:  sudo gw anchor adopt")
        print("(This holder's daemon serves the claim — it must be running.)")
        return 0

    if args.action == "adopt":
        if args.path:
            raw = (sys.stdin.buffer.read() if args.path == "-"
                   else Path(args.path).read_bytes())
        else:
            raw = _claim_anchor_offer(cfg)
        try:
            af = anchorfile.AnchorFile.from_bytes(raw)
        except ValueError as e:
            sys.exit(f"not adoptable: {e}")
        if af.mesh_domain != cfg.mesh_domain:
            sys.exit(f"this anchor file belongs to mesh {af.mesh_domain!r}; "
                     f"this membership is {cfg.mesh_domain!r} — refusing a "
                     f"cross-mesh adoption")
        ca_pub = af.ca_keys().ca_pub_hex
        if cfg.ca_pubs_hex and ca_pub not in cfg.ca_pubs_hex:
            sys.exit("this anchor file's CA is not in this node's trusted_pubs "
                     "— it is not (or no longer) this mesh's root. If this is "
                     "a deliberate re-root, add the new CA pub to [ca] "
                     "trusted_pubs first.")
        p = af.save(cfg.data_dir)
        print(f"adopted → {p} — this node now holds anchor authority")
        # Grant ourselves the anchor roles: a replicated setcaps statement,
        # applied at our next renewal and visible to every holder and node.
        from ..ca import CA
        from ..keys import NodeKeys
        keys = NodeKeys.load_or_generate(cfg.data_dir)
        _pubs = [bytes.fromhex(h) for h in cfg.ca_pubs_hex]
        ca = CA(af.ca_keys(), cfg.data_dir, dir_cache_path=cfg.dir_cache_path,
                get_ca_pubs=(lambda: _pubs) if _pubs else None)
        own = ca.node_info(keys.id_pub_bytes)
        if own is not None:
            caps = list(own[1])
            for c in ("role:*", "role:anchor"):
                if c not in caps:
                    caps.append(c)
            ca.set_caps(keys.id_pub_bytes, caps)
            print("anchor roles granted (replicated setcaps — adopted at the "
                  "next credential renewal)")
        else:
            print("note: this node has no record in its directory cache yet — "
                  "its anchor roles will need `gw set-roles` once it has one")
        if not cli._service_restart(membership_key(cfg.mesh_domain),
                                why="to begin serving as an anchor"):
            print("Restart the daemon to begin serving:")
            print(f"  {cli._svc_restart_hint(membership_key(cfg.mesh_domain))}")
        return 0

    if args.action == "drop":
        af = anchorfile.load(cfg.data_dir)
        if af is None:
            if cfg.role == "anchor" and cfg.ca_key_file:
                sys.exit("this is a LEGACY anchor (role=anchor + ca_key_file), "
                         "not a file-holder — `gw anchor init` first if you "
                         "want file semantics, or decommission it per the "
                         "operations runbook")
            print("no anchor file here — nothing to drop")
            return 0
        # While we still hold the key: shed our anchor roles via a replicated
        # setcaps, so the fleet stops treating this node as a holder once its
        # credential renews.
        from ..ca import CA
        from ..keys import NodeKeys
        keys = NodeKeys.load_or_generate(cfg.data_dir)
        _pubs = [bytes.fromhex(h) for h in cfg.ca_pubs_hex]
        ca = CA(af.ca_keys(), cfg.data_dir, dir_cache_path=cfg.dir_cache_path,
                get_ca_pubs=(lambda: _pubs) if _pubs else None)
        own = ca.node_info(keys.id_pub_bytes)
        if own is not None:
            caps = [c for c in own[1] if c not in ("role:*", "role:anchor")]
            ca.set_caps(keys.id_pub_bytes, caps)
        anchorfile.anchor_path(cfg.data_dir).unlink()
        print(f"dropped — {anchorfile.anchor_path(cfg.data_dir)} deleted; "
              f"this machine no longer holds anchor authority")
        print("Note: deleting a copy is the COOPERATIVE de-anchor (leave, for "
              "anchors). It proves nothing about other copies — if this "
              "machine is no longer trusted, rotate the CA key (re-root) "
              "instead: knowledge can't be revoked.")
        if not cli._service_restart(membership_key(cfg.mesh_domain),
                                why="to stop serving as an anchor"):
            print("Restart the daemon to stop serving:")
            print(f"  {cli._svc_restart_hint(membership_key(cfg.mesh_domain))}")
        return 0

    sys.exit(f"unknown anchor action {args.action!r}")




def cmd_anchor_backup(args) -> int:
    """Write a single encrypted archive of this anchor's trust state (CA key, the
    nodes/ registry, revoke list, door key). Restoring the same key onto a new
    host is a restore, not a re-root — no fleet-wide trust change."""
    from ..config import load_config
    from .. import backup as bak

    cli._require_root("anchor-backup", "it reads the CA key and the anchor registry")
    cfg = load_config(Path(args.config))
    if not cli._holds_anchor(cfg):
        sys.exit(f"gw anchor-backup needs anchor authority. {cli.NOT_A_HOLDER_MSG}")
    files = bak.collect_anchor_state(cfg.data_dir, cfg.ca_key_file)
    if "ca.key" not in files and "anchor.gwa" not in files:
        sys.exit("no CA root found (neither anchor.gwa nor ca.key) — "
                 "nothing to back up")

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

    if to_stdout:
        sys.stdout.buffer.write(blob)          # binary to stdout; notes to stderr
        sys.stdout.buffer.flush()
        print(f"streamed anchor backup ({len(files)} file(s))", file=sys.stderr)
        return 0

    out = Path(args.out) if args.out else \
        cfg.data_dir / f"greasewood-anchor-backup-{cfg.hostname}.gwbk"
    from ..keys import atomic_write
    atomic_write(Path(out), blob)          # 0600, atomic: the fleet's root key
    print(f"wrote encrypted anchor backup → {out}")
    print("  CA key + identity + statements/revoke list + door key "
          "(membership itself lives in the replicated directory — every "
          "node's record IS its registry entry)")
    print("Store it OFFLINE. Anyone with this file AND the passphrase can "
          "impersonate your CA. Test-restore it before you rely on it.")
    return 0




def cmd_anchor_restore(args) -> int:
    """Decrypt an anchor backup into a data dir. For standing up a replacement anchor
    on the same CA key (see RUNBOOK 'destroyed anchor')."""
    cli._require_root("anchor-restore")
    from .. import backup as bak

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

    print(f"restored {len(written)} file(s) into {data_dir}")
    print("  CA key + identity + statements/revoke list + door key "
          "(membership itself lives in the replicated directory — every "
          "node's record IS its registry entry)")
    print("Next: write /etc/greasewood.toml pointing ca_key_file at "
          f"{data_dir / 'ca.key'} (role = anchor), then `sudo gw run`. Because the "
          "CA key is unchanged, existing nodes keep trusting it — no re-root.")
    return 0




def cmd_anchor_activate(args) -> int:
    """[sudo] Promote a failover standby node to anchor.  Decrypts the CA blob
    received at enrollment, rebuilds the node registry from the cached
    directory, and rewrites this node's config to role=anchor.  Run `gw run`
    afterwards to start serving control plane + door.  Refuses if the existing
    anchor still looks reachable."""
    cli._require_root("anchor-activate")
    from ..config import load_config, _parse_duration
    from ..keys import CAKeys, NodeKeys, atomic_write
    from ..ca import CA
    from .. import backup as bak

    cfg = load_config(Path(args.config))
    if cfg.role == "anchor" and not args.force:
        sys.exit("this node is already configured as an anchor; "
                 "pass --force to re-activate anyway")
    if "failover" not in cfg.caps:
        sys.exit("this node does not hold the 'failover' capability — "
                 "re-enroll it with `gw invite --caps failover`")
    failover_path = cfg.data_dir / "failover_anchor.gwbk"
    if not failover_path.exists():
        sys.exit(f"no failover blob at {failover_path} — "
                 "was this node enrolled with --caps failover?")

    passphrase = _failover_passphrase(confirm=False)
    try:
        files = bak.unpack(failover_path.read_bytes(), passphrase)
    except bak.BackupError as e:
        sys.exit(f"failed to decrypt failover blob: {e}")
    if "ca.key" not in files:
        sys.exit("failover blob is missing the CA key")

    # Refuse if the current anchor is still reachable.
    urls_to_try = [cfg.root_url] if cfg.root_url else cfg.seeds
    import urllib.request
    for url in urls_to_try:
        if not url:
            continue
        try:
            urllib.request.urlopen(f"{url.rstrip('/')}/health", timeout=3)
        except Exception:
            continue
        sys.exit(
            "a live anchor is still reachable — refusing to activate a standby "
            "while the current anchor appears up. If the URL is stale, remove/"
            "repoint [network] root_url before running this command."
        )

    data_dir = cfg.data_dir
    ca_key_path = data_dir / "ca.key"
    written = []
    for name in ["ca.key", "ca.key.pub", "ca.cert.pem", "door.key", "revoked.json"]:
        if name in files:
            dest = data_dir / name
            if dest == ca_key_path and dest.exists() and not args.force:
                sys.exit(f"{dest} already exists — pass --force to overwrite")
            atomic_write(dest, files[name])
            written.append(name)
    if not ca_key_path.exists():
        sys.exit("CA key was not written from the failover blob")

    # No registry to rebuild: every node's (hostname, caps) live in its
    # replicated record, which this node's directory cache already holds —
    # renewal re-issues straight from those. The one change to make is OURS:
    # this node is becoming an anchor, so mint the setcaps statement that
    # grants it the anchor roles at its next renewal.
    ca_keys = CAKeys.load(ca_key_path)
    ca = CA(ca_keys, data_dir, credential_ttl=_parse_duration(args.credential_ttl),
            dir_cache_path=cfg.dir_cache_path)
    node_keys = NodeKeys.load_or_generate(data_dir)
    own = ca.node_info(node_keys.id_pub_bytes)
    if own is not None:
        caps = list(own[1])
        for c in ("role:*", "role:anchor"):
            if c not in caps:
                caps.append(c)
        ca.set_caps(node_keys.id_pub_bytes, caps)

    # Rewrite this node's config as an anchor.
    control_port = args.control_port
    door_port = args.door_port
    ca_pub_hex = ca_keys.ca_pub_bytes.hex()
    cfg_path = Path(args.config)
    anchor_caps = list(cfg.caps)
    for c in ("role:*", "role:anchor"):
        if c not in anchor_caps:
            anchor_caps.append(c)
    cfg_path.write_text(render_config(
        hostname=cfg.hostname, data_dir=data_dir, role="anchor", caps=anchor_caps,
        endpoints=cfg.endpoints, interface=cfg.wg_interface,
        listen_port=cfg.listen_port, overlay_prefix=cfg.overlay_prefix,
        seeds=[], root_url=f"http://[::1]:{control_port}",
        hosts_sync=cfg.hosts_sync, mesh_domain=cfg.mesh_domain,
        trusted_pubs=[ca_pub_hex],
        endpoint_auto=cfg.endpoint_auto,
        anchor={"ca_key_file": ca_key_path, "control_port": control_port,
                "credential_ttl": args.credential_ttl,
                "door_port": door_port}))
    log.info("rewrote %s for role=anchor", cfg_path)
    print("\nStandby activated as anchor.")
    print(f"  CA pub key   : {ca_pub_hex}")
    print(f"  control URL  : http://[{node_keys.addr}]:{control_port}")
    print(f"  files written: {', '.join(written)}")
    print("  membership   : served from the replicated directory "
          f"({cfg.dir_cache_path}) — nothing to rebuild")
    if not cli._service_restart(membership_key(cfg.mesh_domain),
                          why="to serve the control plane + door"):
        print("\nStart the daemon to serve the control plane:")
        print(f"  sudo gw -c {cfg_path} run")
    return 0




def cmd_anchor_standby(args) -> int:
    """[sudo, anchor] Re-enroll an existing node so it can pick up new caps
    (e.g. `failover`) and the matching encrypted blob. The node reuses its
    existing identity keys and runs `gw join <token>` like a normal enrollment."""
    cli._require_root("anchor-standby")
    from ..config import load_config
    from ..ca import CA
    import argparse

    cfg = load_config(Path(args.config))
    if not cli._holds_anchor(cfg):
        sys.exit(f"gw anchor-standby needs anchor authority. {cli.NOT_A_HOLDER_MSG}")
    ca_keys, _guard = cli._anchor_ca_source(cfg)
    _pubs = [bytes.fromhex(h) for h in cfg.ca_pubs_hex]
    ca = CA(ca_keys, cfg.data_dir, dir_cache_path=cfg.dir_cache_path,
            get_ca_pubs=lambda: _pubs or [ca_keys.ca_pub_bytes])

    hostname = args.hostname
    owner_hex = ca.hostname_owner(hostname)
    if owner_hex is None:
        sys.exit(f"no enrolled node named {hostname!r} — use `gw invite` for a new node")
    info = ca.node_info(bytes.fromhex(owner_hex))
    if info is None:
        sys.exit(f"no live record for {hostname!r}")

    current_caps = list(info[1])
    extras = [c.strip() for c in args.caps.split(",") if c.strip()] if args.caps else []
    new_caps = list(dict.fromkeys(current_caps + extras + ["failover"]))

    inv_args = argparse.Namespace(
        config=args.config,
        hostname=hostname,
        caps=",".join(new_caps),
        roles="",
        exact=True,
        self_roles=None,
        self_roles_from_grants=False,
        endpoint=getattr(args, "endpoint", None),
        standing=False,
        supersede=False,
        quiet=False,
        allow_existing_hostname=True,
    )
    log.info("re-issuing invite for %s with caps=%s", hostname, new_caps)
    return cli.cmd_invite(inv_args)




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
    from ..config import load_config, membership_key

    cli._require_root("anchor-transfer", "it moves the CA key and stops the local anchor")
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
    if not cli._systemd_available():
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
        stop_local=lambda u: cli._systemctl_run(["systemctl", "stop", u]),
        start_remote=lambda u: rssh(f"sudo systemctl enable --now {u}",
                                    capture_output=True).returncode == 0,
        remote_active=remote_active,
        start_local=lambda u: cli._systemctl_run(["systemctl", "start", u]),
    )
    if not ok:
        sys.exit(f"⚠ {dest} did not come up as the anchor — ROLLED BACK; this anchor "
                 "is running again. Check the target (journalctl -eu " + unit + ") "
                 "and retry.")

    cli._systemctl_run(["systemctl", "disable", unit], capture_output=True)  # no auto-restart
    print(f"✓ anchor transferred to {dest} — same CA, the fleet reconnects, no re-root.")
    print(f"  This host is stopped and won't auto-start. Decommission when ready: "
          "sudo gw purge")
    return 0
