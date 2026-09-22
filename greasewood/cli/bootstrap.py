"""greasewood.cli.bootstrap — Mesh bootstrap: gw create, gw invite / close-door (the door windows), and gw join (token routing + the door dance with handshake-gated host fallback)."""
import base64
import datetime as dt
import json
import logging
import os
import socket
import sys
import time
from pathlib import Path

from ..config import membership_key, render_config

# The package namespace is the late-binding seam: cross-module helpers are
# called as cli.<name> so a monkeypatch on the package (the tests' historic
# patch point) reaches every caller, exactly as it did when this was one file.
import greasewood.cli as cli

_UTC = dt.timezone.utc
log = logging.getLogger("greasewood")




def cmd_create(args) -> int:
    cli._require_root("create")
    cli._require_tools()
    from ..hosts import valid_label as _vl
    if not _vl(args.name):
        sys.exit(f"mesh name {args.name!r} must be a DNS label "
                 "(lowercase letters/digits/hyphens, e.g. 'prod-fleet')")
    if args.interface is not None:
        cli._reject_bad_interface(args.interface)
    from ..keys import CAKeys, NodeKeys
    from ..ca import CA
    from ..wire import NodeRecord
    from ..directory import Directory
    from ..config import _parse_duration
    from ..door import load_or_generate_door_key
    from .. import wg as wgmod

    # Everything derives from the mesh name unless explicitly overridden —
    # nothing unsuffixed exists: the first mesh on a host is named like the Nth.
    _mp = cli._membership_paths(args.name)
    cfg_path = Path(args.config) if args.config else _mp["config"]
    data_dir = Path(args.data_dir) if args.data_dir else _mp["data_dir"]
    ca_key_path = data_dir / "ca.key"
    # The role is "anchor"; the hostname is just this machine's name by default
    # (short form, no domain), overridable with --hostname.
    from ..keys import set_overlay_prefix, parse_overlay_prefix
    hostname = args.hostname or socket.gethostname().split(".")[0] or "anchor"
    listen_port = args.listen_port if args.listen_port is not None else cli._free_listen_port()
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
        clash = cli._iface_collision(interface, cfg_path)
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

    endpoints = cli._advertised_endpoints(args.endpoint, listen_port)
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
                "already-RUNNING daemon was signing with the OLD key until "
                "restarted.")
            if not cli._service_restart(args.name, why="to sign with the new CA key"):
                print("Restart the daemon to sign with the new CA key:")
                print(f"  {cli._svc_restart_hint(args.name)}")
                print("Then re-run `gw invite` to mint fresh invites.")

    # Door keypair (persistent across invites)
    door_raw = load_or_generate_door_key(data_dir)
    log.info("door key ready")

    # The ANCHOR FILE: both root secrets (CA + door key) in one transferable
    # file. Possession = anchor authority; new meshes are file-based from
    # birth (the standalone ca.key/door.key remain beside it for downgrade
    # compatibility). Idempotent: never clobber an existing file on re-create
    # without --force having already rotated the CA above.
    from .. import anchorfile
    if anchorfile.load(data_dir) is None or getattr(args, "force", False):
        anchorfile.AnchorFile.build(mesh_domain, ca_keys, door_raw).save(data_dir)
        log.info("anchor file ready → %s", anchorfile.anchor_path(data_dir))

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
        trusted_pubs=[ca_pub_hex],
        endpoint_auto=(args.endpoint is None),   # pinned iff --endpoint was given
        anchor={"ca_key_file": ca_key_path, "control_port": control_port,
                "credential_ttl": args.credential_ttl,
                "door_port": args.door_port}))
    log.info("wrote config → %s", cfg_path)

    # Drop the default grant table: DEFAULT-CLOSED (a secure star — only
    # role:admin, i.e. the anchor, can SSH nodes; nodes reach only the control
    # plane). Alternatives ship commented in the file. Idempotent: never clobber
    # an existing grants.toml on re-create.
    from ..policy import GRANTS_BASENAME, DEFAULT_GRANTS_TOML, sign_default_policy
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
    cli._print_daemon_guidance(args.name, cfg_path, "then invite nodes to enroll them",
                           no_service=getattr(args, "no_service", False))
    print()
    print(f"Enroll a new node:")
    print(f"  TOKEN=$(sudo gw invite)          # on this machine")
    print(f"  sudo gw join \"$TOKEN\" --hostname <name>   # on the new machine")
    print()
    cli._print_firewall_help(listen_port, control_port, interface)
    print()
    from .. import firewall as _fw
    _fw.check(_fw.anchor_rules(listen_port, control_port, interface), log)
    return 0




def _menu_from_grants(data_dir: "Path") -> list:
    """The role menu derived from grants.toml (`gw invite --self-roles-from-grants`):
    every role name referenced in any grant's from/to, minus the roles that must
    never be self-serve — the reserved set ('*', 'anchor'), the default 'node'
    (it's what a plain invite grants anyway), and 'admin' (fleet-wide terminal
    access doesn't belong on an auto-derived standing token; offer it explicitly
    with --self-roles if you mean it). grants.toml is the human-authored source
    of truth, so the menu tracks the policy vocabulary with no second list."""
    from ..policy import parse_grants_toml, GRANTS_BASENAME, RESERVED_ROLES
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
    cli._require_root("invite")
    if getattr(args, "quiet", False):
        # -q: emit only the token on stdout — silence the informational stderr
        # chatter (superseding-window warning, door/wg setup logs) for scripting.
        logging.getLogger().setLevel(logging.ERROR)
    from ..config import load_config
    from ..door import (
        generate_seed, derive_door_params, encode_token,
        load_or_generate_door_key, door_pub_bytes_from_key,
    )
    from .. import wg as wgmod

    cfg = load_config(Path(args.config))
    if not cli._holds_anchor(cfg):
        sys.exit(f"gw invite needs anchor authority. {cli.NOT_A_HOLDER_MSG}")

    # Preflight: a token is only redeemable if the daemon is up (it hosts the
    # enroll server) with its mesh interface present (it installs the joiner as
    # a peer). Catch both NOW, when the operator can act — not minutes later as
    # a cryptic rejection on the joining node.
    _mgr = cli._service_backend()
    _key = membership_key(cfg.mesh_domain)
    _start = (_mgr.restart_hint(_key) if _mgr
              else f"sudo systemctl start {cli._unit_for_config(args.config)}")
    _logs = (_mgr.logs_hint(_key) if _mgr
             else f"journalctl -u {cli._unit_for_config(args.config)} -n 20")
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
        _url.urlopen(f"http://[::1]:{cli._control_port(cfg)}/directory", timeout=3)
    except Exception:
        sys.exit(f"the anchor daemon isn't answering on loopback (port "
                 f"{cli._control_port(cfg)}) — it hosts the enroll server, so this "
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

    from .. import door as doormod
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

    ca_keys, _guard = cli._anchor_ca_source(cfg)

    # Anchor underlay host(s) for the token (bare addresses; the joiner adds the
    # door port). Carry v6 and/or v4 so a joiner reaches the anchor over whichever
    # family it has — stored comma-separated in the token's single host field
    # (a v6 literal has colons but never commas, so the split is unambiguous).
    if args.endpoint:
        anchor_hosts = [args.endpoint]
    else:
        anchor_hosts = []
        v6 = cli._detect_public_ipv6()
        if v6:
            anchor_hosts.append(v6)
        v4 = cli._detect_public_ipv4()
        if v4:
            anchor_hosts.append(v4)
        if not anchor_hosts:
            sys.exit("could not detect a public address; use --endpoint <addr>")
    endpoint = ",".join(anchor_hosts)

    # Sanity-check the hosts going into the token against peer TESTIMONY: if
    # peers attest to reaching this holder, but never at any of these hosts,
    # the token likely embeds a mirage (the VPN-/128 class) and the joiner
    # will hang dialing it. Advisory only — a fresh mesh has no testimony.
    try:
        from ..attest import AttestLog, attest_path
        from ..keys import NodeKeys as _NK
        _own = _NK.load_or_generate(data_dir)
        _conf = AttestLog.load(attest_path(data_dir),
                               lambda _h: True).confirmations_for(_own.id_pub_hex)
        if _conf:
            def _host_of(ep: str) -> str:
                ep = ep.rsplit(":", 1)[0] if not ep.startswith("[") \
                    else ep[1:ep.index("]")]
                return ep
            confirmed_hosts = {_host_of(e) for e in _conf}
            if not (set(anchor_hosts) & confirmed_hosts):
                print(f"⚠ no peer currently confirms reaching this holder at "
                      f"{', '.join(anchor_hosts)} — peers attest "
                      f"{', '.join(sorted(confirmed_hosts))} instead. The "
                      f"token may embed an unreachable door (see `gw watch`'s "
                      f"confirmed line); consider --endpoint with a working "
                      f"address.")
    except Exception as e:  # noqa: BLE001 — advisory, never blocks an invite
        log.debug("could not check endpoint confirmations: %s", e)

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
    cli._reject_reserved_roles(allowed_roles, "--self-roles")   # never self-serve *, anchor
    if args.roles is not None:
        roles = [r.strip() for r in args.roles.split(",") if r.strip()]
        cli._reject_reserved_roles(roles, "--roles")
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
    cli._reject_reserved_roles([c[len("role:"):] for c in caps if c.startswith("role:")],
                           "the invite's caps/default_roles")
    # `hostname-pinned` is DERIVED: the --hostname path re-adds it below, and only
    # there. Screen it out of the user-supplied caps first (see the helper). (L4-adjacent)
    cli._reject_derived_caps(caps)
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
        from ..ca import CA as _CA
        owner = _CA(ca_keys, data_dir,
                    dir_cache_path=cfg.dir_cache_path).hostname_owner(pinned_hostname)
        if owner is not None and not getattr(args, "allow_existing_hostname", False):
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

    failover_blob = None
    if "failover" in caps:
        from .. import backup as bak
        fpass = cli._failover_passphrase(confirm=True)
        fblob = bak.pack(
            bak.collect_failover_state(data_dir, cfg.ca_key_file), fpass)
        failover_blob = base64.b64encode(fblob).decode()
        log.info("packing encrypted failover blob for this standby")

    seed = generate_seed()
    params = derive_door_params(seed)

    # Set up door routing (idempotent — survives reboots if called here too)
    wgmod.setup_door_routing()

    # Bring up the anchor's door WG interface on the configured door port
    door_key_path = data_dir / "door.key"
    from .. import audit
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
        from ..keys import atomic_write
        atomic_write(window_path, json.dumps({
            "v": 1,
            "standing": True,
            "caps": caps,
            "allowed_roles": allowed_roles,   # menu: roles a joiner may self-select
            "hostname": None,          # standing doors can't pin one name
            "guest_pub": params.guest_pub_b64,
            "psk": params.psk_b64,
            "token": token,
            "failover_blob": failover_blob,
        }), mode=0o600)
        log.info("STANDING door opened — this token enrolls any number of "
                 "nodes until: sudo gw close-door")
    else:
        expires = dt.datetime.now(dt.timezone.utc) + window
        # atomic_write (0600 from creation) — no world-readable pre-chmod window.
        # No key material here (the timed door isn't persisted for reboot), but it
        # discloses the caps/roles being granted, and consistency avoids the L6
        # class of bug entirely. (L1)
        from ..keys import atomic_write
        atomic_write(window_path, json.dumps({
            "v": 1,
            "expires": expires.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "caps": caps,
            "allowed_roles": allowed_roles,   # menu: roles a joiner may self-select
            "hostname": pinned_hostname,   # None → joiner names itself (unpinned)
            "failover_blob": failover_blob,
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
    from ..config import load_config
    from .. import door as doormod
    from .. import wg as wgmod

    cli._require_root("close-door", "it removes the anchor's door window and interface")
    cfg = load_config(Path(args.config))
    if not cli._holds_anchor(cfg):
        sys.exit(f"gw close-door needs anchor authority. {cli.NOT_A_HOLDER_MSG}")

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




def _enroll_over_door(*args, **kwargs):
    """Crash guard around the door dance: the inner function's graceful
    refusals tear gw-door down themselves before sys.exit, but a CRASH path
    (missing binary, Ctrl-C mid-wait, unexpected error) used to leave the
    half-made interface behind (seen in the field). On success the door is
    deliberately left UP — the caller pushes the signed record back through
    it."""
    from .. import wg as wgmod
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




def _door_handshake_up(wgmod, timeout: float) -> bool:
    """Poll the transient door interface until its (single) peer shows a
    WireGuard handshake, or the timeout passes. The handshake is the ONLY
    honest reachability signal for a door host: local-family heuristics and
    ping say nothing about whether the anchor's door answers on this address."""
    from ..door import DOOR_IFACE
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        peers = wgmod.get_peers(DOOR_IFACE)
        if peers and any(p.latest_handshake > 0 for p in peers.values()):
            return True
        time.sleep(0.5)
    return False




_DOOR_HANDSHAKE_TIMEOUT = 10.0    # per candidate host




def _dial_door(wgmod, anchor_hosts: "list[str]", guest_priv_bytes: bytes,
               anchor_door_pub_b64: str, psk_b64: str, door_port) -> str:
    """Dial the anchor's door on each candidate host in order, gated on the
    real WireGuard handshake, and return the host that answered — leaving the
    door interface up against it. On total failure, tear the door down and
    exit with a per-host report (never a silent hang on the first address)."""
    from .. import audit
    from ..door import DOOR_IFACE
    failures: "list[tuple[str, str]]" = []
    for host in anchor_hosts:
        with audit.context(f"join: bring up node door interface → {host}"):
            wgmod.ensure_node_door_interface(
                guest_priv_bytes, anchor_door_pub_b64, psk_b64, host, door_port)
        log.info("dialing the door at [%s]:%s — waiting for WireGuard handshake ...",
                 host, door_port)
        if _door_handshake_up(wgmod, cli._DOOR_HANDSHAKE_TIMEOUT):
            return host
        failures.append((host, f"no WireGuard handshake within "
                               f"{cli._DOOR_HANDSHAKE_TIMEOUT:.0f}s"))
        log.warning("no handshake via %s — trying the next host", host)
    wgmod.destroy_interface(DOOR_IFACE)
    report = "\n".join(f"  {h} — {why}" for h, why in failures)
    hints = ["is the anchor daemon running, and the invite window still open? "
             "(the door only exists while a window is open — mint a fresh "
             "token and join within its lifetime)"]
    if any(":" not in h for h, _ in failures):
        hints.append("a v4 endpoint dialed from INSIDE the anchor's own "
                     "network needs NAT hairpin, which many routers lack — "
                     "from inside, the anchor's v6 or LAN address works")
    sys.exit("could not reach the anchor's door on any advertised host:\n"
             f"{report}\n" + "\n".join(f"Hint: {h}" for h in hints))




def _enroll_over_door_inner(data_dir, node_keys, hostname: str,
                            anchor_hosts: "list[str]",
                            anchor_door_pub_b64: str, params, door_port,
                            ca_pub_bytes: bytes, already_enrolled: bool,
                            requested_roles: "list | tuple" = ()):
    """The door dance: bring up the transient gw-door interface, connect to the
    anchor's enroll daemon through it, exchange request → credential, and
    verify the credential against the token's CA. Every failure exits with an
    actionable message (tearing the door down first). On success the door is
    left UP and the socket OPEN: the caller pushes its signed record back on
    the same connection as the second leg, then tears down. Returns
    (conn, resp, cred).

    `anchor_hosts` is the token's candidate list in dialing order (see
    _order_door_hosts). Each is tried in turn, gated on the actual WireGuard
    handshake — not on family heuristics — so a node with several paths to the
    anchor heals over whichever one really works, and a total failure reports
    every host with its reason instead of hanging on the first."""
    from .. import wg as wgmod
    from ..wire import Credential

    # Bring up the local door interface (door port comes from the token) and
    # dial each candidate host until one completes a handshake.
    from .. import audit
    audit.attach_file(data_dir / "audit.log")   # one-shot door commands → the trail
    _dial_door(wgmod, anchor_hosts, params.guest_priv_bytes,
               anchor_door_pub_b64, params.psk_b64, door_port)

    # Connect to anchor's enroll daemon via the door tunnel
    from ..door import ANCHOR_DOOR_IP, ENROLL_PORT
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
    from ..wire import enroll_pop_body
    req["id_sig"] = _b64mod.b64encode(node_keys.id_priv.sign(
        enroll_pop_body(node_keys.id_pub_bytes, node_keys.wg_pub_bytes,
                        hostname or ""))).decode()
    from ..door import recv_msg as _recv_framed, send_msg as _send_framed

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
    from ..config import load_config

    if args.interface is not None:                # covers every join branch
        cli._reject_bad_interface(args.interface)

    cfg_path = Path(args.config) if args.config else None
    data_dir = Path(args.data_dir) if args.data_dir else None
    listen_port = args.listen_port

    joined_key = None
    auto = args.config is None and args.data_dir is None
    if auto:
        known = cli._membership_for_ca(ca_pub_hex)
        if known is not None:
            # Re-join: use the existing membership's config as-is (its real,
            # possibly-customized values win; `prior` below supplies the rest).
            cfg_path = cli._membership_paths(known)["config"]
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
            mp = cli._membership_paths(key)
            cfg_path, data_dir = mp["config"], mp["data_dir"]
            listen_port = (args.listen_port
                           if args.listen_port is not None else cli._free_listen_port())
            if args.interface is None:
                args.interface = mp["interface"]
                clash = cli._iface_collision(args.interface, cfg_path)
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
            listen_port = cli._free_listen_port()

    # HARD domain-collision refusal, BEFORE the door dance (so a refusal never
    # burns the invite): a mesh has ONE domain everywhere, and a node cannot
    # bridge two meshes that share one — no alias, no flag, no exception. The
    # only membership that may legitimately carry this domain is the one being
    # REFRESHED — identified by CA, not by config path: a *different* mesh with
    # the same name derives the same config path, so excluding by path would
    # mask exactly the collision we must catch.
    if token_domain:
        _rk = cli._membership_for_ca(ca_pub_hex)
        _refresh_cfg = cli._membership_paths(_rk)["config"].resolve() if _rk else None
        for _n, _p in cli._memberships():
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
    cli._require_root("join")
    cli._require_tools()
    from ..keys import NodeKeys
    from ..wire import NodeRecord
    from ..directory import Directory
    from ..door import decode_token, derive_door_params
    from ..config import load_config
    from .. import wg as wgmod
    # way we tolerantly extract the gw1.… line, so `gw invite | ssh B gw join -`
    # works even without `invite -q`.
    token = cli._extract_token(sys.stdin.read() if args.token == "-" else args.token)

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
    anchored = cli._anchor_membership()
    if anchored:
        from ..door import DOOR_TABLE, GUEST_DOOR_IP
        akey, apath = anchored
        sys.exit(
            f"this host is the anchor for mesh '{akey}' ({apath}). A host can't be "
            f"an anchor AND join another mesh — the enrollment door (gw-door, table "
            f"{DOOR_TABLE}) is a shared singleton, so the anchor's door isolation "
            f"would blackhole this join (it hangs at 'connecting to enroll daemon'). "
            f"Join from a non-anchor host. To override for a one-off: "
            f"`sudo ip -6 rule del from {GUEST_DOOR_IP} lookup {DOOR_TABLE}`, run the "
            f"join, then `{cli._svc_restart_hint(akey)}` to restore it.")

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
    node_endpoints = cli._advertised_endpoints(
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
    # The token may carry several anchor underlay hosts (v4 and/or v6, comma-
    # sep). Order them for dialing (v6 first when we can originate v6) and drop
    # any that are OUR OWN addresses — a shared commercial VPN can put the
    # anchor's detected "public" address on this machine too, and dialing it
    # would loop back to ourselves forever. The door dance then tries each
    # remaining host in turn, gated on the real WireGuard handshake.
    anchor_hosts, _skipped_hosts = cli._order_door_hosts(anchor_host.split(","))
    for _h, _why in _skipped_hosts:
        log.warning("not dialing anchor host %s: %s", _h, _why)
    if not anchor_hosts:
        detail = "\n".join(f"  {h} — {why}" for h, why in _skipped_hosts)
        sys.exit("every anchor host in this token is undialable from here:\n"
                 f"{detail}\n"
                 "Hint: the anchor is advertising an address this machine also "
                 "owns (a VPN both ends run?). On the anchor, pin a real "
                 "address: sudo gw invite --endpoint <the anchor's actual "
                 "LAN or public address>")

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
        data_dir, node_keys, hostname, anchor_hosts, anchor_door_pub_b64,
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
    if "failover" in caps:
        fblob = resp.get("failover_blob")
        if not fblob:
            wgmod.destroy_interface("gw-door")
            sys.exit("failover capability granted but no encrypted blob was received")
        from ..keys import atomic_write
        atomic_write(data_dir / "failover_anchor.gwbk",
                     base64.b64decode(fblob), mode=0o600)
        log.info("stored encrypted failover blob for later anchor-activate")
    if cred.id_pub != node_keys.id_pub_bytes:
        wgmod.destroy_interface("gw-door")
        sys.exit("credential id_pub mismatch — something went wrong")
    log.info("credential verified, expires %s", cred.exp.strftime("%Y-%m-%d %H:%M UTC"))

    # Learn the fleet's overlay /64 from the credential the CA just issued (the
    # authoritative source), and activate it so our own address / record are
    # built under the right prefix. This is what lets a node join a mesh on any
    # prefix without being told out of band.
    import ipaddress as _ip
    from ..keys import set_overlay_prefix, format_overlay_prefix
    overlay_prefix = format_overlay_prefix(_ip.IPv6Address(cred.addr).packed[:8])
    set_overlay_prefix(_ip.IPv6Address(cred.addr).packed[:8])
    # Multi-mesh legibility check: same /64 as another membership on this host?
    cli._warn_shared_overlay_prefix(cfg_path, overlay_prefix)

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
        from ..policy import POLICY_BASENAME
        (data_dir / POLICY_BASENAME).write_text(json.dumps(resp["policy"], indent=2))

    # Send our signed record back over the SAME door connection; the anchor merges
    # it into its directory so the ReconcileLoop keeps the peer it just installed
    # (the bootstrap chicken-and-egg). Doing this on the door tunnel — rather
    # than a separate POST /publish — means the control plane never has to listen
    # on the door interface.
    from ..door import recv_msg, send_msg
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
        cli._print_daemon_guidance(joined_key, cfg_path,
                               no_service=getattr(args, "no_service", False))
    else:
        # Explicit custom -c path: the template's ExecStart hardcodes
        # /etc/greasewood_%i.toml, so systemd can't serve it — run it yourself.
        print("Start this mesh's daemon:")
        print(f"  sudo gw -c {cfg_path} run")
        print("  (custom -c path isn't served by the greasewood@ template; run "
              "it yourself or write your own unit)")
    print()
    from .. import firewall as _fw
    cli._print_firewall_help(listen_port, mesh_iface=interface, role="node")
    print()
    _fw.check(_fw.node_rules(listen_port), log)
    return 0
