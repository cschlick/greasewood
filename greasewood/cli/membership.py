"""greasewood.cli.membership — Membership lifecycle: revoke, set-caps/set-roles, leave, rename-node, rename-mesh, renew, purge."""
import datetime as dt
import json
import logging
import os
import shutil
import re
import subprocess
import sys
import time
from pathlib import Path

from ..config import membership_key

# The package namespace is the late-binding seam: cross-module helpers are
# called as cli.<name> so a monkeypatch on the package (the tests' historic
# patch point) reaches every caller, exactly as it did when this was one file.
import greasewood.cli as cli

_UTC = dt.timezone.utc
log = logging.getLogger("greasewood")




def _migrate_membership(cfg_path: "Path", new_key: str,
                        etc: "Path" = Path("/etc"),
                        var: "Path" = Path("/var/lib")) -> "Path":
    """Move a membership old-name → new-name: config file, data dir, kernel
    interface, systemd instance, name domain — everything is keyed to the mesh
    name, so a rename renames it all (brief tunnel blip at the interface
    rename). Leaves the OLD domain's /etc/hosts block in place and drops a
    grace marker in the new data dir: the daemon keeps old names resolving
    until the grace deadline, then retires them. Returns the new config path."""
    from ..config import load_config
    from .. import wg as wgmod

    cfg = load_config(cfg_path)
    old_key = membership_key(cfg.mesh_domain)
    new_domain = f"{new_key}.internal"
    mp = cli._membership_paths(new_key, etc=etc, var=var)
    if mp["config"].exists():
        sys.exit(f"{mp['config']} already exists — is this host already on a "
                 f"mesh named {new_key!r}?")
    clash = cli._iface_collision(mp["interface"], mp["config"], etc=etc)
    if clash:
        sys.exit(f"derived interface {mp['interface']!r} is already used by "
                 f"{clash} — rename to something whose first 12 chars differ")

    svc_mgr = cli._service_backend()
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
    from .. import certs as certmod
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
    from ..config import load_config
    from ..hosts import valid_label

    cli._require_root("rename-mesh", "it moves this mesh's config/state/interface")
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





# ---------------------------------------------------------------------------
# revoke
# ---------------------------------------------------------------------------

def cmd_revoke(args) -> int:
    # Same anchor-only guard as set-caps/set-roles: explicit role check first,
    # then ca_key_file + CA load — so a non-anchor fails with one clear message and
    # never reaches a traceback.
    cfg, ca = cli._load_anchor_ca(args, "revoke")

    # Accept a hostname / mesh name as well as a raw id hex; a hostname resolves
    # via the registry, a raw id is honored even if already forgotten.
    id_pub_bytes, name = cli._resolve_node(ca, cfg, args.node, require_enrolled=False)

    freed = ca.add_revoke(id_pub_bytes)
    # Durable membership event, symmetric with event=enroll/event=leave. This
    # runs as a CLI process (not the daemon), so the audit-file sink isn't
    # attached yet — attach it so the revoke lands in the same audit.log the
    # daemon writes; `grep 'event='` there reads the full membership history.
    from .. import audit
    if cfg.audit_log is not None:
        audit.attach_file(cfg.audit_log)
    audit.event("revoke", node=name, id=id_pub_bytes.hex()[:16],
                hostname_freed=freed)
    print(f"revoked: {name}  ({id_pub_bytes.hex()})")
    if freed:
        print("Its hostname is now free for reuse by a different node.")
    print("Takes effect live — the running daemon refuses its renew/publish and "
          "evicts it on the next reconcile; its credential also expires naturally.")
    return 0




def cmd_set_caps(args) -> int:
    cfg, ca = cli._load_anchor_ca(args, "set-caps")
    id_pub, name = cli._resolve_node(ca, cfg, args.node)
    caps = [c.strip() for c in args.caps.split(",") if c.strip()]
    # set-caps takes raw caps, so it's also a role-assignment path — reject the
    # reserved role: tags here too (else `set-caps role:anchor` would bypass the
    # single-member guard).
    cli._reject_reserved_roles([c[len("role:"):] for c in caps if c.startswith("role:")],
                           "set-caps")
    if not any(c.startswith("role:") for c in caps):
        log.warning("caps %s include no role: tag — once a grant table is "
                    "applied, %r will reach only the anchor (add e.g. "
                    "role:node)", caps, name)
    ca.set_caps(id_pub, caps)
    print(f"caps for {name} ({id_pub.hex()}) → {caps}")
    print(cli._NEXT_RENEWAL_NOTE)
    return 0




def cmd_set_roles(args) -> int:
    cfg, ca = cli._load_anchor_ca(args, "set-roles")
    id_pub, name = cli._resolve_node(ca, cfg, args.node)
    # Declarative mode: a host listed in grants.toml's [assign] table has its
    # roles DECLARED there — an imperative edit would silently drift from the
    # file (and be reverted by the next `gw policy apply`). Point at the file.
    from ..policy import parse_assignments, GRANTS_BASENAME
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
    cli._reject_reserved_roles(names, "set-roles")
    # role:node is STICKY. It's the default membership role, and fleet grants
    # (the shipped admin -> node ssh, metrics scrapes, ...) target it — so a
    # set-roles list that merely doesn't mention it must not silently seal the
    # box out of that coverage. Keep it unless the operator says --exact, and
    # under --exact show exactly which grants stop covering the host.
    current_roles = [c[len("role:"):] for c in current if c.startswith("role:")]
    if "node" in current_roles and "node" not in names:
        if getattr(args, "exact", False):
            refs = cli._grants_naming_role(cfg, "node")
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
        now = cli._request_fleet_renewal(cfg)
        print(f"--now: requested a fleet renewal (renew_after = "
              f"{now:%Y-%m-%d %H:%M UTC}) — {name}'s daemon renews within a poll "
              f"interval and adopts the new roles live, no restart. (Fleet-wide; "
              f"for a batch, prefer several set-roles then one `gw renew-all`.)")
    else:
        print(cli._NEXT_RENEWAL_NOTE)
    return 0




def cmd_leave(args) -> int:
    """[sudo] Voluntarily depart the mesh — the node removes ITSELF from the
    anchor, so nobody has to log into the anchor to revoke it or wait for the
    drop-grace sweep to free its name.

    Order matters: the signed LeaveRequest goes to the anchor FIRST, over the
    still-up tunnel (the control plane is overlay-only — tearing down before
    telling would strand the request). Only after the anchor confirms does the
    local side come down: daemon stopped and removed from boot, WireGuard
    interface destroyed, the managed /etc/hosts block removed. Local keys,
    config, and data are KEPT — `gw purge` erases them; keeping them here
    means an accidental leave is recoverable with a fresh invite + join
    without minting a new identity.

    Not a revocation: the departing credential stays valid until expiry (the
    same fleet-wide bound revocation has), and this node cooperates by tearing
    its side down. Peers' cached records age out on their own."""
    import secrets as _secrets
    import urllib.request
    import urllib.error
    from ..config import load_config
    from ..keys import NodeKeys
    from ..wire import LeaveRequest
    from .. import wg as wgmod
    from .. import audit
    from .. import hosts as _hosts

    cli._require_root("leave", "it stops the daemon and removes the interface")
    cfg = load_config(Path(args.config))
    if cli._holds_anchor(cfg):
        sys.exit("an anchor holder can't leave its own mesh — it holds the "
                 "mesh's authority. Drop the anchor file first "
                 "(sudo gw anchor drop) if other holders remain, hand the "
                 "authority over (gw anchor export → adopt elsewhere), or "
                 "tear the mesh down (see operations.md).")
    if not (cfg.root_url or cfg.seeds):
        sys.exit("no anchor URL configured (root_url/seeds) — nothing to leave.")
    key = membership_key(cfg.mesh_domain)

    if not args.yes:
        print(f"This node will leave mesh '{key}':")
        print(f"  anchor forgets it     : {cfg.root_url or cfg.seeds[0]}  "
              f"(hostname '{cfg.hostname}' frees immediately; renewals refused)")
        print(f"  daemon                : stopped and removed from boot")
        print(f"  WireGuard interface   : {cfg.wg_interface} destroyed")
        print(f"  local keys/config/data: KEPT — 'gw purge' erases them")
        print("Peers keep their tunnel to this node until its credential "
              "expires (same bound as a revocation).")
        if input("Proceed? [y/N] ").strip().lower() not in ("y", "yes"):
            print("cancelled — nothing changed.")
            return 1

    keys = NodeKeys.load_or_generate(cfg.data_dir)
    req = LeaveRequest(
        id_pub=keys.id_pub_bytes,
        nonce=_secrets.token_hex(16),
        ts=dt.datetime.now(_UTC).replace(microsecond=0),
    ).sign(keys.id_priv)

    # Any holder can accept the departure (its tombstone replicates to the
    # rest) — try the whole anchor set, configured seeds first.
    from ..directory import Directory as _Dir
    _targets = cli._anchor_urls(cfg, _Dir.load(cfg.dir_cache_path),
                            own_addr=keys.addr)
    data = None
    _last_err: "str | None" = None
    for base in _targets:
        url = f"{base.rstrip('/')}/leave"
        http_req = urllib.request.Request(
            url, data=json.dumps(req.to_dict()).encode(),
            headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(http_req, timeout=15) as resp:
                data = json.loads(resp.read())
            break
        except (urllib.error.URLError, OSError) as e:
            _last_err = f"{url}: {e}"
            if len(_targets) > 1:
                print(f"couldn't reach {base} — trying the next holder")
    if data is None:
        sys.exit(f"couldn't reach any anchor holder (last: {_last_err})\n"
                 "Leaving needs a holder reachable (the request must be "
                 "authenticated and delivered) — nothing was changed locally.\n"
                 "If the anchors are gone for good, there is nothing to leave: "
                 "this node ages out of the fleet at credential expiry; "
                 "'gw purge' cleans up this host.")
    if "error" in data:
        sys.exit(f"anchor refused the leave: {data['error']}\n"
                 "Nothing was changed locally.")
    print(f"anchor confirmed: departed '{key}'"
          + (" (hostname freed)" if data.get("hostname_freed") else ""))

    # Now — and only now — the local teardown.
    mgr = cli._service_backend()
    if mgr is not None:
        if mgr.disable_now(key):
            print(f"stopped {mgr.unit_name(key)} (removed from boot).")
    with audit.context(f"leave: departing mesh {key}"):
        wgmod.destroy_interface(cfg.wg_interface)
    try:
        if cfg.hosts_sync and _hosts.remove_block(cfg.mesh_domain):
            print("removed the managed /etc/hosts block.")
    except Exception as e:
        log.warning("could not clean /etc/hosts: %s", e)
    print(f"left. Local keys/config/data remain — 'sudo gw purge' erases them; "
          f"rejoining later takes a fresh invite.")
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
    cli._require_root("rename-node")
    import secrets
    import urllib.error
    import urllib.request
    from ..config import load_config
    from ..keys import NodeKeys
    from ..directory import Directory
    from ..wire import RenewRequest, Credential

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
        from ..wire import GrantTable as _GT
        from .. import policy as _polmod
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

    # Any holder can serve the rename (it's a renewal with a hostname) — try
    # the whole anchor set, like renewal and leave do. A holder's REFUSAL
    # (name taken, pinned) is final and not retried elsewhere: every holder
    # answers from the same replicated view, so shopping the request around
    # would only race the very uniqueness check that refused it.
    targets = cli._anchor_urls(cfg, Directory.load(cfg.dir_cache_path),
                           own_addr=keys.addr)
    if not targets:
        sys.exit("no anchor holders known — is this node enrolled and the mesh up?")

    req = RenewRequest(
        id_pub=keys.id_pub_bytes,
        wg_pub=keys.wg_pub_bytes,
        nonce=secrets.token_hex(16),
        ts=dt.datetime.now(_UTC).replace(microsecond=0),
        hostname=newname,
    ).sign(keys.id_priv)

    body = json.dumps(req.to_dict()).encode()
    data = None
    anchor_url = None
    last_err = None
    for base in targets:
        http_req = urllib.request.Request(
            f"{base.rstrip('/')}/renew", data=body,
            headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(http_req, timeout=15) as resp:
                data = json.loads(resp.read())
            anchor_url = base
            break
        except urllib.error.HTTPError as e:
            try:
                data = json.loads(e.read())
            except Exception:
                data = {"error": f"HTTP {e.code}"}
            anchor_url = base
            break                     # an answer (even a refusal) is final
        except (urllib.error.URLError, OSError) as e:
            last_err = f"{base}: {e}"
            if len(targets) > 1:
                print(f"couldn't reach {base} — trying the next holder")
    if data is None:
        sys.exit(f"could not reach any anchor holder (last: {last_err}) — "
                 f"is the mesh up?")
    if "error" in data:
        sys.exit(f"rename rejected by anchor: {data['error']}")

    cred = Credential.from_dict(data)

    # Re-sign our record with the new name + fresh credential and publish it, so
    # peers and /etc/hosts pick up the rename promptly.
    cli._republish_own_record(cfg, keys, Directory.load(cfg.dir_cache_path),
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
    if not cli._service_restart(membership_key(cfg.mesh_domain),
                          why="so it keeps advertising the new name"):
        print("Restart the daemon so it keeps advertising the new name: "
              f"{cli._svc_restart_hint()}  (or re-run sudo gw run)")
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
    cli._require_root("renew")
    from ..config import load_config
    from ..keys import NodeKeys
    from ..directory import Directory
    from ..renewal import _do_renew
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
    cli._republish_own_record(cfg, keys, Directory.load(cfg.dir_cache_path),
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

    if not cli._service_restart(membership_key(cfg.mesh_domain),
                          why="to fully adopt the renewed credential"):
        print("Restart the daemon to fully adopt it: "
              f"{cli._svc_restart_hint()}  (or re-run sudo gw run)")
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
        alive = [p for p in alive if cli._pid_alive(p)]
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
        from ..directory import Directory
        from ..keys import _own_identity
        own_id, _ = _own_identity(cfg.data_dir)
        recs = Directory.load(cfg.dir_cache_path).all()
        return sum(1 for r in recs if r.id_pub.hex() != own_id)
    except Exception:
        return 0




def cmd_purge(args) -> int:
    cli._require_root("purge")
    cfg_path = Path(args.config)

    # Nothing is unsuffixed anymore, so there are no guessable defaults: the
    # config must exist (main() discovery already resolved -c, or errored).
    try:
        from ..config import load_config
        cfg = load_config(cfg_path)
        iface = cfg.wg_interface
        data_dir = cfg.data_dir
        mesh_domain = cfg.mesh_domain
    except Exception as e:
        sys.exit(f"can't read {cfg_path} ({e}) — pass -c <this mesh's config> "
                 f"(purge won't guess which mesh to destroy)")
    key = membership_key(cfg.mesh_domain)
    svc_mgr = cli._service_backend()
    unit = svc_mgr.unit_name(key) if svc_mgr else cli._unit_for_config(cfg_path)

    if not args.yes:
        last = not [k for k, p in cli._memberships() if p.resolve() != cfg_path.resolve()]
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
            n = cli._other_peer_count(cfg)
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
    from ..door import DOOR_IFACE
    for name in dict.fromkeys([DOOR_IFACE, DOOR_IFACE.replace("-", "_")]):
        r = subprocess.run(["ip", "link", "show", name], capture_output=True)
        if r.returncode == 0:
            subprocess.run(["ip", "link", "delete", name], capture_output=True)
            removed.append(f"door interface {name}")
    try:
        from .. import wg as wgmod
        wgmod.teardown_door_routing()
    except Exception as e:
        failed.append(f"door routing: {e}")

    # Remove greasewood's own nftables table (port enforcement). It PERSISTS
    # across daemon stop by design (fail closed); purge is its explicit
    # teardown. Idempotent — a no-op if enforcement was never on.
    from ..portfilter import table_name as _nft_table
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
        from .. import hosts
        if hosts.remove_block(mesh_domain):
            removed.append("/etc/hosts greasewood block")
    except Exception as e:
        failed.append(f"/etc/hosts: {e}")

    # Service teardown. This membership's instance was already disabled above;
    # if it was the LAST mesh on the host, remove the shared template unit too,
    # so `gw purge` on a single-mesh host is a true from-scratch reset. Other
    # meshes still need the template, so it stays while any remain.
    if svc_mgr is not None:
        remaining = cli._memberships()   # cfg_path is already unlinked above
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
