"""greasewood.cli.parser — The argparse tree and main(). Handlers are referenced late (cli.cmd_*) so a patched command is what dispatch actually runs."""
import argparse
import datetime as dt
import json
import logging
import os
import shutil
import subprocess
import sys
from pathlib import Path

from ..status import _version, cmd_diagnose

# The package namespace is the late-binding seam: cross-module helpers are
# called as cli.<name> so a monkeypatch on the package (the tests' historic
# patch point) reaches every caller, exactly as it did when this was one file.
import greasewood.cli as cli

_UTC = dt.timezone.utc
log = logging.getLogger("greasewood")




# ---------------------------------------------------------------------------
# narrate / config — the thin read-only commands (the heavyweight
# presentation — watch, diagnose, the roster — lives in status.py)
# ---------------------------------------------------------------------------

def cmd_narrate(args) -> int:
    """Read the data-plane command trail and translate it into plain English —
    what greasewood did to the kernel's network state, when, why, and whether it
    worked. Reads <data_dir>/audit.log by default; a path, or '-' for stdin."""
    from ..config import load_config, _parse_duration
    from .. import narrate as N

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
        entries = [e for e in entries if g in N.searchable(e)]

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




def cmd_config(args) -> int:
    """Print resolved config facts, machine-readable — for scripting. With no
    argument, one `key<TAB>value` line per fact; with a key, just that value
    (e.g. `IFACE=$(gw config interface)` to scope a firewall rule to the mesh
    interface). Reads config only — no root, no network."""
    from ..config import load_config
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
        facts["control_port"] = str(cli._control_port(cfg))
        facts["door_port"] = str(cfg.door_port)
    if args.key:
        if args.key not in facts:
            sys.exit(f"unknown config key {args.key!r} — have: {', '.join(facts)}")
        print(facts[args.key])
        return 0
    for k, v in facts.items():
        print(f"{k}\t{v}")
    return 0




# ---------------------------------------------------------------------------
# policy — the mesh's grant table (roles → roles : ports; derives the topology)
# ---------------------------------------------------------------------------

def _resolve_editor() -> list:
    """The editor argv for `gw policy edit`, visudo-style: $SUDO_EDITOR, then
    $VISUAL, then $EDITOR (any may carry arguments, e.g. 'code --wait'), else
    nano, else vi. Under sudo the user's EDITOR is often stripped by env_reset,
    which is exactly why the nano fallback matters."""
    import shlex
    for var in ("SUDO_EDITOR", "VISUAL", "EDITOR"):
        val = os.environ.get(var)
        if val:
            argv = shlex.split(val)
            if argv and shutil.which(argv[0]):
                return argv
    for fallback in ("nano", "vi"):
        if shutil.which(fallback):
            return [fallback]
    sys.exit("no editor found — set $EDITOR, or install nano")




def cmd_policy(args) -> int:
    """`gw policy show` — render the active grant table (any node, no root).
    `gw policy edit` — anchor: open grants.toml in the operator's editor,
    validate on save (re-edit loop on a parse error, so a typo never lands),
    then offer to run the apply preview immediately — the edit → apply gap is
    where forgotten applies come from.
    `gw policy apply [file]` — anchor: validate grants.toml, PREVIEW the change
    (grant diff + tunnel delta), ask to confirm, then sign + publish. This is
    the deliberate path a policy change takes — grants.toml is the source, but
    it is never applied silently: a change tears down tunnels, so it is
    confirmed, not triggered by a stray file save."""
    from ..config import load_config
    from .. import policy as polmod
    from ..wire import GrantTable

    if args.action == "show":
        cfg = load_config(Path(args.config))
        table = None
        cache = cfg.data_dir / polmod.POLICY_BASENAME
        if cache.exists():
            try:
                table = GrantTable.from_dict(json.loads(cache.read_text()))
            except (ValueError, KeyError) as e:
                sys.exit(f"policy cache at {cache} is corrupt: {e}")
        print(polmod.render_grants(table))
        pending = polmod.unapplied_edits(cfg.data_dir)
        if pending:
            print(f"\n⚠ grants.toml has unapplied changes ({pending}) — run "
                  f"`sudo gw policy apply` to review and apply them.")
        return 0

    # ---- edit (anchor, root: editor → validate loop → offer apply) ----
    if args.action == "edit":
        cli._require_root("policy edit", "grants.toml lives in the root-owned data dir")
        cfg = load_config(Path(args.config))
        if not cli._holds_anchor(cfg):
            sys.exit("gw policy edit needs anchor authority — grants.toml is "
                     "authored on holders; this node only receives the signed "
                     f"policy. {cli.NOT_A_HOLDER_MSG}")
        gpath = Path(args.file) if args.file else cfg.data_dir / polmod.GRANTS_BASENAME
        if not gpath.exists():
            gpath.write_text(polmod.DEFAULT_GRANTS_TOML)
            print(f"no grants.toml yet — seeded the default-closed template at {gpath}")
        editor = _resolve_editor()
        print(f"editing {gpath}  ({' '.join(editor)})")
        while True:
            r = subprocess.run([*editor, str(gpath)])
            if r.returncode != 0:
                sys.exit(f"{editor[0]} exited {r.returncode} — {gpath} left "
                         f"as-is, nothing applied")
            try:
                _text = gpath.read_text()
                polmod.parse_grants_toml(_text)
                polmod.parse_assignments(_text)   # the [assign] table too
                break
            except ValueError as e:
                print(f"  ✗ {e}")
                try:
                    again = input("re-edit? [Y/n] ").strip().lower()
                except EOFError:
                    again = "n"
                if again in ("n", "no"):
                    sys.exit(f"saved but INVALID — {gpath} cannot be applied "
                             f"until fixed (`gw policy show` will flag it)")
        if args.file is None:
            pending = polmod.unapplied_edits(cfg.data_dir)
            if not pending:
                print("✓ valid — identical to the applied policy; nothing to do")
                return 0
            print(f"✓ valid — {pending}")
        else:
            print("✓ valid")
        try:
            go = input("run the apply preview now? [Y/n] ").strip().lower()
        except EOFError:
            go = "n"
        if go in ("n", "no"):
            print("not applied — edits are inert until:  sudo gw policy apply")
            return 0
        # confirmed: fall through into apply below (it re-reads + previews).

    # ---- apply (anchor, root: signs with the CA key) ----
    from ..directory import Directory
    from ..keys import atomic_write
    cli._require_root("policy apply", "it signs the table with the CA key")
    cfg = load_config(Path(args.config))
    if not cli._holds_anchor(cfg):
        sys.exit(f"gw policy apply needs anchor authority. {cli.NOT_A_HOLDER_MSG}")

    grants_path = Path(args.file) if args.file else cfg.data_dir / polmod.GRANTS_BASENAME
    if not grants_path.exists():
        sys.exit(f"no grants file at {grants_path} — write one (see "
                 f"grants.toml.example) or pass a path")
    try:
        grants_text = grants_path.read_text()
        grants = polmod.parse_grants_toml(grants_text)
        assignments = polmod.parse_assignments(grants_text)
    except ValueError as e:
        sys.exit(str(e))

    # Current table (for seq + delta) and the fleet (for delta + typo check).
    old_table = None
    cache = cfg.data_dir / polmod.POLICY_BASENAME
    if cache.exists():
        try:
            old_table = GrantTable.from_dict(json.loads(cache.read_text()))
        except (ValueError, KeyError):
            log.warning("existing policy cache unreadable; treating as none")
    directory = Directory.load(cfg.dir_cache_path)
    records = directory.all()

    # Declarative role assignments ([assign]): compute role diffs up front —
    # they feed the typo check (a role granted and assigned in the SAME apply
    # is not a typo) and the tunnel delta (caps_override), and print with the
    # grant diff so the whole change previews as one.
    caps_override, assign_lines = {}, []
    if assignments is not None:
        by_host = {r.cred.hostname: r for r in records}
        for host, roles in sorted(assignments.items()):
            rec = by_host.get(host)
            if rec is None:
                assign_lines.append(
                    f"  ⚠ [assign] names {host!r} but no current member has "
                    f"that hostname — reconciles once it joins")
                continue
            cur = sorted(c[len('role:'):] for c in rec.cred.caps
                         if c.startswith('role:'))
            if cur != list(roles):
                kept = [c for c in rec.cred.caps if not c.startswith("role:")]
                caps_override[rec.id_pub.hex()] = \
                    kept + [f"role:{r}" for r in roles]
                assign_lines.append(
                    f"  ~ roles  {host}: {', '.join(cur) or '(none)'} → "
                    f"{', '.join(roles) or '(none)'}")

    for tag in sorted(polmod.unmatched_tags(grants, records, caps_override)):
        if tag.startswith("host:"):
            print(f"  ⚠ grant names {tag!r} but NO current member has that "
                  f"hostname — typo, or a not-yet-joined machine? Until then it "
                  f"grants nothing; when a node DOES take that name it inherits "
                  f"these grants, so pin the name at invite "
                  f"(gw invite --hostname {tag[len('host:'):]}).")
        else:
            print(f"  ⚠ grant names {tag!r} but NO current node holds role:{tag} "
                  f"— typo? (it grants nothing until a node holds it)")
    for name in polmod.unpinned_host_grants(grants, records):
        print(f"  ⚠ host grant on {name!r}, but that node named ITSELF (its "
              f"hostname isn't anchor-pinned): it could rename away from its "
              f"grants, and after decommissioning the freed name — and these "
              f"grants — pass to whoever claims it. Prefer pinning: re-invite "
              f"with `gw invite --hostname {name}`.")

    new_seq = (old_table.seq + 1) if old_table else 1
    old_grants = old_table.grants if old_table else []
    print(f"this will change the policy: v{old_table.seq if old_table else '—'} "
          f"→ v{new_seq}")

    # Grant-level diff (the rules themselves — the "X → Y").
    def _fmt(g):
        return (f"{', '.join(g['from'])} -> {', '.join(g['to'])} : "
                f"{', '.join(g['ports'])}")
    added = [g for g in grants if g not in old_grants]
    dropped = [g for g in old_grants if g not in grants]
    if not added and not dropped:
        print("  grants: (unchanged)")
    for g in dropped:
        print(f"  - grant  {_fmt(g)}")
    for g in added:
        print(f"  + grant  {_fmt(g)}")

    for line in assign_lines:
        print(line)

    # Tunnel-level effect (what actually connects/disconnects on the wire).
    created, removed = polmod.tunnel_delta(records, old_grants or None, grants,
                                           caps_override=caps_override)
    for a, b in created:
        print(f"  + tunnel {a} ↔ {b}")
    for a, b in removed:
        print(f"  - tunnel {a} ↔ {b}")
    if not created and not removed:
        print("  tunnels: (no change — port scopes only)")

    if not getattr(args, "yes", False):
        answer = input("apply? [y/N] ").strip().lower()
        if answer not in ("y", "yes"):
            print("not applied.")
            return 1

    ca_keys, _guard = cli._anchor_ca_source(cfg)
    table = GrantTable(seq=new_seq, grants=grants).sign(ca_keys.ca_priv)
    atomic_write(cache, json.dumps(table.to_dict(), indent=2), mode=0o644)
    print(f"policy v{new_seq} applied — nodes adopt it on their next directory "
          f"sync; tunnels reconcile within a cycle.")

    # Reconcile the registry to [assign] (idempotent — a no-change apply is
    # silent). One fleet renew hint for the whole batch, so every re-roled
    # node adopts its new credential within a poll interval.
    if assignments is not None:
        from ..ca import CA as _CA
        changed, _missing = polmod.apply_assignments(
            assignments, _CA(ca_keys, cfg.data_dir, cfg.credential_ttl,
                             dir_cache_path=cfg.dir_cache_path))
        for host, old, new in changed:
            print(f"  ~ roles {host}: {', '.join(old) or '(none)'} → "
                  f"{', '.join(new) or '(none)'}")
        if changed:
            cli._request_fleet_renewal(cfg)
            print(f"  {len(changed)} node(s) re-roled — fleet renewal "
                  f"requested; they adopt live within a poll interval.")
    return 0




def build_parser() -> argparse.ArgumentParser:
    """Construct the full `gw` argument parser (all subcommands wired to their
    cmd_* handlers via set_defaults(fn=…)). Split out of main() so the same
    parser object feeds both runtime dispatch and offline tooling — the man page
    (argparse-manpage) and shell completions are generated from THIS, so they
    can't drift from `--help`."""
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
            "  gw watch --snapshot · config · cert-status · cert-profiles\n"
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
    # required=False: bare `gw` routes to the dashboard (see _cmd_bare), not a
    # usage error — the naive invocation should answer, not scold.
    sub = p.add_subparsers(dest="cmd", required=False)

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
                         "role:* to reach every node), e.g. 'tls'")
    sp.add_argument("--credential-ttl", dest="credential_ttl", default="24h")
    sp.add_argument("--force", action="store_true", help="overwrite existing CA key")
    sp.add_argument("--no-hosts-sync", dest="hosts_sync", action="store_false",
                    help="don't maintain the managed /etc/hosts block "
                         "(<name>.gw.internal -> overlay addr); it's on by default")
    sp.add_argument("--no-service", action="store_true",
                    help="don't set up the systemd service; print the manual "
                         "'gw run' line instead (for non-systemd hosts)")
    sp.set_defaults(fn=cli.cmd_create, hosts_sync=True)

    # invite
    sp = sub.add_parser("invite",
                        help="[sudo, anchor] open a 15-min door window and print a single-use join token")
    sp.add_argument("--hostname", default=None,
                    help="pin the invited node's mesh hostname (the anchor fixes it; "
                         "the joiner can't choose or later `gw rename-node` it). Omit "
                         "to let the node name itself at join.")
    sp.add_argument("--roles", default=None, metavar="R1,R2",
                    help="roles the invited node holds (comma-sep) — the grant-table "
                         "vocabulary (`gw policy`). The anchor decides this; the "
                         "joiner cannot. ADDS to the anchor's [anchor] "
                         "default_roles (ships as 'node') unless --exact. "
                         "Omitted → just the defaults. With no policy applied "
                         "every node peers regardless; grants reference these roles.")
    sp.add_argument("--exact", action="store_true",
                    help="--roles is the complete role list — don't add the "
                         "default membership role(s) ([anchor] default_roles)")
    sp.add_argument("--caps", default=None,
                    help="ability caps granted to the invited node (comma-sep), "
                         "e.g. 'tls'. Omitted → the anchor's [anchor] default_caps "
                         "(ships as 'tls'). Roles are set with --roles.")
    sp.add_argument("--self-roles", default=None, metavar="R1,R2",
                    help="role MENU the joiner may self-select from at `gw join "
                         "--roles` (comma-sep) — one standing invite provisions many "
                         "classes. The anchor still signs, and the joiner can never "
                         "land outside this set. Sets no default role (the joiner "
                         "opts in). NEVER include '*' (reach-all). Combine with "
                         "--roles to also grant a fixed base role.")
    sp.add_argument("--self-roles-from-grants", action="store_true",
                    dest="self_roles_from_grants",
                    help="derive the menu from grants.toml instead: offer every "
                         "role referenced in a grant, minus the built-ins (*, "
                         "anchor, node, admin). The policy vocabulary becomes the "
                         "provisioning menu — no second list to maintain. Mutually "
                         "exclusive with --self-roles.")
    sp.add_argument("--endpoint", default=None, metavar="ADDR",
                    help="underlay address, v6 or v4, to embed in the token (auto-detected if omitted)")
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
    sp.set_defaults(fn=cli.cmd_invite)

    # close-door
    sp = sub.add_parser("close-door",
                        help="[sudo, anchor] close the current door window — "
                             "permanently invalidates its token (standing or "
                             "single-use); enrolled nodes are unaffected")
    sp.set_defaults(fn=cli.cmd_close_door)

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
    sp.add_argument("--roles", default=None, metavar="R1,R2",
                    help="role(s) to self-select (comma-sep) when the invite offers "
                         "a menu (`gw invite --self-roles`). Must be within the "
                         "menu; the anchor authorizes and signs. Ignored (with a "
                         "warning) for a classic invite, where the anchor sets roles.")
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
    sp.set_defaults(fn=cli.cmd_join)

    # purge
    sp = sub.add_parser("leave",
        help="[sudo] voluntarily depart the mesh — the anchor forgets this "
             "node (name freed, renewals refused) with no anchor-side action; "
             "local keys/config are kept (purge erases them)")
    sp.add_argument("--yes", action="store_true",
                    help="skip the confirmation prompt")
    sp.set_defaults(fn=cli.cmd_leave)

    sp = sub.add_parser("service",
        help="[sudo] enable/disable this config's daemon service (adopt a "
             "migrated config; on launchd only greasewood can write the plist)")
    sp.add_argument("action", choices=("enable", "disable"))
    sp.set_defaults(fn=cli.cmd_service)

    sp = sub.add_parser("purge",
                        help="[sudo] remove this mesh entirely — stop+disable its "
                             "service, tear down the interface, delete data dir + "
                             "config + /etc/hosts block (and the systemd template "
                             "if it was the last mesh). A from-scratch reset.")
    sp.add_argument("--yes", "-y", action="store_true", help="skip confirmation prompt")
    sp.set_defaults(fn=cli.cmd_purge)

    # run
    sp = sub.add_parser("run", help="[sudo] start the daemon (creates WireGuard interface)")
    sp.add_argument("--no-enforce-ports", dest="no_enforce_ports",
                    action="store_true",
                    help="run WITHOUT nftables port enforcement (on by default). "
                         "For a host with no usable nftables — grants still "
                         "control which tunnels exist; port scopes go advisory. "
                         "The persistent form is `enforce_ports = false` under "
                         "[network] (systemd runs `gw run` with no flags).")
    sp.set_defaults(fn=cli.cmd_run)

    # watch — live mesh view by default; --snapshot for a static one-shot
    sp = sub.add_parser("watch",
                        help="[sudo] live mesh dashboard (redraws in place): the "
                             "roster + link state, per-second throughput, and a "
                             "latency column that fills in as pings return. "
                             "Ctrl-C to exit. Use --snapshot for a static view.")
    sp.add_argument("--snapshot", action="store_true",
                    help="print a single static view and exit (no root needed) — "
                         "for piping/logging. Auto-used when there's no terminal.")
    sp.add_argument("--json", action="store_true",
                    help="emit one-shot machine-readable JSON (stable versioned "
                         "schema) instead of the text view — for monitors/jq. "
                         "Add live WireGuard stats by running as root.")
    sp.add_argument("--by-role", dest="by_role", action="store_true",
                    help="group into one table per role (a node appears under "
                         "each of its roles; the anchor appears under all) with "
                         "per-group connectivity health")
    sp.add_argument("--interval", type=float, default=2.0, metavar="SECS",
                    help="live refresh interval (default 2s; min 1s)")
    sp.add_argument("--all", action="store_true",
                    help="also show expired nodes (hidden by default — the roster "
                         "shows only the live mesh)")
    sp.add_argument("--firewall", action="store_true",
                    help="expand the firewall area (the host-rule check + "
                         "greasewood's own nftables table, verbatim). Default is "
                         "a one-line summary; in the live view the f key toggles")
    sp.add_argument("--total", action="store_true",
                    help="live view shows cumulative traffic instead of per-second "
                         "rate (toggle with 't' while watching)")
    sp.set_defaults(fn=cli.cmd_watch)

    # config — machine-readable resolved facts, for scripting
    sp = sub.add_parser("config",
                        help="print resolved config facts (machine-readable) for "
                             "scripting, e.g. `gw config interface`")
    sp.add_argument("key", nargs="?",
                    help="print just this value (interface, mesh_domain, "
                         "listen_port, data_dir, role, hostname, root_url, …); "
                         "omit to list all as key<TAB>value")
    sp.set_defaults(fn=cmd_config)

    # (No `firewall` subcommand — the host-firewall port check lives in gw watch
    #  now, and create/join still print the recommended rules at setup.)

    # diagnose
    sp = sub.add_parser(
        "diagnose",
        help="pairwise link diagnosis: compare up to two nodes + the anchor side "
             "by side and explain whether a tunnel can form (policy/roles, "
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
    sp.set_defaults(fn=cli.cmd_revoke)

    # upgrade — clean pipx reinstall of this node, from PyPI or the repo.
    sp = sub.add_parser("upgrade",
                        help="[sudo] reinstall greasewood (PyPI or the repo) and "
                             "restart this mesh's daemon — shows the commands "
                             "and asks first")
    sp.add_argument("--from", dest="source", choices=["pypi", "github"],
                    default="pypi",
                    help="pypi: the published release (default); github: the git "
                         "repo, for running a fix that isn't released yet")
    sp.add_argument("--ref",
                    help="which one: a git ref (branch/tag/commit, default main) "
                         "with --from github, or an exact version with --from "
                         "pypi (default: latest)")
    sp.add_argument("--yes", "-y", action="store_true",
                    help="skip the confirmation prompt")
    sp.set_defaults(fn=cli.cmd_upgrade)

    # set-caps (anchor) — change an enrolled node's full tag set
    sp = sub.add_parser("set-caps",
                        help="[sudo, anchor] change an enrolled node's caps (effective next renewal)")
    sp.add_argument("node", help="node hostname (or its 64-char id_pub hex)")
    sp.add_argument("caps", help="comma-separated full tag set, e.g. "
                                 "'role:web,tls' (replaces the node's current caps)")
    sp.set_defaults(fn=cli.cmd_set_caps)

    # set-roles (anchor) — change only a node's roles
    sp = sub.add_parser("set-roles",
                        help="[sudo, anchor] change an enrolled node's roles "
                             "(effective next renewal)")
    sp.add_argument("node", help="node hostname (or its 64-char id_pub hex)")
    sp.add_argument("roles", help="comma-separated roles, e.g. 'web,worker' "
                                  "(replaces role: tags; keeps tls; the default "
                                  "'node' role is kept unless --exact; empty = "
                                  "mesh default)")
    sp.add_argument("--exact", action="store_true",
                    help="use exactly this role list — allows dropping the "
                         "default 'node' role, which is otherwise kept (fleet "
                         "grants like `admin -> node : tcp/22` target it)")
    sp.add_argument("--now", action="store_true",
                    help="apply immediately — also request a fleet renewal (as "
                         "`gw renew-all` does) so the node adopts the new roles "
                         "live, no restart. Omit and it takes effect at the node's "
                         "next natural renewal (~half TTL). Fleet-wide, so for a "
                         "batch prefer several set-roles then one renew-all.")
    sp.set_defaults(fn=cli.cmd_set_roles)

    # policy — the grant table (roles → roles : ports; derives the topology)
    sp = sub.add_parser("policy",
                        help="show the mesh's grant table, or [sudo, anchor] "
                             "apply grants.toml — the allow-only role policy "
                             "that derives which tunnels exist")
    sp.add_argument("action", choices=["show", "edit", "apply"],
                    help="show: render the active table (no root). "
                         "edit: [sudo, anchor] open grants.toml in your editor "
                         "($SUDO_EDITOR/$VISUAL/$EDITOR, else nano), validate "
                         "on save, then offer the apply preview. "
                         "apply: validate + preview tunnel delta + sign + publish")
    sp.add_argument("file", nargs="?", default=None,
                    help="grants.toml path (apply only; default: "
                         "<data_dir>/grants.toml)")
    sp.add_argument("-y", "--yes", action="store_true",
                    help="apply without the interactive confirmation")
    sp.set_defaults(fn=cmd_policy)

    # anchor-promote (on the prospective new anchor)
    sp = sub.add_parser("anchor-promote",
                        help="[sudo] turn this enrolled node into an anchor (generate CA key, set role=anchor)")
    sp.add_argument("--control-port", dest="control_port", type=int, default=51902)
    sp.add_argument("--credential-ttl", dest="credential_ttl", default="24h")
    sp.set_defaults(fn=cli.cmd_anchor_promote)

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
    sp.set_defaults(fn=cli.cmd_cert_request)

    # cert-profiles
    sp = sub.add_parser("cert-profiles",
                        help="list the bundled cert profile templates for common "
                             "TLS services (postgres, nginx, haproxy, redis, nats, minio, mosquitto)")
    sp.set_defaults(fn=cli.cmd_cert_profiles)

    # cert-remove
    sp = sub.add_parser("cert-remove",
                        help="[sudo] stop managing a cert (drop it from auto-renewal); "
                             "--delete-files also removes the placed key/cert/ca")
    sp.add_argument("name", help="the managed cert's name (see gw cert-status)")
    sp.add_argument("--delete-files", dest="delete_files", action="store_true",
                    help="also delete the placed key/cert/ca files (default: "
                         "leave them — a service may still be reading them)")
    sp.set_defaults(fn=cli.cmd_cert_remove)

    # cert-status
    sp = sub.add_parser("cert-status",
                        help="show every daemon-managed TLS cert (expiry, renewal, "
                             "SANs, files, profile) from the manifest")
    sp.set_defaults(fn=cli.cmd_cert_status)

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
    sp.set_defaults(fn=cli.cmd_rename_mesh)

    sp = sub.add_parser("rename-node",
                        help="[sudo] change this node's mesh hostname (anchor-validated, no re-join)")
    sp.add_argument("hostname", help="the new hostname")
    sp.set_defaults(fn=cli.cmd_rename_node)

    # renew
    sp = sub.add_parser("renew",
                        help="[sudo] force an immediate credential renewal for THIS "
                             "node (applies an anchor-side set-caps/set-roles now, "
                             "instead of waiting ~half the TTL)")
    sp.set_defaults(fn=cli.cmd_renew)

    # renew-all
    sp = sub.add_parser("renew-all",
                        help="[sudo, anchor] request a fleet-wide renewal — advertise "
                             "renew_after=now so cooperating nodes renew (jittered, "
                             "rate ~constant with mesh size)")
    sp.set_defaults(fn=cli.cmd_renew_all)

    # anchor — the anchor FILE (portable authority)
    sp = sub.add_parser(
        "anchor",
        help="manage the ANCHOR FILE — the mesh's portable authority: any "
             "node holding anchor.gwa performs anchor duties (several at "
             "once); copy = transfer, delete = de-anchor")
    sp.add_argument("action",
                    choices=["status", "init", "offer", "adopt", "export",
                             "drop"],
                    help="status: this node's holder state + the fleet's "
                         "holders (no root). "
                         "init: [sudo] fold a legacy anchor's ca.key + "
                         "door.key into anchor.gwa. "
                         "offer: [sudo, holder] mint a single-use 15-min "
                         "offer for NODE, sealed to its CA-attested WireGuard "
                         "key and served over the control plane — no file "
                         "shuttling. "
                         "adopt: [sudo] with no argument, collect the offer "
                         "minted for this node and become a holder; with a "
                         "PATH (or '-'), install an exported file instead. "
                         "export: [sudo, holder] write the file for manual "
                         "transfer (PATH, or '-' for a pipe). "
                         "drop: [sudo, holder] shed the anchor roles and "
                         "delete this copy (cooperative de-anchor)")
    sp.add_argument("path", nargs="?", default=None,
                    help="offer: the target node (hostname / mesh name / id "
                         "hex); export: destination path or '-'; adopt: "
                         "optional source path or '-' (default: claim the "
                         "offer over the mesh)")
    sp.set_defaults(fn=cli.cmd_anchor)

    # anchor-backup
    sp = sub.add_parser("anchor-backup",
                        help="[sudo, anchor] write an encrypted backup of the CA key + "
                             "node registry + revoke list (passphrase via prompt "
                             "or $GW_BACKUP_PASSPHRASE)")
    sp.add_argument("--out", default=None, metavar="PATH",
                    help="output file (default: <data_dir>/greasewood-anchor-backup-"
                         "<hostname>.gwbk); '-' streams the blob to stdout (for a pipe)")
    sp.set_defaults(fn=cli.cmd_anchor_backup)

    # anchor-restore
    sp = sub.add_parser("anchor-restore",
                        help="[sudo] restore an anchor backup into a data dir (stand "
                             "up a replacement anchor on the same CA key — not a re-root)")
    sp.add_argument("archive", help="the .gwbk backup file, or '-' to read from stdin")
    sp.add_argument("--data-dir", default="/var/lib/greasewood",
                    help="where to restore (default: /var/lib/greasewood)")
    sp.add_argument("--force", action="store_true",
                    help="overwrite an existing ca.key in the target dir")
    sp.set_defaults(fn=cli.cmd_anchor_restore)

    # anchor-activate (failover standby -> anchor)
    sp = sub.add_parser("anchor-activate",
                        help="[sudo, failover standby] decrypt the escrowed CA blob, "
                             "rebuild the registry from the directory cache, and "
                             "rewrite this node as the anchor")
    sp.add_argument("--control-port", dest="control_port", type=int, default=51902)
    sp.add_argument("--door-port", dest="door_port", type=int, default=51901)
    sp.add_argument("--credential-ttl", dest="credential_ttl", default="24h")
    sp.add_argument("--force", action="store_true",
                    help="overwrite an existing ca.key / config")
    sp.set_defaults(fn=cli.cmd_anchor_activate)

    # anchor-standby (re-enroll an existing node to give it failover/updated caps)
    sp = sub.add_parser("anchor-standby",
                        help="[sudo, anchor] re-enroll an existing node so it can "
                             "receive updated caps (e.g. failover) and the encrypted blob")
    sp.add_argument("hostname", help="the existing node's hostname")
    sp.add_argument("--caps", default=None, metavar="C1,C2",
                    help="additional caps to add for this re-enrollment (failover is "
                         "always added)")
    sp.add_argument("--endpoint", default=None, metavar="ADDR",
                    help="underlay address to embed in the token (auto-detected if omitted)")
    sp.set_defaults(fn=cli.cmd_anchor_standby)

    # anchor-transfer
    sp = sub.add_parser("anchor-transfer",
                        help="[sudo, anchor] hand the anchor role to another host over "
                             "SSH — same CA, no re-root; stops this anchor as part of "
                             "the handoff. The target assumes this anchor's identity.")
    sp.add_argument("dest", metavar="[user@]host",
                    help="UNDERLAY (out-of-band) SSH destination of the target — its "
                         "real address, NOT its overlay/mesh address. The target "
                         "takes over this anchor's overlay identity, so the handoff "
                         "can't ride the overlay; open underlay SSH for the transfer "
                         "if you normally run overlay-only.")
    sp.add_argument("--ssh-opts", default=None,
                    help="extra options passed to ssh (e.g. '-p 2222 -i key')")
    sp.add_argument("--force", action="store_true",
                    help="overwrite an existing anchor on the target")
    sp.add_argument("--yes", "-y", action="store_true", help="skip the confirmation")
    sp.set_defaults(fn=cli.cmd_anchor_transfer)

    return p




_EVERYDAY_COMMANDS = """\
everyday commands:
  sudo gw watch                 live mesh dashboard (peers, links, firewall)
  gw watch --snapshot           the same, static — no root, pipeable
  gw diagnose [peer]            why a pair can or can't tunnel
  sudo gw invite                mint a join token            (anchor)
  sudo gw join <token>          enroll this machine in a mesh
  sudo gw policy edit           edit grants.toml: validate, preview, apply (anchor)
  gw policy show                the active grant table
  sudo gw cert-request          mesh-CA TLS certs for a service
  sudo gw set-roles <node> ...  change a node's roles         (anchor)
  sudo gw revoke <node>         revoke a node; frees its name (anchor)
  gw narrate --since 2h         the audit trail, in plain English

full reference:  gw --help   ·   man gw"""




def _cmd_bare(args) -> int:
    """Bare `gw` — the dashboard, not a usage error. The naive invocation
    answers both questions a naive typist has: what is my mesh doing (the
    watch view) and what can I type (the everyday commands). Context decides
    the shape: root + a terminal → the live TUI; otherwise the no-root static
    snapshot with the commands below it; unconfigured or multi-mesh → the
    commands, with how to start (or which -c) front and center."""
    if getattr(args, "config", None):
        target = Path(args.config)
    else:
        ms = cli._memberships()
        if not ms:
            print("no greasewood mesh is configured on this host.\n"
                  "  start one:  sudo gw create <name>   (this machine becomes "
                  "the anchor)\n"
                  "  join one:   sudo gw join <token>    (token from `sudo gw "
                  "invite` on the anchor)\n")
            print(_EVERYDAY_COMMANDS)
            return 0
        if len(ms) > 1:
            listing = "\n".join(f"  gw -c {p} watch   ({k})" for k, p in ms)
            print(f"this host is on {len(ms)} meshes — say which one:\n"
                  f"{listing}\n")
            print(_EVERYDAY_COMMANDS)
            return 0
        target = ms[0][1]
    live = sys.stdout.isatty() and os.geteuid() == 0
    wargs = argparse.Namespace(config=str(target), snapshot=not live)
    rc = cli.cmd_watch(wargs)
    if not live:
        print(_EVERYDAY_COMMANDS)
    return rc




def main(argv=None) -> int:
    p = cli.build_parser()
    args = p.parse_args(argv)
    cli._setup_logging(args.verbose)
    cli._require_supported_os()   # after parse_args, so --version/-h still work
    if args.cmd is None:
        return _cmd_bare(args)
    # -c discovery: with one membership on the host, every command finds it
    # unaided; with several, demand -c (loudly, listing them). create/join
    # derive their own config from the mesh name; cert-profiles (and
    # cert-request --show) just read bundled templates — no mesh needed.
    _no_config = args.cmd in ("create", "join", "cert-profiles") or (
        args.cmd == "cert-request" and getattr(args, "show", False))
    if args.config is None and not _no_config:
        args.config = str(cli._discover_config())
    try:
        return args.fn(args)
    except FileNotFoundError as e:
        # Safety net for a data-plane tool vanishing mid-command (the entry
        # points preflight wg/ip, but nft is optional-per-feature and a tool
        # can be missing on paths preflight doesn't cover). A missing data
        # FILE is not ours to prettify — re-raise anything else.
        tool = getattr(e, "filename", None)
        pkg = {"wg": "wireguard-tools", "ip": "iproute2", "nft": "nftables"}.get(tool)
        if pkg is not None:
            sys.exit(f"'{tool}' is not installed — greasewood shells out to the "
                     f"stock tools for every data-plane change.\n"
                     f"Install it:  sudo apt install {pkg}   "
                     f"# or your distro's equivalent")
        raise
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
