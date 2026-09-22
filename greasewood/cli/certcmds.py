"""greasewood.cli.certcmds — TLS service certificates: cert-request / cert-status / cert-remove / cert-profiles."""
import datetime as dt
import ipaddress
import logging
import sys
from pathlib import Path

from ..config import membership_key
from ..status import _dur_short

# The package namespace is the late-binding seam: cross-module helpers are
# called as cli.<name> so a monkeypatch on the package (the tests' historic
# patch point) reaches every caller, exactly as it did when this was one file.
import greasewood.cli as cli

_UTC = dt.timezone.utc
log = logging.getLogger("greasewood")




# ---------------------------------------------------------------------------
# TLS service certificates (§12) — cert-request / cert-status
# ---------------------------------------------------------------------------

def _shipped_profiles_dir() -> "Path":
    # One level up: this file lives in the cli PACKAGE; the shipped profiles
    # sit beside it at greasewood/profiles.
    return Path(__file__).resolve().parent.parent / "profiles"




def _shipped_profile_names() -> list:
    d = _shipped_profiles_dir()
    return sorted(p.stem for p in d.glob("*.toml")) if d.is_dir() else []




def _load_cert_profile(ref: str) -> dict:
    """Resolve a --profile argument to {reload, files, path, text}. `ref` is a
    file path, or the bare name of a shipped template (postgres, nginx, …)."""
    import tomllib
    p = Path(ref)
    if not p.exists():
        cand = _shipped_profiles_dir() / f"{ref}.toml"
        if not cand.exists():
            names = ", ".join(_shipped_profile_names()) or "(none)"
            sys.exit(f"no cert profile {ref!r} — pass a file path, or a shipped "
                     f"name: {names}")
        p = cand
    text = p.read_text()
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as e:
        sys.exit(f"profile {p}: invalid TOML — {e}")
    files = data.get("file", [])
    if not files:
        sys.exit(f"profile {p}: no [[file]] entries (need role + path each)")
    for f in files:
        if "role" not in f or "path" not in f:
            sys.exit(f"profile {p}: every [[file]] needs a role and a path")
        if f["role"] not in ("key", "cert", "ca", "fullchain", "bundle"):
            sys.exit(f"profile {p}: unknown role {f['role']!r} "
                     f"(key|cert|ca|fullchain|bundle)")
    return {"reload": data.get("reload"), "dns": data.get("dns", []),
            "files": files, "path": str(p), "text": text}




def cmd_cert_profiles(args) -> int:
    """List the bundled cert profile templates (starting points to copy + edit
    for common TLS services). They record the OS/software version they were
    written against; adapt paths to yours."""
    names = _shipped_profile_names()
    if not names:
        print("no bundled profiles found")
        return 0
    print("bundled cert profiles (templates — copy + adapt to your paths):")
    for n in names:
        based = ""
        for ln in (_shipped_profiles_dir() / f"{n}.toml").read_text().splitlines():
            if "based on" in ln:
                based = ln.split(":", 1)[1].strip() if ":" in ln else ""
                break
        print(f"  {n:<10} {('· ' + based) if based else ''}")
    print("\nView/copy one:   gw cert-request --profile <name> --show")
    print("Use one:         sudo gw cert-request --profile <name|path.toml>")
    return 0




def _cert_already_current(data_dir, name: str, *, dns, ips, files=None,
                          paths=None, renew: bool) -> "dt.datetime | None":
    """If re-requesting `name` would be a no-op — same SANs, same placement, and
    a cert that's present and not yet due for renewal — return its expiry (so
    the caller can say 'nothing to do'). Otherwise None: a first request, a
    changed request (new SAN/paths), a missing/old cert, or --renew all proceed."""
    if renew:
        return None
    from .. import certs as certmod
    entry = next((c for c in certmod.load_manifest(data_dir)
                  if c.get("name") == name), None)
    if entry is None:
        return None
    if sorted(entry.get("dns", [])) != sorted(dns) or \
       sorted(entry.get("ips", [])) != sorted(ips):
        return None
    if files is not None:
        if entry.get("files") != files:            # placement (paths/owner/mode) changed
            return None
    else:
        if (entry.get("key_path"), entry.get("crt_path"), entry.get("ca_path")) \
                != tuple(str(p) for p in paths):
            return None
    crt = certmod.ManagedCert.from_dict(entry).cert_path
    if crt is None or certmod.cert_due_for_renewal(crt):   # missing/old → re-issue
        return None
    return certmod.cert_expiry(crt)




def _print_cert_noop(name: str, exp, *, via: str) -> None:
    left = (exp - dt.datetime.now(_UTC)).total_seconds()
    print(f"TLS cert '{name}' already present ({via}), valid until "
          f"{exp:%Y-%m-%d %H:%M UTC} ({_dur_short(left)}) — nothing to do.")
    print(f"  re-issue now: --renew   ·   stop managing it: gw cert-remove {name}")




def cmd_cert_remove(args) -> int:
    """Stop managing a TLS cert: drop it from the auto-renewal manifest (and its
    profile snapshot). By default the placed key/cert/ca files are LEFT in place
    — a running service may still be reading them; pass --delete-files to remove
    them too."""
    from ..config import load_config
    from .. import certs as certmod
    cli._require_root("cert-remove",
                  "it edits the managed-cert manifest and may delete cert files")
    cfg = load_config(Path(args.config))
    entries = certmod.load_manifest(cfg.data_dir)
    entry = next((c for c in entries if c.get("name") == args.name), None)
    if entry is None:
        have = ", ".join(c.get("name", "?") for c in entries) or "(none managed)"
        sys.exit(f"no managed cert named {args.name!r} — have: {have}")

    certmod.remove_managed(cfg.data_dir, args.name)
    certmod.profile_snapshot_path(cfg.data_dir, args.name).unlink(missing_ok=True)
    print(f"deregistered '{args.name}' — the daemon will no longer renew it.")

    paths = certmod.ManagedCert.from_dict(entry).placed_paths()
    if args.delete_files:
        for p in paths:
            try:
                Path(p).unlink()
                print(f"  removed {p}")
            except FileNotFoundError:
                pass
    else:
        print("  the placed files are LEFT in place (a service may be using them):")
        for p in paths:
            print(f"    {p}")
        print("  pass --delete-files to remove them too.")
    return 0




def cmd_cert_request(args) -> int:
    """Request an x509 TLS cert from the anchor for a local service (e.g. Postgres).
    Generates the leaf key locally; only its public key is sent to the anchor. Unless
    --no-auto-renew is given, the cert is recorded so the daemon renews it at
    ~half its TTL (and runs --reload-cmd afterward)."""
    from ..config import load_config
    from ..keys import NodeKeys
    from .. import certs as certmod

    # A cert PROFILE bundles the file placements (paths + owner + mode) and the
    # reload command for a service, so one command issues, places, chowns, and
    # registers renewal. --show just prints the template (to copy + adapt) and
    # needs neither root nor config.
    profile = None
    if getattr(args, "profile", None):
        profile = _load_cert_profile(args.profile)
        if getattr(args, "show", False):
            print(profile["text"], end="")
            return 0

    cli._require_root("cert-request",
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
        if profile and profile["dns"]:
            dns = list(profile["dns"])
        else:
            from ..hosts import mesh_name
            dns = [mesh_name(cfg.hostname, cfg.mesh_domain)]
            ips = [keys.addr]

    # CN is not operator-settable: it's cosmetic under verify-full (the SAN is
    # what's checked) and the anchor constrains it to an owned name anyway, so we
    # just derive it from the first SAN.
    cn = dns[0] if dns else (ips[0] if ips else keys.addr)
    name = args.name or (Path(profile["path"]).stem if profile
                         else (dns[0] if dns else "service"))

    anchor_url = args.anchor or cfg.root_url
    if not anchor_url:
        sys.exit("no anchor URL — set root_url in config or pass --anchor")

    if profile:
        # Idempotent: an unchanged re-request of a still-fresh cert is a no-op.
        exp = _cert_already_current(cfg.data_dir, name, dns=dns, ips=ips,
                                    files=profile["files"], renew=getattr(args, "renew", False))
        if exp:
            _print_cert_noop(name, exp, via=f"profile '{Path(profile['path']).name}'")
            return 0
        # Pre-validate every owner before we bother the anchor, so a typo'd
        # user fails instantly rather than after burning a cert.
        for f in profile["files"]:
            if f.get("owner"):
                try:
                    certmod._resolve_owner(f["owner"])
                except RuntimeError as e:
                    sys.exit(str(e))
        try:
            key_pem, cert_pem, ca_pem = certmod.fetch_cert(
                anchor_url, keys, dns=dns, ips=ips, cn=cn)
            certmod.place_cert_files(profile["files"], key_pem, cert_pem, ca_pem)
        except certmod.CertRejected as e:
            sys.exit(f"cert request rejected: {e}")
        except (RuntimeError, OSError) as e:
            sys.exit(f"cert request/placement failed: {e}")

        reload_cmd = args.reload_cmd or profile["reload"]
        auto = not args.no_auto_renew
        certmod.record_managed(cfg.data_dir, {
            "name": name, "cn": cn, "dns": dns, "ips": ips,
            "files": profile["files"], "reload_cmd": reload_cmd,
            "auto_renew": auto, "profile": Path(profile["path"]).stem,
        })
        # Record-keeping: snapshot the exact profile used (with its provenance
        # comments), separate from the manifest's effective config.
        certmod.snapshot_profile(cfg.data_dir, name, profile["text"])
        print(f"TLS certificate issued + placed via profile "
              f"'{Path(profile['path']).name}'.")
        print(f"  cn / SAN : {cn}" + (f"  (+{len(dns) - 1} more)" if len(dns) > 1 else ""))
        for f in profile["files"]:
            own = f.get("owner", "root:root")
            mode = int(f["mode"], 8) if f.get("mode") else \
                certmod._ROLE_MODE.get(f["role"], 0o644)
            print(f"  {f['role']:<9}→ {f['path']}  [{own} {mode:04o}]")
        if reload_cmd:
            print(f"  reload   : {reload_cmd}")
        if auto:
            print("The daemon re-issues, re-places (with owner/mode), and runs "
                  "reload at ~half TTL — the whole lifecycle is hands-off.")
        else:
            print("Auto-renewal disabled (--no-auto-renew) — re-run before expiry.")
        return 0

    # Resolve the three destinations. Default is <out-dir>/<name>.{key,crt} +
    # <out-dir>/ca.crt; each can be overridden independently so the key, cert,
    # and CA cert may live in different directories.
    out_dir = Path(args.out_dir) if args.out_dir else (cfg.data_dir / "tls")
    key_path = Path(args.key_out) if args.key_out else out_dir / f"{name}.key"
    crt_path = Path(args.cert_out) if args.cert_out else out_dir / f"{name}.crt"
    ca_path = Path(args.ca_out) if args.ca_out else out_dir / "ca.crt"

    # Idempotent: an unchanged re-request of a still-fresh cert is a no-op.
    exp = _cert_already_current(cfg.data_dir, name, dns=dns, ips=ips,
                                paths=(key_path, crt_path, ca_path),
                                renew=getattr(args, "renew", False))
    if exp:
        _print_cert_noop(name, exp, via=f"at {crt_path}")
        return 0

    # Re-requesting an existing name RELOCATES it (record_managed keys on name).
    # Capture the prior destinations so we can flag any that are now orphaned.
    prior = [c for c in certmod.load_manifest(cfg.data_dir) if c.get("name") == name]
    old_paths = set(certmod.entry_paths(prior[0])) if prior else set()

    try:
        key_path, crt_path, ca_path = certmod.issue_cert(
            anchor_url, keys, dns=dns, ips=ips, cn=cn,
            key_path=key_path, crt_path=crt_path, ca_path=ca_path)
    except certmod.CertRejected as e:
        sys.exit(f"cert request rejected: {e}")
    except RuntimeError as e:
        sys.exit(f"cert request to {anchor_url} failed: {e}")

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
    from ..hosts import mesh_name as _mesh_name
    labels = [lbl for d in dns if (lbl := cli._san_to_owned_label(d, cfg))]
    if labels:
        added = cli._add_config_aliases(Path(args.config), cfg, labels)
        own = _mesh_name(cfg.hostname, cfg.mesh_domain)
        if added:
            print()
            print("published name(s) so peers can resolve this service on the mesh:")
            for lbl in added:
                print(f"  {lbl}.{own}")
            if not cli._service_restart(membership_key(cfg.mesh_domain),
                                  why="so peers can resolve the new names"):
                print("Restart the daemon to advertise them now "
                      "(else they propagate at the next renewal): "
                      f"{cli._svc_restart_hint()}  (or re-run sudo gw run).")
    return 0




def cmd_cert_status(args) -> int:
    """Show every daemon-MANAGED TLS cert (from the manifest) — its expiry,
    renewal state, SANs, placed files, and profile — wherever the files live.
    (Reads the cert files, so a 0600 bundle needs sudo to show its expiry.)"""
    from ..config import load_config
    from .. import certs as certmod

    cfg = load_config(Path(args.config))
    entries = sorted(certmod.load_manifest(cfg.data_dir),
                     key=lambda e: e.get("name", ""))
    if not entries:
        print("no managed TLS certs — 'gw cert-request' (optionally --profile) "
              "creates one.")
        return 0

    now = dt.datetime.now(_UTC)
    for e in entries:
        name = e.get("name", "?")
        head = f"● {name}"
        if e.get("profile"):
            head += f"   (profile: {e['profile']})"
        print(head)

        crt = certmod.ManagedCert.from_dict(e).cert_path
        exp = certmod.cert_expiry(crt) if crt else None
        auto = "auto-renew on" if e.get("auto_renew", True) else "auto-renew OFF"
        if exp is None:
            print(f"    expires : ⚠ cert file missing/unreadable ({crt}) · {auto}")
        else:
            left = (exp - now).total_seconds()
            when = "EXPIRED" if left < 0 else f"in {_dur_short(left)}"
            flag = "⚠ " if left < 0 else ""
            print(f"    expires : {flag}{exp:%Y-%m-%d %H:%M UTC} ({when}) · {auto}")

        sans = list(e.get("dns", [])) + list(e.get("ips", []))
        if sans:
            print(f"    SANs    : {', '.join(sans)}")
        if e.get("files"):
            for f in e["files"]:
                print(f"    {f['role']:<9}: {f['path']}")
        else:
            k, c, a = certmod.entry_paths(e)
            print(f"    files   : key={k}  cert={c}  ca={a}")
        if e.get("reload_cmd"):
            print(f"    reload  : {e['reload_cmd']}")
    return 0
