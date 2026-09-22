"""greasewood.cli._common — Shared gates and discovery: root/OS checks, membership slots, anchor authority (_holds_anchor / _anchor_ca_source / _anchor_urls), fleet-renew hints, node resolution."""
import datetime as dt
import ipaddress
import json
import logging
import os
import re
import sys
from pathlib import Path

from .. import platform as gwplat

# The package namespace is the late-binding seam: cross-module helpers are
# called as cli.<name> so a monkeypatch on the package (the tests' historic
# patch point) reaches every caller, exactly as it did when this was one file.
import greasewood.cli as cli

_UTC = dt.timezone.utc
log = logging.getLogger("greasewood")




def _setup_logging(verbose: bool) -> None:
    from ..audit import UTCFormatter
    level = logging.DEBUG if verbose else logging.INFO
    handler = logging.StreamHandler()
    # Full ISO-8601 UTC timestamps: a command trail spanning days must be
    # unambiguous (the old format was time-only).
    handler.setFormatter(UTCFormatter(
        "%(asctime)s %(levelname)s %(name)s: %(message)s"))
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level)




def _config_aliases(cfg) -> list:
    """The node's published service labels from [network] aliases, keeping only
    valid DNS labels (a bad entry is dropped, not mangled)."""
    from .. import hosts
    return [a for a in cfg.aliases if hosts.valid_label(a)]




def _san_to_owned_label(san: str, cfg) -> "str | None":
    """If `san` is a strict subdomain of this node's own mesh name, return the
    single label under it (e.g. 'pg.db01.gw.internal' → 'pg'); else None.
    Cert SANs live in the mesh's CANONICAL namespace (see cert-request)."""
    from .. import hosts
    own = hosts.mesh_name(cfg.hostname, cfg.mesh_domain)
    suffix = "." + own
    if san.endswith(suffix):
        label = san[: -len(suffix)]
        if hosts.valid_label(label):        # single label only, DNS-safe
            return label
    return None




def _add_config_aliases(cfg_path: Path, cfg, labels: list) -> list:
    """Merge `labels` into [network] aliases in the TOML, in place. Returns the
    labels actually added (empty if all were already present / couldn't edit)."""
    have = set(cfg.aliases)
    new = [l for l in labels if l not in have]
    if not new:
        return []
    merged = json.dumps(sorted(have | set(new)))
    text = cfg_path.read_text()
    line = f"aliases = {merged}"
    if re.search(r"(?m)^\s*aliases\s*=", text):
        text = re.sub(r"(?m)^\s*aliases\s*=.*$", line, text, count=1)
    elif re.search(r"(?m)^\[network\]\s*$", text):
        text = re.sub(r"(?m)^(\[network\]\s*)$", r"\1\n" + line, text, count=1)
    else:
        return []                            # no place to put it — caller warns
    cfg_path.write_text(text)
    return new




def _get_passphrase(env_var: str | None) -> bytes | None:
    if not env_var:
        return None
    val = os.environ.get(env_var)
    if not val:
        sys.exit(f"{env_var} is set in config but that environment variable is empty")
    return val.encode()




def _print_firewall_help(listen_port: int = 51900, control_port: int = 51902,
                         mesh_iface: str = "gw-mesh", header: bool = True,
                         enforce_ports: bool = True, role: str = "anchor") -> None:
    """
    Print (never apply) the recommended firewall posture for THIS node's role.
    greasewood binds its control/enroll planes only to the overlay + loopback, so
    nothing it runs is exposed on the underlay regardless of firewall. On a
    default-drop host you still allow the few things below to *reach* those
    sockets. Role-specific: a plain node needs only its mesh UDP port + the coarse
    overlay admit; the enrollment door (port + iface) is the ANCHOR's alone.
    """
    from ..door import DOOR_PORT, DOOR_IFACE, ENROLL_PORT
    is_anchor = role == "anchor"
    who = "an anchor" if is_anchor else "a node"
    if gwplat.IS_MACOS:
        # macOS default = no packet filter configured; that's the expected
        # posture and there is nothing to add. The UDP ports just need to not
        # be blocked if the user runs the (off-by-default) application
        # firewall or a pf config of their own.
        print("Firewall (greasewood never edits it). macOS runs no packet filter by")
        print("default — nothing to configure. If you enable one, allow inbound")
        if is_anchor:
            print(f"udp/{listen_port} (mesh WireGuard) and udp/{DOOR_PORT} (enrollment door).")
        else:
            print(f"udp/{listen_port} (mesh WireGuard).")
        print("Port enforcement (the grant table's port scopes) is not available on")
        print("macOS yet — a pf backend is planned; tunnel-level access control is")
        print("fully enforced. The enrollment door is isolated by WireGuard keys +")
        print("IPv6 forwarding staying off (greasewood checks and warns).")
        return
    if header:
        print(f"Firewall (greasewood never edits it). Recommended posture for {who}.")
        print("On a default-drop host, allow (nftables):")
    else:
        print(f"Recommended posture for {who}. On a default-drop input chain (nftables):")
    if is_anchor:
        print(f"  udp dport {{ {listen_port}, {DOOR_PORT} }} accept   # WireGuard (underlay: mesh + door)")
    else:
        print(f"  udp dport {listen_port} accept              # WireGuard (underlay: mesh)")
    print("  iifname \"lo\" accept                    # this host talks to itself")
    if enforce_ports:
        # Enforcement on (default): greasewood's own nftables table filters the
        # overlay interfaces (control plane, enrollment + door lockdown, and the
        # grant-derived ports). The firewall just admits the overlay so that
        # table can act — it can only tighten what you admit, never open it.
        print("  iifname \"gw-*\" accept                  # admit the overlay; greasewood's")
        print("                                         # nftables table filters the ports on it")
    elif is_anchor:
        # Enforcement off on an anchor: greasewood installs no table, so YOU gate
        # its overlay ports. (These need nftables too; if you have it, prefer
        # leaving enforce_ports on and greasewood applies all of this.)
        print("  # (these need nftables; if you have it, prefer enforce_ports = true)")
        print(f"  iifname \"{mesh_iface}\" tcp dport {control_port} accept   # control plane")
        print(f"  iifname \"{DOOR_IFACE}\" tcp dport {ENROLL_PORT} accept   # enrollment")
        print(f"  iifname \"{DOOR_IFACE}\" drop                    # door carries ONLY enrollment")
    else:
        # Enforcement off on a plain node: no greasewood overlay service to gate,
        # just admit the overlay coarsely (no table to filter it).
        print(f"  iifname \"{mesh_iface}\" accept          # admit the overlay (no table filters it)")




def _enforce_ports_default() -> bool:
    """The enforce_ports value to write into a fresh config (create/join): on
    iff nftables is usable on this host right now. An nft-less host is written
    `enforce_ports = false` explicitly, so its daemon never trips the startup
    guard — the restart-loop this avoids."""
    from ..portfilter import nft_usable
    if not gwplat.port_enforcement_available():
        log.warning("port enforcement is not available on %s yet (a pf backend "
                    "is planned) — writing enforce_ports = false (port scopes "
                    "advisory; grants still gate which tunnels exist).",
                    gwplat.os_name())
        return False
    if nft_usable():
        return True
    log.warning("nftables not usable here — writing enforce_ports = false "
                "(port scopes advisory; grants still gate which tunnels exist). "
                "Install nftables and set enforce_ports = true to enforce ports.")
    return False




def _daemon_fatal(cfg, msg: str):
    """Exit the daemon on an unrecoverable STARTUP condition — but VISIBLY.
    Under the systemd unit's Restart=on-failure, a bare sys.exit is about the
    most invisible failure possible: a silent 5s restart loop. This makes it
    loud on both channels the operator actually watches:
      - CRITICAL to the journal (`logs :` in the watch header points here);
      - a breadcrumb `gw watch` surfaces as the daemon's death reason, so you
        don't have to already know to read journalctl.
    The unit also bounds the loop (StartLimit) so it lands in a `failed` state
    rather than thrashing forever. Then exit non-zero (systemd sees the failure)."""
    from .. import reconcile as rmod
    log.critical("FATAL: cannot start daemon: %s", msg)
    try:
        rmod.write_daemon_fatal(cfg.data_dir, msg)
    except Exception as e:                       # never mask the real cause
        log.warning("could not write daemon-fatal breadcrumb: %s", e)
    sys.exit(msg)




def _make_port_enforcer(cfg, args, grant_policy):
    """Decide port enforcement for `gw run`: return a PortFilter (enforcing) or
    None (unenforced). `gw create`/`gw join` write [network] enforce_ports
    explicitly (on iff nftables was usable then); --no-enforce-ports overrides
    for this run.

    Crucially this NEVER raises or exits on a missing/broken nftables — it
    degrades to None with a loud error. Exiting here would be a systemd restart
    loop that never resolves (exactly the bug an nft-less host hit). An
    unenforced node still peers per policy — grants gate which tunnels exist
    regardless; only the per-port scopes within them drop to advisory."""
    from .. import reconcile as _rec
    if not (cfg.enforce_ports and not getattr(args, "no_enforce_ports", False)):
        log.info("port enforcement OFF (enforce_ports=false): grants still "
                 "control which tunnels exist; port scopes are advisory")
        _rec.clear_enforce_degraded(cfg.data_dir)    # OFF is deliberate, not degraded
        return None
    from ..portfilter import (PortFilter, NftUnavailable, ensure_available,
                             table_name)
    from ..config import membership_key
    try:
        ensure_available()
    except NftUnavailable as e:
        log.error("port enforcement requested (enforce_ports=true) but "
                  "nftables is unusable: %s", e)
        log.error("running WITHOUT port enforcement to avoid a crash loop — "
                  "install nftables, or set `enforce_ports = false` under "
                  "[network] in %s to make this the intended state.",
                  getattr(args, "config", "the config"))
        # Leave a breadcrumb so the unfiltered state is VISIBLE in gw watch /
        # --json, not just a line in the journal. (H2)
        _rec.write_enforce_degraded(cfg.data_dir, str(e))
        return None
    log.info("port enforcement ON: greasewood's own nftables table on %s "
             "(realizing the grant table — default-closed on a fresh anchor)",
             cfg.wg_interface)
    _rec.clear_enforce_degraded(cfg.data_dir)        # healthy
    return PortFilter(table_name(membership_key(cfg.mesh_domain)),
                      cfg.wg_interface, _control_port(cfg), cfg.caps, grant_policy,
                      local_hostname=cfg.hostname)




_IFACE_RE = re.compile(r"^[A-Za-z0-9_-]{1,15}$")




def _reject_bad_interface(name: str) -> None:
    """Refuse an interface name that isn't a valid Linux ifname (1-15 chars of
    [A-Za-z0-9_-]). The derived `gw-<mesh>` names always pass; this guards an
    operator-supplied --interface, whose value is interpolated verbatim into
    greasewood's `nft -f` ruleset and into filesystem paths — a `"`, newline, or
    `;` would otherwise break the ruleset render (falling open) or escape a path."""
    if not _IFACE_RE.match(name or ""):
        sys.exit(f"--interface {name!r} must be 1-15 characters of "
                 f"[A-Za-z0-9_-] (a valid Linux interface name)")




# ---------------------------------------------------------------------------
# invite  (anchor — generate a join token and open a door window)
# ---------------------------------------------------------------------------

def _extract_token(text: str) -> str:
    """Pull the join token out of arbitrary text — a clean token, or the full
    stdout of `gw invite`. Returns the first line that looks like a token so
    `gw join -` works whether or not the producer used `invite -q`."""
    from ..door import TOKEN_PREFIX
    for line in text.splitlines():
        s = line.strip()
        if s.startswith(TOKEN_PREFIX):
            return s
    s = text.strip()
    if s.startswith(TOKEN_PREFIX):
        return s
    sys.exit("no join token (gw1.…) found in input")




def _reject_reserved_roles(names, where: str) -> None:
    """Refuse any anchor-reserved role on an assignment path. Keeps 'anchor' a
    single-member role (only the create-time anchor holds it) and '*' (reach-all)
    unassignable to a joiner or node. `names` are bare role names (no role:)."""
    from ..policy import RESERVED_ROLES
    bad = [r for r in names if r in RESERVED_ROLES]
    if bad:
        sys.exit(f"role(s) {', '.join(bad)} are reserved for the anchor and "
                 f"cannot be assigned via {where}: 'anchor' is single-member "
                 f"(the anchor is its sole member) and '*' is reach-all. Use a "
                 f"concrete role (e.g. node, web, admin).")




def _reject_derived_caps(caps) -> None:
    """Refuse anchor-DERIVED caps on the user-supplied caps path. `hostname-pinned`
    is added by the invite path itself, ONLY when --hostname fixes the name; hand-
    supplying it via --caps or [anchor] default_caps is always wrong — with no
    pinned name it marks a self-naming node permanently un-renameable, and on a
    --standing door it back-doors the "one pinned name for many nodes" state the
    --hostname + --standing guard forbids."""
    if "hostname-pinned" in caps:
        sys.exit("`hostname-pinned` can't be set via --caps/default_caps — it's "
                 "added automatically by --hostname. To pin a name, use "
                 "--hostname NAME (not on a --standing door).")




# ---------------------------------------------------------------------------
# join  (new node — door-based enrollment, no SSH)
# ---------------------------------------------------------------------------

# Memberships are keyed by the MESH NAME (given once at `gw create <name>`,
# carried in every join token as <name>.internal). Nothing is unsuffixed and
# nothing is numbered: the very first mesh on a host gets the same name-derived
# artifacts as the fifth — /etc/greasewood_<name>.toml, /var/lib/
# greasewood_<name>, interface gw-<name[:12]>, service greasewood@<name>.
# Explicit flags override any derived value.

def _membership_paths(key: str, etc: "Path" = Path("/etc"),
                      var: "Path" = Path("/var/lib")) -> dict:
    """The derived artifacts for membership `key`. The interface truncates to
    the kernel's 15-char limit (gw- + 12); a truncation collision between two
    memberships is a loud join/create-time refusal, never a silent rename."""
    return {
        "config": etc / f"greasewood_{key}.toml",
        "data_dir": var / f"greasewood_{key}",
        "interface": f"gw-{key[:12].rstrip('-')}",
        "unit": f"greasewood@{key}",
    }




def _memberships(etc: "Path" = Path("/etc")) -> "list[tuple[str, Path]]":
    """Existing membership configs on this host as (key, config_path)."""
    out = []
    for p in etc.glob("greasewood_*.toml"):
        m = re.fullmatch(r"greasewood_([a-z0-9-]+)\.toml", p.name)
        if m:
            out.append((m.group(1), p))
    return sorted(out)




def _anchor_membership(etc: "Path" = Path("/etc")) -> "tuple[str, Path] | None":
    """The (key, config_path) of a role=anchor membership on this host, or None.

    `gw join` refuses on an anchor host: the enrollment door is a shared singleton
    (one gw-door interface, one door subnet, one policy-routing table), so the
    anchor's permanent door isolation would blackhole any join this host attempts
    — it hangs at 'connecting to enroll daemon'. Better to refuse loudly up front."""
    from ..config import load_config
    for key, p in cli._memberships(etc):
        try:
            if _holds_anchor(load_config(p)):
                return key, p
        except Exception:
            continue
    return None




def _membership_for_ca(ca_pub_hex: str, etc: "Path" = Path("/etc")) -> "str | None":
    """The membership key already trusting this CA, or None. This is how a
    token is routed: its CA pub identifies WHICH mesh it belongs to, so a token
    for a mesh we're already on refreshes that membership (even after a re-root
    — trusted_pubs carries old+new during migration), and an unknown CA means a
    genuinely new mesh."""
    from ..config import load_config
    for key, p in cli._memberships(etc):
        try:
            if ca_pub_hex in load_config(p).ca_pubs_hex:
                return key
        except Exception:
            continue
    return None




def _free_listen_port(etc: "Path" = Path("/etc")) -> int:
    """First of 51900, 51910, 51920, … claimed by neither an existing membership
    config NOR a live WireGuard interface. The latter matters: a purged mesh can
    leave a kernel interface still bound to its port with no config to show for
    it, and picking that port would crash the new daemon at interface-up with
    EADDRINUSE."""
    from ..config import load_config
    used = set()
    for _k, p in cli._memberships(etc):
        try:
            used.add(load_config(p).listen_port)
        except Exception:
            continue
    try:
        from .. import wg as wgmod
        used.update(wgmod.wg_interface_ports().values())
    except Exception:
        pass
    port = 51900
    while port in used:
        port += 10
    return port




def _iface_collision(iface: str, cfg_path: "Path",
                     etc: "Path" = Path("/etc")) -> "Path | None":
    """Another membership already using `iface` (the 15-char truncation can
    collide for long names sharing a 12-char prefix), or None."""
    from ..config import load_config
    for _k, p in cli._memberships(etc):
        if p.resolve() == Path(cfg_path).resolve():
            continue
        try:
            if load_config(p).wg_interface == iface:
                return p
        except Exception:
            continue
    return None




def _discover_config(etc: "Path" = Path("/etc")) -> "Path":
    """Resolve the config when -c wasn't given: exactly one membership → use it
    (the single-mesh experience needs no flags); several → demand -c, loudly;
    none → say how to start."""
    ms = cli._memberships(etc)
    if len(ms) == 1:
        return ms[0][1]
    if not ms:
        sys.exit("no greasewood mesh is configured on this host — run "
                 "'sudo gw create <name>' (anchor) or 'sudo gw join <token>' first")
    listing = "\n".join(f"  -c {p}   ({k})" for k, p in ms)
    sys.exit(f"this host is on {len(ms)} meshes — say which one:\n{listing}")




def _warn_shared_overlay_prefix(cfg_path: "Path", my_prefix: str,
                                etc: "Path" = Path("/etc")) -> bool:
    """Warn when another membership on this host uses the same overlay /64.
    NOT a functional failure — greasewood's data plane is /128-only (address,
    kernel route, and WireGuard allowed-ip are all identity-derived host
    routes), so two meshes on one prefix never produce an ambiguous route.
    What a shared prefix DOES break is prefix-based reasoning: a firewall rule
    or script scoped to the /64 now silently matches BOTH meshes, and an
    address no longer tells a human which mesh it belongs to. Returns True if
    it warned (for tests)."""
    from ..config import load_config
    try:
        mine = ipaddress.ip_network(f"{my_prefix}/64")
    except ValueError:
        return False
    for n, p in cli._memberships(etc):
        if p.resolve() == Path(cfg_path).resolve():
            continue
        try:
            theirs = ipaddress.ip_network(f"{load_config(p).overlay_prefix}/64")
        except Exception:
            continue
        if theirs == mine:
            log.warning(
                "this mesh uses the SAME overlay /64 (%s) as membership %r "
                "(%s). Everything still works — greasewood routes only "
                "identity-derived /128s, never the /64 — but the prefix no "
                "longer identifies a mesh on this host: any firewall rule or "
                "script scoped to %s now matches BOTH meshes, and addresses "
                "are indistinguishable by eye. For legibility, create meshes "
                "with distinct `create --overlay-prefix`.",
                mine, n, p, mine)
            return True
    return False




def _republish_own_record(cfg, keys, directory, *, cred=None, endpoints=None,
                          aliases=None, reachable=None, version=None,
                          families=None, push_to=(), quiet_push=False):
    """Re-sign this node's record (seq+1) carrying forward whatever isn't
    overridden, save the cache, and best-effort push. Renewal, rename,
    config-refresh, and the reachable-set publish ALL go through here — the
    directory is the single seq source, so they compose with no shared state.
    Returns the new record, or None if there's nothing to re-sign yet (no
    record and no fresh credential supplied)."""
    from ..wire import NodeRecord
    from ..sync import push_record
    from .. import reconcile as _rmod
    existing = directory.get(keys.id_pub_hex)
    if existing is None and cred is None:
        return None

    def carry(override, attr, default):
        if override is not None:
            return list(override)
        return list(getattr(existing, attr)) if existing else default

    if version is None:
        version = _rmod.read_daemon_version(cfg.data_dir)
        if not version and existing is not None:
            version = existing.version

    record = NodeRecord(
        id_pub=keys.id_pub_bytes,
        seq=(existing.seq + 1) if existing else 1,
        endpoints=carry(endpoints, "endpoints", list(cfg.endpoints)),
        cred=cred if cred is not None else existing.cred,
        aliases=carry(aliases, "aliases", _config_aliases(cfg)),
        reachable=carry(reachable, "reachable", []),
        version=version or "",
        # Which underlay families we can ORIGINATE on, re-detected rather than
        # carried. It is an unsigned display field (like version) used for
        # diagnostics; it does not affect peering decisions.
        families=sorted(families if families is not None else cli._local_families()),
    ).sign(keys.id_priv)
    directory.put(record)
    directory.save(cfg.dir_cache_path)
    for url in push_to:
        try:
            push_record(url, record)
        except Exception as e:
            (log.debug if quiet_push else log.warning)(
                "published locally but push to %s failed (will sync): %s", url, e)
    return record




# ---------------------------------------------------------------------------
# set-caps / set-roles — change an enrolled node's caps on the anchor
# ---------------------------------------------------------------------------

def _anchor_urls(cfg, directory, own_addr: "str | None" = None,
                 get_ca_pubs=None) -> "list[str]":
    """The ANCHOR SET: every control-plane URL this node can use. Configured
    seeds come first (the bootstrap — always dialable knowledge), then every
    holder discovered in the replicated directory: a record carrying the
    anchor roles in a credential signed by a TRUSTED CA (the trust check
    matters — a structurally-valid but forged record must not steer traffic;
    such a record also never becomes a WG peer, so its URL would only dangle).
    Holders exclude themselves so their sync pulls from the OTHER holders.
    Order is stable (seeds, then holders sorted by address) so retry behavior
    is predictable; consumers try each in order."""
    urls: "list[str]" = []
    for u in list(getattr(cfg, "seeds", []) or []):
        if u and u not in urls:
            urls.append(u)
    root = getattr(cfg, "root_url", "") or ""
    if root and root not in urls:
        urls.insert(0, root)
    port = _control_port(cfg)
    discovered = []
    for r in directory.all():
        if not any(c in ("role:*", "role:anchor") for c in r.cred.caps):
            continue
        if own_addr and r.cred.addr == own_addr:
            continue
        if get_ca_pubs is not None:
            try:
                r.cred.verify(get_ca_pubs(), allow_expired=True)
            except ValueError:
                continue
        discovered.append(f"http://[{r.cred.addr}]:{port}")
    for u in sorted(discovered):
        if u not in urls:
            urls.append(u)
    return urls




def _holds_anchor(cfg) -> bool:
    """Does this membership hold anchor authority? The anchor FILE
    (<data_dir>/anchor.gwa) is the authority — any node possessing it
    performs anchor duties, and deleting it de-anchors the machine. A legacy
    role=anchor config with ca_key_file still counts (unmigrated anchors)."""
    from .. import anchorfile
    data_dir = getattr(cfg, "data_dir", None)
    if data_dir is not None:
        try:
            if anchorfile.load(data_dir) is not None:
                return True
        except ValueError as e:
            sys.exit(f"anchor file {anchorfile.anchor_path(data_dir)} is "
                     f"corrupt: {e} — restore it from another holder "
                     f"(gw anchor export | gw anchor adopt) or a backup")
        except PermissionError:
            # Can't read it but it exists → this machine IS a holder; the
            # caller needing its contents hits the permission error with
            # context.
            return anchorfile.anchor_path(data_dir).exists()
    # A bare role=anchor still counts (legacy configs; the key-needing
    # operations surface their own error if ca_key_file is also missing).
    return getattr(cfg, "role", "node") == "anchor"




NOT_A_HOLDER_MSG = (
    "this node holds no anchor authority — no anchor.gwa in its data dir and "
    "no legacy [anchor] ca_key_file. Run this on a holder, or make this node "
    "one: `gw anchor export` on a holder, copy the file over YOUR channel "
    "(scp), `sudo gw anchor adopt <file>` here.")




def _anchor_ca_source(cfg):
    """(CAKeys, guard_path) for anchor-authority operations: the anchor
    file's CA key when present (guard_path = anchor.gwa, arming CA's
    stale-key snapshot against the file changing under a live daemon), else
    the legacy ca.key. Exits with the adoption hint when neither exists."""
    from .. import anchorfile
    af = anchorfile.load(cfg.data_dir)
    if af is not None:
        return af.ca_keys(), anchorfile.anchor_path(cfg.data_dir)
    if cfg.ca_key_file is None:
        sys.exit(NOT_A_HOLDER_MSG)
    from ..keys import CAKeys
    return (CAKeys.load(Path(cfg.ca_key_file),
                        _get_passphrase(cfg.ca_key_passphrase_env)),
            Path(cfg.ca_key_file))




def _load_anchor_ca(args, cmd: str):
    """Shared setup for anchor-side membership commands: load config + CA.
    The CA reads its view from the on-disk directory/statement caches the
    daemon maintains, and any statement it mints lands in statements.json —
    where the daemon's sync loop re-merges it within a cycle (and every other
    holder within a pull), so no restart is needed for the decision to
    propagate."""
    from ..config import load_config
    from ..ca import CA
    # Gate up front: the CA key and statement log are root-owned, and these
    # commands write them. Without this, a non-root run fails partway with
    # whatever file access breaks first — historically misread as the node not
    # existing at all.
    cli._require_root(cmd, "it reads and writes the anchor's state and CA key")
    cfg = load_config(Path(args.config))
    if not _holds_anchor(cfg):
        sys.exit(f"gw {cmd} needs anchor authority. {NOT_A_HOLDER_MSG}")
    ca_keys, _guard = _anchor_ca_source(cfg)
    ca_pubs = [bytes.fromhex(h) for h in cfg.ca_pubs_hex]
    return cfg, CA(ca_keys, cfg.data_dir,
                   get_ca_pubs=lambda: ca_pubs or [ca_keys.ca_pub_bytes],
                   dir_cache_path=cfg.dir_cache_path)




def _resolve_node(ca, cfg, handle: str, *, require_enrolled: bool = True):
    """Resolve a node handle — a hostname, a full `<host>.<mesh_domain>` mesh
    name, or a 64-char id_pub hex — to (id_pub_bytes, hostname). A hostname
    always needs the anchor's registry (the only name→id map). With
    require_enrolled=False a raw id hex is accepted even if the node isn't in
    the registry — so `revoke` can still deny an already-forgotten identity."""
    s = handle.strip()
    if len(s) == 64 and all(c in "0123456789abcdefABCDEF" for c in s):
        info = ca.node_info(bytes.fromhex(s))
        if info is None:
            if require_enrolled:
                sys.exit(f"no enrolled node with id {s[:16]}…")
            return bytes.fromhex(s), s[:16] + "…"      # raw id, name unknown
        return bytes.fromhex(s), info[0]
    suffix = "." + cfg.mesh_domain
    if s.endswith(suffix):
        s = s[: -len(suffix)]
    owner = ca.hostname_owner(s)
    if owner is None:
        sys.exit(f"no node named {handle!r} on this anchor — pass its hostname, "
                 f"its <host>.{cfg.mesh_domain} name, or its 64-char id_pub hex "
                 f"(see `gw watch`)")
    return bytes.fromhex(owner), s




_NEXT_RENEWAL_NOTE = (
    "Takes effect at the node's next renewal (~half the credential TTL); no "
    "re-join needed. To apply now WITHOUT touching the node, run `sudo gw "
    "renew-all` on the anchor — its daemon renews and adopts the new roles "
    "live (no restart). (`sudo gw renew` on the node works too, but that CLI "
    "path needs a daemon restart to take effect.)"
)




def _request_fleet_renewal(cfg) -> "dt.datetime":
    """Write the anchor's fleet-wide renew_after=now hint (served in GET
    /directory). Shared by `gw renew-all` and `gw set-roles --now`. Returns the
    timestamp written."""
    now = dt.datetime.now(_UTC).replace(microsecond=0)
    (cfg.data_dir / "renew_after").write_text(now.isoformat())
    return now




def _adopt_renew_after(cfg, ts: "dt.datetime") -> bool:
    """Holder-side gossip for the fleet-renew hint: when a pull from ANOTHER
    holder carries a renew_after newer than what this holder serves, persist
    it locally (latest-wins) so this holder's /directory carries it too.
    Without this, `gw renew-all` on holder A only nudged the nodes whose
    first-success sync happened to pull from A — nodes syncing from holder B
    never saw the hint. With it, the hint converges across holders exactly
    like statements do, and every node gets it from whichever holder it polls.
    Returns True when the local hint advanced."""
    path = cfg.data_dir / "renew_after"
    try:
        current = dt.datetime.fromisoformat(path.read_text().strip())
        if current.tzinfo is None:
            current = current.replace(tzinfo=_UTC)
    except (FileNotFoundError, ValueError, OSError):
        current = None
    if current is not None and ts <= current:
        return False
    try:
        path.write_text(ts.isoformat())
    except OSError as e:
        log.warning("could not persist gossiped renew_after: %s", e)
        return False
    log.info("adopted fleet renew hint from another holder (renew_after=%s)", ts)
    return True




def _grants_naming_role(cfg, role: str) -> str:
    """Human lines for the active grants that name `role` — the concrete
    coverage a host loses when it leaves that role. '' when there is no
    policy cache, or none name it (display-only, like status's grant read)."""
    from ..policy import POLICY_BASENAME
    from ..wire import GrantTable
    try:
        grants = GrantTable.from_dict(json.loads(
            (cfg.data_dir / POLICY_BASENAME).read_text())).grants
    except Exception:
        return ""
    return "\n".join(
        f"    {', '.join(g['from'])} -> {', '.join(g['to'])} : "
        f"{', '.join(g['ports'])}"
        for g in grants or [] if role in list(g["from"]) + list(g["to"]))




# ---------------------------------------------------------------------------
# anchor-promote — turn an enrolled node into an anchor (generate a CA)
# ---------------------------------------------------------------------------

def _control_port(cfg) -> int:
    """The control-plane port from cfg.control_listen (':51902' -> 51902)."""
    try:
        return int(cfg.control_listen.rsplit(":", 1)[1])
    except (ValueError, IndexError, AttributeError):
        return 51902




def _require_root(cmd: str, why: "str | None" = None) -> None:
    """Exit cleanly if not root, instead of crashing partway through on EACCES —
    the complaint comes FIRST, loudly, not from whichever file access happens to
    fail deepest into the command. For commands that create WireGuard
    interfaces, edit routing, write /etc, or read/write root-owned state."""
    if os.geteuid() != 0:
        why = why or "it changes WireGuard/routing/system files"
        sys.exit(f"'gw {cmd}' needs root ({why}).\nTry: sudo gw {cmd}")




def _require_tools() -> None:
    """Exit cleanly if the wg/ip binaries are missing — BEFORE any state is
    created. Same posture as _require_root: the complaint comes first, not
    from whichever subprocess call happens to crash deepest into the command
    (seen in the field: a join with no wireguard-tools died mid-door-bringup
    with a raw FileNotFoundError, leaving the half-made interface behind)."""
    from .. import wg as wgmod
    missing = wgmod.missing_tools()
    if missing:
        pkgs = {"wg": "wireguard-tools", "ip": "iproute2"}
        need = " ".join(dict.fromkeys(pkgs[t] for t in missing))
        sys.exit(f"required tool(s) not installed: {', '.join(missing)} — "
                 f"greasewood drives the data plane with the stock tools "
                 f"(pipx installs only the Python side).\n"
                 f"Install them first:  sudo apt install {need}   "
                 f"# or your distro's equivalent")




# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def _require_supported_os() -> None:
    """Exit cleanly on an unsupported host instead of failing deep in an
    ip/ifconfig/wg call. greasewood runs on Linux (in-kernel WireGuard,
    nftables, iproute2) and macOS (wireguard-go, launchd); PyPI
    is public, so any other OS could pip-install and run a command. --version
    and -h are handled by parse_args before this, so they work everywhere."""
    gwplat.require_supported()
