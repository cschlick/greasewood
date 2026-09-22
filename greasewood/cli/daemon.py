"""greasewood.cli.daemon — The daemon: cmd_run assembles every loop (reconcile, sync, renewal, attest, sweep, watchdog) and, on holders, the control plane + door."""
import datetime as dt
import json
import logging
import os
import signal
import threading
from pathlib import Path

from ..keys import _key_file_warnings, _secret_key_paths
from ..status import _load_revoked, _version

# The package namespace is the late-binding seam: cross-module helpers are
# called as cli.<name> so a monkeypatch on the package (the tests' historic
# patch point) reaches every caller, exactly as it did when this was one file.
import greasewood.cli as cli

_UTC = dt.timezone.utc
log = logging.getLogger("greasewood")




# ---------------------------------------------------------------------------
# run
# ---------------------------------------------------------------------------

def _start_anchor_control_plane(cfg, keys, directory, get_ca_pubs, grant_policy,
                                stmt_log, att_log=None):
    """Bring up the anchor-only services and return (get_revoked, door_watcher):
    load the CA, start the HTTP control plane, and start the enrollment door
    watcher. get_revoked is the live revoke-list reader the reconcile loop uses;
    door_watcher is returned so cmd_run can stop it at shutdown (the HTTP server
    is a daemon thread that dies with the process, so it isn't returned)."""
    from ..ca import CA
    from ..server import ControlServer, ControlPlaneAddrInUse
    from ..enroll import DoorWatcher, EnrollContext
    from .. import wg as wgmod

    ca_keys, guard_path = cli._anchor_ca_source(cfg)
    # key_file arms the stale-key guard: this CA lives as long as the daemon,
    # and must refuse to sign if the key (anchor.gwa or legacy ca.key) changes
    # on disk underneath it. The live directory + statement log ARE the
    # registry view it issues from.
    ca = CA(ca_keys, cfg.data_dir, cfg.credential_ttl,
            key_file=guard_path,
            directory=directory, statements=stmt_log,
            get_ca_pubs=get_ca_pubs, dir_cache_path=cfg.dir_cache_path)
    get_revoked = ca.load_revoked_set
    log.info("CA loaded, pub=%s...", ca_keys.ca_pub_bytes.hex()[:16])
    # Re-apply door routing in case the machine rebooted since create.
    wgmod.setup_door_routing()

    # Bind the control plane to the overlay address (reachable only through the
    # mesh) and loopback (for the anchor talking to itself) — NOT "::". This
    # keeps it off the underlay structurally, no firewall rule needed.
    port = cli._control_port(cfg)
    listen_addrs = [f"[{keys.addr}]:{port}", f"[::1]:{port}"]

    # Fleet-wide renew hint (gw renew-all): served in /directory, re-read per
    # request so a bump takes effect without restarting the anchor.
    def read_renew_after():
        try:
            return (cfg.data_dir / "renew_after").read_text().strip() or None
        except FileNotFoundError:
            return None

    # grants.toml is the SOURCE OF TRUTH, but changes are APPLIED DELIBERATELY:
    # `gw policy apply` previews the X→Y change and asks to confirm before
    # signing it into policy.json. The daemon does NOT silently auto-apply edits
    # — a background daemon can't prompt, and a policy change tears down tunnels,
    # so it should be confirmed, not triggered by a stray file save. At startup
    # (and via `gw policy show`) an unapplied edit is surfaced, so a forgotten
    # apply is visible rather than silently ineffective.
    from ..policy import unapplied_edits
    pending = unapplied_edits(cfg.data_dir)
    if pending:
        log.warning("grants.toml has unapplied changes (%s) — run "
                    "`sudo gw policy apply` to review and apply them", pending)

    def read_policy():
        # Serve the signed, APPLIED policy.json (or None). Nodes trust the CA
        # signature; they never see raw grants.toml.
        from ..policy import POLICY_BASENAME
        try:
            return json.loads((cfg.data_dir / POLICY_BASENAME).read_text())
        except FileNotFoundError:
            return None
        except (OSError, ValueError) as e:
            log.warning("policy.json unreadable, serving none: %s", e)
            return None

    try:
        server = ControlServer(
            listen_addrs, directory, get_ca_pubs=get_ca_pubs, get_revoked=get_revoked,
            ca=ca, cache_path=cfg.dir_cache_path, tls_cert_ttl=cfg.tls_cert_ttl,
            mesh_domain=cfg.mesh_domain, get_renew_after=read_renew_after,
            get_policy=read_policy, statements=stmt_log,
            data_dir=cfg.data_dir, attestations=att_log)
    except ControlPlaneAddrInUse as e:
        cli._daemon_fatal(cfg, f"anchor control plane can't start: {e}")
    server.start()

    door_watcher = DoorWatcher(
        EnrollContext(
            ca=ca, directory=directory, node_keys=keys, wg_iface=cfg.wg_interface,
            get_ca_pubs=get_ca_pubs, get_revoked=get_revoked,
            cache_path=cfg.dir_cache_path, control_port=port,
            mesh_domain=cfg.mesh_domain, data_dir=cfg.data_dir),
        door_port=cfg.door_port)
    door_watcher.start()
    log.info("door watcher started")

    # Garbage-collect abandoned nodes: past the fleet drop grace an aged-out
    # record is pruned, which ends both its visibility and its ability to
    # renew (renewal re-issues from the record) — a churned cloud fleet left
    # to expire is forgotten without manual `gw revoke`.
    from ..sweep import StaleSweep
    StaleSweep(directory, cfg.dir_cache_path, statements=stmt_log,
               protect=keys.id_pub_hex, grace=cfg.drop_grace).start()
    log.info("stale-node sweep started (drop_grace=%s)", cfg.drop_grace)
    return get_revoked, door_watcher




def _cleanup_legacy_port_table(cfg) -> None:
    """Port enforcement is gone (0.7.0): greasewood decides which tunnels
    exist; what flows inside them is the host firewall's business. A fleet
    upgrading from <=0.6 still carries the old per-mesh nftables table — left
    alone it would silently keep filtering ports forever — so remove it once,
    best-effort, at startup. Harmless where nft or the table is absent."""
    if cli.gwplat.IS_MACOS:
        return
    key = cli.membership_key(cfg.mesh_domain)
    safe = "".join(c if c.isalnum() else "_" for c in key)
    try:
        r = cli.subprocess.run(["nft", "delete", "table", "inet",
                            f"greasewood_{safe}"],
                           capture_output=True, text=True)
        if r.returncode == 0:
            log.info("removed the legacy port-enforcement nftables table "
                     "(greasewood_%s) — port scoping is the host firewall's "
                     "job now", safe)
    except FileNotFoundError:
        pass


def cmd_run(args) -> int:
    cli._require_root("run")
    cli._require_tools()
    from ..config import load_config
    from ..keys import NodeKeys
    from ..directory import Directory
    from ..reconcile import ReconcileLoop
    from ..sync import SyncLoop, push_record
    from ..renewal import RenewalLoop
    from .. import wg as wgmod

    cfg = load_config(Path(args.config))

    # Durable data-plane command trail: attach the rotating audit file so every
    # ip/wg command the daemon issues is recorded independently of the journal.
    if cfg.audit_log is not None:
        from .. import audit
        if audit.attach_file(cfg.audit_log):
            log.info("data-plane command audit → %s", cfg.audit_log)

    log.info("starting — role=%s hostname=%s", cfg.role, cfg.hostname)

    # Stamp the version we're actually running, so `gw watch` can warn if the
    # package was upgraded but the daemon wasn't restarted (it keeps the OLD
    # code in memory until then). Rewritten each start → matches after a restart.
    from .. import reconcile as _rmod
    _rmod.write_daemon_version(cfg.data_dir, _version())

    # Service-definition self-heal: pick up improvements shipped by upgrades
    # (no-op when unchanged, on an unmanaged host, or running by hand). Backend
    # of the host: systemd unit or OpenRC script.
    _svc = cli._service_backend()
    if _svc is not None:
        _svc.refresh_template()

    # Roles are the grant-table vocabulary. With no policy applied everyone
    # peers regardless; once one exists, a node with no role: tag reaches only
    # the anchor — worth saying once, up front.
    if not any(c.startswith("role:") for c in cfg.caps):
        log.warning("[node] caps = %s contains no role:<name> tag — once a "
                    "grant table is applied, this node will reach only the "
                    "anchor (add e.g. role:node)", cfg.caps)

    keys = NodeKeys.load_or_generate(cfg.data_dir)
    log.info("overlay addr: %s", keys.addr)

    # Key-hygiene check at every daemon start: a secret owned by a non-root
    # user, or readable past its owner, is a standing hole (for the CA key,
    # credential-minting). Catches legacy installs whose create chowned the
    # data dir to the operator.
    for w in _key_file_warnings(_secret_key_paths(cfg)):
        log.warning("%s", w)

    directory = Directory.load(cfg.dir_cache_path)

    # Trust is static, straight from config: the trusted CA set, the seeds to
    # pull the directory from, and the anchor URL. (Moving the anchor is a deliberate
    # re-root — a trusted_pubs/root_url config change — not a runtime event.)
    ca_pubs = [bytes.fromhex(h) for h in cfg.ca_pubs_hex]
    def get_ca_pubs():
        return ca_pubs

    from .. import audit
    with audit.context(f"startup: ensure interface {cfg.wg_interface} [{keys.addr}]"):
        try:
            wgmod.ensure_interface(
                cfg.wg_interface, keys.addr, cfg.listen_port, cfg.wg_key_path
            )
        except wgmod.PortInUse as e:
            # A fatal, operator-fixable startup condition — exit VISIBLY (journal
            # + a breadcrumb gw watch shows) rather than a silent crash-loop
            # under the systemd unit's Restart=on-failure.
            cli._daemon_fatal(cfg, str(e))

    sync: SyncLoop | None = None
    renewal: RenewalLoop | None = None
    door_watcher = None

    # Revoke list is re-read live (not snapshotted) so `gw revoke` takes effect
    # without a daemon restart — both for control-plane refusal and local
    # eviction. The anchor owns the canonical list; plain nodes cache a copy
    # pulled from the anchor's /revoked endpoint during sync. The live grant
    # table (roles → roles : ports) drives tunnel existence. Loaded from
    # last-known-good on disk; the sync loop offers fresh tables
    # (CA-verified, seq-monotonic). Built BEFORE the anchor block so the anchor
    # can feed its own copy from grants.toml (see _start_anchor_control_plane).
    from ..policy import GrantPolicy, POLICY_BASENAME
    grant_policy = GrantPolicy(cache_path=cfg.data_dir / POLICY_BASENAME,
                               get_ca_pubs=get_ca_pubs)
    grant_policy.load_cache()

    # The replicated membership-decision log (revoke/tombstone/setcaps
    # statements — see greasewood.statements). Loaded on every role: plain
    # nodes merge and apply what holders decide; holders additionally mint
    # into it and serve it. Load re-verifies against the CURRENT trusted set.
    from ..statements import StatementLog, statements_path
    stmt_log = StatementLog.load(statements_path(cfg.data_dir), get_ca_pubs())

    # Peers' endpoint testimony (see greasewood.attest). Loaded on every
    # role: nodes merge what holders serve (for watch's confirmed/mirage
    # display); holders additionally accept POST /attest and serve the log.
    from ..attest import AttestLog, AttestLoop, attest_path

    def _known_attester(hex_id: str) -> bool:
        rec = directory.get(hex_id)
        if rec is None:
            return False
        try:
            rec.cred.verify(get_ca_pubs(), allow_expired=True)
        except ValueError:
            return False
        return True

    att_log = AttestLog.load(attest_path(cfg.data_dir), _known_attester)

    if cli._holds_anchor(cfg):
        get_revoked, door_watcher = _start_anchor_control_plane(
            cfg, keys, directory, get_ca_pubs, grant_policy, stmt_log, att_log)
    else:
        # Start from the cached copy (if any) and let the SyncLoop refresh it.
        get_revoked = lambda: _load_revoked(cfg)

    # Directory sync — pull from the configured seeds (the anchor). The renewal loop
    # is built below; the callback reads it lazily (the first pull is one interval
    # out), so acting on the anchor's fleet renew hint needs no reordering.
    sync = SyncLoop(
        directory,
        # The ANCHOR SET, refreshed per pull: configured seeds plus every
        # holder discovered in the directory. Plain nodes gain failover to
        # any live holder; holders pull from the OTHER holders (self
        # excluded), which is how statements/records converge between them.
        lambda: cli._anchor_urls(cfg, directory, own_addr=keys.addr,
                             get_ca_pubs=get_ca_pubs),
        cfg.dir_cache_path,
        on_renew_after=lambda ts: (
            renewal.maybe_renew_after(ts) if renewal else None,
            cli._adopt_renew_after(cfg, ts) if cli._holds_anchor(cfg) else None,
        ),
        expected_domain=cfg.mesh_domain,
        on_policy=grant_policy.offer,
        statements=stmt_log,
        get_ca_pubs=get_ca_pubs,
        own_id_hex=keys.id_pub_hex,
        attestations=att_log,
    )
    sync.start()

    # Testify about the endpoints this node's live tunnels actually ride —
    # ground truth for the fleet's confirmed/mirage display. A holder hands
    # its own testimony to itself first (loopback); everyone else, to the
    # first live holder. Diagnostic layer: failures are debug-quiet.
    AttestLoop(keys, directory, cfg.wg_interface,
               lambda: (([f"http://[::1]:{cli._control_port(cfg)}"]
                         if cli._holds_anchor(cfg) else [])
                        + cli._anchor_urls(cfg, directory, own_addr=keys.addr,
                                       get_ca_pubs=get_ca_pubs))).start()

    # Name resolution via a managed /etc/hosts block (opt-in). When off, remove
    # any block we left behind before (clean opt-out).
    from .. import hosts as _hosts
    if cfg.hosts_sync:
        log.info("hosts: maintaining /etc/hosts mesh block under .%s", cfg.mesh_domain)
    else:
        try:
            if _hosts.remove_block(cfg.mesh_domain):
                log.info("hosts: removed managed /etc/hosts block (sync disabled)")
        except Exception as e:
            log.warning("hosts: could not clean /etc/hosts: %s", e)

    def _ensure_mesh_iface():
        # Self-heal hook: recreate the mesh interface if it vanishes under a
        # running daemon (purge/re-create on this host, manual ip link del).
        with audit.context(f"heal: recreate missing interface {cfg.wg_interface}"):
            wgmod.ensure_interface(
                cfg.wg_interface, keys.addr, cfg.listen_port, cfg.wg_key_path
            )

    def _publish_reachable(reachable: list) -> None:
        # Re-sign our record with the new live-link set and push it, so the
        # fleet sees the edge change. quiet_push: the anchor being down already
        # warns via the sync loop; a 30s-cadence publish shouldn't pile on.
        if cli._republish_own_record(cfg, keys, directory, reachable=reachable,
                                 push_to=cfg.seeds, quiet_push=True):
            log.debug("published reachable set (%d live links)", len(reachable))

    _cleanup_legacy_port_table(cfg)

    recon = ReconcileLoop(
        iface=cfg.wg_interface,
        directory=directory,
        local_id_pub=keys.id_pub_bytes,
        local_caps=cfg.caps,
        get_ca_pubs=get_ca_pubs,
        get_revoked=get_revoked,
        policy=grant_policy,
        hosts_domain=cfg.mesh_domain if cfg.hosts_sync else None,
        get_local_families=cli._local_families,   # re-detected each cycle (v6→v4 mid-run)
        ensure_iface=_ensure_mesh_iface,
        data_dir=cfg.data_dir,
        on_reachable=_publish_reachable,
        policy_refresh=grant_policy.refresh_from_cache,
        local_hostname=cfg.hostname,
        # Self-reported running version for `gw watch`. Not signed (omitted from
        # _body_dict) so older peers that don't parse it still verify.
        republish_version=lambda ver: cli._republish_own_record(
            cfg, keys, directory, version=ver, push_to=cfg.seeds, quiet_push=True),
    )
    recon.start()

    # Roles live in the CA-signed credential, not the config file. The loops were
    # built with cfg.caps, but the credential is authoritative — so adopt its
    # roles now (in case the anchor changed them while we were down) and on every
    # renewal, feeding the reconcile loop live. That's what makes
    # `gw set-roles` + `gw renew-all` take full effect with no restart. A routine
    # renewal (roles unchanged) is a no-op, so this is quiet in steady state.
    _applied_caps = [sorted(cfg.caps)]

    def _adopt_caps(cred):
        caps = list(cred.caps)
        if sorted(caps) == _applied_caps[0]:
            return
        _applied_caps[0] = sorted(caps)
        recon.set_local_caps(caps)
        roles = [c[len("role:"):] for c in caps if c.startswith("role:")]
        log.info("roles changed by the anchor — adopted live from the credential: "
                 "%s (no restart needed)", roles or "(none)")

    # We advertise whatever endpoint config gives us (empty = naturally
    # outbound-only; peers back off a dead one).
    eff_endpoints = list(cfg.endpoints)

    # Honor config changes on (re)start: if our record's endpoints/aliases no
    # longer match config (e.g. a `gw cert-request` that added a service name),
    # re-sign it so what we advertise is current — the daemon reads config only
    # at startup.
    want_aliases = cli._config_aliases(cfg)
    own_record = directory.get(keys.id_pub_hex)
    if own_record and (list(own_record.endpoints) != list(eff_endpoints)
                       or sorted(own_record.aliases) != sorted(want_aliases)):
        own_record = cli._republish_own_record(cfg, keys, directory,
                                           endpoints=eff_endpoints,
                                           aliases=want_aliases)
        log.info("updated own record (endpoints=%s, aliases=%s)",
                 eff_endpoints, want_aliases)

    if own_record:
        _adopt_caps(own_record.cred)      # honor a role change made while we were down

    # Push our own record so the rest of the mesh knows about us. This gets a
    # newly enrolled node into the anchor's directory; it is also how endpoint
    # changes propagate without waiting for the next renewal cycle.
    if own_record:
        for seed in cfg.seeds:
            try:
                push_record(seed, own_record)
                log.info("pushed own record to %s", seed)
            except Exception as e:
                log.warning("push to %s failed (will retry on next sync): %s", seed, e)

    # Renewal loop — targets the configured anchor.
    if own_record:
        renewal = RenewalLoop(
            node_keys=keys,
            directory=directory,
            # Any holder can serve the renewal — try the whole anchor set.
            # A holder serves ITSELF first (loopback): always up, and a sole
            # holder must not depend on a stale root_url pointing elsewhere.
            get_anchor_url=lambda: (
                ([f"http://[::1]:{cli._control_port(cfg)}"]
                 if cli._holds_anchor(cfg) else [])
                + cli._anchor_urls(cfg, directory, own_addr=keys.addr,
                               get_ca_pubs=get_ca_pubs)),
            get_ca_pubs=get_ca_pubs,
            current_cred=own_record.cred,
            hostname=cfg.hostname,
            endpoints=eff_endpoints,
            cache_path=cfg.dir_cache_path,
            aliases=want_aliases,
            on_renew=_adopt_caps,         # adopt anchor-side role changes live
        )
        renewal.start()
    else:
        log.warning("no credential in directory — run 'gw join <token>' first")

    # TLS service-cert auto-renewal: renew each cert recorded by `gw cert-request`
    # at ~half its lifetime and run its reload_cmd. No-op if none are managed.
    from ..certs import CertRenewalLoop, load_manifest as _load_cert_manifest
    cert_renewal = None
    _managed = _load_cert_manifest(cfg.data_dir)
    if _managed:
        cert_renewal = CertRenewalLoop(keys, lambda: cfg.root_url,
                                       cfg.data_dir, mesh_domain=cfg.mesh_domain)
        cert_renewal.start()
        log.info("TLS cert auto-renewal started (%d managed cert(s))", len(_managed))

    # Advertised-endpoint auto-refresh: re-detect our public endpoint(s) and
    # re-advertise on a REAL change (an IPv6 prefix renumbering swaps the stable
    # GUA; a v6→v4 move). Detection prefers the stable address, so privacy-
    # extension rotation never trips it and steady state is a no-op. Opt-out with
    # [node] endpoint_auto=false — set when the operator pinned an --endpoint.
    endpoint_loop = None
    if cfg.endpoint_auto:
        from ..endpoints import EndpointLoop
        def _current_endpoints():
            own = directory.get(keys.id_pub_hex)
            return list(own.endpoints) if own else list(eff_endpoints)
        endpoint_loop = EndpointLoop(
            detect=lambda: cli._advertised_endpoints(None, cfg.listen_port),
            current=_current_endpoints,
            republish=lambda eps: cli._republish_own_record(
                cfg, keys, directory, endpoints=eps, push_to=cfg.seeds),
        )
        endpoint_loop.start()
        log.info("endpoint auto-refresh on (re-advertise on address change)")

    # Liveness watchdog. Under systemd, sd_notify + WatchdogSec owns wedge
    # detection (a NOTIFY_SOCKET is present), so we stay out of its way. Off
    # systemd there's no notify socket — arm the portable self-exit watchdog so
    # a death-restart supervisor (OpenRC's supervise-daemon, runit, a bare
    # respawn) can recover a wedged daemon the same way systemd would.
    #
    # The health age is composite: stale reconcile, stale sync (non-anchors),
    # or a credential that is about to expire without having been recently
    # renewed. The latter catches a dead/silent RenewalLoop before the whole
    # mesh tears down.
    watchdog = None
    if not os.environ.get("NOTIFY_SOCKET"):
        from ..loop import WedgeWatchdog
        from ..reconcile import seconds_since_reconcile
        from ..sync import seconds_since_sync

        def _health_age():
            now = dt.datetime.now(_UTC)
            ages = []

            r_age = seconds_since_reconcile(cfg.data_dir)
            if r_age is not None:
                ages.append((r_age, "reconcile"))

            if cfg.role != "anchor":
                s_age = seconds_since_sync(cfg.data_dir)
                if s_age is not None:
                    ages.append((s_age, "sync"))

            own = directory.get(keys.id_pub_hex)
            if own is not None:
                since_iat = (now - own.cred.iat).total_seconds()
                lifetime = (own.cred.exp - own.cred.iat).total_seconds()
                # The RenewalLoop renews at half the credential's lifetime
                # ±10% jitter (see renewal._next_delay), so "not keeping up"
                # starts BEYOND half + a margin that must exceed the jitter —
                # 15% of lifetime, floored at 10 minutes for tiny TTLs. The
                # old margin was a flat 600s: smaller than the jitter itself,
                # so a healthy node whose draw came out late got killed at
                # half-life + 10min on every non-systemd host (systemd nodes
                # never arm this watchdog, which is why the fleet never saw
                # it — the first launchd node did, within minutes).
                if since_iat > lifetime / 2 + max(600.0, lifetime * 0.15):
                    ages.append((since_iat, "credential renewal"))

            if not ages:
                return None
            return max(ages, key=lambda x: x[0])

        watchdog = WedgeWatchdog(age_fn=_health_age)
        watchdog.start()
        log.info("liveness watchdog on (self-exit if reconcile/sync/renewal "
                 "wedges; no systemd notify socket)")

    # Startup fully succeeded (interface up, control plane up, loops running) —
    # forget any death breadcrumb from a prior failed boot so `gw watch` stops
    # reporting a stale fatal reason.
    from .. import reconcile as _rmod
    _rmod.clear_daemon_fatal(cfg.data_dir)

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
    if cert_renewal:
        cert_renewal.stop()
    if endpoint_loop:
        endpoint_loop.stop()
    if watchdog:
        watchdog.stop()
    if door_watcher:
        door_watcher.stop()
    log.info("shutdown complete")
    return 0
