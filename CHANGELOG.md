# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.5.0] - 2026-08-25

### Changed

- **macOS is a native platform again; the Lima-VM appliance is gone.** The macOS port (originally built and archived at tag `macos-port-archive`, then replaced by the Lima appliance) is revived and rebuilt against the seams that postdate it: `greasewood.platform` answers "which OS", `wg.py` grows a Darwin backend (wireguard-go on a `utun`, resolved from logical names via the wg-quick name-file convention; `ifconfig`/`route` primitives; socket-removal teardown; blip-free logical rename; forwarding-off door isolation; an explicit lo0 self-route), and launchd joins systemd/OpenRC as a third `ServiceManager` backend (per-mesh plists derived from the key like systemd's `%i`, RunAtLoad + KeepAlive, the async-bootout bootstrap retry). CLI detection, guards, firewall help, and status probes all go per-OS. Port enforcement is not available on macOS yet (pf backend planned) — port scopes run advisory there; tunnel existence stays fully policy-enforced. The whole Lima line — `gw-mac`, the priv helper, gateway/seal rulesets, transfer net, VM recipes, the shim formula — is deleted (preserved at tag `lima-era-archive` with the full abandonment rationale: every layer of it existed to compensate for the VM boundary, and each of vmnet's failures — dropped IPv6 fragments, dying NAT66, host-blind bridging, unsegmentable TSO delivery — was discovered empirically against a closed, undocumented layer). The brew formula now installs the real `gw` (own-venv Python, wireguard-go + wireguard-tools deps, cryptography as a wheel — still no CLT). `docs/macos.md` is rewritten around the native node and carries the VM→native migration (identity moves intact; the fleet never notices).

### Fixed

- **Two latent bugs that put any non-systemd node into a permanent 2-minute crash loop after downtime across its credential's half-life** — found live, minutes into the first launchd node's life (systemd nodes never arm the self-exit watchdog, so the fleet had never executed this code path). First: `RenewalLoop` scheduled the next renewal at half the *remaining* TTL from now — so a daemon restarting past the halfway point pushed renewal hours out on every restart, while the watchdog's renewal heuristic declared it wedged 120 seconds later and killed it, forever (the credential would simply have expired). Renewal now schedules from the credential's own timeline — halfway through its iat→exp lifetime, ±10% jitter — and a daemon already past that point renews within seconds (1–30s herd jitter); an expired-but-not-revoked credential recovers the same way. Second: the watchdog's "renewal not keeping up" margin was a flat 10 minutes, *smaller than the renewal jitter itself* (±10% of half-life = ±72 minutes at a 24h TTL), so even a healthy node whose jitter drew late would have been killed at half-life+10min roughly every other cycle. The margin is now 15% of the credential lifetime, floored at 10 minutes.

### Added

- `gw service enable|disable` — enable or disable this config's daemon service through the ServiceManager seam: the adoption path for a membership whose service was never installed on this host (a migrated config, a `--no-service` join revisited). On launchd this is the only way — there is no shared template to enable by hand.

- **macOS: the node VM's non-mesh interfaces are sealed by default.** `gw-mac` installs a small default-closed nftables ruleset (`gw-mac-lan.nft`, plus a systemd unit and an OpenRC script) into every VM it creates, and retro-fits it to an existing VM on the next `gw-mac` run. Under `vzNAT` the VM is unreachable and its listeners — sshd, mDNS, LLMNR — are closed by construction rather than by a rule; the moment the VM is given a real NIC so it can be dialled inbound, that stops being true, and greasewood's own table deliberately governs only the mesh interfaces. The seal closes everything that isn't loopback or `gw-*`, then reopens exactly what a node needs: established flows, ICMP (IPv6 does not work without it), DHCP, inbound WireGuard on the node's configured port, and Lima's host→guest ssh scoped to the RFC1918 ranges Lima's own NATs use. It seals by exclusion rather than by interface name, so which of `lima0`/`lima1` is the bridged one doesn't matter and a NIC added later is closed the day it appears. The final `drop` is counted, so `nft list table inet gwlan` answers "is the seal eating this?" without guessing.
- **macOS: a documented path to making a Mac node dialable.** `docs/macos.md` gains [Make the node dialable (bridged)](docs/macos.md) — field-tested `socket_vmnet` setup, why bridging beats pinning an endpoint by hand (only a node that can see its own address can follow a rotating residential prefix), and an honest warning that bridging over Wi-Fi puts a second MAC behind one 802.11 association and some APs drop it. Adding the NIC alongside `vzNAT` rather than replacing it makes a failed attempt a one-line revert.

### Fixed

- **Mac→mesh uploads were ~230× slower than the path allows; fixed by disabling TSO on the Mac.** With TCP segmentation offload on (the macOS default), the Mac hands multi-segment TCP trains to the vmnet virtio NIC, and Virtualization.framework delivers them into the guest as over-MTU frames without usable GSO metadata (`rx-gro-hw` is a fixed feature) — so the VM's forward path can only drop each one and emit an ICMPv6 Packet-Too-Big. Measured on a live mesh: 118 PTB drops in 4 seconds, cwnd pinned at 2 segments, 1.26 Mbit/s on a path that does 300 both as raw underlay and in the download direction (downloads never traverse Mac TSO — the asymmetry was the diagnostic tell). `gw-mac up` now asserts `net.inet.tcp.tso=0` via a new scoped priv-helper op, re-asserting after reboots; TSO's CPU saving only matters at multi-gigabit rates on real NICs. After the fix: Mac→mesh 300 Mbit/s, zero PTBs, matching the VM's own tunnel throughput.
- **`gw upgrade --from github` can no longer strand a node when the network fails mid-upgrade.** The uninstall→install sequence had the full network clone inside the window: a GitHub outage after the uninstall left greasewood removed, `gw` gone, and the daemon alive only on the deleted venv's inodes — one restart from taking the node off the mesh (exactly this happened in the field: a 133s connect timeout mid-clone; the printed recovery command was the only thread back). The repo is now cloned to local disk *before* anything is uninstalled — a fetch failure aborts with the node untouched and says so ("Nothing was changed") — and the install runs from the local clone, so only dependency wheels (usually cached) remain inside the window. If the install itself still fails, the recovery command now names the on-disk clone rather than a spec that needs the network again.
- The macOS VM recipes (Debian and Alpine) now provision `git`, so `gw upgrade --from github` — the documented way to run an unreleased fix — works in the appliance VM instead of dying with "installing from the repo needs git". Existing VMs: install it once (`sudo apt install git` / `sudo apk add git` inside the VM).
- `gw diagnose`'s link-viability verdict now respects address families. It declared a direction dialable whenever the target advertised any endpoint — so a v4-only node facing a v6-only endpoint was told "dial <v6-addr>" and then, on silence, "⚠ it isn't answering — check its host firewall", sending the operator to debug the wrong machine when the block was the dialer's own connectivity (found live: a node whose vmnet NAT66 died fell back to v4-only and diagnose blamed the healthy peer's firewall). Dialability is now the intersection of the target's endpoint families with the dialer's published `families`, matching what the reconcile loop actually does; an empty `families` (an old node that doesn't publish it) stays permissive — silence never asserts a mismatch. The mismatch case names both sides ("X advertises only ip6 endpoints and Y can only dial out on ip4"), and the isn't-answering hint fires only when the dial was actually possible.
- **The mac-gateway MSS clamp was actively causing ~10× TCP throughput loss from the Mac.** The clamp rule (`tcp flags syn tcp option maxseg size set rt mtu`) is unconditional, and on the peer's SYN-ACK being forwarded toward the Mac, `rt mtu` is the route MTU *to the Mac* (1500) — so it **raised** the peer's honest MSS (1360, sized to the tunnel) to 1440. The Mac then sent 1500-byte packets into the 1420 tunnel and every bulk Mac→peer transfer (rsync, iperf3) collapsed into PMTU-blackhole stalls: macOS's blackhole detection eventually forces the connection down to a 1280-byte path with retransmission timeouts throughout. Verified at the packet level (SYN-ACK on the Mac-facing interface carried mss 1440 before the fix, 1360 after). The rule is now scoped to `oifname "gw-*"` — clamp only SYNs entering the mesh, never rewrite advertisements leaving it. This matters doubly because Apple's vmnet silently drops IPv6 fragments between guest and host (measured: 100% loss both directions), so an overshooting packet has no fragmentation fallback; the same finding is now documented as a whole-Mac-routing caveat (large UDP/ICMPv6 mesh↔Mac cannot work). `gw-mac up` now also self-heals the gateway ruleset on existing VMs when the shipped copy differs (same philosophy as the daemon's service-template refresh), so deployed Macs pick the fix up on the next run.
- Whole-Mac overlay routing no longer depends on vmnet's NAT66 or on the VM's default route. It used to work by accident twice over: the mesh route's next hop was the `fd…` ULA vmnet's NAT66 put on `lima0` (adding a second Lima network — `lima: bridged`, to make the node dialable — rebuilds the shared bridge with v4 + link-local only, so that ULA never comes back and `gw-mac up` failed with "VM has no vzNAT IPv6 on lima0"), and the VM's replies to the Mac only found their way home because the default route pointed at vzNAT (a bridged VM's default route moves to the bridged link, which Apple's vmnet makes *host-blind* — no host↔guest traffic at all — so replies were silently dropped even once the route was fixed). `gw-mac` now gives both ends of the vzNAT link a fixed transfer address (`fd6d:6163::1/2`, applied idempotently by `gw-mac up` and at VM boot by the gateway unit): the route's next hop, and the source macOS picks for mesh-bound traffic (RFC 6724 prefers the on-interface, prefix-matching source over the `en0` GUA), which makes the reply path on-link over vzNAT by construction. The priv helper gains a `transfer-add` op, and its address validator now accepts an `%scope` suffix while still rejecting anything shell-active. Also fixed: `gw-mac`'s interactive-sudo fallback tested for a terminal on *stdin*, which the hosts-sync step pipes the hosts block into by design — so on a Mac without the autostart helper installed, every `gw-mac up` synced the route but silently refused to sync `/etc/hosts`. The check now uses stderr. `install-autostart`'s sudoers validation is now scoped to the file it installs (`visudo -c -f`) — the previous global `visudo -c` failed on unrelated `sudoers.d` files, e.g. Lima's, which is deliberately 0444 because `limactl` refuses a rule file it cannot read back.
- `gw watch`'s `reach` line read the *config* (`cfg.endpoints`) rather than the published record, so a node that gained an endpoint after joining — via `endpoint_auto`/`EndpointLoop`, which re-signs the record but never rewrites the TOML — reported "no endpoint (outbound-only)" forever while `gw diagnose` correctly reported it as dialable. It now reads the signed record, falling back to the config only before the first record exists.
- The per-interface `accept_ra=2` in `gw-mac-gateway.sysctl.conf` never took effect. `sysctl.d` is applied by `systemd-sysctl` at boot, before the interface has been renamed to `lima0`, so the write failed and was ignored (`Couldn't write '2' to 'net/ipv6/conf/lima0/accept_ra', ignoring: No such file or directory`). Its job — keeping the vzNAT link's RA-derived address and default route alive despite the gateway's `forwarding=1` — is now done where ordering is guaranteed: a systemd-networkd drop-in (`IPv6AcceptRA=yes`, which is what actually governs RA on networkd-managed images) installed beside whatever `.network` file networkd matched to the link, and in `gw-mac-gateway`'s `start()` on OpenRC, which runs after `need net`.

## [0.4.0] - 2026-08-01

### Added

- **`gw upgrade`** — upgrade a node in place, from PyPI (`--from pypi`, the default) or straight from the git repo (`--from github [--ref <branch|tag|commit>]`, for running a fix that isn't released yet). It does a clean `pipx uninstall` + `pipx install` rather than `pipx upgrade`, which has left the previous version's `__pycache__` behind in the venv, and it targets the `PIPX_HOME`/`PIPX_BIN_DIR` this install actually came from (fleet nodes use `/opt/pipx`, not pipx's default) instead of guessing. The exact commands are printed and confirmed before anything runs — the uninstall step briefly removes `gw` from a machine you may be connected through — and a failed install names the recovery command. It also prunes app symlinks pipx leaves behind in `PIPX_BIN_DIR` when a package drops an entry point (`gw-admin-upgrade`, removed in 0.3.0, was still sitting there dangling and being announced as "globally available" on every install). Finishes by restarting the mesh's daemon. `--yes` skips the prompt.

### Added

- Node records publish `families` — the underlay address families that node can originate on (`[4]`, `[6]`, `[4, 6]`), re-detected and republished when it changes. It answers a question endpoints cannot: a node behind NAT advertises no endpoint whether it's on the same LAN or on IPv4-only cafe wifi, so peers had no way to tell "it will dial me in a second" from "it genuinely cannot reach me". Unsigned and optional (like `version`), so mixed-version fleets interoperate.
- `gw watch` gains a `via` column: the underlay address family in use for each live direct tunnel (`ip6`/`ip4`), observed from live WireGuard state without reading `wg show`.
- `gw diagnose` gains a `can dial out` row: the underlay families each node can originate on. It answers what `reachable` cannot — an outbound-only node can't be dialled, but that says nothing about whether it can dial you.

### Fixed

- `reconcile` no longer drops `persistent-keepalive` to 0 when the `EndpointTracker` thinks a peer's endpoint is dead **if this node advertises no underlay endpoints of its own**. An outbound-only peer (typical laptop behind NAT) cannot be called back, so stopping keepalives after a sleep or network change meant the tunnel never recovered on its own.
- `reconcile` now keeps a post-sleep/roaming "wake window" keyed to the last anchor (or any peer, on the anchor) handshake. If the witness has not handshaked recently, the `EndpointTracker` ignores backoff so every peer gets `keepalive=25` for a settle period; once the witness recovers, the window extends further so the rest of the fleet has time to re-establish before normal backoff can resume.
- `gw-mac` and `gw-mac-priv` no longer use `python3` on the Mac side. On a fresh macOS install the system `python3` is a stub that prompts for Xcode command-line tools, so `gw-mac up` and the `/etc/hosts` sync could fail headlessly. They now use `awk` for the prefix and hosts-block rewrite.

### Known issues

- `tests/test_server.py::TestControlServerConcurrency::test_bounded_pool_sheds_load_at_capacity` is flaky on macOS: it expects a clean EOF when the anchor drops an over-capacity control-plane connection, but the OS sometimes returns `ConnectionResetError` instead. The load-shedding behavior itself is correct (the log shows `dropping a connection from ::1`). This is a test-level tolerance issue, not a product bug, and is deferred.

### Removed

- **Anchor relay has been removed.** The mesh returns to strict direct-or-fail: if two nodes cannot form a direct WireGuard tunnel, the link fails rather than being routed through the anchor. The `gw relay` command, the per-pair `relay = true` grant key, and the anchor's IPv6 forwarding/relay marker management are gone. Old signed `NodeRecord` and `GrantTable` files with `relay` fields still verify — `relay` is now a no-op legacy field — but new records and grants never set it.

## [0.3.0] - 2026-07-26

### Added

- `gw watch` now shows a `ver` column with each node's self-reported running greasewood version, so you can see at a glance which peers still need to be upgraded. The version is an unsigned display field on the directory record, so older nodes that don't parse it still verify the self-signature.

### Removed

- `gw-admin-upgrade` and the bundled `admin-upgrade.sh` script. Fleet-wide SSH upgrades were too fragile across heterogeneous `pipx`/`ssh`/`sudo` setups; the version column in `gw watch` now shows the operator what to update by hand.

## [0.2.2] - 2026-07-26

### Added

- `gw-admin-upgrade --from-mesh --user <user>`: build the SSH host list directly from the local `gw watch --json` snapshot, so fleet upgrades no longer require a manual `jq` pipeline and a host file.

## [0.2.1] - 2026-07-26

### Added

- **Relay/anchor routing**: `gw relay on` on the anchor enables forwarding for peers that cannot reach each other directly (e.g. one is IPv4-only and the other is IPv6-only). The anchor advertises a relay flag; nodes automatically route unreachable granted peers through the anchor. Direct tunnels remain preferred and are re-established as soon as they become possible. Includes `gw relay off` and `gw relay status`.

## [0.2.0] - 2026-07-26

### Added

- **Anchor failover (standby unlock)**: `gw anchor-activate` on a standby node decrypts an escrowed CA blob, rebuilds the `nodes/` registry from the directory cache, and rewrites the node as the new anchor.
- `gw anchor-standby` to re-enroll an existing live node as a failover standby.
- `failover` capability granted at `gw invite --caps failover`; enrolled nodes receive an encrypted `failover_anchor.gwbk` containing the CA key.
- Podman integration tests covering failover setup, activation, and re-invite flows.
- `gw` shim on macOS now names the node after the Mac hostname, matching Linux behavior.
- Managed-daemon auto-restart: `gw` now restarts systemd/OpenRC directly after `renew`, `rename-node`, `anchor-activate`, `anchor-promote`, `cert-request` (when SAN aliases are published), and `invite --force` CA re-key, falling back to the previous hints only when no service manager is present.
- `gw-admin-upgrade`: explicit, interactive, fault-tolerant SSH-based upgrade tool for rolling out package updates across mesh peers one host at a time. Installed as a console script and packaged so `pipx` users can run it directly (dry-run, per-host confirm, customizable command, never auto-updates silently).

### Changed

- `gw invite` packs and hands off an encrypted failover blob when the `failover` capability is present.
- `gw join` writes a `failover_anchor.gwbk` on nodes that are granted the `failover` cap.
- Alpine install recipe updated to 256 MiB RAM + an in-guest swapfile, reflecting field-tested numbers.
- Homebrew formula pinned to the v0.1.4 tarball SHA256.
- Documentation: Activity Monitor's VM number is explained as footprint, not occupancy.

### Fixed

- `DoorWatcher` now rebinds the `EnrollServer` when `door_window.json` is superseded by a new `gw invite`, so `gw watch` reports the correct door type (e.g. `OPEN (standing)`) and the retrievable token instead of continuing to show the previous single-use window.
