# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **`gw upgrade`** — upgrade a node in place, from PyPI (`--from pypi`, the default) or straight from the git repo (`--from github [--ref <branch|tag|commit>]`, for running a fix that isn't released yet). It does a clean `pipx uninstall` + `pipx install` rather than `pipx upgrade`, which has left the previous version's `__pycache__` behind in the venv, and it targets the `PIPX_HOME`/`PIPX_BIN_DIR` this install actually came from (fleet nodes use `/opt/pipx`, not pipx's default) instead of guessing. The exact commands are printed and confirmed before anything runs — the uninstall step briefly removes `gw` from a machine you may be connected through — and a failed install names the recovery command. It also prunes app symlinks pipx leaves behind in `PIPX_BIN_DIR` when a package drops an entry point (`gw-admin-upgrade`, removed in 0.3.0, was still sitting there dangling and being announced as "globally available" on every install). Finishes by restarting the mesh's daemon. `--yes` skips the prompt.

### Added

- Node records publish `families` — the underlay address families that node can originate on (`[4]`, `[6]`, `[4, 6]`), re-detected and republished when it changes. It answers a question endpoints cannot: a node behind NAT advertises no endpoint whether it's on the same LAN or on IPv4-only cafe wifi, so peers had no way to tell "it will dial me in a second" from "it genuinely cannot reach me". Unsigned and optional (like `version`), so mixed-version fleets interoperate.
- `gw watch` gains a `via` column: the underlay address family in use for each live direct tunnel (`ip6`/`ip4`), observed from live WireGuard state without reading `wg show`.
- `gw diagnose` gains a `can dial out` row: the underlay families each node can originate on. It answers what `reachable` cannot — an outbound-only node can't be dialled, but that says nothing about whether it can dial you.
- `gw bootstrap <underlay-url>` — recover a node whose local directory cache has lost the anchor record. The anchor can optionally expose a read-only bootstrap port on the underlay (`bootstrap_listen` in `[anchor]`); a stuck node fetches the signed directory/revoked/policy snapshot over the underlay, installs the anchor peer, and restarts. This breaks the overlay catch-22 that previously required `scp`-ing a fresh `directory.json`.

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
