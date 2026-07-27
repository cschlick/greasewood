# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
