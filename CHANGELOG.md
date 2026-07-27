# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **`gw upgrade`** — upgrade a node in place, from PyPI (`--from pypi`, the default) or straight from the git repo (`--from github [--ref <branch|tag|commit>]`, for running a fix that isn't released yet). It does a clean `pipx uninstall` + `pipx install` rather than `pipx upgrade`, which has left the previous version's `__pycache__` behind in the venv, and it targets the `PIPX_HOME`/`PIPX_BIN_DIR` this install actually came from (fleet nodes use `/opt/pipx`, not pipx's default) instead of guessing. The exact commands are printed and confirmed before anything runs — the uninstall step briefly removes `gw` from a machine you may be connected through — and a failed install names the recovery command. Finishes by restarting the mesh's daemon. `--yes` skips the prompt.

### Fixed

- **An anchor that is also a router no longer loses IPv6 forwarding.** The relay reconcile forced the machine-wide `net.ipv6.conf.all.forwarding` sysctl to match the relay marker every cycle, so with relay off (the default) it set it to `0` — black-holing IPv6 for every LAN client behind an anchor that was also the site router, and re-doing it within a cycle of any manual fix. greasewood now only ever turns forwarding **on**, and turns it off only if it was the one that enabled it (tracked by a `relay-forwarding-owned` marker in the data dir). Forwarding that predates greasewood is left exactly as found.
- **Turning relay on no longer severs working direct tunnels.** A peer was classified "unreachable" — and so routed through the anchor — purely from the endpoints its record advertised. An outbound-only peer (behind NAT/CGNAT, or a laptop) advertises none, but dials out and roams, so its tunnel is up and direct; relaying it removed the direct peer and tore that tunnel down. Reachability now consults the live session first: a peer with a recent handshake stays direct, and only a session dead longer than the live-link window folds into the relay.

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
