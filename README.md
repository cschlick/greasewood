# Greasewood

[![PyPI](https://img.shields.io/pypi/v/greasewood)](https://pypi.org/project/greasewood/)
[![Python versions](https://img.shields.io/pypi/pyversions/greasewood)](https://pypi.org/project/greasewood/)
[![License: MIT](https://img.shields.io/pypi/l/greasewood)](LICENSE)

A minimal, self-hosted, greasy WireGuard mesh network.

Its one priority is being **easy to reason about**. It was built by someone who
lovingly maintained a fleet of hand-written WireGuard/networkd text files far
past the point of practicality, and wanted the simplest possible upgrade.

**📖 Full documentation: [cschlick.github.io/greasewood](https://cschlick.github.io/greasewood/)** — quickstart, concepts, access control, TLS, operations, and the CLI/config reference. The [`docs/`](docs/) pages are also browsable here in the repo.

- **[Private.](docs/concepts.md#membership)** Membership is gated by a
  certificate authority; revoke a node by not renewing it.
- **[Direct-or-fail.](docs/concepts.md#direct-or-fail)** No routing, no relays.
  A link comes up directly or it honestly fails.
- **[IPv6 only overlay.](docs/concepts.md#ipv6-overlay)** The overlay is
  IPv6-only; the underlay may be IPv4 or IPv6.
- **[Linux-only.](docs/concepts.md#linux-only)** Leans heavily on systemd,
  nftables.
- **[Greasy.](docs/concepts.md#greasy)** Uses the stock `wg`/`ip` tools over
  subprocess.
- **[Named.](docs/networking.md#names)** Every node gets a
  `<host>.<mesh>.internal` name and matching TLS certs from the same CA.
- **[Policy-derived topology.](docs/access-control.md)** Roles + an allow-only
  grant table control who talks to whom.
- **[Self-certifying addresses.](docs/concepts.md#self-certifying-addresses)** A
  node's IPv6 address is a hash of its identity key.
- **[Service TLS.](docs/tls.md)** The same CA issues auto-renewing x509 certs
  for your services (Postgres, nginx, …).
- **[Offline-tolerant.](docs/concepts.md#offline-tolerance)** The anchor can be
  down for a credential lifetime, nodes run from cache.
- **[Hands-off.](docs/networking.md#firewall)** Never automatically configures
  your main firewall. Port access control lives on a dedicated table.
- **[Auditable.](docs/concepts.md#auditable)** Pure Python, one dependency.
  Fanatical logging.
- **[Self-contained.](docs/concepts.md#the-anchor)** The coordination anchor is
  just a normal node. Any node can become the anchor.

## Install

Requires Python 3.11+, the WireGuard tools (`wg`), and `iproute2` (`ip`).

```bash
sudo apt install pipx wireguard-tools     # Debian/Ubuntu; use your distro's pkg mgr
sudo pipx install --global greasewood
```

`--global` puts `gw` on root's `PATH` so `sudo gw …` resolves. Distro `.deb`/
`.rpm` packages and the bundled installer are also available — see the
**[install guide](docs/install.md)** (and its first-run pitfalls, straight from
real fleets coming up).

## Quickstart

```bash
# 1. On the anchor — holds the CA, serves enrollment:
sudo gw create mymesh                 # names live under *.mymesh.internal

# 2. Mint a join token (anchor), redeem it on the new machine:
sudo gw invite                        # prints a token
sudo gw join <token>                  # on the new node

# 3. Watch it link — the live, colored mesh dashboard:
sudo gw watch
```

`create` and `join` set up a managed systemd service, so the daemon stays up
across reboots. That's the whole loop. The **[quickstart](docs/quickstart.md)**
walks through what each step does (the CA, the enrollment "door", the reconcile
loop), and the **[live dashboard](docs/watch.md)** page shows `gw watch` in
action.

## Prior art

The nearest full-featured projects are **Tailscale**, **Nebula**, and
**innernet**. Next to greasewood they're all bigger systems that do more:
routing, NAT traversal, multi-platform, etc. Greasewood aims to be a minimal
alternative — the [non-goals](docs/concepts.md) aren't missing, they're the
point.

## Testing & contributing

Unit tests run in ~30s with no privileges:

```bash
pip install -e '.[test]' && python -m pytest
```

The Podman-based integration/stress/chaos suites and the nightly Hypothesis
tier are documented in **[docs/testing.md](docs/testing.md)**.

## Security & operations

- **[Security](docs/security.md)** — trust boundaries, what the 7-step check
  enforces, accepted risks, and the security-review results.
- **[Operations](docs/operations.md)** — moving the anchor, plus disaster SOPs:
  compromised node, lost/leaked CA key, destroyed anchor, fleet-wide teardown,
  and reading `gw diagnose`.

## License

MIT — see [LICENSE](LICENSE).

## AI Disclaimer

Greasewood is a greasy project, and was built with the assistance of SWE LLM agents.
