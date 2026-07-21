# Greasewood

[![PyPI](https://img.shields.io/pypi/v/greasewood)](https://pypi.org/project/greasewood/)
[![Python versions](https://img.shields.io/pypi/pyversions/greasewood)](https://pypi.org/project/greasewood/)
[![License: MIT](https://img.shields.io/pypi/l/greasewood)](https://github.com/cschlick/greasewood/blob/main/LICENSE)

A minimal, self-hosted, greasy WireGuard mesh network.

Its one priority is being **easy to reason about**. It was built by someone who
lovingly maintained a fleet of hand-written WireGuard/networkd text files far
past the point of practicality, and wanted the simplest possible upgrade.

- **[Private.](concepts.md#membership)** Membership is gated by a certificate
  authority; revoke a node by not renewing it.
- **[Direct-or-fail.](concepts.md#direct-or-fail)** No routing, no relays. A
  link comes up directly or it honestly fails.
- **[IPv6 only overlay.](concepts.md#ipv6-overlay)** The overlay is IPv6-only;
  the underlay may be IPv4 or IPv6.
- **[Linux-only.](concepts.md#linux-only)** Leans heavily on systemd, nftables.
- **[Greasy.](concepts.md#greasy)** Uses the stock `wg`/`ip` tools over
  subprocess.
- **[Named.](networking.md#names)** Every node gets a `<host>.<mesh>.internal`
  name and matching TLS certs from the same CA.
- **[Policy-derived topology.](access-control.md)** Roles + an allow-only grant
  table control who talks to whom.
- **[Self-certifying addresses.](concepts.md#self-certifying-addresses)** A
  node's IPv6 address is a hash of its identity key.
- **[Service TLS.](tls.md)** The same CA issues auto-renewing x509 certs for
  your services (Postgres, nginx, …).
- **[Offline-tolerant.](concepts.md#offline-tolerance)** The anchor can be down
  for a credential lifetime, nodes run from cache.
- **[Hands-off.](networking.md#firewall)** Never automatically configures your
  main firewall. Port access control lives on a dedicated table.
- **[Auditable.](concepts.md#auditable)** Pure Python, one dependency. Fanatical
  logging.
- **[Self-contained.](concepts.md#the-anchor)** The coordination anchor is just
  a normal node. Any node can become the anchor.

## Start here

<div class="grid cards" markdown>

- :material-download: **[Install](install.md)** — pipx, distro packages, or the
  bundled installer.
- :material-rocket-launch: **[Quickstart](quickstart.md)** — bootstrap an
  anchor, enroll a node, watch it link.
- :material-monitor-dashboard: **[Live dashboard](watch.md)** — `gw watch`, the
  colored mesh view.
- :material-shield-key: **[Access control](access-control.md)** — roles, grants,
  host grants, declarative assignments.

</div>

## Prior art

The nearest full-featured projects are **Tailscale**, **Nebula**, and
**innernet**. Next to greasewood they're all bigger systems that do more:
routing, NAT traversal, multi-platform, etc. Greasewood aims to be a minimal
alternative.
