# greasewood

A minimal, self-hosted WireGuard mesh overlay. Nodes form a full mesh of
direct WireGuard tunnels, authorized by a single certificate authority. There
is nothing in the data path but WireGuard itself.

- **IPv6-only.** Every node gets a stable overlay address under
  `fd8d:e5c1:db1a:7::/64`, derived from its own identity key — no allocator.
- **Direct-or-fail.** No routing, no multi-hop, no relays, no NAT traversal. A
  link either comes up directly or it honestly fails.
- **CA-gated.** Membership is a CA-signed credential with an expiry.
  "Revoking" a node means not renewing it; it falls out of the mesh fleet-wide
  when its last credential expires. No CRL.
- **Nothing central in the data path.** The hub serves enrollment and the
  directory, but every node caches the directory locally and keeps its tunnels
  running even if the hub is offline for up to one credential lifetime.
- **Small.** Pure Python (3.11+), one dependency (`cryptography`), one binary
  (`gw`). WireGuard is driven through the standard `wg` / `ip` tools.

> Status: early. The core — enrollment, directory, reconcile loop, door-based
> join — works end to end (see Testing). Renewal, CA migration, and a TLS
> service-cert layer are partially built or planned.

## How it works

**Two keys per node.** Identity and transport are deliberately split:

- `id_priv` / `id_pub` (Ed25519) — durable identity. It derives the node's
  overlay address and authorizes credential renewal. Used rarely; guard it
  hard (a leak is catastrophic).
- `wg_priv` / `wg_pub` (X25519) — the hot WireGuard tunnel key. It lives
  unattended on disk so the node survives reboots, and it's self-limiting: a
  leak expires with the credential.

**Two signed objects.**

- **Credential** — signed by the CA. Binds `id_pub`, `wg_pub`, overlay address,
  capabilities, and an expiry. Slow-moving (default 24 h TTL).
- **NodeRecord** — signed by the node's own `id_priv`. Carries the credential
  plus mutable facts (endpoints, hostname, a sequence number). Fast-moving;
  this is what gets published and gossiped through the directory.

**Self-certifying addresses.** A node's overlay address is
`prefix : truncate64(blake2s(id_pub))`. Any peer recomputes it from `id_pub`
and rejects a record whose claimed address doesn't match — so addresses can't
be spoofed and need no central allocator.

**The reconcile loop** is the only thing that touches the data plane. Every few
seconds each node walks the directory and, per peer, runs seven checks — verify
the CA signature, check expiry, verify the record's self-signature, verify the
address derives from `id_pub`, check the revoke list, check the authorization
policy (`mesh` ↔ `mesh` by default) — then installs or removes that WireGuard
peer with `wg set`. Membership changes, revocations, and key rotations all
reduce to "add or remove a peer," computed locally with no coordinator.

**The control plane** is a small HTTP service the hub runs: `GET /directory`,
`POST /publish`, `POST /renew`, `GET /health`. Nodes poll `/directory`, merge by
highest sequence number, and persist a local cache.

## Install

Requires Linux with the WireGuard kernel module (built into 5.6+), the
`wireguard-tools` (`wg`) and `iproute2` (`ip`) packages, and Python 3.11+.

```bash
git clone https://gitlab.com/cschlick/greasewood.git
cd greasewood
pip install .
```

This installs the `gw` command. Most subcommands need root (they create
WireGuard interfaces and edit routing); `gw status` does not.

## Quickstart

### 1. Bootstrap the hub

On the machine that will hold the CA and serve enrollment:

```bash
sudo gw setup-hub --hostname hub
sudo gw run
```

`setup-hub` generates the CA, the persistent door key, the policy routing for
the enrollment door, and the hub's own credential, then writes
`/etc/greasewood.toml`. `gw run` starts the daemon: it brings up the `gw0`
WireGuard interface, serves the control plane, and watches for door windows.

### 2. Enroll a node

Enrollment uses a transient WireGuard "door" — no SSH, no HTTP exposed on the
underlay. On the hub, open a window and mint a single-use token:

```bash
TOKEN=$(sudo gw mint)
echo "$TOKEN"
```

Deliver that token to the new machine (any channel) and redeem it:

```bash
sudo gw join "$TOKEN" --hostname node01
sudo gw run
```

`join` derives a throwaway guest key from the token, stands up a temporary
`gw-door` tunnel to the hub, receives a CA-signed credential over it, tears the
door down, and writes the node's config. `gw run` then brings the node into the
mesh; within a couple of reconcile cycles every node has a direct tunnel to it.

### 3. Check it

```bash
gw status            # local node + directory view
sudo wg show gw0     # live WireGuard peers
```

## Provisioning many nodes

Enrollment tokens are **pushed by the hub, never pulled by nodes**. A node
cannot request admission; the hub (or an orchestrator acting on it) decides to
admit a machine, runs `gw mint`, and delivers the token out of band. The node
only redeems what it was handed.

Because of this the door is **single-slot and orderly by construction**: one
mint opens one enrollment window, and the hub closes it the instant the node
finishes joining. To provision N machines, mint and join in a sequential loop:

```bash
for host in node01 node02 node03; do
    TOKEN=$(ssh hub 'sudo gw mint')          # hub opens the door
    ssh "$host" "sudo gw join '$TOKEN'"      # node joins; hub closes the door
done                                         # next mint only runs after join returns
```

Each `gw join` blocks until the node is enrolled, so the window is always closed
again before the next `gw mint` — no locks or queue needed.

A new `gw mint` regenerates the door's guest key and overwrites the current
window, **invalidating any previously minted-but-unused token**. Minting while a
window is still open prints a warning to stderr (the token still goes to stdout,
so `TOKEN=$(gw mint)` is unaffected). Treat that warning as a sign the
provisioner is minting ahead of itself.

> The door enrolls one node at a time on the wire by design. Running the minting
> side as parallel workers would not speed this up, so the sequential loop is
> the intended model.

## Firewall

On each node's **underlay** (public) interface, open:

| Port        | Proto | Purpose                                  |
|-------------|-------|------------------------------------------|
| `51820`     | UDP   | mesh WireGuard (`gw0`)                    |
| `51821`     | UDP   | enrollment door (`gw-door`), during join |

The control plane (`7946/tcp`) and enrollment RPC (`7947/tcp`) are **not**
reached over the underlay — they travel inside the overlay and door tunnels
respectively. If a host runs a default-drop input policy, allow them on the
tunnel interfaces instead of the public NIC, e.g. with nftables:

```
iifname { "gw0", "gw-door" } tcp dport { 7946, 7947 } accept
udp dport { 51820, 51821 } accept
```

## Command reference

| Command            | Root? | What it does                                              |
|--------------------|-------|-----------------------------------------------------------|
| `setup-hub`        | yes   | One-shot hub bootstrap: CA, door key, routing, self-cred. |
| `run`              | yes   | Start the daemon (WireGuard iface, control plane, loops). |
| `mint`             | yes   | Open a 15-min door window, print a single-use join token. |
| `join <token>`     | yes   | Enroll this machine using a token from `mint`.            |
| `status`           | no    | Show local node and directory state.                      |
| `revoke <id_pub>`  | no    | Add an identity to the revoke list (on the hub).          |
| `hub-promote`      | yes   | Turn this enrolled node into a hub (mint its own CA key).  |
| `hub-endorse`      | no    | Endorse a successor hub's CA (on the current hub).         |
| `hub-retire`       | no    | Retire a CA so the fleet stops accepting its signatures.   |
| `purge`            | yes   | Remove all greasewood state from this machine.            |

Global flags: `-c/--config FILE` (default `/etc/greasewood.toml`) and
`-v/--verbose`. Both must precede the subcommand (`gw -v run`, not `gw run -v`).

Enrollment is door-only: `mint` on the hub, `join` on the node. There is no
manual credential-copy path.

## Configuration

`gw setup-hub` and `gw join` write `/etc/greasewood.toml` for you; see
`greasewood.toml.example` for the full annotated schema. Key fields:

```toml
[node]
hostname = "node01"
role     = "node"          # "hub" | "node"
inbound  = "yes"           # can this node accept cold inbound handshakes?
caps     = ["mesh"]

[network]
interface  = "gw0"
listen_port = 51820
seeds    = ["http://[<hub-overlay>]:7946"]   # directory URLs to pull (the hub)
root_url = "http://[<hub-overlay>]:7946"     # where to publish / renew

[ca]
trusted_pubs = ["<hex Ed25519 CA pubkey>"]   # a set, to allow CA migration

[hub]                        # hub role only
ca_key_file    = "/var/lib/greasewood/ca.key"
control_listen = ":7946"
credential_ttl = "24h"
```

### Roles

- **hub** — holds the CA private key; serves the control plane and the
  enrollment door; participates in the mesh.
- **node** — a plain mesh participant.

## Moving the hub (CA succession)

Hub status — both the control plane and the certificate authority — can be
handed from one node to another with no downtime and no config edit on any
node, and this can repeat indefinitely (A → B → C → …; every node can take a
turn). The private CA key never moves; the successor generates its own.

Trust is a **set**, not a single key. Each node bootstraps from its configured
`trusted_pubs`, then grows and shrinks that set at runtime from signed
statements in a *CA bundle* the hub serves (`GET /ca-bundle`) and every node
syncs. Two statement kinds, each signed by an already-trusted CA:

- **endorse** — "CA X vouches for CA Y as a successor" (and advertises Y's hub
  endpoint). Nodes resolve trust transitively: trusting A and seeing A→B→C…
  means trusting the whole chain, so a node enrolled long ago under A follows
  the hub all the way to the current one.
- **retire** — "CA X is no longer an accepted signer." It is **scheduled** with
  a grace period (default one credential TTL), so it propagates and every node
  re-credentials under the successor *before* it takes effect — nobody is cut
  off mid-handover. A retired CA's past endorsements stay valid (successors
  survive), but it can't make new ones (a leaked decommissioned key can't inject
  a rogue successor).

Migrating from hub **A** to a new node **B**:

```bash
# 1. Enroll B as an ordinary node (gw join …) and start it.

# 2. On B — mint B's own CA key and flip it to a hub-in-waiting:
sudo gw hub-promote                 # prints B's CA pubkey + control endpoint

# 3. On A — endorse B; the whole fleet now trusts A *and* B:
gw hub-endorse --ca-pub <B-pubkey> --endpoint <B-endpoint>

# 4. On B — restart so it serves as a hub:
sudo gw run

# Nodes repoint to B and, over the next credential cycle, renew under B.

# 5. After the overlap, on B — retire A, then decommission A:
gw hub-retire --ca-pub <A-pubkey>   # grace defaults to one credential TTL
```

Throughout, existing tunnels stay up (the data plane never depends on the hub),
so the handover is non-disruptive.

## Testing

```bash
pip install -e '.[test]'   # or: pip install pytest
python -m pytest           # unit tests (fast, no privileges)
```

Integration and stress tests run real WireGuard inside privileged Podman
containers and are skipped by the default run. They need Podman 4+ and the
WireGuard kernel module:

```bash
# Functional tests: mesh connectivity, re-enrollment, and hub/CA succession
# (hub handover on real containers) — all under tests/integration/
python -m pytest tests/integration/

# Scale tests — grow the mesh to many nodes and verify full convergence.
# Gated behind GW_STRESS; knobs: GW_STRESS_N / _WAVES / _WORKERS.
GW_STRESS=1 GW_STRESS_N=8 python -m pytest tests/integration/test_stress.py -v -s
```

## Design notes & non-goals

Deliberately **not** implemented (and not bugs): routing or relays, NAT
traversal / hole-punching, gossip between nodes, lazy on-demand tunnels,
continuous key rotation, or a mobile CA key. These are revisited only at
specific scale or threat triggers — e.g. gossip if the network genuinely
partitions, lazy tunnels at hundreds of nodes, a threshold CA when hub
compromise becomes unacceptable.

**Clock integrity is part of the security posture.** Every allow/deny is a
timestamp comparison against a credential expiry, so run NTP/chrony on every
node.

**CA trust is a set, not a single key.** The CA (and hub) is rotated by a signed
handoff with a one-TTL overlap, never by moving the private key — see
[Moving the hub](#moving-the-hub-ca-succession).
