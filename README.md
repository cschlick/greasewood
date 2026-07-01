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
  **hostname**, capabilities, and an expiry. Slow-moving (default 24 h TTL). The
  hostname lives here (not in the record) so a node can't self-assert a name the
  CA didn't grant it — the name is CA-attested end to end.
- **NodeRecord** — signed by the node's own `id_priv`. Carries the credential
  plus fast-moving facts (endpoints, a sequence number); its `hostname` is read
  from the credential. This is what gets published through the directory.

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

The Quickstart below runs the daemon by hand with `gw run`. For real use, run it
as a managed systemd service instead — see [Running as a
service](#running-as-a-service); then the workflow is just install → setup/join.

## Quickstart

### 1. Bootstrap the hub

On the machine that will hold the CA and serve enrollment:

```bash
sudo gw setup-hub --hostname hub
sudo gw run
```

`setup-hub` generates the CA, the persistent door key, the policy routing for
the enrollment door, and the hub's own credential, then writes
`/etc/greasewood.toml`. `gw run` starts the daemon: it brings up the `gw-mesh`
WireGuard interface, serves the control plane, and watches for door windows.

### 2. Enroll a node

Enrollment uses a transient WireGuard "door" — no SSH, no HTTP exposed on the
underlay. On the hub, open a window and create a single-use token:

```bash
TOKEN=$(sudo gw invite)
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
gw status               # local node + directory view
sudo gw diagnose        # per-peer: why each link is/isn't forming
sudo wg show gw-mesh    # live WireGuard peers
```

`gw diagnose` is the tool to reach for when a peer won't connect. Because the
mesh is direct-or-fail, a link that doesn't form is otherwise silent; diagnose
runs the full verification chain per peer and overlays the live WireGuard
handshake state, so it tells you *which* step failed — expired credential,
untrusted CA, policy denial, or "configured but no handshake, check the peer's
firewall." See [RUNBOOK.md](RUNBOOK.md) for how to read it and what to do next.

## Running as a service

`gw run` in a terminal is fine for trying things out, but in practice you want
the daemon managed by systemd — survives reboots, restarts on failure, logs to
the journal. The model is **install once, then forget `gw run`**: a path unit
watches for `/etc/greasewood.toml` and starts the daemon the moment `setup-hub`
or `join` writes it. So the workflow becomes just **install → setup/join**.

Install the service (pip-only, no Ansible):

```bash
sudo gw install-service
```

This writes `/etc/systemd/system/greasewood.{service,path}`, enables the path
watcher (armed immediately) and the service (for boot), and does **not** start a
daemon until you configure the node. After it's installed:

```bash
sudo gw setup-hub --hostname hub      # on the hub        → daemon auto-starts
sudo gw join "$TOKEN" --hostname n01  # on a node         → daemon auto-starts
journalctl -u greasewood -f           # watch it (no live terminal anymore)
```

Opt out / undo:

```bash
sudo gw uninstall-service             # disable + remove the units
# or just: sudo systemctl disable --now greasewood.path greasewood.service
```

Notes:
- It runs `gw run` as root (it manages WireGuard interfaces and routing). Don't
  also run `gw run` by hand while the service is up — both would fight over `gw-mesh`.
- A **config-changing re-join** (new hub, new caps) isn't auto-detected — the
  daemon reads its config at startup, so run `sudo systemctl restart greasewood`
  afterward.
- Via Ansible: the `greasewood` role (in the `postinstall` repo) installs and
  enables the same units for you, so a freshly provisioned node is service-ready
  before you even enroll it.

## Provisioning many nodes

Enrollment tokens are **pushed by the hub, never pulled by nodes**. A node
cannot request admission; the hub (or an orchestrator acting on it) decides to
admit a machine, runs `gw invite`, and delivers the token out of band. The node
only redeems what it was handed.

Because of this the door is **single-slot and orderly by construction**: one
each invite opens one enrollment window, and the hub closes it the instant the node
finishes joining. To provision N machines, invite and join in a sequential loop:

```bash
for host in node01 node02 node03; do
    TOKEN=$(ssh hub 'sudo gw invite')          # hub opens the door
    ssh "$host" "sudo gw join '$TOKEN'"      # node joins; hub closes the door
done                                         # next invite only runs after join returns
```

Each `gw join` blocks until the node is enrolled, so the window is always closed
again before the next `gw invite` — no locks or queue needed.

A new `gw invite` regenerates the door's guest key and overwrites the current
window, **invalidating any previously issued-but-unused token**. Issuing while a
window is still open prints a warning to stderr (the token still goes to stdout,
so `TOKEN=$(gw invite)` is unaffected). Treat that warning as a sign the
provisioner is issuing ahead of itself.

> The door enrolls one node at a time on the wire by design. Running the issuing
> side as parallel workers would not speed this up, so the sequential loop is
> the intended model.

## Firewall

**greasewood never touches your firewall unless you ask it to.** Its control
plane (`51902/tcp`) and enrollment RPC (`51903/tcp`) bind only to the node's
overlay address and loopback — *never* the underlay — so nothing it runs is
reachable off-mesh regardless of firewall policy. The only thing that must face
the underlay is WireGuard itself (UDP), which you open like for any VPN.

`setup-hub`, `join`, and `set-inbound` **check** the local nftables ruleset and
loudly warn if a needed port looks blocked by a default-drop policy, printing the
exact rule to add. That's all greasewood does — **it never modifies your
firewall.** You apply the printed rules yourself (put them in your nftables
config, or the Ansible `nftables` role does it for you).

On a default-drop host, allow (nftables):

| Interface  | Rule                          | Purpose                              |
|------------|-------------------------------|--------------------------------------|
| underlay   | `udp dport 51900 accept`      | mesh WireGuard                       |
| underlay   | `udp dport 51901 accept`      | enrollment door (during join)        |
| `lo`       | `iifname "lo" accept`         | the hub talks to itself (`::1:51902`)|
| `gw-mesh`  | `tcp dport 51902 accept`      | control plane — **only used when this node is the hub** |
| `gw-door`  | `tcp dport 51903 accept`      | enrollment exchange — **only when hub** |

```
udp dport { 51900, 51901 } accept
iifname "lo" accept
iifname "gw-mesh" tcp dport 51902 accept
iifname "gw-door" tcp dport 51903 accept
```

The four ports sit in one contiguous block, **51900–51903**, deliberately clear
of the WireGuard default (51820) and Docker Swarm / Serf (7946) so greasewood
doesn't squat a port something else likely wants. All are configurable: mesh
`[network] listen_port`, control `[hub] control_listen`, door `[hub] door_port`
(or `setup-hub --listen-port/--control-port/--door-port`). The door port rides
in join tokens and the control port in the enrollment response, so nodes pick up
non-default values automatically — no client config. (The internal enrollment
port lives inside the door tunnel and can't collide, so it isn't a knob.)

Your base default-drop ruleset should also carry `ct state established,related
accept` (almost everyone has it). It's what lets an **outbound-only** node work:
such a node opens *no* greasewood inbound ports — it dials peers and the hub,
and the replies come back through `established,related`.

**Recommended posture: apply the same ruleset on *every* node, not just the
current hub.** Any node can be promoted to hub ([Moving the
hub](#moving-the-hub-re-root)), so a uniform ruleset means a hub handover
needs **no firewall change anywhere**. Opening `51902`/`51903` on a node that
isn't a hub is harmless: nothing is bound there, so the kernel just refuses the
connection until that node actually becomes a hub and binds it. Plain nodes run
no control plane, so on a node that will never be a hub you can omit the `gw-mesh`/
`gw-door` TCP rules and open only the two UDP ports.

**Multi-user hosts:** the overlay is host-wide — *any* local user can use the
tunnel once it's up (identity is per-machine, not per-user). To restrict which
users may originate overlay traffic, add an nftables owner-match on the output
chain; see the "Multi-user hosts" section of [SECURITY.md](SECURITY.md).

### Reachability (`inbound`)

WireGuard has no client/server roles — both peers try to handshake and the
direction that physically works wins, then endpoint roaming pins it. So a link
forms as long as **at least one side is reachable**: a firewalled node dials an
open one, and the reply returns via `established,related`. Two fully-blocked
nodes can't pair (direct-or-fail — no relays).

Declare a node's reachability at join (`--inbound yes|no`, default `yes`) or
change it later with `gw set-inbound`:

- **`yes`**: advertises its endpoint; needs the mesh UDP port open.
- **`no`** (outbound-only): the node advertises *no* endpoint, so peers don't
  waste handshakes dialing it; it opens no inbound ports. It can only pair with
  inbound-reachable nodes, and **can't be promoted to hub** (a hub must be
  reachable). Switch it back with `sudo gw set-inbound yes` (then open the port).

`inbound` is an optimization + a guard, not what decides direction — WireGuard
does that on its own.

## Command reference

| Command            | Root? | What it does                                              |
|--------------------|-------|-----------------------------------------------------------|
| `setup-hub`        | yes   | One-shot hub bootstrap: CA, door key, routing, self-cred. |
| `run`              | yes   | Start the daemon (WireGuard iface, control plane, loops). |
| `invite`           | yes   | Open a 15-min door window, print a single-use join token. |
| `join <token>`     | yes   | Enroll this machine using a token from `invite`.          |
| `status`           | no    | Show local node and directory state.                      |
| `revoke <id_pub>`  | no    | Add an identity to the revoke list (on the hub).          |
| `hub-promote`      | yes   | Turn this enrolled node into a hub (generate its own CA key).  |
| `cert-request`     | no    | Get an x509 TLS cert from the hub for a local service.     |
| `cert-status`      | no    | Show local TLS certs and their expiry.                     |
| `set-inbound`      | yes   | Change reachability (yes/no).                              |
| `rename <name>`    | yes   | Change this node's mesh hostname (hub-validated, no re-join). |
| `install-service`  | yes   | Install + enable the systemd units (run as a service).     |
| `uninstall-service`| yes   | Disable + remove the systemd units.                        |
| `purge`            | yes   | Remove all greasewood state from this machine.            |

Global flags: `-c/--config FILE` (default `/etc/greasewood.toml`) and
`-v/--verbose`. Both must precede the subcommand (`gw -v run`, not `gw run -v`).

Enrollment is door-only: `invite` on the hub, `join` on the node. There is no
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
interface  = "gw-mesh"
listen_port = 51900
overlay_prefix = "fd8d:e5c1:db1a:7::"        # the fleet's overlay /64 (ULA)
seeds    = ["http://[<hub-overlay>]:51902"]  # directory URLs to pull (the hub)
root_url = "http://[<hub-overlay>]:51902"    # where to publish / renew
hosts_sync  = false                          # manage /etc/hosts names (opt-in)
mesh_domain = "internal"                     # name suffix + default TLS cert name

[ca]
trusted_pubs = ["<hex Ed25519 CA pubkey>"]   # a set, to allow CA migration

[hub]                        # hub role only
ca_key_file    = "/var/lib/greasewood/ca.key"
control_listen = ":51902"
credential_ttl = "24h"
```

### Roles

- **hub** — holds the CA private key; serves the control plane and the
  enrollment door; participates in the mesh.
- **node** — a plain mesh participant.

### One host on two meshes

The overlay `/64` is configurable (`[network] overlay_prefix`, set at
`setup-hub --overlay-prefix`; a node learns it from its credential at join). A
node learns and verifies addresses prefix-agnostically — the self-certifying
part is the host bits, `blake2s(id_pub)`, and the CA signature attests the
prefix — so **one host can be a plain node on two independent meshes at once**.
Give each membership its own config, data dir, interface, listen port, and mesh
domain (hub-in-two-meshes is not supported):

```bash
sudo gw -c /etc/gw-a.toml join "$TOKEN_A" --data-dir /var/lib/gw-a \
    --interface gw-a --listen-port 51900 --mesh-domain alpha
sudo gw -c /etc/gw-a.toml run          # (and the same, with -b/51910/beta, for mesh B)
```

`hosts_sync` blocks are tagged per mesh domain and file-locked, so the two
daemons don't clobber each other's `/etc/hosts` entries.

## Names (.internal)

Every node has a stable overlay address and `gw status` shows the name↔address
map, so `ping <overlay-addr>` always works. For names, there's an **opt-in**
managed `/etc/hosts` block: enable it with `--hosts-sync` (on `setup-hub` /
`join`) or `hosts_sync = true` in config, and the daemon keeps a marked block
mapping each node's address to `<hostname>.internal`, refreshed from the local
directory cache each reconcile:

```
# BEGIN greasewood — managed, do not edit
fd8d:e5c1:db1a:7:…  db.internal
fd8d:e5c1:db1a:7:…  node01.internal
# END greasewood
```

Then `ping db.internal`, `psql -h db.internal`, etc. just work — no DNS server,
and it keeps resolving even if the hub is down (it's from the cache). It only
ever touches the region between its markers; your own `/etc/hosts` lines are
left alone, and disabling it (then restarting) or `gw purge` removes the block.

The domain (`mesh_domain`, default `internal` — an ICANN-reserved private TLD)
is shared with TLS: `gw cert-request` with no `--san` defaults the cert to this
node's `<hostname>.internal` **plus** its overlay address. So the name a node is
reached by is exactly the name its certificate is valid for — resolve
`db.internal` → connect over WireGuard → TLS validates the `db.internal` SAN.

A node's hostname defaults to the machine's own hostname at enrollment; change
it later with `sudo gw rename <newname>` (then restart the daemon). Rename goes
through the hub, so it's uniqueness-checked and frees the old name — the keys and
overlay address don't change. (Editing `hostname` in the config directly is not
enough: the hub wouldn't know, so always use `gw rename`.)

> Names are sanitized to a DNS-safe form (`ops@node01` → `ops-node01`). The
> hub **enforces uniqueness at enrollment** — a `join` whose (sanitized) name is
> already taken is refused — so resolution stays unambiguous. A node can still
> rename or renew itself; a decommissioned node keeps its name until its
> `nodes/<id>.json` is removed on the hub.

## TLS certificates for services

The same CA that gates the mesh also issues ordinary **x509 TLS certificates**,
so a service on a node (Postgres, an internal API, …) gets a cert that every
peer validates against one trust root — no second PKI. These are real x509
certs with SANs, distinct from the mesh credential, but signed by the same
Ed25519 CA key.

**What this is for (and isn't).** WireGuard already encrypts and authenticates
traffic between nodes, so TLS here is **not** about adding encryption — that part
would be redundant. Its value is at the layers WireGuard doesn't cover:

- **Service identity by name.** WireGuard authenticates the *node* you reached,
  not that you reached the *right* node for a name — the `db.internal`→address
  mapping lives outside its crypto. A cert with `SAN=db.internal`, validated by
  the client, is what proves "this endpoint is authorized for that name."
- **Process/tenant identity.** The `gw-mesh` interface is host-global, so any
  process on a node can use the tunnel. **mTLS** (client certs) narrows a
  connection to a specific identity and surfaces it into the app (e.g. Postgres
  cert→role) for authz and audit.
- **A free, mesh-rooted PKI.** Services that require TLS anyway (`sslmode=verify-full`,
  HTTPS clients) get certs without you running a second CA.

The value **requires the client to verify** — use `verify-full`/mTLS. Using the
cert only for opportunistic encryption (no SAN check) *is* just redundant with
WireGuard.

A node may request certs only if its credential carries the **`tls`**
capability — grant it at enrollment:

```bash
sudo gw join "$TOKEN" --hostname dbnode --caps mesh,tls
```

Then, on that node:

```bash
# A node may only get a cert for names it OWNS: its own <hostname>.<mesh_domain>,
# subdomains of it, and its own overlay address. So on node "dbnode":
sudo gw cert-request --san postgres.dbnode.internal --name postgres
sudo gw cert-request                 # no --san → defaults to dbnode.internal + addr
# writes <data_dir>/tls/postgres.key, postgres.crt, ca.crt
gw cert-status                       # show what's issued and when it expires
```

The leaf private key is generated locally and never sent to the hub; only its
public key goes in the request, which is signed by the node's identity key. The
hub returns the leaf cert plus the CA cert. Point the service at them — e.g.
Postgres `ssl_cert_file=postgres.crt`, `ssl_key_file=postgres.key`, and clients
`sslrootcert=ca.crt` with `sslmode=verify-full`. Certs are short-lived (default 7
days, `[hub] tls_cert_ttl`); re-run `cert-request` from cron/timer to renew.
Revocation is passive — stop renewing and it expires.

> **SANs are constrained to what the node owns** (its CA-registered
> `<hostname>.<mesh_domain>`, subdomains, and its overlay address) — the hub
> refuses a cert for another node's name, so a `tls`-capable node can't
> impersonate a service it doesn't run. The `tls` capability is still the gate;
> grant it only to nodes that run services. The hub's CA cert is also at
> `GET /ca-cert`. (After a re-root the CA changes; re-request to pick up the new
> issuer.)

## Moving the hub (re-root)

No node is forever-critical: because a node trusts a CA **key**, not a machine,
any node that holds the CA authority and serves the directory *is* the hub.
Moving the hub is therefore a deliberate **re-root** — swap which CA key the
fleet trusts — not an automatic handover. `trusted_pubs` is a **set**, so you
trust the old and new CA during an overlap and the move is non-disruptive.

The CA private key never moves: the new hub generates its own key, and you push
the new *public* key into every node's `trusted_pubs`. Migrating from hub **A**
to a new node **B**:

```bash
# 1. Enroll B as an ordinary node (gw join …) and start it.

# 2. On B — generate B's own CA key and flip it to role=hub:
sudo gw hub-promote                 # prints B's CA pubkey + control endpoint

# 3. Add B's CA pubkey to [ca] trusted_pubs on EVERY node (keep A's), and
#    restart their daemons — the fleet now trusts A *and* B. (Ansible.)

# 4. Repoint nodes' root_url + seeds to B (config push). Start B: sudo gw run
#    Nodes renew under B over the next credential cycle.

# 5. After every node has a B-signed credential, drop A's CA pubkey from
#    trusted_pubs fleet-wide, then decommission A.
```

Throughout, existing tunnels stay up (the data plane never depends on the hub),
so the handover is non-disruptive. This leans on your config management for the
`trusted_pubs`/`root_url` pushes — see [RUNBOOK.md](RUNBOOK.md) for the graceful
vs emergency (compromised-key) variants.

## Testing

```bash
pip install -e '.[test]'   # or: pip install pytest
python -m pytest           # unit tests (fast, no privileges)
```

Integration and stress tests run real WireGuard inside privileged Podman
containers and are skipped by the default run. They need Podman 4+ and the
WireGuard kernel module:

```bash
# Functional tests: mesh connectivity, re-enrollment, rename, TLS, reboot survival
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

**CA trust is a set, not a single key.** The CA (and hub) is moved by a
re-root — trust the new key alongside the old during an overlap, then drop the
old — never by moving the private key. See [Moving the hub](#moving-the-hub-re-root).

## Security & operations

- **[SECURITY.md](SECURITY.md)** — trust boundaries, what the 7-step check
  enforces, accepted risks, and the results of the security review.
- **[RUNBOOK.md](RUNBOOK.md)** — disaster SOPs: compromised node, lost/leaked CA
  key, destroyed hub, fleet-wide teardown, and how to read `gw diagnose`.
