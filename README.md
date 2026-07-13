# Greasewood

A minimal, self-hosted, and greasy Wiregaurd mesh network. 

Its one priority is being **easy to reason about**. It was built by someone who
lovingly maintained a fleet of hand-written WireGuard/networkd text files far
past the point of practicality, and wanted the simplest possible upgrade.

- **[Private.](#membership)** Membership is gated by a certificate authority;
  revoke a node by not renewing it.
- **[Direct-or-fail.](#direct-or-fail)** No routing, no relays. A link comes up
  directly or it honestly fails.
- **[IPv6 only overlay.](#ipv6-overlay)** The overlay is IPv6-only; the underlay may be
  IPv4 or IPv6.
- **[Named.](#names)** Every node gets a `<host>.<mesh>.internal` name and
  matching TLS certs from the same CA.
- **[Policy-derived topology.](#access-control-roles--grants)** Roles + an allow-only grant table control who
  talks to whom.
- **[Self-certifying addresses.](#self-certifying-addresses)** A node's IPv6
  address is a hash of its identity key.
- **[Linux-only.](#linux-only)** Leans heavily on systemd, nftables. Uses
  the stock `wg`/`ip` tools over subprocess. Greasy.
- **[Service TLS.](#tls-certificates-for-services)** The same CA issues auto-renewing
  x509 certs for your services (Postgres, nginx, …), with profiles that place them where each wants them.
- **[Offline-tolerant.](#offline-tolerance)** The anchor can be down for a credential
  lifetime, nodes run from cache.
- **[Hands-off.](#firewall)** Never automatically configures your main firewall.
  Port access control for the overlay lives on a dedicated table
- **[Auditable.](#auditable)** Pure Python, one dependency. Fanatical logging.
- **[Self-contained.](#the-anchor)** The coordination anchor is just a normal functioning node.
  Any node can become the coordination anchor.

## Prior art

The nearest full-featured projects are **Tailscale**, **Nebula**, and
**innernet**. Next to greasewood they're all bigger systems that do more: routing,
NAT traversal, multi-platform, etc. Greasewood aims to be a minimal alternative.

## Membership

Membership is a **CA-signed credential with an expiry**

**Two keys per node**, deliberately split:

- `id_priv` / `id_pub` (Ed25519) — durable identity. It derives the node's
  overlay address and authorizes credential renewal. 
- `wg_priv` / `wg_pub` (X25519) — your normal wireguard keys.

**Two signed objects:**

- **Credential** — signed by the CA. Binds `id_pub`, `wg_pub`, overlay address,
  hostname, capabilities, and an expiry. Slow-moving (default 24h TTL).
- **NodeRecord** — signed by the node's own `id_priv`. Carries the credential
  plus fast-moving facts (endpoints, a sequence number) Its `hostname` is read
  from the credential. This is what gets published to other nodes through a directory.

**Revocation is expiry-based (no CRL).** `gw revoke <id>` on the anchor takes effect
there immediately — the anchor re-reads its revoke list each reconcile cycle,
dropping the node from its own interface within seconds, and refuses the node's
renewals from then on. It does **not** reach the rest of the fleet instantly:
other nodes keep trusting the node's credential until it expires. But since the
node can no longer renew, that credential lapses within at most one
`credential_ttl`, at which point every node rejects it.
Shorten `credential_ttl` for a tighter bound.

## The anchor

The anchor is **just a normal mesh node** that additionally holds the CA key and
runs a small HTTP **control plane**: `GET /directory`, `POST /publish`, `POST
/renew`, `GET /health` — bound to its overlay address (reachable only through the
mesh, never the underlay). There is no separate coordination service, no relays, no SaaS,
nothing always-on in the data path. Nodes poll `/directory`, merge records by
highest sequence number, and cache them locally.

Because trust is anchored to the CA *key* (not a machine), any node can become
the anchor — restore the key onto a replacement, or stand up a new CA and re-point
the fleet. See [Moving the anchor](#moving-the-anchor-re-root).

## Direct-or-fail

There is no routing, no multi-hop, no relays, and no NAT traversal. Two nodes
either form a **direct** WireGuard tunnel or the link fails. It never
silently falls back to relaying through a third party, so there's no hidden path
to reason about.

The only logic that modifies a normal wireguard configuration is the **reconcile loop**: 
every few seconds each node walks the directory and, per peer, runs seven checks: verify
the CA signature, check expiry, verify the self-signature, verify the address
derives from `id_pub`, check the revoke list, check the authorization policy —
then installs or removes that peer with `wg set`. Membership changes,
revocations, key rotations, and access policy all reduce to "add or remove a
peer," computed locally with no coordinator. A link forms as long as at least one
side is reachable (see [Reachability](#reachability)) two unreachable
nodes can't pair.

## IPv6 overlay

The **overlay is IPv6-only**. Every node's mesh address is a hash of its
identity key under a ULA prefix, and all in-tunnel traffic is IPv6. 

The **underlay** (the real network each WireGuard endpoint lives on) can be
**IPv4 or IPv6**. A node advertises whatever public endpoint(s) it has, and each
node dials a peer over a family they share.

A dual-stack peer advertises **both** its v6 and v4 endpoints (v6 first). If the
preferred one produces no handshake for ~20s, the reconcile loop rotates to the
next advertised endpoint and keeps round-robining until one connects. So a peer
reachable on v4 but with a broken v6 path still links, with no manual
intervention. This is still direct-or-fail: only endpoints the *peer* advertised
are ever tried, never a relay.

## Self-certifying addresses

A node's overlay address is a **hash of its identity public key**:

```
fd8d:e5c1:db1a:7 : truncate64(blake2s(id_pub))
                   └── the last 64 bits ARE the key's fingerprint ──┘
```

That function is public and deterministic, so anyone holding a node's `id_pub`
can recompute its address and check it matches. The address *certifies itself*
against the key — no allocator, and no authority needs to vouch that "this
address belongs to this node."

## Offline tolerance

Every node caches the directory on disk and keeps its tunnels running from that
cache, so the **anchor can be down for up to one credential lifetime** and existing
node↔node links are unaffected. The anchor is never in the data path. Only new
enrollments and credential renewals need a reachable anchor. Restore or replace the
anchor within that window (see [Moving the anchor](#moving-the-anchor-re-root) and the
[RUNBOOK](RUNBOOK.md)) and nothing ever drops.

## Linux-only

greasewood is built on **Linux-specific kernel interfaces** — the in-kernel
WireGuard module and the kernel's own networking — and is best run as a
**systemd** service (the recommended way to keep the daemon up across reboots and
crashes; a bare `gw run` works for dev). It relies on the
kernel's WireGuard and on systemd rather than shipping its own userspace
transport (the way a Go implementation such as `wireguard-go` does) or its own
supervisor. It reaches those kernel interfaces via the stock `wg`/`ip` tools
(see [Auditable](#auditable)). Other platforms would need a different data-plane
backend and a different supervisor, and are out of scope: greasewood is,
deliberately, a Linux tool.

## Auditable

The entire thing is **pure Python (3.11+), one dependency (`cryptography`), one
binary (`gw`)**, and it manages the data plane by shelling out to `wg`/`ip` via
subprocess. That's gre-eee-easy. The clean way would be
netlink bindings. It's a deliberate trade: you can read the exact `wg set
peer …` commands, run them by hand, and compare them against what `wg show`
reports.

That trade pays off in the **command trail**. Because every data-plane change is
a subprocess, greasewood records *every `ip`/`wg` command it issues* — always, 
with the exit code, how long it took, and **why it
ran** — to a durable, rotating `<data_dir>/audit.log` and to the journal.
One greppable [logfmt](https://brandur.org/logfmt) line per command:

```
ts=2026-07-02T10:15:03Z INFO greasewood.audit: cmd rc=0 t=12ms \
  ctx="reconcile: +peer db01 [fd8d:e5c1:db1a:7::a1] seg=prod" \
  argv="wg set gw-myfleet peer <pub> allowed-ips fd8d:e5c1:db1a:7::a1/128 endpoint [203.0.113.7]:51900 ..."
```

In addition to the per-command lines, the same file carries a **domain-event trail** one
line per *mesh state transition* `grep event= audit.log`:

```
ts=2026-07-02T22:12:03Z INFO greasewood.audit: event=policy prev=4 seq=5 grants=3
ts=2026-07-02T22:12:08Z INFO greasewood.audit: event=topology added=2 removed=1 peers=7
```

So the narrative reads at a glance: policy v4→v5 was adopted, and the next
reconcile settled the topology (+2/−1, 7 peers) with the per-peer `+peer`/
`-peer` commands right below carrying the who and why. A topology line appears
only when membership actually changes (a re-verified endpoint isn't a
transition), so steady state stays silent.

And you don't have to read raw logs: **`gw narrate` translates the trail into
plain English** — grouping the commands of each operation and explaining what
each did and why:

```
$ gw narrate --since 2h
● 2026-07-02 22:12:03Z  A new node enrolled through the door and was installed
                        as a peer (db01 [fd8d:e5c1:db1a:7::a1] from fd52:ba5e::9).
    ✓ Set up the WireGuard tunnel to peer qa7IAQabcd=: accept and route its
      overlay address fd8d:e5c1:db1a:7::a1 (a /128 host route — one address per
      peer, derived from its identity key); dial it at 203.0.113.7:51900; send a
      keepalive every 25s to hold the path open.                          (14ms)
    ✓ Route traffic for fd8d:e5c1:db1a:7::a1 over gw-myfleet — wg configures the
      peer but not the kernel route, so greasewood adds it explicitly.     (3ms)
```

Filter it (`--peer db01`, `--failures`, `--grep`, `--stats`), point it at any
log file or `-` for stdin, or `--raw` to see the argv alongside. This is the
core of the auditability claim: **you can reconstruct and read as a
narrative every change greasewood ever made to your kernel's network state.**

## Install

Requires Python 3.11+, the WireGuard userspace tools (`wireguard-tools`/`wg`),
and `iproute2` (`ip`). The kernel WireGuard module is built into Linux 5.6+ and
autoloads on first use.

greasewood isn't on PyPI yet — every install builds **from this git repo**, not
a package index. Two ways to install on a host that will run the daemon; both set
up the managed systemd service.

**With pipx (recommended on Linux)** — the standard way to install a Python
application in its own isolated environment. pipx installs **straight from the
git URL, not PyPI**, so it builds the latest commit on the default branch — no
clone needed:

```bash
sudo apt install pipx wireguard-tools    # Debian/Ubuntu; use your distro's pkg mgr
sudo pipx install --global "git+https://gitlab.com/cschlick/greasewood.git"
```

`--global` puts `gw` on root's `PATH` so `sudo gw …` resolves, and the daemon
service launches as `<interpreter> -m greasewood`, so it stays valid wherever
pipx put the package. pipx manages only the Python side — install the WireGuard
tools separately with your distro's package manager (shown above). To pull newer
commits later, `sudo pipx reinstall greasewood` (a clean re-pull from the repo;
plain `pipx upgrade` can skip a git install when the version string hasn't moved).

**With the bundled installer** — a self-contained alternative that also installs
the WireGuard deps and pins a fixed venv at `/opt/greasewood`. Re-run any time
(after a `git pull`) to upgrade in place:

```bash
git clone https://gitlab.com/cschlick/greasewood.git
cd greasewood
sudo ./install.sh
```

Either way you get the `gw` command, and `gw create`/`join` install + enable the
systemd service. Most subcommands need sudo/root (they create WireGuard
interfaces and edit routing); `gw watch` does not. For a plain library/dev use,
`pip install .` (add `'.[test]'` for pytest) from a checkout is all you need.

After install the workflow is just setup/join → the daemon runs as a managed
systemd service that `gw create`/`gw join` set up for you — see [Running as a
service](#running-as-a-service). The Quickstart below
runs it by hand with `gw run` to show the moving parts.

## Quickstart

### 1. Bootstrap the anchor

On the machine that will hold the CA and serve enrollment:

```bash
sudo gw create mymesh          # names live under *.mymesh.internal
```

`create` generates the CA, the persistent door key, the policy routing for
the enrollment door, and the anchor's own credential, then writes
`/etc/greasewood_mymesh.toml`. By default `create` also starts the daemon: it brings up the `gw-mymesh`
WireGuard interface, serves the control plane, and watches for door windows.

The anchor takes this machine's hostname like any other node. 
You tell which node is the anchor from `role: anchor` in
`gw watch`, not from its name. (Pass `--hostname <name>` to override the default.)

### 2. Enroll a node

Enrollment uses a transient WireGuard "door". This provides a mechanism to allow new nodes
onto the mesh that is much lower trust than, for example, relying on ssh. Also since wireguard doesn't
respond to connections without a recognized credential, it is a much cleaner external profile than, for
example, running an http server for configuration on the underlay. To add a new node to the mesh, create an 
invite token on the anchor:

```bash
sudo gw invite # prints token
```

Deliver that token to the new machine (any channel) and redeem it:

```bash
sudo gw join <token>
```

`join` derives a throwaway guest key from the token, stands up a temporary
`gw-door` tunnel to the anchor, receives a CA-signed credential over it, tears the
door down, and writes the node's config, then the anchor brings the node into the
mesh.

**Why a door — why can't the token just contain everything to peer over
your mesh interface?** Because WireGuard peering is *mutual*: to bring up a tunnel to the
anchor over any interface, the anchor must already have **your** public key in its peer
list. At invite time your real keys don't exist yet (they're generated locally
at `join`, and private keys never travel) so the anchor cannot pre-authorize your
real identity key. 

What the token *can* do is carry a 32-byte seed that **both sides expand (HKDF)
into the same throwaway door keypair + PSK**. The anchor derives that throwaway
pubkey from the seed it minted and pre-installs it as a peer; you derive the
matching private key — so now a tunnel can actually form. But it forms under a
**disposable, credential-less key, not your identity**. That's why the door is a
*separate* interface:

- it runs on its own **dedicated door subnet** (`fd8d:…:d::/64`) — not a
  throwaway address squatting on the real overlay (which would break the
  self-certifying `address = hash(identity)`)
- it reaches **only the enroll daemon** (not the directory/control plane, not
  other peers) A token-holder can do exactly one thing: request a credential;
- it's **torn down** the moment your credential is issued.

So the door bootstraps joining the mesh with your real identity. You bring up the 
mesh interface, with your *real* key and its self-certifying address, only
once you hold that credential. Running the throwaway peering over the mesh interface
instead would drop a credential-less stranger onto the live mesh with a fake
address and expose the whole control plane. The door is a temporary quarantine.

### 3. Check it

```bash
sudo gw watch              # a live ( or --snapshot) view of the mesh peers
sudo wg show gw-mymesh     # wg show works normally, showing each tunnel
```

`gw diagnose` is the tool to reach for when a peer won't connect. It's
**pairwise**: it lays up to two named nodes plus the anchor side by side and
explains, per pair, whether a tunnel can form — policy (roles/grants), reachability, and the
firewall/routing directionality that's usually the real question. (`gw watch`
is the fleet-wide link overview; diagnose is the focused deep-dive.)

```bash
sudo gw diagnose            # this host ↔ the anchor
sudo gw diagnose db01       # this host ↔ db01   (+ anchor as reference)
sudo gw diagnose db01 web1  # db01 ↔ web1        (+ anchor as reference)
```

The comparison table shows each node's addresses, reachability, roles,
credential, and firewall for the mesh UDP port. 

## Running as a service

On a systemd host the daemon is managed for you — **`create` and `join` install
the service and start it**, no extra command. A single **template unit** serves
every mesh as its own instance `greasewood@<name>` (survives reboots, restarts
on failure, logs to the journal), so the whole workflow is just:

```bash
sudo gw create mymesh                 # anchor  → greasewood@myfleet installed + running
sudo gw join "$TOKEN" --hostname n01  # node → greasewood@<mesh> installed + running
journalctl -u greasewood@mymesh  -f   # watch a mesh's daemon
systemctl status 'greasewood@*'       # all of them
```

There is no separate install/uninstall step: the service lifecycle rides on the
mesh lifecycle. **`gw purge`** removes a mesh's instance (and the shared
template when it's the last mesh) providing a from-scratch reset in one command.

- **Not on systemd, or want to run it yourself?** Pass `--no-service` to
  `create`/`join`; they print the `sudo gw -c <config> run` line instead and
  touch nothing under `/etc/systemd`. (A non-systemd host auto-falls-back to
  this even without the flag.)
- Instances run `gw run` as root (they manage WireGuard interfaces and
  routing). Don't also run `gw run` by hand while an instance is up,  both
  would fight over the interface.
- A **config-changing re-join** (new anchor, etc) isn't auto-detected — the
  daemon reads its config at startup, so run `sudo systemctl restart greasewood@<name>`
  afterward.

## Provisioning many nodes

Enrollment tokens are **initiated by the anchor, never by nodes**. A node
cannot request admission; you (or an orchestrator acting on the anchor) decide to
admit a machine, run `gw invite`, and deliver the token out of band. The node
only redeems what it was handed. The door is **single-slot by construction**:
each invite opens one enrollment window, and the anchor closes it the instant that
node finishes joining. To persist a door over multiple joins (reuse a token, useful for 
provisioning many instances at once), use the `--standing` flag:

On the anchor:

```bash
sudo gw invite               # prints a one-time token
sudo gw invite --standing    # prints a multi-use token
```

Joining is the same either way

```bash
sudo gw join <token>
```

## Firewall

**greasewood never modfies your external (underlay) firewall** Its control
plane (`51902/tcp`) and enrollment RPC (`51903/tcp`) bind only to the node's
overlay address and loopback *never* the underlay, so nothing it runs is
reachable off-mesh regardless of firewall policy. The only thing that must face
the underlay is WireGuard itself (UDP), which you open yourself like for any VPN.

greasewood uses **four ports**, one contiguous block — two WireGuard udp ports
on the underlay, and two TCP service ports on the overlay.

|         | UDP — WireGuard transport | TCP — service inside the tunnel |
|---------|---------------------------|---------------------------------|
| **mesh** | `51900` — overlay data plane | `51902` — control plane |
| **door** | `51901` — ephemeral join tunnel | `51903` — enroll exchange |

`create` and `join` **check** the local nftables ruleset and
loudly warn if a needed port looks blocked by a default-drop policy, printing the
exact rule to add. That's all greasewood does. You apply the printed rules yourself (put them in your nftables
config, or however you configure your firewall).

**No firewall at all? Then there's nothing to do — and nothing extra is
exposed.** greasewood binds nothing to the underlay except its WireGuard UDP
port(s): `51900` (mesh) on any node, plus `51901` (the enrollment door)
on the anchor. Those are WireGuard, which is designed to face the internet — it
silently drops any packet that isn't a valid handshake from a configured peer (no
reply, no info leak). Everything else — the control plane (`51902`) and the
enrollment exchange (`51903`) — binds to the overlay address or the door tunnel,
so it's *structurally* off the underlay whether or not you run a firewall. A
greasewood host with no firewall is therefore no more exposed than a plain
WireGuard host with no firewall. The rules below matter only on a host that runs
a **default-drop** policy and so must explicitly *allow* those ports through.

On a default-drop host, allow (nftables). With port enforcement on (the
default), greasewood's own nftables table filters the overlay interfaces
(control plane, enrollment + door lockdown, and the grant-derived ports), so
your firewall just opens the two underlay UDP ports and **admits** the overlay —
greasewood does the rest:

| Interface  | Rule                          | Purpose                              |
|------------|-------------------------------|--------------------------------------|
| underlay   | `udp dport 51900 accept`      | mesh WireGuard                       |
| underlay   | `udp dport 51901 accept`      | enrollment door (during join)        |
| `lo`       | `iifname "lo" accept`         | the host talks to itself (`::1:51902`)|
| `gw-*`     | `iifname "gw-*" accept`       | admit the overlay; greasewood's table filters the ports on it |

```
udp dport { 51900, 51901 } accept
iifname "lo" accept
iifname "gw-*" accept
```

That coarse `iifname "gw-*" accept` is required in a default drop context to allow
traffic to reach greasewood's overlay table (greasewood's table can only
*tighten* what your firewall admits, never open it). Greasewood's table then scopes the control plane to `gw-<mesh>`,
locks `gw-door` to enrollment only, and applies the grant table's port scopes.

**If you turn enforcement off** (`enforce_ports = false`), greasewood installs no
table. It's purpose is to enforce access control to ports on this machine from a central location
(the anchor), which requires cooperation from to enforce. It is opt-in. 

**Multi-user hosts:** the overlay is host-wide, *any* local user can use the
tunnel once it's up (identity is per-machine, not per-user). To restrict which
users may originate overlay traffic, add an nftables owner-match on the output
chain; see the "Multi-user hosts" section of [SECURITY.md](SECURITY.md).

### Reachability

WireGuard has no client/server roles. Both peers try to handshake and the
direction that physically works wins, then endpoint roaming pins it. So a link
forms as long as **at least one side is reachable**: a firewalled node dials an
open one, and the reply returns via the NAT hole it punched. Two fully-blocked
nodes can't pair (direct-or-fail — no relays). Greasewood inherits this semi-tolerance
of NAT/firewall issues from WireGuard directly, but it makes no serious effort to reason 
about the underlying network state and automatically just work (that is the domain of Tailscale, etc).
The best greasewood can do is to examine IP address and determine when a node obviously has no
externally reachable address (LAN NAT, CGNAT, etc) and print that in `gw diagnose`. 
So, when a reachability issue arise it is very likely to be that BOTH peers are behind a
NAT/Firewall that does not provide them an externally reachable endpoint. The only solution
in that case would be to try and make changes to the underlying network state. 

An **anchor** must be reachable (it serves the control plane), so in order for a node
to become the anchor, it must have a reachable external address. So
`anchor-promote` refuses on a node that knows it advertises no endpoint.

## Access control (roles & grants)

A fresh anchor ships **default-closed**: the grant table is a **secure star** —
the anchor (which holds `role:admin`) can SSH every node, nodes reach only the
anchor's control plane, and **nodes cannot reach each other at all**. You open
what you need by adding grants.

To control **who talks to whom, on what**, give nodes **roles** and write a
**grant table**. The mesh then *derives its tunnel topology from the policy*.
Three roles are built in:

| Role | Who holds it | Meaning |
|------|--------------|---------|
| `node` | every ordinary member (the default) | an ordinary fleet node |
| `anchor` | the anchor, and **only** the anchor | single-member reserved. Addressable in grants as `to = ["anchor"]` |
| `admin` | the anchor by default, tag any box | **terminal access** — SSH to every node.|

**Roles are CA-signed caps** (`role:<name>`), and crucially, the anchor
assigns them, a node cannot assert its own. However, the anchor can choose to
provide new nodes with a "menu" of available roles. This is helpful for auto-provisioning,
where multiple roles can join with a single standing token. 

```bash
# Fixed role — the invite decides; join takes what the token granted:
TOKEN=$(sudo gw invite --roles web)          # this token → a role:web node
sudo gw join "$TOKEN" --hostname web1

# ...or a MENU — one standing token, and the joiner picks a role from it:
MENU=$(sudo gw invite --self-roles web,worker,db)
sudo gw join "$MENU" --roles worker --hostname worker1   # anchor signs iff 'worker' is on the menu

# Change roles later without re-joining (effective at the node's next renewal):
`sudo gw set-roles web1 web,worker`
```

**Defaults for new nodes** live in the anchor's config — `[anchor]
default_roles` (`["node"]`) and `default_caps` (`["tls"]`). A
plain `gw invite` uses them; the flags override per token; they're read fresh
at each invite, so editing the config changes future enrollments with no
restart.

### The grant table derives the topology (examples)

```toml
# <data_dir>/grants.toml on the anchor  (full reference: grants.toml.example)
[[grant]]
from  = ["web", "worker"]
to    = ["api"]
ports = ["tcp/8000"]
# why: the app tier calls the API; nothing else does.

[[grant]]
from  = ["metrics"]
to    = ["*"]
ports = ["tcp/9100"]
# why: prometheus scrapes everyone — hub-and-spoke tunnels, not a clique.
```

```bash
# edit the anchor's <data_dir>/grants.toml, then apply it — with a preview:
sudo gw policy apply
#   this will change the policy: v1 → v2
#     - grant  * -> * : *
#     + grant  web -> api : tcp/8000     ← the rule change (X → Y)
#     - tunnel web1 ↔ web2               ← what actually connects/disconnects
#   apply? [y/N]
gw policy show              # on any node: the active table (flags unapplied edits)
```

**grants.toml is the source of truth.** `gw create`
writes it (the default-closed baseline — `admin -> anchor,node : tcp/22`) and signs it into the
distributed, CA-signed `policy.json` — the form nodes actually receive and
trust (a node can't trust a plaintext file from another host). To change
policy you edit grants.toml and run `gw policy apply`, which **previews the
change and asks you to confirm** before signing it: a policy change tears down
tunnels, so it is never applied silently by a stray file save. `gw policy show`
flags an edited-but-unapplied grants.toml so a forgotten apply is visible. A
joining node is handed the current signed policy at enrollment, so it enforces
the real table from its first run — the mesh never operates on an implicit
default.

With a policy applied, a tunnel exists between two nodes **only if some grant
connects their roles** (either direction — tunnels are symmetric; the grant's
direction is for port filtering). Tunnels are **minimal by construction**:
delete a grant and its tunnels are torn down on the next sync; peers,
keepalives, and handshake exposure all shrink to the grant graph. Two `web`
nodes have no tunnel unless someone writes `web -> web`, client and server
are roles that coexist without talking sideways.

**Segments are emergent, not configured.** There is no segment cap, flag, or
config key: a "segment" is the unnamed connected structure the grant graph
produces — `role:web` and `role:api` nodes granted an interface share one,
and it dissolves when the grant does. `gw watch --by-role` shows the groups
and flags **policy-expected links that are down** (a real fault) without
false-alarming on pairs the policy correctly keeps apart.

Properties to rely on:

- **Allow-only, by schema.** A flow passes iff some grant covers it; there's
  no deny rule (no action field) — grants are a set, not an ordered program,
  so no conflicts.
- **The anchor is hardwired beneath the table.** Every node always tunnels to
  the anchor (`role:*`), and no grant can prune it — the policy rides the
  directory sync, which rides the anchor tunnel, so the channel that carries
  the policy can't be severed *by* the policy.
- **Signed and replay-proof.** The table is CA-signed with a monotonic
  version; nodes adopt only newer, validly-signed tables and keep
  last-known-good on disk across reboots.
- **Anchor-assigned, mutually enforced.** A tunnel needs *both* ends to
  install each other, each reading the other's roles from its CA-signed
  credential — a node can't talk its way into a role it wasn't issued, nor be
  forced into a link it denies.

**Port enforcement is on by default.** The daemon realizes each grant's
`ports` in **greasewood's own** `table inet greasewood_<mesh>`, scoped to the
mesh interface: it default-denies mesh traffic and admits only the granted
flows (server-side inbound; a client's replies ride `ct established`, so the
asymmetry needs no rule). A fresh anchor ships **default-closed** — a secure
star where only `role:admin` (the anchor) can SSH nodes; you open services by
writing grants. Enforcement is a policy *state*, always installed, not a mode
you switch on.

It writes **only** its own table on `gw-<mesh>` — never your host firewall,
never a physical NIC — so it can only ever *tighten*, and it presupposes
you've admitted the overlay (`iifname "gw-<mesh>" accept`, or no host
firewall; `gw firewall` advises exactly that). The table **persists across
daemon restarts** (fail closed); `gw purge` removes it.

Because enforcement is on by default, **nftables must be usable** — the daemon
refuses to start rather than run silently unenforced. A host without it sets
`enforce_ports = false` under `[network]` (or a one-off `gw run
--no-enforce-ports`): grants still gate which *tunnels* exist, but port scopes
go advisory.

## Command reference

| Command            | sudo? | What it does                                              |
|--------------------|-------|-----------------------------------------------------------|
| `create`        | yes   | One-shot anchor bootstrap: CA, door key, routing, self-cred. |
| `run`              | yes   | Start the daemon (WireGuard iface, control plane, loops). Port enforcement (grant port scopes, nftables) is on by default; `--no-enforce-ports` (or `enforce_ports=false`) disables it for an nft-less host. See [Access control](#access-control-roles--grants). |
| `invite`           | yes   | Open a 15-min door window, print a single-use join token. `--standing` opens a [standing door](#baked-images--autoscaling-the-standing-door) instead: one token, any number of enrollments, until `close-door`. |
| `close-door`       | yes   | Close the current door window — permanently invalidates its token (standing or single-use); enrolled nodes unaffected. |
| `join <token>`     | yes   | Enroll this machine using a token from `invite`.          |
| `watch`            | sudo  | **Live** mesh dashboard (redraws in place, so it needs sudo for live WireGuard state): the split roster + link state, per-second throughput, and a latency column that fills in as pings return. Ctrl-C to exit. **`--snapshot`** prints one static view and exits (no root; auto-used when piped); **`--json`** emits that snapshot as a stable, versioned schema for monitors/jq (add `sudo` for live WireGuard stats) — and the human roster is *rendered from that very JSON*, so the machine contract can't silently drift from what you see. **`--by-role`** groups by role and, per group, reports **connectivity** — connected components (the emergent segments), and policy-expected-but-down edges with a firewall/NAT hint — computed fleet-wide from each node's self-reported live links. Shows how fresh the view is (time since last sync) up top. |
| `config [key]`     | no    | Print resolved config facts machine-readably for scripting — `gw config interface` gives the mesh interface name (`gw-<mesh>`), no arg lists all as `key<TAB>value`. |
| `firewall`         | no    | Print the recommended firewall ruleset (a **suggestion** — greasewood never changes your firewall; nothing is applied). The same posture on every node; with `sudo` also flags anything that looks blocked. |
| `diagnose [A [B]]` | sudo  | Pairwise link diagnosis: compare up to two nodes + the anchor side by side and explain whether a tunnel can form (policy/roles, reachability, firewall directionality with `OPEN`-inferred-from-handshake and upstream-router localization). No args = this host ↔ anchor. |
| `revoke <node>`    | no    | Revoke a node on the anchor (denies renew/publish, evicts it, frees its hostname). `<node>` = hostname, `<host>.<mesh_domain>` mesh name, or 64-char id_pub hex. |
| `set-roles <node> <r>` | no | Change a node's roles (on the anchor; effective next renewal). |
| `policy`           | show: no · apply: sudo | The mesh's grant table (roles → roles : ports; derives which tunnels exist). `show` renders the active policy on any node; `apply` (anchor) validates `grants.toml`, previews the tunnel delta, signs with the CA key, publishes. See [Roles & the grant table](#roles--the-grant-table-gw-policy). |
| `set-caps <node> <caps>` | no | Change a node's full tag set (on the anchor; effective next renewal). |
| `anchor-promote`      | yes   | Turn this enrolled node into an anchor (generate its own CA key).  |
| `cert-request`     | no    | Get an x509 TLS cert from the anchor for a local service. The daemon auto-renews it at ~half its TTL; `--reload-cmd` runs a command after each renewal, `--no-auto-renew` opts out. **`--profile <name\|path>`** issues + places the key/cert/ca where the service wants them (right owner/mode) and re-places on every renewal; `--profile <name> --show` prints a bundled template to adapt. |
| `cert-profiles`    | no    | List the bundled cert profile templates (postgres, nginx, haproxy, redis, nats, minio, mosquitto) — starting points to copy and adapt. |
| `cert-remove <name>` | sudo | Stop managing a cert (drop it from auto-renewal + remove its profile snapshot). Leaves the placed files by default; `--delete-files` removes them too. |
| `cert-status`      | no    | Show every daemon-managed TLS cert (expiry, renewal state, SANs, placed files, profile) from the manifest — wherever the files live. |
| `narrate`          | no    | Translate the `ip`/`wg` command trail (`audit.log`) into a plain-English story of what greasewood did and why. Filters: `--since`, `--peer`, `--grep`, `--failures`, `--stats`, `--raw`. |
| `rename-node <name>` | yes | Change this node's mesh hostname (anchor-validated, no re-join; refused if the anchor pinned the name). |
| `rename-mesh <name>` | yes | Rename this mesh — domain, config, data dir, interface, and service move together. Run on the anchor, then on each member (surfaced in its `gw watch`). Old names resolve + verify in TLS through a one-TTL grace window. See the [RUNBOOK SOP](RUNBOOK.md). |
| `renew`            | yes   | Force an immediate credential renewal for this node (applies an anchor-side `set-caps`/`set-roles` now, instead of at the ~half-TTL renewal). |
| `renew-all`        | no    | On the anchor: request a fleet-wide renewal (advertise `renew_after=now`; cooperating nodes renew, jittered so the anchor's rate stays ~constant with mesh size). |
| `anchor-backup`       | no    | On the anchor: write one passphrase-encrypted archive of the CA key, node registry, revoke list, door key, and anchor identity. Store it offline. |
| `anchor-restore`      | yes   | Restore a `anchor-backup` archive onto a replacement host (same CA key → a restore, not a re-root). |
| `anchor-transfer <host>` | yes | On the anchor: hand the anchor role to another host **over SSH** (same CA → no re-root; the CA never touches the mesh). Streams the encrypted state, copies the config, then stops here / starts there / verifies — rolling back if the target doesn't come up. See the [RUNBOOK SOP](RUNBOOK.md). |
| `purge`            | yes   | Remove all greasewood state from this machine.            |

Global flags: `-c/--config FILE` (default: discovered — with one mesh on the host every command finds its config unaided; with several, gw lists them and asks for `-c`) and
`-v/--verbose`. Both must precede the subcommand (`gw -v run`, not `gw run -v`).

Enrollment is door-only: `invite` on the anchor, `join` on the node. There is no
manual credential-copy path.

## Configuration

`gw create` and `gw join` write `/etc/greasewood_<name>.toml` for you; see
`greasewood.toml.example` for the full annotated schema. Key fields:

```toml
[node]
hostname = "node01"
role     = "node"          # "anchor" | "node"
caps     = ["role:mesh"]     # role:<x> tags are the grant-table vocabulary; "tls" allows certs

[network]
interface  = "gw-myfleet"
listen_port = 51900
overlay_prefix = "fd8d:e5c1:db1a:7::"        # the fleet's overlay /64 (ULA)
seeds    = ["http://[<anchor-overlay>]:51902"]  # directory URLs to pull (the anchor)
root_url = "http://[<anchor-overlay>]:51902"    # where to publish / renew
hosts_sync  = true                           # manage /etc/hosts names (on by default)
mesh_domain = "myfleet.internal"             # the mesh's ONE domain (from create <name>)

[ca]
trusted_pubs = ["<hex Ed25519 CA pubkey>"]   # a set, to allow CA migration

[anchor]                        # anchor role only
ca_key_file    = "/var/lib/greasewood/ca.key"
control_listen = ":51902"
credential_ttl = "24h"
```

### Roles

- **anchor** — holds the CA private key; serves the control plane and the
  enrollment door; participates in the mesh.
- **node** — a plain mesh participant.

### One host on two meshes

The overlay `/64` is configurable (`[network] overlay_prefix`, set at
`create --overlay-prefix`; a node learns it from its credential at join). A
node learns and verifies addresses prefix-agnostically — the self-certifying
part is the host bits, `blake2s(id_pub)`, and the CA signature attests the
prefix — so **one host can be a plain node on two independent meshes at once**
(anchor-in-two-meshes is not supported). Joining a second mesh is just:

```bash
sudo gw join "$TOKEN_B"        # that's it
```

`join` routes by the token's **CA**: a token for a mesh you're already on
refreshes that membership; an unknown CA **auto-provisions the next membership
slot** — config `/etc/greasewood2.toml`, data `/var/lib/greasewood2`, interface
`gw-<name>`, UDP `51910` (then +10 each). The mesh's **name domain rides
in the token** (declared once at `gw create <name>` → `<name>.internal`), so
every member of a mesh, including multi-mesh hosts, mounts it under the SAME
suffix, and TLS names agree fleet-wide with no flags.

**Domain collisions**: a node cannot bridge two meshes with the
same domain — no local aliasing exists (a per-host alias would diverge from the
names in the mesh's TLS certs, a debugging trap; and rewriting is off the table
since names are CA-attested). The join refuses *before* the door dance (the
token is not consumed) and tells you the fix: rename one mesh on its anchor.
Requiring a mesh name at create (becomes subdomain) should makes this a rare coincidence.

Every derived value is still overridable — pass any of the explicit knobs and
the auto-slotting steps aside entirely:

```bash
sudo gw -c /etc/gw-b.toml join "$TOKEN_B" --data-dir /var/lib/gw-b \
    --interface gw-b --listen-port 51920 --mesh-domain beta
```

**The mesh domain must differ between the two, for the same reason the interface
name must** — both are flat, host-global namespaces with no scoping. The
`/etc/hosts` block is *keyed by* `mesh_domain`, so two meshes sharing one would
(a) clobber each other's block every reconcile, each daemon strips and rewrites
the same-tagged block, and (b) collide on the names themselves: both meshes'
`db.mymesh.internal` would claim the same name for two different addresses. 

## Names

Every node has a stable overlay address, and `gw watch` shows each node's
resolvable name↔address map. Name resolution is **encouraged**: the daemon
keeps a marked `/etc/hosts` block mapping each node's address to
`<hostname>.<mesh>.internal` (e.g. `db.mymesh.internal`), built from the records that pass the reconcile loop's
full verification — the same gate that decides WireGuard peers, so a revoked or
expired node's name stops resolving on the same cycle its tunnel comes down.
It's re-checked each reconcile but *only rewritten when the block actually
changes* (a join, departure, revocation, or rename) — in steady state it never
touches the file, so it won't hammer `/etc/hosts`

```
# BEGIN greasewood — managed, do not edit
fd8d:e5c1:db1a:7:…  db.mymesh.internal
fd8d:e5c1:db1a:7:…  node01.mymesh.internal
# END greasewood
```

So `ping db.mymesh.internal`, `ssh db.mymesh.internal`, etc. just work — no DNS
server, and it keeps resolving even if the anchor is down (it's from the cache,
for as long as the cached credentials remain valid — one credential TTL, the
same horizon as the tunnels themselves). It
only ever touches the region between its markers; your own `/etc/hosts` lines are
left alone, and `--no-hosts-sync` (or `hosts_sync = false` + restart) or `gw
purge` removes the block.

A node can also publish extra **service names** under its own name via
`[network] aliases` (or automatically from a subdomain TLS cert) — a label `pg`
becomes an extra `pg.<hostname>.myfleet.internal` line pointing at that node. See the
TLS section for how this ties cert SANs to resolvable names.

**Who chooses the name.** By default a node names itself at `gw join` (defaulting
to its machine hostname) and can change it later with `gw rename-node`. If you'd rather
the anchor control it, **pin it at invite**: `gw invite --hostname db` fixes the name
at enrollment (the joiner's requested name is ignored) and marks the credential so
the node **can't `gw rename-node` itself** — to change a pinned name, re-invite with a
new `--hostname`. Either way the name is CA-attested; pinning just moves the
decision from the node to the anchor.

Two things make defaulting this on safe:
- **Names are CA-attested** (the hostname lives in the signed credential), so a
  member can't publish a record claiming another node's name to poison your hosts.
- **Names are namespaced** under the mesh's own `<name>.internal` label.

The domain is shared with TLS: `gw cert-request` with no `--san` defaults the
cert to this node's `<hostname>.myfleet.internal` **plus** its overlay address. So the
name a node is reached by is exactly the name its certificate is valid for —
resolve `db.myfleet.internal` → connect over WireGuard → TLS validates the
`db.myfleet.internal` SAN (Subject Alternative Name — the x509 field listing the
names a certificate is valid for).

A node's hostname defaults to the machine's own hostname at enrollment; change
it later with `sudo gw rename-node <newname>` (then restart the daemon). Rename goes
through the anchor, so it's uniqueness-checked and frees the old name. The keys and
overlay address don't change. (Editing `hostname` in the config directly is not
enough: the anchor wouldn't know, so always use `gw rename-node`.)

> Names are sanitized to a DNS-safe form (`ops@node01` → `ops-node01`) and must
> be **unique**. For a self-chosen name, uniqueness is checked at enrollment: a
> `join` whose (sanitized) name is already taken is refused. However, the token isn't
> immediately burned, so the joiner is told how many attempts remain and can retry with a
> different `--hostname` (a few tries per window). For a **anchor-pinned** name
> (`gw invite --hostname`), uniqueness is checked at *invite* instead, so a
> pinned name is guaranteed free before the token goes out and can't collide at
> enrollment (the joiner couldn't fix it anyway). Either way, a decommissioned
> node keeps its name until its `nodes/<id>.json` is removed on the anchor, which
> frees it for reuse.

## TLS certificates for services

The same CA that gates the mesh also issues ordinary **x509 TLS certificates**,
so a service on a node (Postgres, an internal API, etc) gets a cert that every
peer validates against one trust root — no second PKI (public-key
infrastructure). These are real x509 certs with SANs, distinct from the mesh
credential, but signed by the same Ed25519 CA key.

**What this is for (and isn't).** WireGuard already encrypts and authenticates
traffic between nodes, so TLS here is **not** about adding encryption — that part
would be redundant. Its value is at the layers WireGuard doesn't cover:

- **Service identity by name.** WireGuard authenticates the *node* you reached,
  not that you reached the *right* node. The `db.myfleet.internal`→address
  mapping lives outside its crypto. A cert with `SAN=db.myfleet.internal`, validated by
  the client, is what proves "this endpoint is authorized for that name."
- **Process/tenant identity.** The mesh interface is host-global, so any
  process on a node can use the tunnel. **mTLS** (client certs) narrows a
  connection to a specific identity and surfaces it into the app (e.g. Postgres
  cert→role) for authz and audit.
- **A free, mesh-rooted PKI.** Services that require TLS anyway (`sslmode=verify-full`,
  HTTPS clients) get certs without you running a second CA.

The value **requires the client to verify** — use `verify-full`/mTLS. Using the
cert only for opportunistic encryption (no SAN check) *is* just redundant with
WireGuard.

A node may request certs only if its credential carries the **`tls`**
capability. It's granted by the anchor, and **is on by default** (`[anchor]
default_caps = ["tls"]`), so a plain `gw invite` already yields a cert-capable
node — no extra flag:

```bash
TOKEN=$(sudo gw invite)                 # tls is in the default caps
sudo gw join "$TOKEN" --hostname dbnode
```

To make `tls` opt-in instead, set `default_caps = []` in `[anchor]` (effective on
the next invite) and grant it per-node with `gw invite --caps tls` or later with
`gw set-caps <node> …`. Either way `tls` is bounded by SAN authorization (below),
so a cert-capable node can still only get certs for its *own* names.

Then, on that node. A node can only get a cert for names it **owns**: its own
`<hostname>.<mesh_domain>`, any **subdomain** of that, and its own overlay
address. The anchor (the CA) enforces this, so a node can never obtain a valid cert
for *another* node's name and impersonate its service to TLS clients.

```bash
# On node "dbnode" — postgres.dbnode.myfleet.internal is a subdomain it owns:
sudo gw cert-request --san postgres.dbnode.myfleet.internal --name postgres
#   → writes <data_dir>/tls/postgres.key, postgres.crt, and ca.crt, AND
#     registers the label so peers can resolve postgres.dbnode.myfleet.internal

# With no --san, the cert defaults to the node's own name + overlay address:
sudo gw cert-request                 # SAN = dbnode.myfleet.internal (and its addr)

# The three files need not share a directory — override any of them, e.g. put
# the key where the service expects it and the CA in the system trust store:
sudo gw cert-request --name postgres \
     --key-out  /etc/postgresql/ssl/postgres.key \
     --cert-out /etc/postgresql/ssl/postgres.crt \
     --ca-out   /usr/local/share/ca-certificates/mesh-ca.crt

gw cert-status                       # list issued certs and their expiry
```

**Profiles — one command, files in the right place.** Assembling the per-file
flags (and getting the *ownership* right so the service can read its own key) is
the fiddly part — and worse, plain `--cert-out` leaves files `root:root`, so
auto-renewal months later rewrites them as `root:root` and silently breaks a
service running as `postgres`. A **profile** fixes the whole lifecycle: a small
TOML that says where each file goes, who owns it, and how to reload — and the
daemon **re-places and re-owns on every renewal**, not just the first issue.

```bash
gw cert-profiles                              # list bundled templates
gw cert-request --profile postgres --show     # print one to copy + adapt
sudo gw cert-request --profile ./postgres.toml   # issue + place + register reload
```

A profile is a set of `[[file]]` entries (`role` = `key`/`cert`/`ca`/`fullchain`/
`bundle`, plus `path`, `owner`, `mode`) and a `reload` command. Bundled templates
ship for **postgres, nginx, haproxy, redis, nats, minio, mosquitto** — they're *starting points, not
turnkey*: each records the OS/software version it was written against, and a
wrong path or missing service user **fails loudly** at request time rather than
mis-placing a cert. Copy one, adapt the paths to your system, pass it in.

`cert-request` is **idempotent**: an unchanged re-request of a still-valid cert is a no-op (safe to run from config management), so a change (new SAN, edited profile path) is what triggers a re-issue; `--renew` forces one. The profile you pass is snapshotted to `<data_dir>/tls/profiles/<name>.toml` for record-keeping (the manifest already holds the effective config). `gw cert-status` lists everything the daemon manages, and `gw cert-remove <name>` stops managing one (keeping the placed files unless `--delete-files`).

The leaf private key is generated locally and never sent to the anchor; only its
public key goes in the request, which is signed by the node's identity key. The
anchor returns the leaf cert plus the CA cert. Point the service at them — e.g.
Postgres `ssl_cert_file=postgres.crt`, `ssl_key_file=postgres.key`, and clients
`sslrootcert=ca.crt` with `sslmode=verify-full`. Certs are short-lived (default 7
days, `[anchor] tls_cert_ttl`), and **the daemon auto-renews each one at ~half its
TTL** into whatever paths you chose — pass `--reload-cmd "systemctl reload
postgresql"` so the service picks up the rotation (or `--no-auto-renew` for a
one-shot). Managed certs are keyed by `--name`, so re-running `cert-request` with
the same name **relocates** it (the daemon renews into the new paths and flags
the old files as orphaned) rather than leaving a duplicate. See
[RUNBOOK.md](RUNBOOK.md). Revocation is passive — stop renewing and it expires.

**Subdomain names resolve too.** A cert for `postgres.dbnode.myfleet.internal` is only
useful if clients can resolve that name — so when a `--san` is a subdomain of the
node's own mesh name, `cert-request` also **publishes** it: it adds the label
(`postgres`) to `[network] aliases`, and the daemon advertises
`postgres.dbnode.myfleet.internal → <dbnode's address>` into every node's `/etc/hosts`
block (restart the daemon, or wait for the next renewal, to propagate). Aliases
travel as bare labels in the (self-signed) `NodeRecord` and every reader expands
them under the record's *CA-attested* mesh name — so a node can only ever publish
names inside its **own** namespace, pointing at its **own** address; it can't
name or hijack anything else. You can also set `aliases = ["pg", "metrics"]`
directly in `[network]` without a cert.

**Where things live** — three files, don't conflate them:

| File | Role | Location |
|------|------|----------|
| the leaf **key/cert** + **CA cert** | what your service reads | wherever you point them (`--key-out`/`--cert-out`/`--ca-out`, else `<data_dir>/tls/`); the three need not share a directory |
| `greasewood.toml` | the daemon config; `cert-request` only *reads* it (for `data_dir` + the default SAN) and never writes it | wherever you pass `gw -c …` (default: the discovered `/etc/greasewood_<name>.toml`) |
| `<data_dir>/tls/managed.json` | the **renewal source of truth** — records each managed cert's three paths; the daemon reads it to know where to re-issue | pinned to `data_dir` (there's no separate flag; move `data_dir` in the config and it follows) |

So the file that actually "controls" where renewed certs land is the *manifest*,
not `greasewood.toml`: the TOML only locates the manifest (via `data_dir`), and
the manifest holds the per-cert paths. `cert-request` prints both so you always
know which config it read and where the renewal record is.

> **SANs are constrained to what the node owns** (its CA-registered
> `<hostname>.<mesh_domain>`, subdomains, and its overlay address) — the anchor
> refuses a cert for another node's name, so a `tls`-capable node can't
> impersonate a service it doesn't run. The `tls` capability is still the gate;
> grant it only to nodes that run services. The anchor's CA cert is also at
> `GET /ca-cert`. (After a re-root the CA changes; re-request to pick up the new
> issuer.)

### Worked example: mutual TLS for Postgres

This wires up a Postgres server that authenticates clients by their mesh
identity, with certs that rotate transparently. Nothing below hardcodes a
hostname: greasewood **binds the cert's CN and SAN to the node's own attested
`<hostname>.<mesh_domain>` automatically** — you can't set them to another
identity (the anchor *refuses* a SAN the node doesn't own and *forces* the CN to the
node's own name), so each host gets a cert for exactly its own identity with no
name typed.

**The one thing to understand about CN.** greasewood makes the CN attested, not
cosmetic, and it's the mesh FQDN — the same on the server and client cert:
- **Server cert:** clients validate `SAN = DNS:<db-host>.<mesh_domain>` under
  `sslmode=verify-full`. Connecting by overlay address works too — the node's own
  address is a SAN by default.
- **Client cert:** the CN *is* the identity Postgres maps to a role. It is the
  connecting node's `<hostname>.<mesh_domain>` (e.g. `nats01.myfleet.internal`), so
  that FQDN — not a bare label — is what your `pg_ident.conf` map keys on.

**On the database host.** Point the three files at fixed, host-agnostic paths
(the Debian `ssl-cert` group layout, which satisfies Postgres's key-permission
check with a root-owned key):

```bash
sudo gw cert-request --name pg-server \
  --key-out  /etc/ssl/private/gw-postgres.key \
  --cert-out /etc/ssl/certs/gw-postgres.crt \
  --ca-out   /etc/ssl/certs/gw-myfleet-ca.crt \
  --reload-cmd /usr/local/sbin/gw-pg-reload
# CN + SAN default to THIS node's mesh name — no --san needed.
# --name is just the manifest key (so cert-status is readable and a re-request
# relocates in place); it does NOT affect the cert's identity.
```

One-time ownership so `postgres` can read a root-owned key (needs a restart):

```bash
sudo adduser postgres ssl-cert
sudo chgrp ssl-cert /etc/ssl/private/gw-postgres.key
sudo chmod 640      /etc/ssl/private/gw-postgres.key
sudo systemctl restart postgresql
```

`postgresql.conf` — set once, never touched again:

```
ssl = on
ssl_cert_file = '/etc/ssl/certs/gw-postgres.crt'
ssl_key_file  = '/etc/ssl/private/gw-postgres.key'
ssl_ca_file   = '/etc/ssl/certs/gw-myfleet-ca.crt'   # verifies client certs
```

**Why rotation just works.** greasewood renews *in place* — it truncates and
rewrites each file at its path and never re-chmods an existing one — so the
ownership and mode you set that first time are **preserved on every rotation**.
Postgres doesn't watch the files; it re-reads them on `SIGHUP`. So the
`--reload-cmd` only needs to reload (a restart is unnecessary and drops
connections). Make it a script that asserts the key perms first, as a guard
against a botched change:

```sh
#!/bin/sh
# /usr/local/sbin/gw-pg-reload   (chmod 0755, root-owned)
set -e
key=/etc/ssl/private/gw-postgres.key
test "$(stat -c '%U:%G %a' "$key")" = "root:ssl-cert 640" || {
  echo "gw-pg-reload: $key is $(stat -c '%U:%G %a' "$key"), want root:ssl-cert 640" >&2
  exit 1   # refuse to reload with wrong perms rather than break TLS
}
exec systemctl reload postgresql
```

**On each client node.** Request its own cert (again, identity is automatic) and
point libpq at it:

```bash
sudo gw cert-request --name pg-client \
  --key-out  /etc/gw/pg-client.key \
  --cert-out /etc/gw/pg-client.crt \
  --ca-out   /etc/gw/gw-myfleet-ca.crt
# connect: sslmode=verify-full sslrootcert=/etc/gw/gw-myfleet-ca.crt \
#          sslcert=/etc/gw/pg-client.crt sslkey=/etc/gw/pg-client.key
```

**Map identities to roles on the server.** `pg_hba.conf`:

```
hostssl all all ::/0 cert map=mesh clientcert=verify-full
```

`pg_ident.conf` — the map keys on each client's mesh FQDN (its automatic CN):

```
# MAPNAME   CERT CN (= client's <hostname>.<mesh_domain>)   PG ROLE
mesh        nats01.mymesh.internal                              nats
mesh        chat01.mymesh.internal                              chat
```

This is the only place client hostnames appear, it's the allow-list of *which*
identities may connect, and each entry is that node's own automatic name.

> **CA rotation.** The `ssl_ca_file` matters only because of client-cert auth. A
> re-root changes the CA, and both the server's CA file and every client cert
> re-issue under the new CA on their next renewal, so rotate the CA (re-root)
> and let the fleet re-issue together; don't swap a CA independently, or client
> certs signed by the old one stop validating.

## Moving the anchor (re-root)

No node is forever-critical: because a node trusts a CA **key**, not a machine,
any node that holds the CA authority and serves the directory *is* the anchor.
Moving the anchor is therefore a deliberate **re-root** — swap which CA key the
fleet trusts — not an automatic handover. `trusted_pubs` is a **set**, so you
trust the old and new CA during an overlap and the move is non-disruptive.

The CA private key never moves: the new anchor generates its own key, and you push
the new *public* key into every node's `trusted_pubs`. Migrating from anchor **A**
to a new node **B**:

1. **Enroll B as an ordinary node** (`gw join …`) and start it — so it's a
   reachable mesh member every node can renew against over the overlay.
2. **Promote B:** `sudo gw anchor-promote` generates B's own CA key and flips it to
   `role=anchor` (keeping trust in A), printing B's CA pubkey + control endpoint;
   then `sudo gw run`, and B serves the control plane on its own overlay address.
3. **On every node** (Ansible): add B's CA pubkey to `[ca] trusted_pubs` (keep
   A's) and repoint `root_url` + `seeds` to B; restart the daemon. The fleet now
   trusts A **and** B — this is the overlap.
4. **Nodes renew under B.** B never enrolled them, but re-issues from each node's
   still-trusted directory record (hostname/caps are CA-attested) — nothing to
   copy. `sudo gw renew-all` on B pulls the fleet over promptly. Re-apply any
   `gw revoke` on B first (a fresh CA doesn't inherit A's revoke list).
5. **Once every node holds a B-signed credential,** drop A's CA pubkey from
   `trusted_pubs` fleet-wide, then decommission A.

Throughout, **A and B both run as anchors** — that's the point of the overlap, and
there's no clash: each anchor's control plane binds to its *own* overlay address
(the hash of its own identity key), the fleet trusts both CAs at once, and the
directory is eventually-consistent (records merge by highest sequence number, and
each node renews against the one anchor its `root_url` points at). Existing tunnels
stay up throughout (the data plane never depends on the anchor), so the handover is
non-disruptive. Plan the overlap to last at least one credential TTL so every node
renews under B in time. See [RUNBOOK.md](RUNBOOK.md) for the full graceful vs
emergency (compromised/lost-key) procedures.

## Testing

Unit tests run in ~30s with no privileges (`pip install -e '.[test]' && python
-m pytest`). The Podman-based integration/stress suite and the nightly
Hypothesis "deep" tier are documented in **[TESTING.md](TESTING.md)**.

## Design notes & non-goals

The [non-goals](#how-it-compares) — routing/relays, NAT traversal, IPv4 overlay,
cross-platform — aren't missing, they're the point. A few internal ideas are
**deferred rather than overlooked** — named here with the *trigger* that would
make them worth building:

- **Gossip between nodes** — if the network ever genuinely partitions (today every
  node pulls the directory from the anchor).
- **Lazy, on-demand tunnels** — at hundreds of nodes, if a full peer mesh becomes
  too many links to hold open.
- **Threshold CA** — if single-anchor-key compromise becomes unacceptable.
- **CA cross-signing to smooth re-root** — let the old CA sign a short-lived,
  directory-distributed "also trust the new CA" delegation, so a graceful
  [re-root](#moving-the-anchor-re-root) doesn't require pushing the new key into every
  node's `trusted_pubs` up front (the config edit becomes a calm, batchable
  follow-up instead of a race against credential expiry). Trigger: re-root friction
  in practice. Would be opt-in, short-lived, and logged, since it loosens the
  config-only trust root; emergency re-root (old CA lost) still needs the
  out-of-band config push.

**Clock integrity is part of the security posture.** Every allow/deny is a
timestamp comparison against a credential expiry, so run NTP/chrony on every
node.

**CA trust is a set, not a single key.** The CA (and anchor) is moved by a
re-root — trust the new key alongside the old during an overlap, then drop the
old — don't move the private key to a new machine. See [Moving the anchor](#moving-the-anchor-re-root).

## Security & operations

- **[SECURITY.md](SECURITY.md)** — trust boundaries, what the 7-step check
  enforces, accepted risks, and the results of the security review.
- **[RUNBOOK.md](RUNBOOK.md)** — disaster SOPs: compromised node, lost/leaked CA
  key, destroyed anchor, fleet-wide teardown, and how to read `gw diagnose`.


## AI Disclaimer

Greasewood was built with the assistance of SWE LLM agents, if that matters to you. 

