# Greasewood

A minimal, self-hosted WireGuard mesh overlay — by far the greasiest of them all.

Its one priority is being **easy to reason about**. It was built by someone who
lovingly maintained a fleet of hand-written WireGuard/networkd text files far
past the point of practical, and wanted the smallest possible thing that turns
those files into a real mesh.

Many of its features are also limitations, chosen for simplicity. Let me show you
its features!

- **[Private.](#membership)** Membership is gated by a certificate authority;
  revoke a node by not renewing it.
- **[Self-contained.](#the-hub)** The hub is just a normal node with a CA — no
  coordination service, no SaaS.
- **[Direct-or-fail.](#direct-or-fail)** No routing, no relays. A link comes up
  directly or it honestly fails.
- **[IPv6 overlay.](#ipv6-overlay)** The overlay is IPv6-only; the underlay may be
  IPv4 or IPv6. No NAT traversal.
- **[Self-certifying addresses.](#self-certifying-addresses)** A node's IPv6
  address is a hash of its identity key.
- **[Segmented.](#access-control-segments)** Optional `segment:` tags control who
  talks to whom.
- **[Named.](#names-gwinternal)** Every node gets a `<host>.gw.internal` name and
  matching TLS certs from the same CA.
- **[Offline-tolerant.](#offline-tolerance)** The hub can be down for a credential
  lifetime — nodes run from cache.
- **[Hands-off.](#firewall)** Never touches your firewall — it prints the rules,
  you apply them.
- **[Linux-only.](#linux-only)** Built on the Linux kernel's own WireGuard and
  networking — not a portable userspace/Go stack. Best run as a systemd service.
- **[Auditable.](#auditable)** Pure Python, one dependency, driving it all through
  the stock `wg`/`ip` tools over subprocess. Greasy.

> Status: early but functional. The full path — enrollment, directory, the
> reconcile loop, door-based join, credential renewal, expiry-driven revocation,
> segmentation, TLS service certs, and name resolution — works end to end
> and is covered by unit + container integration tests. It's a personal project,
> so expect rough edges.

## How it compares

The nearest full-featured projects are **Tailscale**, **Nebula**, and
**innernet**. Next to greasewood they're all bigger systems that do more — and
the "more" is consistent:

- **More infrastructure to get peers connected.** Relays and hole-punching
  (Tailscale), lighthouses and hole-punching (Nebula), a coordination server
  (innernet) — plus an always-on control plane or registry. greasewood does none
  of it: the hub is a normal node that can be *offline* for a credential
  lifetime, and links are **direct-or-fail** — no traversal, no relays.
- **They assign addresses.** A control plane hands them out, or they're baked
  into the cert. greasewood **derives** the address from the identity key — no
  allocator.
- **Broader reach.** All three run beyond Linux. greasewood is **Linux-only**,
  with an **IPv6-only overlay** (the underlay may be v4 or v6).

That's the whole trade — and it's why the feature list above doubles as a list of
limitations. Everything greasewood *won't* do — traverse NAT, assign addresses,
route, run on Windows, keep a service always on — is a capability those projects
add and greasewood drops on purpose, for simplicity. **The limitations are the
features.** Reach for one of the others when you want "just works
anywhere"; reach for greasewood when your network is already sane and you'd rather
own and audit every piece.

## Membership

Membership is a **CA-signed credential with an expiry** — there is no membership
list to push around and no CRL. Two keys and two signed objects carry it:

**Two keys per node**, deliberately split:

- `id_priv` / `id_pub` (Ed25519) — durable identity. It derives the node's
  overlay address and authorizes credential renewal. Used rarely; guard it hard
  (a leak is catastrophic).
- `wg_priv` / `wg_pub` (X25519) — the hot WireGuard tunnel key. It lives
  unattended on disk so the node survives reboots, and it's self-limiting: a leak
  expires with the credential.

**Two signed objects:**

- **Credential** — signed by the CA. Binds `id_pub`, `wg_pub`, overlay address,
  hostname, capabilities, and an expiry. Slow-moving (default 24h TTL). The
  hostname lives here (not in the record), so a node can't self-assert a name the
  CA didn't grant — the name is CA-attested end to end.
- **NodeRecord** — signed by the node's own `id_priv`. Carries the credential
  plus fast-moving facts (endpoints, a sequence number); its `hostname` is read
  from the credential. This is what gets published through the directory.

**Revocation is expiry-based (no CRL).** `gw revoke <id>` on the hub takes effect
there immediately — the hub re-reads its revoke list each reconcile cycle,
dropping the node from its own interface within seconds, and refuses the node's
renewals from then on. It does **not** reach the rest of the fleet instantly:
other nodes keep trusting the node's credential until it expires. But since the
node can no longer renew, that credential lapses within at most one
`credential_ttl`, at which point every node rejects it — the fleet-wide eviction.
Shorten `credential_ttl` for a tighter bound.

## The hub

The hub is **just a normal mesh node** that additionally holds the CA key and
runs a small HTTP **control plane** — `GET /directory`, `POST /publish`, `POST
/renew`, `GET /health` — bound to its overlay address (reachable only through the
mesh, never the underlay). There is no separate coordination service, no SaaS,
nothing always-on in the data path. Nodes poll `/directory`, merge records by
highest sequence number, and cache them locally.

Because trust is anchored to the CA *key* (not a machine), any node can become
the hub — restore the key onto a replacement, or stand up a new CA and re-point
the fleet. See [Moving the hub](#moving-the-hub-re-root).

## Direct-or-fail

There is no routing, no multi-hop, no relays, and no NAT traversal. Two nodes
either form a **direct** WireGuard tunnel or the link honestly fails — it never
silently falls back to relaying through a third party, so there's no hidden path
to reason about.

The only thing that touches the data plane is the **reconcile loop**: every few
seconds each node walks the directory and, per peer, runs seven checks — verify
the CA signature, check expiry, verify the self-signature, verify the address
derives from `id_pub`, check the revoke list, check the authorization policy —
then installs or removes that peer with `wg set`. Membership changes,
revocations, key rotations, and segmentation all reduce to "add or remove a
peer," computed locally with no coordinator. A link forms as long as at least one
side is reachable (see [Reachability](#reachability-inbound)); two unreachable
nodes can't pair.

## IPv6 overlay

The **overlay is IPv6-only** — every node's mesh address is a hash of its
identity key under the ULA prefix, and all in-tunnel traffic is IPv6. That's a
deliberate identity choice, and it stays.

The **underlay** (the real network each WireGuard endpoint lives on) can be
**IPv4 or IPv6**. A node advertises whatever public endpoint(s) it has, and each
node dials a peer over a family they share — so greasewood runs on v4-only cloud
VMs (EC2, Vultr — both IPv4-by-default) just as well as on IPv6 GUAs. The overlay
is v6 either way; only the transport underneath differs. (Managing backend cloud
instances was the motivating use, which is exactly why the v4 underlay matters.)

Still deliberately absent — **no NAT traversal, no routing, no relays**. The
direct-or-fail model assumes the network already permits a direct connection (no
STUN, no hole-punching). A NAT'd node is simply `inbound=no`: it dials out to
reachable peers and the hub, but two unreachable nodes can't pair — and a v4-only
node and a v6-only node share no underlay family, so they can't pair either
(direct-or-fail across address families).

Inbound v4 nodes behind 1:1 NAT (e.g. EC2, whose interface holds only a private
v4) can't autodetect their public address — pass `--endpoint <public-v4>:<port>`
at `create`/`join`. Outbound-only (NAT'd) nodes need nothing: they advertise
no endpoint and dial out.

A dual-stack peer advertises **both** its v6 and v4 endpoints (v6 first). If the
preferred one produces no handshake for ~20s, the reconcile loop rotates to the
next advertised endpoint and keeps round-robining until one connects — so a peer
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

No encoding step is needed to fit the hash into an address: an IPv6 address is
just 128 bits, so the low 64 (the interface identifier) can be *any* value — the
first 8 bytes of the digest drop straight in, and the familiar `xxxx:xxxx:…`
colon-hex is only how those bytes are printed. (Those 64 bits of entropy are also
where the ~2⁶⁴ collision figure below comes from.)

**Why it can't be spoofed.** To be accepted at an address you present a signed
record, and every verifier (any potential peer, and the hub) runs two independent
checks: `address == hash(id_pub)`
(the address is the legitimate derivation of the key), and the record is
**self-signed by `id_priv`** (you actually hold that key). To steal node `db`'s
address `X = hash(db_id_pub)` you would need an `id_pub` that hashes to `X` — a
~2⁶⁴ preimage search (brute-forcing a key that hashes to that exact address) —
*and* you'd still need db's `id_priv` to sign as db. Two
independent locks. Notably, **not even the CA can reassign an address**: an
address is `hash(your key)` by construction, so the CA can't hand db's address to
a different key. The CA vouches for *membership*; the address vouches for itself.

**How the alternatives get spoofed.** Everywhere else the address is a *number
assigned by an authority* — a control server (Tailscale, innernet) or written
into a signed cert (Nebula) — with no cryptographic tie to the key. That binding
is only as strong as the authority: compromise or trick the assigner into
remapping db's address to your key, poison the distributed mapping, or (in a flat
network) just forge the source IP. In greasewood there's no mapping to poison and
no authority to subvert for the address — it's derived, not granted.

The cost, to keep it honest: the address is an opaque hash (no human- or
segment-legible structure — which is why [segmentation](#access-control-segments)
is tag-based, not CIDR), and the 64-bit host portion makes a *deliberate*
collision ~2⁶⁴ work rather than impossible. Both are deliberate trades for "the
address is the identity, and nobody assigns it."

## Offline tolerance

Every node caches the directory on disk and keeps its tunnels running from that
cache, so the **hub can be down for up to one credential lifetime** and existing
node↔node links are unaffected — the hub is never in the data path. Only new
enrollments and credential renewals need a reachable hub. Restore or replace the
hub within that window (see [Moving the hub](#moving-the-hub-re-root) and the
[RUNBOOK](RUNBOOK.md)) and nothing ever drops.

## Linux-only

greasewood is built on **Linux-specific kernel interfaces** — the in-kernel
WireGuard module and the kernel's own networking — and is best run as a
**systemd** service (the recommended way to keep the daemon up across reboots and
crashes; a bare `gw run` works for dev). It relies on the
kernel's WireGuard and on systemd rather than shipping its own userspace
transport (the way a Go implementation such as `wireguard-go` does) or its own
supervisor. It reaches those kernel interfaces via the stock `wg`/`ip` tools
(see [Auditable](#auditable)). A macOS/Windows port would mean a different
data-plane backend and is out of scope.

## Auditable

The entire thing is **pure Python (3.11+), one dependency (`cryptography`), one
binary (`gw`)**, and it manages the data plane by shelling out to `wg`/`ip` via
subprocess. That's greasy. The clean way would be
netlink bindings — but it's a deliberate trade: you can read the exact `wg set
peer …` commands, run them by hand, and compare them against what `wg show`
reports.

## Install

Requires Linux with the WireGuard kernel module (built into 5.6+), the
`wireguard-tools` (`wg`) and `iproute2` (`ip`) packages, and Python 3.11+.

```bash
pip install greasewood
```

Or from source:

```bash
git clone https://gitlab.com/cschlick/greasewood.git
cd greasewood
pip install .              # add '.[test]' to also get pytest
```

Either installs the `gw` command. Most subcommands need sudo/root (they create
WireGuard interfaces and edit routing); `gw nodes` does not.

The Quickstart below runs the daemon by hand with `gw run`. For real use, run it
as a managed systemd service instead — see [Running as a
service](#running-as-a-service); then the workflow is just install → setup/join.

## Quickstart

### 1. Bootstrap the hub

On the machine that will hold the CA and serve enrollment:

```bash
sudo gw create
sudo gw run
```

`create` generates the CA, the persistent door key, the policy routing for
the enrollment door, and the hub's own credential, then writes
`/etc/greasewood.toml`. `gw run` starts the daemon: it brings up the `gw-mesh`
WireGuard interface, serves the control plane, and watches for door windows.

The hub takes this machine's hostname like any other node — it isn't named
anything special. You tell which node is the hub from `role: hub` in
`gw nodes`, not from its name. (Pass `--hostname <name>` to override the default.)

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

**Why a door — why can't the token just contain everything to peer over
`gw-mesh`?** Because WireGuard peering is *mutual*: to bring up a tunnel to the
hub over any interface, the hub must already have **your** public key in its peer
list. At invite time your real keys don't exist yet — they're generated locally
at `join`, and private keys never travel — so the hub cannot pre-authorize your
real identity key. Handing you the hub's `gw-mesh` details in the token gets you
nowhere: the hub would drop your handshake, never having heard of your key.

What the token *can* do is carry a 32-byte seed that **both sides expand (HKDF)
into the same throwaway door keypair + PSK**. The hub derives that throwaway
pubkey from the seed it minted and pre-installs it as a peer; you derive the
matching private key — so now a tunnel can actually form. But it forms under a
**disposable, credential-less key, not your identity** — and a non-member key
like that has no business on the live overlay. That's why the door is a
*separate* interface, not `gw-mesh`:

- it runs on its own **dedicated door subnet** (`fd8d:…:d::/64`) — not a
  throwaway address squatting on the real overlay, which would break the
  self-certifying `address = hash(identity)` invariant;
- it reaches **only the enroll daemon** (not the directory/control plane, not
  other peers) — a token-holder can do exactly one thing: request a credential;
- it's **torn down** the moment your credential is issued.

You bring up `gw-mesh`, with your *real* key and its self-certifying address, only
once you hold that credential — and from then on every peer learns your key and
address from the directory as usual. Running the throwaway peering over `gw-mesh`
instead would drop a credential-less stranger onto the live mesh with a fake
address and expose the whole control plane to a mere token-holder — which is
exactly what the door exists to prevent.

### 3. Check it

```bash
gw nodes               # local node + directory view
sudo gw diagnose        # per-peer: why each link is/isn't forming
sudo wg show gw-mesh    # live WireGuard peers
```

`gw diagnose` is the tool to reach for when a peer won't connect. Because the
mesh is direct-or-fail, a link that doesn't form is otherwise silent; diagnose
runs the full verification chain per peer and overlays the live WireGuard
handshake state, so it tells you *which* step failed — expired credential,
untrusted CA, policy denial, or "configured but no handshake, check the peer's
firewall."

It's a **local view, not a fleet dashboard** — run it *on the node that's having
trouble*. It judges each link from *that* node's own directory cache, trusted-CA
set, and live tunnels, so every verdict means "can **this** node reach that peer"
(e.g. `REJECTED` = this node won't install it; `LINKED` = this node has a live
tunnel to it) — not the peer's status everywhere. See [RUNBOOK.md](RUNBOOK.md)
for how to read it and what to do next.

For each `LINKED` peer it also runs a **path-MTU probe** — a don't-fragment ping
at the tunnel's interface MTU. WireGuard-over-cloud MTU blackholes are nasty:
small traffic and SSH work, but TLS handshakes and large transfers hang because
full-size tunnel packets exceed the underlay path MTU. If the small ping passes
but the full-size one is dropped, diagnose flags it and suggests lowering the
tunnel MTU. Pass `--no-mtu-probe` to skip the extra pings.

## Running as a service

`gw run` in a terminal is fine for trying things out, but in practice you want
the daemon managed by systemd — survives reboots, restarts on failure, logs to
the journal. The model is **install once, then forget `gw run`**: a path unit
watches for `/etc/greasewood.toml` and starts the daemon the moment `create`
or `join` writes it. So the workflow becomes just **install → setup/join**.

Install the service (pip-only, no Ansible):

```bash
sudo gw install-service
```

This writes `/etc/systemd/system/greasewood.{service,path}`, enables the path
watcher (armed immediately) and the service (for boot), and does **not** start a
daemon until you configure the node. After it's installed:

```bash
sudo gw create                     # on the hub        → daemon auto-starts
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

### Root vs. sudo

`gw` needs root (it manages WireGuard interfaces), and the systemd service always
runs as root, so config and data paths (`/etc/greasewood.toml`,
`/var/lib/greasewood`) are read identically however you invoke it — nothing gets
corrupted either way. Two behaviors *do* differ, so pick one style and stick with
it:

- **State ownership.** Run **via `sudo`** and greasewood chowns the data dir back
  to the invoking user afterward (secrets stay mode `0600`), so you can run
  read-only commands like `gw nodes` without sudo. Run **as bare root** and the
  files stay root-owned (no passwordless reads). Don't *alternate* — a later
  `sudo gw …` re-chowns everything to your user, a root-direct run doesn't, so
  ownership will flip back and forth. It won't break the service (root reads
  everything), but it's untidy. The documented path is **`sudo gw …` as your
  normal user**.
- **Environment variables.** `sudo` strips the environment by default. This only
  matters if you protect the CA key with `ca_key_passphrase_env`: a var exported
  in your shell won't reach `sudo gw` (you'd get "environment variable is
  empty"). Use `sudo -E` for one-off commands, and for the **service** set it in
  the unit's `Environment=` / `EnvironmentFile=`, never a login shell.

(Keep config paths absolute — a `~` in `data_dir`/`ca_key_file` expands to the
*running* user's home, which differs under sudo.)

## Provisioning many nodes

Enrollment tokens are **pushed by the hub, never pulled by nodes**. A node
cannot request admission; you (or an orchestrator acting on the hub) decide to
admit a machine, run `gw invite`, and deliver the token out of band. The node
only redeems what it was handed. The door is **single-slot by construction**:
each invite opens one enrollment window, and the hub closes it the instant that
node finishes joining — so provisioning is one node at a time.

**The usual way is copy-paste.** On the hub:

```bash
sudo gw invite            # prints a one-time token
```

Copy the token, open a terminal on the new node, and run:

```bash
sudo gw join <token>
sudo gw run
```

For several machines just repeat — invite, paste, join — one at a time. There's
only **one door open at a time**: each `gw invite` replaces the previous window,
so a token you generated but haven't used yet stops working the moment you
generate another. (If you do overwrite an unused token, `gw invite` warns you —
on stderr, so the new token still prints cleanly to stdout and `TOKEN=$(gw
invite)` keeps working.)

**To automate over SSH**, two flags make the token pipeable: `gw invite -q`
prints only the token, and `gw join -` reads it from stdin (so it stays out of
the node's `ps`, and it tolerates raw `gw invite` output). Wiring those into a
loop is left to you — just two things to respect:

- Keep it **sequential** — invite, wait for that join to finish, then the next
  invite. The door serves one node at a time on the wire, so issuing in parallel
  buys nothing.
- If you pipe the token over SSH stdin, `sudo` can't also prompt for a password
  on that channel, so that form needs passwordless privilege **scoped to join**
  (`<user> ALL=(root) NOPASSWD: /usr/local/bin/gw join *`). Never grant blanket
  `NOPASSWD: gw` — with `install-service --exec` that's effectively passwordless
  root.

## Firewall

**greasewood never modfies your firewall ever.** Its control
plane (`51902/tcp`) and enrollment RPC (`51903/tcp`) bind only to the node's
overlay address and loopback — *never* the underlay — so nothing it runs is
reachable off-mesh regardless of firewall policy. The only thing that must face
the underlay is WireGuard itself (UDP), which you open like for any VPN.

`create`, `join`, and `set-inbound` **check** the local nftables ruleset and
loudly warn if a needed port looks blocked by a default-drop policy, printing the
exact rule to add. That's all greasewood does. You apply the printed rules yourself (put them in your nftables
config, or however you configure your firewall).

**No firewall at all? Then there's nothing to do — and nothing extra is
exposed.** greasewood binds nothing to the underlay except its WireGuard UDP
port(s): `51900` (mesh) on any inbound node, plus `51901` (the enrollment door)
on the hub. Those are WireGuard, which is designed to face the internet — it
silently drops any packet that isn't a valid handshake from a configured peer (no
reply, no info leak). Everything else — the control plane (`51902`) and the
enrollment exchange (`51903`) — binds to the overlay address or the door tunnel,
so it's *structurally* off the underlay whether or not you run a firewall. A
greasewood host with no firewall is therefore no more exposed than a plain
WireGuard host with no firewall. The rules below matter only on a host that runs
a **default-drop** policy and so must explicitly *allow* those ports through.

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
(or `create --listen-port/--control-port/--door-port`). The door port rides
in join tokens and the control port in the enrollment response, so nodes pick up
non-default values automatically — no client config. (The internal enrollment
port lives inside the door tunnel and can't collide, so it isn't a knob.)

Your base default-drop ruleset should also include `ct state established,related
accept`. It's what lets an **outbound-only** node work:
such a node opens *no* greasewood inbound ports — it dials peers and the hub,
and the replies come back through `established,related`.

**Recommended posture: apply the same ruleset on *every* node, not just the
current hub.** Any node can be promoted to hub ([Moving the
hub](#moving-the-hub-re-root)), so a uniform ruleset means a hub handover
needs **no firewall change anywhere**. Opening `51902`/`51903` on a node that
isn't a hub is harmless: nothing is bound there, so the kernel just refuses the
connection until that node actually becomes a hub and binds it. Plain nodes run
no control plane, so on a node that will never be a hub you *could* omit the `gw-mesh`/
`gw-door` TCP rules and open only the two UDP ports if you really want the most minimal config.

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
does that on its own. So leaving it `yes` when you're actually unreachable doesn't
break connectivity (you still dial out); peers just waste handshake attempts on
your dead endpoint and converge slower — and `gw diagnose` will flag those as
"configured but no handshake."

## Access control (segments)

By default every mesh node can talk to every other — one flat segment. To
control **who talks to whom**, put nodes in different **segments**. Two nodes peer
only if they **share a segment**; every node is in `segment:mesh` by default (the
flat default pool), and putting a node in another segment isolates it.

Segments are `segment:<name>` tags in the node's CA-signed credential. Crucially,
**the hub assigns them at `gw invite` — a joining node cannot choose its own** (no
self-assertion). Whoever you hand a token to gets exactly the segments that invite
specified:

```bash
# On the hub — the invite decides the node's segments:
TOKEN=$(sudo gw invite --segments prod,web)   # a token for a node in prod + web
# On the new node — join takes no segment flags; it gets what the token granted:
sudo gw join "$TOKEN" --hostname web1
```

A node's segments show up in `gw nodes` (a `segments` column). To change them
later **without re-joining**, run `gw set-segments <node> prod,web` on the hub —
it takes effect at the node's next renewal (or re-invite + re-join for an
immediate change).

**Defaults for new nodes** live in the hub's config — `[hub] default_segments`
(ships `["mesh"]`) and `default_caps` (ships `["tls"]`, so TLS is on by default).
A plain `gw invite` with no `--segments`/`--caps` uses them; the flags override
per token. They're read fresh at each invite, so **editing the config changes
what future enrollments get, anytime, with no restart** — e.g. set
`default_caps = []` to make TLS opt-in, or `default_segments = ["core"]` to rename
the default segment. (Renaming it only affects *new* nodes; existing
`segment:mesh` nodes stay in `mesh` until you `gw set-segments` them too.)

The rule is one line — **share a segment** (`reconcile.default_policy`):

- **share a segment** → may peer (a node in several segments peers with anyone
  sharing one — a "bridge" node).
- **default** → every node gets `segment:mesh`, so a fleet with no segments set is
  one open mesh (everyone shares `mesh`).
- **`segment:*`** on either side → reaches everyone. The hub carries it
  automatically (it must serve every node); grant it to a shared-services node
  with `gw invite --segments '*'`.
- **no shared segment** → **denied** (putting a node in `segment:prod` drops it
  from `mesh`, isolating it from the default pool; a node in *no* segment peers
  with no one).

**`mesh` vs `*`:** `mesh` is just the default segment every node lands in — an
ordinary name that reaches only other `mesh` nodes; `*` is the reach-all wildcard
(special-cased), so a `segment:*` node reaches *every* segment:

| node A | node B | peer? | why |
|--------|--------|-------|-----|
| `segment:mesh` | `segment:mesh` | ✅ | share `mesh` |
| `segment:mesh` | `segment:prod` | ❌ | no shared segment |
| `segment:*`    | `segment:prod` | ✅ | `*` reaches all |
| `segment:*`    | `segment:mesh` | ✅ | `*` reaches all |

Two properties worth knowing:

- **Hub-assigned, attested, mutually enforced.** Segments are decided by the hub
  at admission and bound into the CA-signed credential — a node **can't
  self-assert** a segment it wasn't granted. A tunnel needs *both* ends to install
  each other, and each side reads the *other's* segments from its credential, so a
  node can neither talk its way into a segment nor be forced into a link it denies.
- **Node-level and symmetric**, not port-level or one-way. Segments decide whether
  two nodes may have a tunnel *at all*; "A may reach B:5432 but not B:22" is a
  firewall concern — use your own nftables on `gw-mesh` (see
  [SECURITY.md](SECURITY.md)).

## Command reference

| Command            | sudo? | What it does                                              |
|--------------------|-------|-----------------------------------------------------------|
| `create`        | yes   | One-shot hub bootstrap: CA, door key, routing, self-cred. |
| `run`              | yes   | Start the daemon (WireGuard iface, control plane, loops). |
| `invite`           | yes   | Open a 15-min door window, print a single-use join token. |
| `join <token>`     | yes   | Enroll this machine using a token from `invite`.          |
| `nodes`            | no    | List the mesh nodes (this node's directory) + who you are. `--by-segment` groups into one table per segment (a node appears under each of its segments; `segment:*` nodes under all). |
| `revoke <id_pub>`  | no    | Add an identity to the revoke list (on the hub).          |
| `set-segments <node> <s>` | no | Change a node's segments (on the hub; effective next renewal). |
| `set-caps <node> <caps>` | no | Change a node's full tag set (on the hub; effective next renewal). |
| `hub-promote`      | yes   | Turn this enrolled node into a hub (generate its own CA key).  |
| `cert-request`     | no    | Get an x509 TLS cert from the hub for a local service. The daemon then auto-renews it at ~half its TTL; `--reload-cmd` runs a command (e.g. `systemctl reload postgresql`) after each renewal, `--no-auto-renew` opts out. |
| `cert-status`      | no    | Show local TLS certs and their expiry.                     |
| `set-inbound`      | yes   | Change reachability (yes/no).                              |
| `rename <name>`    | yes   | Change this node's mesh hostname (hub-validated, no re-join; refused if the hub pinned the name). |
| `renew`            | yes   | Force an immediate credential renewal for this node (applies a hub-side `set-caps`/`set-segments` now, instead of at the ~half-TTL renewal). |
| `renew-all`        | no    | On the hub: request a fleet-wide renewal (advertise `renew_after=now`; cooperating nodes renew, jittered so the hub's rate stays ~constant with mesh size). |
| `hub-backup`       | no    | On the hub: write one passphrase-encrypted archive of the CA key, node registry, revoke list, door key, and hub identity. Store it offline. |
| `hub-restore`      | yes   | Restore a `hub-backup` archive onto a replacement host (same CA key → a restore, not a re-root). |
| `install-service`  | yes   | Install + enable the systemd units (run as a service).     |
| `uninstall-service`| yes   | Disable + remove the systemd units.                        |
| `purge`            | yes   | Remove all greasewood state from this machine.            |

Global flags: `-c/--config FILE` (default `/etc/greasewood.toml`) and
`-v/--verbose`. Both must precede the subcommand (`gw -v run`, not `gw run -v`).

Enrollment is door-only: `invite` on the hub, `join` on the node. There is no
manual credential-copy path.

## Configuration

`gw create` and `gw join` write `/etc/greasewood.toml` for you; see
`greasewood.toml.example` for the full annotated schema. Key fields:

```toml
[node]
hostname = "node01"
role     = "node"          # "hub" | "node"
inbound  = "yes"           # can this node accept cold inbound handshakes?
caps     = ["segment:mesh"]  # segment:<x> tags segment the mesh; "tls" allows certs

[network]
interface  = "gw-mesh"
listen_port = 51900
overlay_prefix = "fd8d:e5c1:db1a:7::"        # the fleet's overlay /64 (ULA)
seeds    = ["http://[<hub-overlay>]:51902"]  # directory URLs to pull (the hub)
root_url = "http://[<hub-overlay>]:51902"    # where to publish / renew
hosts_sync  = true                           # manage /etc/hosts names (on by default)
mesh_domain = "gw.internal"                  # name suffix + default TLS cert name

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
`create --overlay-prefix`; a node learns it from its credential at join). A
node learns and verifies addresses prefix-agnostically — the self-certifying
part is the host bits, `blake2s(id_pub)`, and the CA signature attests the
prefix — so **one host can be a plain node on two independent meshes at once**.
Give each membership its own config, data dir, interface, listen port, and mesh
domain (hub-in-two-meshes is not supported):

```bash
# Mesh A
sudo gw -c /etc/gw-a.toml join "$TOKEN_A" --data-dir /var/lib/gw-a \
    --interface gw-a --listen-port 51900 --mesh-domain alpha
sudo gw -c /etc/gw-a.toml run

# Mesh B — the same two commands, with every A-specific value swapped for a B one:
# its own config, token, data dir, interface, UDP port, and mesh domain.
sudo gw -c /etc/gw-b.toml join "$TOKEN_B" --data-dir /var/lib/gw-b \
    --interface gw-b --listen-port 51910 --mesh-domain beta
sudo gw -c /etc/gw-b.toml run
```

(Run each daemon as its own systemd service in practice — `gw run` stays in the
foreground.)

`hosts_sync` blocks are tagged per mesh domain and file-locked, so the two
daemons don't clobber each other's `/etc/hosts` entries.

## Names (.gw.internal)

Every node has a stable overlay address, and `gw nodes` shows each node's
resolvable name↔address map. Name resolution is **on by default**: the daemon
keeps a marked `/etc/hosts` block mapping each node's address to
`<hostname>.gw.internal`, built from the records that pass the reconcile loop's
full verification — the same gate that decides WireGuard peers, so a revoked or
expired node's name stops resolving on the same cycle its tunnel comes down.
It's re-checked each reconcile but **only rewritten when the block actually
changes** (a join, departure, revocation, or rename) — in steady state it never
touches the file, so it won't churn your `/etc/hosts` or noise up
etckeeper/config management:

```
# BEGIN greasewood — managed, do not edit
fd8d:e5c1:db1a:7:…  db.gw.internal
fd8d:e5c1:db1a:7:…  node01.gw.internal
# END greasewood
```

So `ping db.gw.internal`, `ssh db.gw.internal`, etc. just work — no DNS
server, and it keeps resolving even if the hub is down (it's from the cache,
for as long as the cached credentials remain valid — one credential TTL, the
same horizon as the tunnels themselves). It
only ever touches the region between its markers; your own `/etc/hosts` lines are
left alone, and `--no-hosts-sync` (or `hosts_sync = false` + restart) or `gw
purge` removes the block.

**Who chooses the name.** By default a node names itself at `gw join` (defaulting
to its machine hostname) and can change it later with `gw rename`. If you'd rather
the hub control it, **pin it at invite**: `gw invite --hostname db` fixes the name
at enrollment (the joiner's requested name is ignored) and marks the credential so
the node **can't `gw rename` itself** — to change a pinned name, re-invite with a
new `--hostname`. Either way the name is CA-attested; pinning just moves the
decision from the node to the hub.

Two things make defaulting this on safe:
- **Names are CA-attested** (the hostname lives in the signed credential), so a
  member can't publish a record claiming another node's name to poison your hosts.
- **Names are namespaced** under a dedicated `gw.internal` sub-label.

The domain is shared with TLS: `gw cert-request` with no `--san` defaults the
cert to this node's `<hostname>.gw.internal` **plus** its overlay address. So the
name a node is reached by is exactly the name its certificate is valid for —
resolve `db.gw.internal` → connect over WireGuard → TLS validates the
`db.gw.internal` SAN (Subject Alternative Name — the x509 field listing the
name(s) a certificate is valid for).

A node's hostname defaults to the machine's own hostname at enrollment; change
it later with `sudo gw rename <newname>` (then restart the daemon). Rename goes
through the hub, so it's uniqueness-checked and frees the old name — the keys and
overlay address don't change. (Editing `hostname` in the config directly is not
enough: the hub wouldn't know, so always use `gw rename`.)

> Names are sanitized to a DNS-safe form (`ops@node01` → `ops-node01`) and must
> be **unique**. For a self-chosen name, uniqueness is checked at enrollment: a
> `join` whose (sanitized) name is already taken is refused — but the token isn't
> burned, so the joiner is told how many attempts remain and can retry with a
> different `--hostname` (a few tries per window). For a **hub-pinned** name
> (`gw invite --hostname`), uniqueness is checked at *invite* instead, so a
> pinned name is guaranteed free before the token goes out and can't collide at
> enrollment (the joiner couldn't fix it anyway). Either way, a decommissioned
> node keeps its name until its `nodes/<id>.json` is removed on the hub, which
> frees it for reuse.

## TLS certificates for services

The same CA that gates the mesh also issues ordinary **x509 TLS certificates**,
so a service on a node (Postgres, an internal API, …) gets a cert that every
peer validates against one trust root — no second PKI (public-key
infrastructure). These are real x509 certs with SANs, distinct from the mesh
credential, but signed by the same Ed25519 CA key.

**What this is for (and isn't).** WireGuard already encrypts and authenticates
traffic between nodes, so TLS here is **not** about adding encryption — that part
would be redundant. Its value is at the layers WireGuard doesn't cover:

- **Service identity by name.** WireGuard authenticates the *node* you reached,
  not that you reached the *right* node for a name — the `db.gw.internal`→address
  mapping lives outside its crypto. A cert with `SAN=db.gw.internal`, validated by
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
capability. It's granted by the hub, and **ships on by default** (`[hub]
default_caps = ["tls"]`), so a plain `gw invite` already yields a cert-capable
node — no extra flag:

```bash
TOKEN=$(sudo gw invite)                 # tls is in the default caps
sudo gw join "$TOKEN" --hostname dbnode
```

To make `tls` opt-in instead, set `default_caps = []` in `[hub]` (effective on
the next invite) and grant it per-node with `gw invite --caps tls` or later with
`gw set-caps <node> …`. Either way `tls` is bounded by SAN authorization (below),
so a cert-capable node can still only get certs for its *own* names.

Then, on that node. A node can only get a cert for names it **owns**: its own
`<hostname>.<mesh_domain>`, any **subdomain** of that, and its own overlay
address. The hub (the CA) enforces this, so a node can never obtain a valid cert
for *another* node's name and impersonate its service to TLS clients.

```bash
# On node "dbnode" — postgres.dbnode.gw.internal is a subdomain it owns:
sudo gw cert-request --san postgres.dbnode.gw.internal --name postgres
#   → writes <data_dir>/tls/postgres.key, postgres.crt, and ca.crt

# With no --san, the cert defaults to the node's own name + overlay address:
sudo gw cert-request                 # SAN = dbnode.gw.internal (and its addr)

# The three files need not share a directory — override any of them, e.g. put
# the key where the service expects it and the CA in the system trust store:
sudo gw cert-request --name postgres \
     --key-out  /etc/postgresql/ssl/postgres.key \
     --cert-out /etc/postgresql/ssl/postgres.crt \
     --ca-out   /usr/local/share/ca-certificates/mesh-ca.crt

gw cert-status                       # list issued certs and their expiry
```

The leaf private key is generated locally and never sent to the hub; only its
public key goes in the request, which is signed by the node's identity key. The
hub returns the leaf cert plus the CA cert. Point the service at them — e.g.
Postgres `ssl_cert_file=postgres.crt`, `ssl_key_file=postgres.key`, and clients
`sslrootcert=ca.crt` with `sslmode=verify-full`. Certs are short-lived (default 7
days, `[hub] tls_cert_ttl`), and **the daemon auto-renews each one at ~half its
TTL** into whatever paths you chose — pass `--reload-cmd "systemctl reload
postgresql"` so the service picks up the rotation (or `--no-auto-renew` for a
one-shot). Managed certs are keyed by `--name`, so re-running `cert-request` with
the same name **relocates** it (the daemon renews into the new paths and flags
the old files as orphaned) rather than leaving a duplicate. See
[RUNBOOK.md](RUNBOOK.md). Revocation is passive — stop renewing and it expires.

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

1. **Enroll B as an ordinary node** (`gw join …`) and start it — so it's a
   reachable mesh member every node can renew against over the overlay.
2. **Promote B:** `sudo gw hub-promote` generates B's own CA key and flips it to
   `role=hub` (keeping trust in A), printing B's CA pubkey + control endpoint;
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

Throughout, **A and B both run as hubs** — that's the point of the overlap, and
there's no clash: each hub's control plane binds to its *own* overlay address
(the hash of its own identity key), the fleet trusts both CAs at once, and the
directory is eventually-consistent (records merge by highest sequence number, and
each node renews against the one hub its `root_url` points at). Existing tunnels
stay up throughout (the data plane never depends on the hub), so the handover is
non-disruptive. Plan the overlap to last at least one credential TTL so every node
renews under B in time. See [RUNBOOK.md](RUNBOOK.md) for the full graceful vs
emergency (compromised/lost-key) procedures.

## Testing

```bash
pip install -e '.[test]'   # or: pip install pytest
python -m pytest           # unit tests (fast, no privileges)
```

Integration and stress tests run real WireGuard inside privileged Podman
containers and are skipped by the default run. They need Podman 4+ and the
WireGuard kernel module:

```bash
# Functional tests: mesh connectivity, re-enrollment, rename, TLS, reboot
# survival, and a full hub re-root A→B (two live hubs, fleet migrates to B's CA) —
# all on real containers, under tests/integration/
python -m pytest tests/integration/

# Scale tests — grow the mesh to many nodes and verify full convergence.
# Gated behind GW_STRESS; knobs: GW_STRESS_N / _WAVES / _WORKERS.
GW_STRESS=1 GW_STRESS_N=8 python -m pytest tests/integration/test_stress.py -v -s
```

## Design notes & non-goals

The [non-goals](#how-it-compares) — routing/relays, NAT traversal, IPv4 overlay,
cross-platform — aren't missing, they're the point. A few internal ideas are
**deferred rather than overlooked** — named here with the *trigger* that would
make them worth building:

- **Gossip between nodes** — if the network ever genuinely partitions (today every
  node pulls the directory from the hub).
- **Lazy, on-demand tunnels** — at hundreds of nodes, if a full peer mesh becomes
  too many links to hold open.
- **Threshold CA** — if single-hub-key compromise becomes unacceptable.
- **CA cross-signing to smooth re-root** — let the old CA sign a short-lived,
  directory-distributed "also trust the new CA" delegation, so a graceful
  [re-root](#moving-the-hub-re-root) doesn't require pushing the new key into every
  node's `trusted_pubs` up front (the config edit becomes a calm, batchable
  follow-up instead of a race against credential expiry). Trigger: re-root friction
  in practice. Would be opt-in, short-lived, and logged, since it loosens the
  config-only trust root; emergency re-root (old CA lost) still needs the
  out-of-band config push.

**Clock integrity is part of the security posture.** Every allow/deny is a
timestamp comparison against a credential expiry, so run NTP/chrony on every
node.

**CA trust is a set, not a single key.** The CA (and hub) is moved by a
re-root — trust the new key alongside the old during an overlap, then drop the
old — don't move the private key to a new machine. See [Moving the hub](#moving-the-hub-re-root).

## Security & operations

- **[SECURITY.md](SECURITY.md)** — trust boundaries, what the 7-step check
  enforces, accepted risks, and the results of the security review.
- **[RUNBOOK.md](RUNBOOK.md)** — disaster SOPs: compromised node, lost/leaked CA
  key, destroyed hub, fleet-wide teardown, and how to read `gw diagnose`.
