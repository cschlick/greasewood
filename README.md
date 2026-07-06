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
- **[Self-contained.](#the-anchor)** The anchor is just a normal node with a CA — no
  coordination service, no SaaS.
- **[Direct-or-fail.](#direct-or-fail)** No routing, no relays. A link comes up
  directly or it honestly fails.
- **[IPv6 overlay.](#ipv6-overlay)** The overlay is IPv6-only; the underlay may be
  IPv4 or IPv6. No NAT traversal.
- **[Self-certifying addresses.](#self-certifying-addresses)** A node's IPv6
  address is a hash of its identity key.
- **[Segmented.](#access-control-segments)** Optional `segment:` tags control who
  talks to whom.
- **[Named.](#names)** Every node gets a `<host>.<mesh>.internal` name and
  matching TLS certs from the same CA.
- **[Service TLS.](#tls-certificates-for-services)** The same CA issues auto-renewing
  x509 certs for your services (Postgres, nginx, …) — with profiles that place them where each wants them.
- **[Offline-tolerant.](#offline-tolerance)** The anchor can be down for a credential
  lifetime — nodes run from cache.
- **[Hands-off.](#firewall)** Never touches your firewall — it prints the rules,
  you apply them.
- **[Linux-only.](#linux-only)** Built on the Linux kernel's own WireGuard and
  networking — not a portable userspace/Go stack. Best run as a systemd service.
- **[Auditable.](#auditable)** Pure Python, one dependency, driving it all through
  the stock `wg`/`ip` tools over subprocess — and logging **every one of those
  commands**, with context, to a durable trail. Greasy.

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
  of it: the anchor is a normal node that can be *offline* for a credential
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

**Revocation is expiry-based (no CRL).** `gw revoke <id>` on the anchor takes effect
there immediately — the anchor re-reads its revoke list each reconcile cycle,
dropping the node from its own interface within seconds, and refuses the node's
renewals from then on. It does **not** reach the rest of the fleet instantly:
other nodes keep trusting the node's credential until it expires. But since the
node can no longer renew, that credential lapses within at most one
`credential_ttl`, at which point every node rejects it — the fleet-wide eviction.
Shorten `credential_ttl` for a tighter bound.

## The anchor

The anchor is **just a normal mesh node** that additionally holds the CA key and
runs a small HTTP **control plane** — `GET /directory`, `POST /publish`, `POST
/renew`, `GET /health` — bound to its overlay address (reachable only through the
mesh, never the underlay). There is no separate coordination service, no SaaS,
nothing always-on in the data path. Nodes poll `/directory`, merge records by
highest sequence number, and cache them locally.

Because trust is anchored to the CA *key* (not a machine), any node can become
the anchor — restore the key onto a replacement, or stand up a new CA and re-point
the fleet. See [Moving the anchor](#moving-the-anchor-re-root).

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
side is reachable (see [Reachability](#reachability)); two unreachable
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
STUN, no hole-punching). A NAT'd node simply advertises no reachable endpoint: it dials out to
reachable peers and the anchor, but two unreachable nodes can't pair — and a v4-only
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
record, and every verifier (any potential peer, and the anchor) runs two independent
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
cache, so the **anchor can be down for up to one credential lifetime** and existing
node↔node links are unaffected — the anchor is never in the data path. Only new
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
(see [Auditable](#auditable)). A macOS/Windows port would mean a different
data-plane backend and is out of scope — but [PORTING.md](PORTING.md) sketches
what a macOS port would actually cost (spoiler: the audit trail is the *cheapest*
part to carry across, and staying "greasy" — root + subprocess, `brew`-installed,
not a Network Extension — is the only version consistent with the project).

## Auditable

The entire thing is **pure Python (3.11+), one dependency (`cryptography`), one
binary (`gw`)**, and it manages the data plane by shelling out to `wg`/`ip` via
subprocess. That's greasy. The clean way would be
netlink bindings — but it's a deliberate trade: you can read the exact `wg set
peer …` commands, run them by hand, and compare them against what `wg show`
reports.

That trade pays off in the **command trail**. Because every data-plane change is
a subprocess, greasewood records *every `ip`/`wg` command it issues* — always
(not behind a verbose flag), with the exit code, how long it took, and **why it
ran** — to a durable, rotating `<data_dir>/audit.log` (0600), and to the journal.
One greppable [logfmt](https://brandur.org/logfmt) line per command:

```
ts=2026-07-02T10:15:03Z INFO greasewood.audit: cmd rc=0 t=12ms \
  ctx="reconcile: +peer db01 [fd8d:e5c1:db1a:7::a1] seg=prod" \
  argv="wg set gw_myfleet peer <pub> allowed-ips fd8d:e5c1:db1a:7::a1/128 endpoint [203.0.113.7]:51900 ..."
```

So months later you can answer "when did db01 get added, why, and did it
succeed?" by grepping one file — `grep db01 audit.log`. Failures are logged at
ERROR with the command's stderr. It's safe to record verbatim because the argv
only ever contains **public** keys and key-file *paths* — the `wg` tool reads
private keys from files, so no secret is ever on a command line. Point it
elsewhere with `[network] audit_log = "/var/log/greasewood/audit.log"`, or
`audit_log = ""` to disable. (State *queries* — `wg show`, `ip … show`, which run
every reconcile cycle — go to debug, so the durable trail is only commands that
*changed* something.)

And you don't have to read raw commands: **`gw narrate` translates the trail into
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
    ✓ Route traffic for fd8d:e5c1:db1a:7::a1 over gw_myfleet — wg configures the
      peer but not the kernel route, so greasewood adds it explicitly.     (3ms)
```

Filter it (`--peer db01`, `--failures`, `--grep`, `--stats`), point it at any
log file or `-` for stdin, or `--raw` to see the argv alongside. This is the
sharpest edge of the auditability claim: **you can reconstruct — and read as a
story — every change greasewood ever made to your kernel's network state.**

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
WireGuard interfaces and edit routing); `gw watch` does not.

The Quickstart below runs the daemon by hand with `gw run`. For real use, run it
as a managed systemd service instead — see [Running as a
service](#running-as-a-service); then the workflow is just install → setup/join.

## Quickstart

### 1. Bootstrap the anchor

On the machine that will hold the CA and serve enrollment:

```bash
sudo gw create myfleet          # names live under *.myfleet.internal
sudo gw run
```

`create` generates the CA, the persistent door key, the policy routing for
the enrollment door, and the anchor's own credential, then writes
`/etc/greasewood_myfleet.toml`. `gw run` starts the daemon: it brings up the `gw_myfleet`
WireGuard interface, serves the control plane, and watches for door windows.

The anchor takes this machine's hostname like any other node — it isn't named
anything special. You tell which node is the anchor from `role: anchor` in
`gw watch`, not from its name. (Pass `--hostname <name>` to override the default.)

### 2. Enroll a node

Enrollment uses a transient WireGuard "door" — no SSH, no HTTP exposed on the
underlay. On the anchor, open a window and create a single-use token:

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
`gw-door` tunnel to the anchor, receives a CA-signed credential over it, tears the
door down, and writes the node's config. `gw run` then brings the node into the
mesh; within a couple of reconcile cycles every node has a direct tunnel to it.

**Why a door — why can't the token just contain everything to peer over
your mesh interface?** Because WireGuard peering is *mutual*: to bring up a tunnel to the
anchor over any interface, the anchor must already have **your** public key in its peer
list. At invite time your real keys don't exist yet — they're generated locally
at `join`, and private keys never travel — so the anchor cannot pre-authorize your
real identity key. Handing you the anchor's mesh-interface details in the token gets you
nowhere: the anchor would drop your handshake, never having heard of your key.

What the token *can* do is carry a 32-byte seed that **both sides expand (HKDF)
into the same throwaway door keypair + PSK**. The anchor derives that throwaway
pubkey from the seed it minted and pre-installs it as a peer; you derive the
matching private key — so now a tunnel can actually form. But it forms under a
**disposable, credential-less key, not your identity** — and a non-member key
like that has no business on the live overlay. That's why the door is a
*separate* interface, not the mesh one:

- it runs on its own **dedicated door subnet** (`fd8d:…:d::/64`) — not a
  throwaway address squatting on the real overlay, which would break the
  self-certifying `address = hash(identity)` invariant;
- it reaches **only the enroll daemon** (not the directory/control plane, not
  other peers) — a token-holder can do exactly one thing: request a credential;
- it's **torn down** the moment your credential is issued.

You bring up the mesh interface, with your *real* key and its self-certifying address, only
once you hold that credential — and from then on every peer learns your key and
address from the directory as usual. Running the throwaway peering over the mesh interface
instead would drop a credential-less stranger onto the live mesh with a fake
address and expose the whole control plane to a mere token-holder — which is
exactly what the door exists to prevent.

### 3. Check it

```bash
gw watch --snapshot        # local node + directory view (fleet-wide link state)
sudo gw diagnose db01 web1 # pairwise: can db01 and web1 form a tunnel?
sudo wg show gw_myfleet    # live WireGuard peers
```

`gw diagnose` is the tool to reach for when a peer won't connect. It's
**pairwise**: it lays up to two named nodes plus the anchor side by side and
explains, per pair, whether a tunnel can form — segments, reachability, and the
firewall/routing directionality that's usually the real question. (`gw watch`
is the fleet-wide link overview; diagnose is the focused deep-dive.)

```bash
sudo gw diagnose            # this host ↔ the anchor
sudo gw diagnose db01       # this host ↔ db01   (+ anchor as reference)
sudo gw diagnose db01 web1  # db01 ↔ web1        (+ anchor as reference)
```

The comparison table shows each node's addresses, reachability, segments,
credential, and firewall for the mesh UDP port. Since diagnose runs on one node,
**only this host's firewall is directly known** — a peer's is *inferred `OPEN`*
whenever a handshake has been observed (packets flowing prove its whole inbound
path: host firewall, any router/NAT, and daemon), and shown `???` otherwise.
The per-pair verdict reads out who can dial whom and the live status, and when a
pair involves this host and there's no handshake it localizes the block — e.g.
"our host firewall is open, so a peer that still can't reach us points at an
upstream router/NAT not forwarding the port." See [RUNBOOK.md](RUNBOOK.md) for
the full verdict table.

A `LINKED` pair involving this host also gets a **path-MTU probe** — a
don't-fragment ping at the tunnel's interface MTU. WireGuard-over-cloud MTU
blackholes are nasty: small traffic and SSH work, but TLS handshakes and large
transfers hang because full-size tunnel packets exceed the underlay path MTU. If
the small ping passes but the full-size one is dropped, diagnose flags it and
suggests lowering the tunnel MTU.

## Running as a service

On a systemd host the daemon is managed for you — **`create` and `join` install
the service and start it**, no extra command. A single **template unit** serves
every mesh as its own instance `greasewood@<name>` (survives reboots, restarts
on failure, logs to the journal), so the whole workflow is just:

```bash
sudo gw create myfleet                # anchor  → greasewood@myfleet installed + running
sudo gw join "$TOKEN" --hostname n01  # node → greasewood@<mesh> installed + running
journalctl -u greasewood@myfleet -f   # watch a mesh's daemon
systemctl status 'greasewood@*'       # all of them
```

There is no separate install/uninstall step: the service lifecycle rides on the
mesh lifecycle. **`gw purge`** removes a mesh's instance (and the shared
template when it's the last mesh) — a from-scratch reset in one command.

- **Not on systemd, or want to run it yourself?** Pass `--no-service` to
  `create`/`join`; they print the `sudo gw -c <config> run` line instead and
  touch nothing under `/etc/systemd`. (A non-systemd host auto-falls-back to
  this even without the flag.)
- Instances run `gw run` as root (they manage WireGuard interfaces and
  routing). Don't also run `gw run` by hand while an instance is up — both
  would fight over the interface.
- A **config-changing re-join** (new anchor, new caps) isn't auto-detected — the
  daemon reads its config at startup, so run `sudo systemctl restart greasewood@<name>`
  afterward.

### Root vs. sudo

`gw` needs root (it manages WireGuard interfaces), and the systemd service always
runs as root, so config and data paths (`/etc/greasewood_<name>.toml`,
`/var/lib/greasewood_<name>`) are read identically however you invoke it — nothing gets
corrupted either way. Two behaviors *do* differ, so pick one style and stick with
it:

- **State ownership.** Everything under the data dir is **root-owned, always** —
  greasewood never chowns state to the invoking user. (It used to hand the data
  dir to the `sudo` user; that put the **CA key on a login account**, which
  could then mint mesh credentials — the daemon now warns at startup if it finds
  that legacy state, and the fix is `chown root:root` on the flagged keys.)
  Read-only commands don't need ownership: the data dir is `0755` and the public
  files (`id_pub.hex`, `directory.json`, `*.pub`) are world-readable, so
  `gw watch --snapshot` works for **any** user; each secret is its own `0600` root-owned
  file. Every command that needs root **says so up front** — a clean
  `'gw <cmd>' needs root (<why>). Try: sudo gw <cmd>` — instead of failing
  partway on whichever file access breaks first. Root-needing commands: the
  data-plane set (`run`, `join`, `create`, `invite`, `purge`, `renew`,
  `rename`, `anchor-promote`, `anchor-restore`) and the anchor
  registry/key set (`revoke`, `set-caps`, `set-segments`, `renew-all`,
  `cert-request`, `anchor-backup`).
- **Environment variables.** `sudo` strips the environment by default. This only
  matters if you protect the CA key with `ca_key_passphrase_env`: a var exported
  in your shell won't reach `sudo gw` (you'd get "environment variable is
  empty"). Use `sudo -E` for one-off commands, and for the **service** set it in
  the unit's `Environment=` / `EnvironmentFile=`, never a login shell.

(Keep config paths absolute — a `~` in `data_dir`/`ca_key_file` expands to the
*running* user's home, which differs under sudo.)

## Provisioning many nodes

Enrollment tokens are **pushed by the anchor, never pulled by nodes**. A node
cannot request admission; you (or an orchestrator acting on the anchor) decide to
admit a machine, run `gw invite`, and deliver the token out of band. The node
only redeems what it was handed. The door is **single-slot by construction**:
each invite opens one enrollment window, and the anchor closes it the instant that
node finishes joining — so provisioning is one node at a time.

**The usual way is copy-paste.** On the anchor:

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

On the anchor, **`gw watch` shows what the door is doing** — open (with the
minutes until it closes, the caps it grants, any failed attempts and their
source IPs, and attempts remaining) or closed (how long ago and why: enrolled,
expired, or too many failed attempts). Handy for watching an enrollment or
spotting someone knocking on the door with a bad token.

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
  `NOPASSWD: gw` — that's effectively passwordless
  root.

## Firewall

**greasewood never modfies your firewall ever.** Its control
plane (`51902/tcp`) and enrollment RPC (`51903/tcp`) bind only to the node's
overlay address and loopback — *never* the underlay — so nothing it runs is
reachable off-mesh regardless of firewall policy. The only thing that must face
the underlay is WireGuard itself (UDP), which you open like for any VPN.

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

On a default-drop host, allow (nftables):

| Interface  | Rule                          | Purpose                              |
|------------|-------------------------------|--------------------------------------|
| underlay   | `udp dport 51900 accept`      | mesh WireGuard                       |
| underlay   | `udp dport 51901 accept`      | enrollment door (during join)        |
| `lo`       | `iifname "lo" accept`         | the anchor talks to itself (`::1:51902`)|
| `gw_<name>` | `tcp dport 51902 accept`      | control plane — **only used when this node is the anchor** |
| `gw-door`  | `tcp dport 51903 accept`      | enrollment exchange — **only when anchor** |

```
udp dport { 51900, 51901 } accept
iifname "lo" accept
iifname "gw_myfleet" tcp dport 51902 accept
iifname "gw-door" tcp dport 51903 accept
```

The four ports sit in one contiguous block, **51900–51903**, deliberately clear
of the WireGuard default (51820) and Docker Swarm / Serf (7946) so greasewood
doesn't squat a port something else likely wants. All are configurable: mesh
`[network] listen_port`, control `[anchor] control_listen`, door `[anchor] door_port`
(or `create --listen-port/--control-port/--door-port`). The door port rides
in join tokens and the control port in the enrollment response, so nodes pick up
non-default values automatically — no client config. (The internal enrollment
port lives inside the door tunnel and can't collide, so it isn't a knob.)

### Worked example: a default-drop host

A complete, loadable ruleset for an anchor host running `policy drop`. It's safe
verbatim on plain nodes too — the `gw-door` rules never match where no door
exists, and `51902` only matters where an anchor listens (greasewood's rules are
the same on every node by design):

```nft
#!/usr/sbin/nft -f
table inet gw_anchor {
    chain input {
        type filter hook input priority filter; policy drop;

        ct state established,related accept
        ct state invalid drop
        iifname "lo" accept                     # control plane also binds ::1

        # --- underlay: the only internet-facing surface, both UDP.
        # Non-peers get silence from WireGuard itself; the door port is
        # inert unless a window / standing door is open (anchor only).
        udp dport 51900 accept comment "greasewood mesh WG"
        udp dport 51901 accept comment "greasewood door WG (anchor only)"

        # --- tunnel-internal services (TCP), scoped to their interface.
        # 51902 is reachable only as a verified mesh peer; 51903 only
        # through a token's door tunnel.
        iifname "gw_myfleet" tcp dport 51902 accept comment "control plane"
        iifname "gw-door" tcp dport 51903 accept comment "enroll server"

        # --- your own management access — adjust to taste ------------------
        tcp dport 22 accept                     # don't lock yourself out
        ip6 nexthdr ipv6-icmp accept            # ND/PMTU — required for v6 at all
        ip protocol icmp accept
    }
}
```

The `iifname` scoping is belt-and-braces rather than load-bearing: `51902`
binds only overlay+loopback and `51903` binds only the door IP, so they're
unreachable from the underlay even without these rules — the scoped accepts
just make the firewall *state* the architecture.

### Worked example: anchor (or node) behind a NAT router

On the **router**, only the two WireGuard UDP ports ever get forwarded —
`51900` always, `51901` only if the *anchor* is the machine behind this router.
Never forward `51902/51903`: they aren't on the underlay at all.

```nft
#!/usr/sbin/nft -f
define GW_HOST   = 192.168.1.50        # LAN address of the greasewood machine
define WAN_IF    = "eth0"              # router's upstream interface

table ip gw_forward {
    chain prerouting {
        type nat hook prerouting priority dstnat; policy accept;
        iifname $WAN_IF udp dport 51900 dnat to $GW_HOST comment "greasewood mesh WG"
        iifname $WAN_IF udp dport 51901 dnat to $GW_HOST comment "greasewood door WG (anchor only — delete on a plain node)"
    }
    chain forward {
        type filter hook forward priority filter; policy accept;
        # If your forward policy is drop (it should be), allow the DNATed flows:
        ip daddr $GW_HOST udp dport 51900 accept comment "greasewood mesh WG"
        ip daddr $GW_HOST udp dport 51901 accept comment "greasewood door WG (anchor only)"
        ip saddr $GW_HOST ct state established,related accept
    }
}
```

Behind NAT, advertise the **router's** public identity, not the LAN address:
`gw join <token> --endpoint <router-public>:51900` on a node, and
`gw invite --endpoint <router-public-or-dns>` on an anchor. With routable IPv6
behind the router there's no DNAT — just accept the same two UDP ports in the
router's v6 forward chain. A node that advertises no endpoint needs **nothing**
forwarded: it dials out and keepalives hold the mapping open. And the machine
behind the router pairs this with the host ruleset above.

Your base default-drop ruleset should also include `ct state established,related
accept`. It's what lets an **outbound-only** node work:
such a node opens *no* greasewood inbound ports — it dials peers and the anchor,
and the replies come back through `established,related`.

**Recommended posture: apply the same ruleset on *every* node, not just the
current anchor.** Any node can be promoted to anchor ([Moving the
anchor](#moving-the-anchor-re-root)), so a uniform ruleset means an anchor handover
needs **no firewall change anywhere**. Opening `51902`/`51903` on a node that
isn't an anchor is harmless: nothing is bound there, so the kernel just refuses the
connection until that node actually becomes an anchor and binds it. Plain nodes run
no control plane, so on a node that will never be an anchor you *could* omit the mesh-interface/
`gw-door` TCP rules and open only the two UDP ports if you really want the most minimal config.

**Multi-user hosts:** the overlay is host-wide — *any* local user can use the
tunnel once it's up (identity is per-machine, not per-user). To restrict which
users may originate overlay traffic, add an nftables owner-match on the output
chain; see the "Multi-user hosts" section of [SECURITY.md](SECURITY.md).

### Reachability

WireGuard has no client/server roles — both peers try to handshake and the
direction that physically works wins, then endpoint roaming pins it. So a link
forms as long as **at least one side is reachable**: a firewalled node dials an
open one, and the reply returns via the NAT hole it punched. Two fully-blocked
nodes can't pair (direct-or-fail — no relays).

Because of that, greasewood has **no `inbound` flag** — reachability is emergent.
A node advertises whatever endpoint it detects (or the `--endpoint` you give it);
one that advertises none is naturally **outbound-only** — it dials peers, and
peers can't dial it. You don't declare this or get it wrong: it's just a
consequence of whether an endpoint exists.

And guessing "reachable" when you aren't is harmless. Peers pin your advertised
endpoint, get no handshake, and after a short probe window **drop keepalive to
that endpoint** — so the futile poll stops and the link still works via you
dialing out. The endpoint stays pinned, so if it later becomes reachable, the
next packet re-establishes it automatically. `gw diagnose` shows a node's
reachability (confirmed from an inbound handshake, or "outbound-only" if it
advertises nothing), and the two-unreachable-nodes case surfaces as `✗ no
dialable direction`.

An **anchor** must be reachable (it serves the control plane), so
`anchor-promote` refuses a node that advertises no endpoint.

## Access control (segments)

By default every mesh node can talk to every other — one flat segment. To
control **who talks to whom**, put nodes in different **segments**. Two nodes peer
only if they **share a segment**; every node is in `segment:mesh` by default (the
flat default pool), and putting a node in another segment isolates it.

Segments are `segment:<name>` tags in the node's CA-signed credential. Crucially,
**the anchor assigns them at `gw invite` — a joining node cannot choose its own** (no
self-assertion). Whoever you hand a token to gets exactly the segments that invite
specified:

```bash
# On the anchor — the invite decides the node's segments:
TOKEN=$(sudo gw invite --segments prod,web)   # a token for a node in prod + web
# On the new node — join takes no segment flags; it gets what the token granted:
sudo gw join "$TOKEN" --hostname web1
```

A node's segments show up in `gw watch` (a `segments` column). To change them
later **without re-joining**, run `gw set-segments <node> prod,web` on the anchor —
it takes effect at the node's next renewal (or re-invite + re-join for an
immediate change).

**Defaults for new nodes** live in the anchor's config — `[anchor] default_segments`
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
- **`segment:*`** on either side → reaches everyone. The anchor carries it
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

- **Anchor-assigned, attested, mutually enforced.** Segments are decided by the anchor
  at admission and bound into the CA-signed credential — a node **can't
  self-assert** a segment it wasn't granted. A tunnel needs *both* ends to install
  each other, and each side reads the *other's* segments from its credential, so a
  node can neither talk its way into a segment nor be forced into a link it denies.
- **Node-level and symmetric**, not port-level or one-way. Segments decide whether
  two nodes may have a tunnel *at all*; "A may reach B:5432 but not B:22" is a
  firewall concern — use your own nftables on the mesh interface (see
  [SECURITY.md](SECURITY.md)).

## Command reference

| Command            | sudo? | What it does                                              |
|--------------------|-------|-----------------------------------------------------------|
| `create`        | yes   | One-shot anchor bootstrap: CA, door key, routing, self-cred. |
| `run`              | yes   | Start the daemon (WireGuard iface, control plane, loops). |
| `invite`           | yes   | Open a 15-min door window, print a single-use join token. `--standing` opens a [standing door](#baked-images--autoscaling-the-standing-door) instead: one token, any number of enrollments, until `close-door`. |
| `close-door`       | yes   | Close the current door window — permanently invalidates its token (standing or single-use); enrolled nodes unaffected. |
| `join <token>`     | yes   | Enroll this machine using a token from `invite`.          |
| `watch`            | sudo  | **Live** mesh dashboard (redraws in place, so it needs sudo for live WireGuard state): the split roster + link state, per-second throughput, and a latency column that fills in as pings return. Ctrl-C to exit. **`--snapshot`** prints one static view and exits (no root; auto-used when piped) — for logging/scripts. `--by-segment` groups by segment; on the anchor it also shows the [door's state](#membership). |
| `config [key]`     | no    | Print resolved config facts machine-readably for scripting — `gw config interface` gives the mesh interface name (`gw_<mesh>`), no arg lists all as `key<TAB>value`. |
| `diagnose [A [B]]` | sudo  | Pairwise link diagnosis: compare up to two nodes + the anchor side by side and explain whether a tunnel can form (segments, reachability, firewall directionality with `OPEN`-inferred-from-handshake and upstream-router localization). No args = this host ↔ anchor. |
| `revoke <node>`    | no    | Revoke a node on the anchor (denies renew/publish, evicts it, frees its hostname). `<node>` = hostname, `<host>.<mesh_domain>` mesh name, or 64-char id_pub hex. |
| `set-segments <node> <s>` | no | Change a node's segments (on the anchor; effective next renewal). |
| `set-caps <node> <caps>` | no | Change a node's full tag set (on the anchor; effective next renewal). |
| `anchor-promote`      | yes   | Turn this enrolled node into an anchor (generate its own CA key).  |
| `cert-request`     | no    | Get an x509 TLS cert from the anchor for a local service. The daemon auto-renews it at ~half its TTL; `--reload-cmd` runs a command after each renewal, `--no-auto-renew` opts out. **`--profile <name\|path>`** issues + places the key/cert/ca where the service wants them (right owner/mode) and re-places on every renewal; `--profile <name> --show` prints a bundled template to adapt. |
| `cert-profiles`    | no    | List the bundled cert profile templates (postgres, nginx, haproxy, redis, nats, minio, mosquitto) — starting points to copy and adapt. |
| `cert-remove <name>` | sudo | Stop managing a cert (drop it from auto-renewal + remove its profile snapshot). Leaves the placed files by default; `--delete-files` removes them too. |
| `cert-status`      | no    | Show every daemon-managed TLS cert (expiry, renewal state, SANs, placed files, profile) from the manifest — wherever the files live. |
| `narrate`          | no    | Translate the `ip`/`wg` command trail (`audit.log`) into a plain-English story of what greasewood did and why. Filters: `--since`, `--peer`, `--grep`, `--failures`, `--stats`, `--raw`. |
| `rename-node <name>` | yes | Change this node's mesh hostname (anchor-validated, no re-join; refused if the anchor pinned the name). |
| `rename-mesh <name>` | yes | Rename this mesh — domain, config, data dir, interface, and service move together. Run on the anchor, then on each member (surfaced in its `gw watch`). Old names resolve + verify in TLS through a one-TTL grace window. See the [RUNBOOK SOP](RUNBOOK.md). |
| `renew`            | yes   | Force an immediate credential renewal for this node (applies an anchor-side `set-caps`/`set-segments` now, instead of at the ~half-TTL renewal). |
| `renew-all`        | no    | On the anchor: request a fleet-wide renewal (advertise `renew_after=now`; cooperating nodes renew, jittered so the anchor's rate stays ~constant with mesh size). |
| `anchor-backup`       | no    | On the anchor: write one passphrase-encrypted archive of the CA key, node registry, revoke list, door key, and anchor identity. Store it offline. |
| `anchor-restore`      | yes   | Restore a `anchor-backup` archive onto a replacement host (same CA key → a restore, not a re-root). |
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
caps     = ["segment:mesh"]  # segment:<x> tags segment the mesh; "tls" allows certs

[network]
interface  = "gw_myfleet"
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

### Baked images & autoscaling: the standing door

The default door is deliberately one-token-one-node. For cloud images and
autoscaling groups — where instances must enroll themselves at first boot —
open a **standing door** instead:

```bash
# On the anchor, once per fleet:
sudo gw invite --standing --segments autoscale --endpoint anchor.example.com -q
# → ONE token. Put it in the image or launch template's user-data.
```

Every instance runs the same `gw join <token>` at first boot. Each join is
still the **full one-node ceremony** — fresh identity keys, its own CA-signed
credential, the same door isolation (a token holder can reach the enroll port
and *nothing else*) — the door just doesn't close afterward. Joins serialize
(all holders share the door's guest key), so a boot burst enrolls one node
every couple of seconds; have the first-boot script retry on failure.

Threat model, honestly: a leaked standing token lets its holder **enroll a
rogue node** into the pinned segment — a bounded, visible (`gw watch` shows
`door: OPEN (standing) — N enrolled`; every join is in the audit trail), and
reversible (`gw revoke`) failure. That is the deliberate trade against the
alternatives (e.g. giving instances SSH to the anchor, whose failure mode is anchor
compromise). Contain it with a quarantine segment and rotate freely:

```bash
sudo gw close-door                 # token permanently dead, fleet-wide, instantly
sudo gw invite --standing ... -q   # fresh seed → fresh token → update user-data
```

Lost the token? A standing token is stored (0600 root) so you can re-retrieve
it without re-issuing — **`sudo gw watch`** on the anchor prints it in the door
block while the standing door is open (root only; it's the enrollment
credential). Re-issuing would invalidate copies already baked into images, so
retrieve rather than re-invite.

Enrolled nodes are never affected by door operations — their credentials come
from the CA, not the door. A standing door survives anchor reboots (the daemon
re-erects it), and a plain `gw invite` refuses to silently supersede one (pass
`--supersede` or `close-door` first), so a one-off invite can't accidentally
invalidate the token baked into your image pipeline.

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
`gw_<name>`, UDP `51910` (then +10 each). The mesh's **name domain rides
in the token** (declared once at `gw create <name>` → `<name>.internal`), so
every member of a mesh — including multi-mesh hosts — mounts it under the SAME
suffix, and TLS names agree fleet-wide with no flags.

**Domain collisions are a hard no**: a node cannot bridge two meshes with the
same domain — no local aliasing exists (a per-host alias would diverge from the
names in the mesh's TLS certs, a debugging trap; and rewriting is off the table
since names are CA-attested). The join refuses *before* the door dance (the
token is not consumed) and tells you the fix: rename one mesh on its anchor.
Requiring a mesh name at create makes this a genuine coincidence rather than
the default-default certainty it used to be.

Every derived value is still overridable — pass any of the explicit knobs and
the auto-slotting steps aside entirely:

```bash
sudo gw -c /etc/gw-b.toml join "$TOKEN_B" --data-dir /var/lib/gw-b \
    --interface gw-b --listen-port 51920 --mesh-domain beta
```

**The mesh domain must differ between the two, for the same reason the interface
name must** — both are flat, host-global namespaces with no scoping. The
`/etc/hosts` block is *keyed by* `mesh_domain`, so two meshes sharing one would
(a) clobber each other's block every reconcile — each daemon strips and rewrites
the same-tagged block — and (b) collide on the names themselves: both meshes'
`db.myfleet.internal` would claim the same name for two different addresses. Unlike a
duplicate `listen-port` (which fails loudly at bind), a duplicate `mesh_domain`
fails *silently*, so greasewood watches for it: if it finds another mesh writing
its `/etc/hosts` block (foreign addresses under its tag), it logs a loud warning
telling you to set a distinct `mesh_domain`. The rest (port, data dir) collide
loudly on their own. With distinct domains, the blocks are tagged per mesh and
file-locked, so the two daemons coexist cleanly.

**What about two meshes on the same overlay `/64`?** (Likely, since both
probably use the stock prefix.) Surprisingly: *it works.* greasewood's data
plane never routes the /64 — every address, kernel route, and WireGuard
allowed-ip is an **identity-derived /128** (`blake2s(id_pub)` host bits), so
two meshes sharing a prefix produce no ambiguous route; an actual /128 overlap
is a birthday collision over 64 bits (ignorable). What a shared prefix breaks
is *prefix-based reasoning*: a firewall rule or script scoped to the /64 now
silently matches **both** meshes, and an address no longer tells a human which
mesh it belongs to — so `join` warns when a new membership lands on a /64
another membership already uses, and distinct `create --overlay-prefix` per
mesh remains the recommendation for legibility. Rewriting one mesh's addresses
to avoid the overlap is not on the table and never will be: addresses are
self-certifying (derived from the node's identity key and attested by the CA),
so a rewritten address is a *lie about identity* that every peer's
verification would reject.

## Names

Every node has a stable overlay address, and `gw watch` shows each node's
resolvable name↔address map. Name resolution is **on by default**: the daemon
keeps a marked `/etc/hosts` block mapping each node's address to
`<hostname>.<mesh>.internal` (e.g. `db.myfleet.internal`), built from the records that pass the reconcile loop's
full verification — the same gate that decides WireGuard peers, so a revoked or
expired node's name stops resolving on the same cycle its tunnel comes down.
It's re-checked each reconcile but **only rewritten when the block actually
changes** (a join, departure, revocation, or rename) — in steady state it never
touches the file, so it won't churn your `/etc/hosts` or noise up
etckeeper/config management:

```
# BEGIN greasewood — managed, do not edit
fd8d:e5c1:db1a:7:…  db.myfleet.internal
fd8d:e5c1:db1a:7:…  node01.myfleet.internal
# END greasewood
```

So `ping db.myfleet.internal`, `ssh db.myfleet.internal`, etc. just work — no DNS
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
name(s) a certificate is valid for).

A node's hostname defaults to the machine's own hostname at enrollment; change
it later with `sudo gw rename-node <newname>` (then restart the daemon). Rename goes
through the anchor, so it's uniqueness-checked and frees the old name — the keys and
overlay address don't change. (Editing `hostname` in the config directly is not
enough: the anchor wouldn't know, so always use `gw rename-node`.)

> Names are sanitized to a DNS-safe form (`ops@node01` → `ops-node01`) and must
> be **unique**. For a self-chosen name, uniqueness is checked at enrollment: a
> `join` whose (sanitized) name is already taken is refused — but the token isn't
> burned, so the joiner is told how many attempts remain and can retry with a
> different `--hostname` (a few tries per window). For a **anchor-pinned** name
> (`gw invite --hostname`), uniqueness is checked at *invite* instead, so a
> pinned name is guaranteed free before the token goes out and can't collide at
> enrollment (the joiner couldn't fix it anyway). Either way, a decommissioned
> node keeps its name until its `nodes/<id>.json` is removed on the anchor, which
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
  not that you reached the *right* node for a name — the `db.myfleet.internal`→address
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
capability. It's granted by the anchor, and **ships on by default** (`[anchor]
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
mesh        nats01.myfleet.internal                              nats
mesh        chat01.myfleet.internal                              chat
```

This is the only place client hostnames appear — it's the allow-list of *which*
identities may connect, and each entry is that node's own automatic name.

> **CA rotation.** The `ssl_ca_file` matters only because of client-cert auth. A
> re-root changes the CA, and both the server's CA file and every client cert
> re-issue under the new CA on their next renewal — so rotate the CA (re-root)
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

```bash
pip install -e '.[test]'   # or: pip install pytest
python -m pytest           # unit tests (fast, no privileges)
```

Integration and stress tests run real WireGuard inside privileged Podman
containers and are skipped by the default run. They need Podman 4+ and the
WireGuard kernel module:

```bash
# Functional tests: mesh connectivity, re-enrollment, rename, TLS, reboot
# survival, and a full anchor re-root A→B (two live anchors, fleet migrates to B's CA) —
# all on real containers, under tests/integration/
python -m pytest tests/integration/

# Scale tests — grow the mesh to many nodes and verify full convergence.
# Gated behind GW_STRESS; knobs: GW_STRESS_N / _WAVES / _WORKERS.
GW_STRESS=1 GW_STRESS_N=8 python -m pytest tests/integration/test_stress.py -v -s
```

**Deep property tests** (`tests/deep/`, marker `deep`) are the exhaustive
Hypothesis tier, kept out of the default run so it stays ~30s. They drive
state machines and adversarial inputs against the security-critical invariants:
credential/record tamper resistance (the wire format signs *canonical
semantics* — equivalent encodings verify, changed semantics never do), the CA
registry's hostname-uniqueness/revocation/rollback rules under arbitrary
operation interleavings, directory merge monotonicity, the audit→narrate logfmt
round trip (including control-character injection via wire-supplied hostnames),
and `/etc/hosts` never damaging user content. Their first run found two real
bugs the fast suite had missed — an audit-log injection via control characters
in hostnames, and a unicode-line-boundary corruption in hosts-file rewrites —
which is the tier's job.

```bash
# Quick sanity pass of the deep tier: stock example counts, a few seconds.
python -m pytest tests/deep -m deep

# THE NIGHTLY: 10,000 examples per property, ~9 minutes. Point cron or a CI
# schedule at this. Extra args pass through to pytest (-k, -x, ...).
scripts/deep-tests.sh

# Same thing spelled out (the script just sets the Hypothesis profile):
HYPOTHESIS_PROFILE=deep python -m pytest tests/deep -m deep -q
```

When the nightly fails, Hypothesis prints the shrunken falsifying example plus
a `@reproduce_failure(...)` blob — paste that decorator onto the failing test
to replay the exact case in a normal fast run. Failing examples are also cached
in `.hypothesis/` (gitignored), so a plain re-run of `tests/deep` retries them
first even without the blob.

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
