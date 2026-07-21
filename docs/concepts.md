# How it works

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
the fleet. See [Moving the anchor](operations.md#moving-the-anchor-re-root).

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
side is reachable (see [Reachability](networking.md#reachability)) two unreachable
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
anchor within that window (see [Moving the anchor](operations.md#moving-the-anchor-re-root) and the
[RUNBOOK](operations.md)) and nothing ever drops.

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

## Greasy

greasewood drives the data plane by **shelling out to the stock `wg`, `ip`, and
`nft` command-line tools** over subprocess, rather than talking to the kernel
directly through netlink (via a binding like `pyroute2`, or the userspace
transport a Go implementation such as `wireguard-go` ships). The clean way would
be netlink; this is the greasy way. It's a deliberate trade, and the single
biggest one in the codebase.

**Why it's the right trade here.** greasewood's top priority is being *easy to
reason about*, and its scale is small — tens of nodes, a reconcile every few
seconds, not thousands of updates a second. At that scale the readability win
dominates, and the surface it depends on (`wg set`, `ip route`, `nft`) is small
and stable, so the fragility is bounded.

**Pros:**

- **It *is* the audit trail.** Every data-plane change is a real command, so
  greasewood can log the exact `wg`/`ip`/`nft` argv it ran, with the exit code
  and the reason — see [Auditable](#auditable). You can copy any line, run it by
  hand, and compare against `wg show`.
- **One dependency.** The tools are already on the host, so the whole thing stays
  **pure Python with one dependency (`cryptography`)**. A netlink binding would
  add a dependency (or a pile of fragile low-level socket code).
- **Reproducible by hand.** Debugging is "what command did it run, and what
  happens when I run it myself" — not decoding a binary protocol.
- **Matches the operator's mental model.** greasewood is for people who already
  manage WireGuard by hand; the code reads the way they'd type.

**Cons:**

- **Slower.** A process spawn per command costs more than a netlink round-trip.
  Fine at this scale; it would not suit a control plane pushing thousands of
  rapid updates.
- **Text parsing is more brittle than structured netlink replies.** greasewood is
  tied to the tools' CLI output, which can shift across versions.
- **Depends on the tools being present and current.** `wg`, `ip`, and `nft` must
  be on `PATH` at compatible versions.
- **No transactional batching.** netlink can apply a set of changes atomically;
  subprocess means more round-trips and per-command error handling (exit codes and
  stderr rather than typed errors).

## Auditable

The entire thing is **pure Python (3.11+), one dependency (`cryptography`), one
binary (`gw`)**, and it manages the data plane by shelling out to `wg`/`ip` via
subprocess ([the greasy trade](#greasy)): you can read the exact `wg set peer …`
commands, run them by hand, and compare them against what `wg show` reports.

That pays off in the **command trail**. Because every data-plane change is
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


## Design notes & non-goals

The [non-goals](index.md#prior-art) — routing/relays, NAT traversal, IPv4 overlay,
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
  [re-root](operations.md#moving-the-anchor-re-root) doesn't require pushing the new key into every
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
old — don't move the private key to a new machine. See [Moving the anchor](operations.md#moving-the-anchor-re-root).

