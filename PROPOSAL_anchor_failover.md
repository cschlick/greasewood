# Proposal: anchor failover (standby unlock)

**Status:** Draft / not started — captured from a design discussion, to pick up later.
**Scope:** host/hardware failure of the anchor. **Explicit non-goal:** automated
recovery from anchor *compromise* (that stays a deliberate re-root — see below).

## The problem

The anchor is a single point of failure for the *control plane*: new
enrollments and credential renewals need it. The data plane is fine without it
(direct-or-fail tunnels run from cache; a node keeps working for up to one
`credential_ttl` with no anchor at all — the offline-tolerance property). But if
the anchor's host dies, today's recovery is either:

- restore a pre-made `gw anchor-backup` onto a replacement, or
- re-root the whole fleet onto a new CA (touch every node's `trusted_pubs`).

Both are manual and neither is "log into a spare and carry on." This proposal
makes the common case — **the anchor's host is gone** — a fast, near-seamless,
self-service unlock, without turning greasewood into a distributed-trust system.

## Design principles (the greasy line)

- **One CA.** One root of trust, one thing to guard. Failover puts an *encrypted*
  copy on a *few hardened* boxes; it does not create a second trust root.
- **No consensus, no hierarchy, no threshold crypto.** greasewood has no total
  order of events (the directory is eventually-consistent, merge-by-seq), so any
  scheme that needs agreement (mutual revocation, leader election, quorum) is out
  of character and out of reach. We don't build it.
- **Humans handle the scary operation.** Compromise recovery is deliberate and
  rare; automating "reject the current root and install a new one" would *be* the
  vulnerability. We make the manual path painless, not automatic.
- **Reuse what exists.** `gw anchor-backup`/`restore` (encrypted CA blob +
  passphrase), multi-valued `trusted_pubs`, the `seeds` list, and the fact that
  every node already caches the full directory.

## Proposed design

Three small pieces:

### 1. A `failover` capability (default off)

Granted at invite to your **most hardened server peers only** — never laptops,
never all nodes:

```
gw invite --hostname standby1 --caps failover
```

Granting it provisions that node with the **encrypted CA blob** (the same thing
`gw anchor-backup` produces, passphrase-protected). It sits inert on disk until
unlocked. It's a capability/ability tag (like `tls`), not a peering role.

Keep the set small (**1–2 nodes**). Each failover node is, by construction, a
node that *can become the anchor* — so it's a takeover point if the box itself is
breached. Bounded surface, chosen boxes.

### 2. Pre-trusted CA + multiple seeds, from day one

For unlock to be *seamless*, two facts must already be true across the fleet at
setup time (not arranged at failover time):

- every node **trusts the CA** — true already (there's one CA), no change; and
- every node's **`seeds`** lists the failover nodes' addresses, so the fleet can
  *find* whichever standby you activate. `seeds` is already a list — just include
  the standbys up front.

If these aren't pre-arranged, failover degrades back into "edit every node's
config" — the re-root pain we're avoiding. **All the value is in provisioning
both on day one.**

### 3. `gw anchor-activate` — unlock a standby

On anchor-host loss, SSH into a failover node and:

```
sudo gw anchor-activate      # prompts for the failover passphrase
```

This:

1. Decrypts the CA blob → the node now holds the CA private key.
2. **Rebuilds the registry from the cached directory.** A failover node has the
   *directory* (it's a syncing node) but not the anchor's *registry* (the
   authoritative node→caps map used to re-issue on renewal). Every directory
   record already carries the CA-signed credential (caps + hostname), so the
   registry can be reconstructed from what's on disk — no extra escrow.
3. Flips this membership to `role = anchor`, starts the control plane + door,
   and begins signing renewals under the (one) CA.

Because the fleet already trusts the CA and already lists this node as a seed, it
converges with **no re-pointing**. And because there was no state to move (the
directory was already cached), activation is genuinely "decrypt and serve."

### Why it's seamless (the properties it leans on)

- **Offline tolerance:** existing node↔node tunnels never touch the anchor, so
  they don't drop while it's down. You have **~one `credential_ttl`** (default
  24h) to activate a standby before anything expires. Inside that window it's
  zero-drop end to end.
- **The standby already has the directory** cached from being a normal node.

### One guard: exactly one active anchor

All failover nodes hold the same CA, so activating two is not a *trust* split
(both are trusted) — but it is two control planes serving `/directory`, which can
diverge. `anchor-activate` should refuse / loudly warn if it can still reach a
live anchor, and the docs should say "promote one."

## Compromise is out of scope (on purpose)

Failover is for **failure**, not **compromise**. If the CA key leaks:

- Failing over to a standby with the *same* CA hands the mesh to an anchor whose
  CA the attacker can also forge — useless. Compromise **requires a trust
  change**, which is inherent to any PKI, not a gap here.
- The recovery is a deliberate **re-root**, not a rebuild: stand up a new CA,
  swap every node's `trusted_pubs` to it (drop the old), nodes re-credential
  under it over one TTL. Node identities, overlay addresses, hostnames, and
  records all survive. `gw anchor-promote` + the re-root SOP already do this.

Trying to automate this is what drags the design into consensus territory
(mutual revocation → who-revokes-whom races with no total order; per-node CAs →
fleet-wide trust distribution or a CA hierarchy; k-of-n quorum → threshold crypto
+ k cooperators at recovery time). All rejected as un-greasy. See "roads not
taken."

## Security tradeoffs (be honest in the docs)

- **The CA now lives on 1–2 boxes, encrypted, instead of 1.** A small, deliberate
  widening. Its confidentiality rests on those boxes' security + the passphrase
  (use a strong KDF — argon2id/scrypt at high cost). Pick hardened nodes.
- **Distribution is irreversible.** A revoked/decommissioned failover node still
  has the encrypted CA on disk forever. **Losing a failover node ⇒ rotate the
  CA** (a re-root). Say this plainly, and keep the failover set to stable boxes.
- **Passphrase management.** The passphrase must be available at failover but not
  stored on the nodes (or it's pointless) → the admin holds it, same burden as a
  backup, with the convenience of not carrying the key file.

## Roads not taken (and why — so we don't re-derive the confusion)

| Idea | Why not |
|------|---------|
| Encrypted CA on **every** node | N brute-force targets; irreversible on departed laptops; least-hardened node sets the floor. |
| **Per-node CAs** (each standby its own CA) | Fleet must trust each → fleet-wide `trusted_pubs` update per standby, or a CA hierarchy with delegation. Both un-greasy. |
| **Mutual revocation** ("any secondary CA can invalidate one other") | Symmetric authority + no total order = revocation war / split brain. "Add new CAs" defeats any per-CA cap. Needs consensus greasewood doesn't have. |
| **k-of-n quorum revocation** | The principled decentralized answer, but threshold crypto + k cooperators at recovery. Right tool for a *different*, bigger project. |
| **Offline root + delegations (PKI hierarchy)** | Clean, but it's a hierarchy — the opposite of greasewood's flat one-CA model. |
| **Automating compromise recovery at all** | The power to reject-and-replace the root *is* a hostile-takeover primitive; software that has it is the liability. Keep it human. |
| Signed, cached, auto-distributed seed set + chained auto-reprovision | Only needed for hands-off "anchor B enrolls standby C" self-healing. Greasy version: keep 2 standbys; re-provision a replacement by hand when you burn one. An operator chore, not a protocol. |

## Rough implementation notes

- **`failover` cap:** add to the invite menu allow-list as an ability tag (like
  `tls`); provisioning it drops the encrypted CA blob into the node's data dir.
  Needs the CA blob available at invite time (the admin has it).
- **Blob:** reuse the `anchor-backup` format (CA key, passphrase-encrypted). It
  does **not** need the registry (rebuilt from the directory on activate).
- **`gw anchor-activate`:** decrypt → rebuild registry from `dir_cache` → rewrite
  this membership's config to `role=anchor` → start control plane/door → refuse
  if a live anchor is still reachable.
- **`gw anchor-standby` (optional):** provision/refresh a standby after setup
  (the manual "re-provision a replacement" path).
- **Config:** document listing all failover nodes in every node's `seeds` from
  day one. (Decision: stays static config in the greasy version; a signed/cached
  dynamic seed set is a possible future step but explicitly out of scope here.)
- **CA rotation:** a `gw anchor-rotate-ca` / documented re-root SOP for the
  compromise case and for "a failover node was lost."

## Open questions to settle when picking this up

1. How many standbys is the sane default to *document* (1? 2)? Guard against more.
2. Passphrase: same as the `anchor-backup` passphrase, or a distinct `failover`
   passphrase? (Distinct lets you rotate independently.)
3. Should `anchor-activate` auto-tell the fleet "I'm the anchor now," or rely
   purely on the pre-listed seed + nodes trying each? (Greasy = the latter.)
4. Where exactly the registry-rebuild lives, and whether any anchor-only state
   (beyond the directory) needs to ride along.
5. Do we want a lightweight `gw anchor-status`/`watch` line showing "N failover
   standbys provisioned" so you can see your redundancy at a glance?

## One-line summary

A `failover` capability escrows the one encrypted CA to a couple of hardened
standbys; pre-trusted CA + pre-listed seeds make `gw anchor-activate` a seamless
unlock when the anchor's host dies. Compromise stays a deliberate re-root. No
consensus, no hierarchy, no second trust root — a feature you can hold in your
head.
