# Security model

greasewood is a control plane for a WireGuard mesh. WireGuard itself (the Noise
protocol) provides confidentiality, integrity, and forward secrecy for traffic
on the wire; greasewood decides **who is allowed into the mesh and who each node
will form a tunnel with**. This document states the threat model, the trust
boundaries, what is enforced, and the accepted risks.

## Threat model

Assets, in order of value: the CA key (mesh admission), node identity keys
(who a node *is*), tunnel keys (traffic), the signed directory + policy
(topology), and control-plane availability.

Adversary positions, weakest to strongest — what each can and cannot achieve:

| Adversary position | Outcome |
|--------------------|---------|
| **Internet attacker** — knows a node's IP and port, holds no secret | Nothing observable. The only underlay surface is WireGuard UDP, which silently drops anything that isn't a valid handshake from a pinned key — no reply, no banner, no HTTP ([Network exposure](#network-exposure)). |
| **On-path attacker** — can read, modify, or replay underlay packets | Sees only WireGuard ciphertext (Noise: confidentiality, integrity, forward secrecy). Control-plane requests are additionally replay-bounded (nonce + skew) even though they already ride inside the tunnel. Can drop packets — underlay availability is out of scope. |
| **Join-token holder** — stole an unexpired invite | Enrolls **one** node, during one time-boxed window, with exactly the roles the token (or its menu) grants — no self-asserted roles, no pinned name. `gw watch` shows door activity; `gw revoke` evicts the result. |
| **Malicious member** — legitimately enrolled, tries to escalate | Bounded by its CA-signed credential: cannot self-assert roles/caps/hostname, forge directory records, obtain TLS certs for names it doesn't own, or reach anything the grant table doesn't allow (default-closed) — mechanisms in [What is enforced](#what-is-enforced). Residual: first-come claim of *unused* hostnames (pin names that matter), plus whatever traffic the grants do permit. |
| **Compromised node** — attacker holds its `id_priv`/`wg_priv` | *Is* that node until revoked: its reachability, its names, its certs — but no other node's, and no wider grants. `gw revoke` cuts it off immediately at the anchor and fleet-wide within one credential TTL. |
| **Compromised anchor** — attacker holds `ca.key` | Full admission control: mint identities, assign roles, sign policy. Cannot passively decrypt tunnels or take over an *existing* node's overlay address (addresses are self-certifying, keys never leave nodes) — but can mint a new node and re-bind mesh *names* to it, hijacking future by-name connections. No defense inside the model: this is the root of trust. Recovery is a re-root ([RUNBOOK](RUNBOOK.md)). |
| **Local non-root user** on a member host | Network reachability over the overlay, not the node's identity — see [Multi-user hosts](#multi-user-hosts). |


## Keys and trust boundaries

| Secret | Held by | What it authorizes (if compromised) | Enforced protection |
|--------|---------|-------------------------------------|---------------------|
| `ca.key` (Ed25519) | the anchor | **Total.** Issue credentials for any identity → join the mesh as anyone. Revocation does not help (the attacker *is* the CA). | `0600` in a root-owned dir; optional encryption at rest (`ca_key_passphrase_env`); never carried by any greasewood protocol — it exists on the anchor only (`gw anchor-transfer` moves it over SSH, out of band). |
| `id_priv` (Ed25519) | each node | Impersonate **that one node**: renew its credential, publish its record, request its TLS certs. | `0600` on disk; no hardware backing on server VMs (accepted risk — hardware-backed identity is a v2 item). |
| `wg_priv` (X25519) | each node | **Impersonate that node on the wire.** Contained by expiry, not a CRL: a `wg_pub` is accepted only while a live credential binds it, so `gw revoke` (or rotating `wg_priv`) drops it fleet-wide within one credential TTL. **Not** auto-contained while the node keeps renewing — act on a known leak. | `0600` on disk; acceptance is credential-bound (expiry + revocation are the structural containment). |
| join token / door seed | transient | Enroll **one** node during a single open window. The anchor still enforces revoke + unique hostname, and the door admits one peer. | High-entropy 32-byte seed; time-boxed (`door_window`, default 15m); single-slot. |

## Network exposure

- **Underlay (the real NIC):** only WireGuard UDP is reachable — the mesh port
  (51900) always, and the door port (51901) only while an enrollment window is
  open. There is no HTTP on the underlay.
- **Control plane (TCP 51902) and enrollment RPC (TCP 51903):** bound to the
  node's overlay address and loopback **only — never `::`**. They are therefore
  unreachable from the underlay *by construction*, independent of any firewall.
  The firewall rules are defense in depth, not the access control.
- The enrollment exchange runs *inside* the transient door WireGuard tunnel, so
  even during a window nothing greasewood-specific is exposed in cleartext.

## What is enforced

Every peer a node installs has passed the 7-step reconcile check (`reconcile.py`,
`wire.NodeRecord.verify`):

1. **CA signature** — the credential is signed by a currently-trusted CA.
2. **Expiry** — the credential has not expired.
3. **Self-signature** — the record is signed by the identity it claims.
4. **Address derivation** — `addr == truncate64(blake2s(id_pub))`; addresses are
   self-certifying, so a node cannot claim an address it didn't derive.
5. **Revocation** — the identity is not on the anchor's revoke list.
6. **Authorization policy** — capability check (e.g. `mesh ↔ mesh`).
7. **Data plane** — install/remove the WireGuard peer to match.

Additional control-plane protections:

- **Request authentication** — `/renew` and `/cert` require a signature by the
  requester's `id_priv`; the leaf TLS private key never leaves the node.
- **TLS SAN authorization** — `/cert` issues a leaf only for names the requester
  *owns*: its CA-registered `<hostname>.<mesh_domain>`, subdomains of it, and its
  own overlay address (`derive_addr(id_pub)`). A `tls`-capable node therefore
  cannot obtain a cert for another node's name, so it cannot impersonate a
  service it doesn't run to a `verify-full` client. (TLS here is for service
  *identity*, not extra encryption — WireGuard already encrypts the tunnel.)
- **Replay protection** — `/renew` and `/cert` are bounded by a ±300s timestamp
  skew window *and* a single-use nonce cache, so a captured request cannot be
  replayed.
- **Structural verification on ingest** — the directory merges by highest
  sequence number, so before a record is cached it must pass the checks that
  depend only on the record itself, not on the CA or the clock: self-signature,
  address-derives-from-`id_pub`, and `id_pub`↔credential match. Forging these
  needs the target's `id_priv`, so a malicious or tampered `/directory` response
  can't slip in a high-`seq` fake to evict ("shadow") a node's real record — a
  cache-poisoning DoS. The CA-signature and expiry checks run later, at reconcile,
  where they're re-evaluated against the current trust set and time (and the cache
  may legitimately hold expired records).
- **Hostname is CA-attested** — the mesh hostname lives in the CA-signed
  credential, not as a self-asserted `NodeRecord` field. A node therefore cannot
  publish a name the CA didn't issue it, so plain name resolution (the managed
  `/etc/hosts` block) can't be hijacked by a member claiming another's name.
  One deliberate consequence: *unused* names are first-come-first-served — a
  joiner names itself unless the anchor pins the name, so any enrolled node could
  claim a sensitive name nobody holds yet (and, with the `tls` cap, get a cert
  for it). **Pin names that matter** (`gw invite --hostname db`): a pinned name
  is checked free at invite, assigned by the anchor, and the node can't rename.
- **Name resolution follows the trust gate** — the `/etc/hosts` block is built
  from the records that pass the reconcile loop's *full* verification (CA
  signature, expiry, revocation), never from the raw directory cache. Revoking
  a node removes its name on the same reconcile cycle that removes its tunnel;
  an expired credential drops out of resolution the same way.
- **Caps/roles are anchor-decided, not self-asserted** — a node's capabilities
  (e.g. `tls`) and roles (`role:<name>` tags, the grant-table vocabulary) are chosen by the anchor at
  `gw invite` and bound into the CA-signed credential; the enroll server issues
  from the door window and ignores anything the joiner sends. A member cannot
  grant itself a capability or a role it wasn't issued (e.g.
  `role:prod`, or the reach-all `role:*`). Renewal re-issues from the tags
  the anchor already recorded, so they can't drift upward at renew either — and
  `gw set-roles`/`gw set-caps` let the anchor change them later (effective next
  renewal). This is what makes the grant-table policy a real boundary, not just
  honest-node configuration.
- **Trust is a static set** (`[ca] trusted_pubs`) — nodes accept credentials
  only from the CA keys they are configured to trust. Moving the CA is a
  deliberate re-root (a config change to that set), not an automatic runtime
  handoff, so a decommissioned or leaked anchor key cannot inject itself into the
  fleet's trust; it stays trusted only as long as it's in `trusted_pubs`.

## Accepted risks / non-goals

- **A malicious *current* anchor can deny service** (withhold directory entries,
  refuse renewals). Trust is rooted in the anchor by design; the "anchor may be offline
  for one credential TTL" window limits the damage, but a live, malicious anchor is
  outside the threat model. It still cannot **intercept** traffic — it never
  holds any node's `wg_priv` or `id_priv`.
- **Revocation is expiry-based on nodes** (no CRL push). At the anchor a revocation
  is immediate (refuses renew/publish and evicts locally, live — no restart). On
  other nodes a revoked peer falls out within at most one credential TTL as its
  credential expires. Shorten `credential_ttl` if you need a tighter bound.
- **Clock integrity is a security dependency.** Every allow/deny is a timestamp
  comparison (expiry, skew). Run NTP/chrony and treat it as part of your security
  posture.

## Multi-user hosts

**The unit of identity is the machine, not the user.** `gw-myfleet` is a kernel
interface in the host's single network namespace, so — like any VPN or route on
a shared host — **every local user can send and receive over the overlay** once
it's up. There is no per-user access control on the tunnel; a local user can
reach mesh peers, be reached, and read the (non-secret) directory over `::1`.

What a non-root local user still **cannot** do:

- read the private keys (`id_priv.pem`, `ca.key`, `wg.key` are `0600` inside a
  `0700` data dir) → no impersonation, no CA abuse, no TLS cert;
- administer or tear down the interface (needs `CAP_NET_ADMIN`);
- forge control-plane requests (`/renew`, `/cert`, `/publish` require signatures).

So a co-tenant gets **network reachability to the mesh**, not the node's identity.
If that reachability itself is unacceptable, enforce it at the OS layer (greasewood
won't, by design.


## Reporting

This is a personal project. File issues on the GitHub repository (the
GitLab copy is a read-only mirror). For the operational response to key loss or
compromise, see [RUNBOOK.md](RUNBOOK.md).
