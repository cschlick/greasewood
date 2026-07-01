# Security model

greasewood is a control plane for a WireGuard mesh. WireGuard itself (the Noise
protocol) provides confidentiality, integrity, and forward secrecy for traffic
on the wire; greasewood decides **who is allowed into the mesh and who each node
will form a tunnel with**. This document describes the trust boundaries, what is
enforced, the accepted risks, and the results of the security review.

## Keys and trust boundaries

| Secret | Held by | Blast radius if leaked | Protection |
|--------|---------|------------------------|------------|
| `ca.key` (Ed25519) | the hub | **Total.** Issue credentials for any identity → join the mesh as anyone. Revocation does not help (the attacker *is* the CA). | Encrypt at rest (`ca_key_passphrase_env`), back up offline, never copy to a node. The CA key never moves — succession hands off by signing, not by copying (§11). |
| `id_priv` (Ed25519) | each node | Impersonate **that one node**: renew its credential, publish its record, request its TLS certs. | On-disk at `0600` on server VMs (the primary deployment; no TPM expected — hardware-backed identity is a v2 item, see the founding doc). Treat a leak as "that node is compromised" → revoke. |
| `wg_priv` (X25519) | each node | **Self-limiting.** Usable only until the node's credential expires; peers tear down the stale key on the next reconcile. | On-disk at `0600`; on-disk exposure is an accepted, bounded risk. |
| join token / door seed | transient | Enroll **one** node during a single open window. The hub still enforces revoke + unique hostname, and the door admits one peer. | High-entropy, time-boxed (`door_window`, default 15m), single-slot. |

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
5. **Revocation** — the identity is not on the hub's revoke list.
6. **Authorization policy** — capability check (e.g. `mesh ↔ mesh`).
7. **Data plane** — install/remove the WireGuard peer to match.

Additional control-plane protections:

- **Request authentication** — `/renew` and `/cert` require a signature by the
  requester's `id_priv`; the leaf TLS private key never leaves the node.
- **Replay protection** — `/renew` and `/cert` are bounded by a ±300s timestamp
  skew window *and* a single-use nonce cache, so a captured request cannot be
  replayed.
- **Structural verification on ingest** — a record must pass the CA- and
  clock-independent checks (self-sig, addr derivation, id/cred consistency)
  before it can enter the directory, so a malicious or compromised directory
  response cannot shadow a real record with a high-sequence forgery.
- **Succession trust** (`trust.resolve_trust`) is the transitive closure of
  endorsements minus retirements, with a **symmetric guard**: a retired CA's key
  can make *no* new statements — neither endorsements nor retirements. This is
  what makes a decommissioned (or leaked) hub key harmless to the live fleet.

## Accepted risks / non-goals

- **A malicious *current* hub can deny service** (withhold directory entries,
  mis-endorse a successor). Trust is rooted in the hub by design; succession and
  the "hub may be offline for one credential TTL" window limit the damage, but a
  live, malicious hub is outside the threat model. It still cannot **intercept**
  traffic — it never holds any node's `wg_priv` or `id_priv`.
- **Revocation is expiry-based on nodes** (no CRL push). At the hub a revocation
  is immediate (refuses renew/publish and evicts locally, live — no restart). On
  other nodes a revoked peer falls out within at most one credential TTL as its
  credential expires. Shorten `credential_ttl` if you need a tighter bound.
- **64-bit address host portion.** A deliberate address collision needs ~2⁶⁴
  work *and* still requires the victim's `id_priv` to be useful — acceptable for
  the fleet sizes this targets.
- **On-disk `id_priv`** on server VMs (no hardware backing). Documented and
  intentional for the primary deployment.
- **Clock integrity is a security dependency.** Every allow/deny is a timestamp
  comparison (expiry, skew, succession windows). Run NTP/chrony and treat it as
  part of your security posture.

## Multi-user hosts

**The unit of identity is the machine, not the user.** `gw-mesh` is a kernel
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
won't, by design — it never touches your firewall unless asked):

1. **nftables owner match** — restrict which local users may originate overlay
   traffic (egress; owner match is output-only). Combined with the base
   `ct state established,related accept`, a denied user can't initiate anything
   over the mesh:

   ```
   # Members of group "gwmesh" (and root, for the daemon) may use the overlay.
   chain output {
       type filter hook output priority 0; policy accept;
       oifname "gw-mesh" meta skuid 0 accept
       oifname "gw-mesh" meta skgid "gwmesh" accept
       oifname "gw-mesh" drop
   }
   ```

   This gates who can *initiate*. It does not gate inbound *new* connections from
   the mesh to a local service (owner match has no input-side equivalent); for
   that, restrict inbound `iifname "gw-mesh"` to an allowlist of dports, or use
   option 2.
2. **Network namespace** — run greasewood and the intended workloads in a
   dedicated netns so `gw-mesh` isn't visible to other users' processes at all.
   Strongest isolation; more setup.
3. **Don't co-tenant** untrusted users on a mesh machine — the implicit default.

## Security review (2026-06-30)

An adversarial review of the crypto, trust, enrollment, and renewal paths. All
findings below are resolved in the current tree, each with a regression test.

| # | Severity | Finding | Resolution |
|---|----------|---------|------------|
| 1 | High | **Renewed credentials never reached the hub** — `RenewalLoop` updated only the local directory, so peers (which pull from the hub) kept seeing the about-to-expire record and would evict every node ~one credential TTL after start. | Renewal now re-publishes the fresh record to the hub as part of a successful renewal (`renewal.py`); failure re-enters the retry/backoff loop. |
| 2 | Med-High | **A retired CA's leaked key could DoS the fleet** — `resolve_trust` rejected *endorsements* by retired CAs but not *retirements*, so a decommissioned hub key could retire (un-trust) the live hub everywhere. | `resolve_trust` now applies the symmetric guard: a retirement counts only if its issuer was itself un-retired when it signed (`trust.py`). |
| 3 | Med | **Revocation required a hub restart** — the revoke set was snapshotted at startup, so `gw revoke` had no effect on the running daemon (renew refusal *and* local eviction). | The revoke list is re-read live each cycle/request (`reconcile.py`, `server.py`, `cli.py`). |
| 4 | Med | **Sticky directory shadow** — `directory.merge` accepted highest-seq without verification, so one forged high-seq record from a bad directory response permanently shadowed a victim's real record. | `directory.merge` structurally verifies every record before accepting it; a forgery (no valid self-signature) can never enter the directory. |
| 5 | Med | **Replay nonces were unused** — `/renew` and `/cert` carried a nonce "to bound replay" that the hub never tracked; only the skew window applied. | Added a thread-safe single-use nonce cache consulted after signature verification. |
| 6 | Low | **Unbounded control-plane request body** (memory DoS by an in-mesh peer). | Bodies are capped at 256 KiB. |
| 7 | Low | **Non-atomic writes** for `revoked.json` / `nodes/*.json` (corruption on crash). | Both write via temp-file + rename. |
| 8 | Low | Stale docstrings claiming SSH-only enrollment. | Updated to describe door-only enrollment. |

## Reporting

This is a personal/homelab project. File issues on the GitLab repository. For the
operational response to key loss or compromise, see [RUNBOOK.md](RUNBOOK.md).
