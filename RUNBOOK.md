# Operations runbook

Disaster SOPs for a greasewood fleet. Commands assume the default
`/etc/greasewood.toml` and data dir `/var/lib/greasewood`. Read
[SECURITY.md](SECURITY.md) for the trust model these procedures rest on.

## First, debug it: `gw diagnose`

Before any recovery, find out what's actually wrong. `gw diagnose` runs the same
7-step checks the daemon uses, per peer, and overlays live WireGuard handshake
state — turning a silent "direct-or-fail" link into a reason:

```
sudo gw diagnose            # all peers
sudo gw diagnose db01       # just one
```

Reading the output:

| Line says | Meaning | Likely fix |
|-----------|---------|------------|
| `LINKED (handshook Ns ago)` | Healthy tunnel. | — |
| `installed, no handshake yet` + "check the peer's firewall" | Peer configured, but no handshake. | Open the mesh UDP port on the peer; confirm its daemon is up. |
| `installed, ...` + "both sides are outbound-only" | Neither side accepts inbound. | Set `inbound=yes` on at least one (`gw set-inbound yes`). |
| `REJECTED` + "credential EXPIRED" | Renewal isn't propagating. | Check hub reachability and clock; see *fleet-wide teardown* below. |
| `REJECTED` + "not from a trusted CA" | Wrong fleet, or `trusted_pubs` not updated after a re-root. | Confirm `[ca] trusted_pubs`; push the current CA key; check the hub. |
| `REJECTED` + "node is REVOKED" | Intentionally revoked. | Expected, or un-revoke and re-issue. |
| `verified but NOT installed` | Daemon not reconciling / not root. | Ensure `gw run` (or the service) is up as root. |

The last line, `reachability: ...`, is an advisory about **this** node's own
`inbound` posture, inferred from live handshakes (root only). `inbound=yes
CONFIRMED` means an outbound-only peer dialed in, so you're provably reachable;
`inbound=yes but no peer has handshaked` suggests your advertised endpoint may be
firewalled (or the daemon just started). It never changes the value — use
`gw set-inbound` for that.

## What to back up

- **`/var/lib/greasewood/ca.key`** (hub only) — encrypted, **offline**. This is
  the one irreplaceable secret; losing it means re-rooting the whole fleet.
- The CA public key / `[ca] trusted_pubs` — also kept in every node's config.
- `/var/lib/greasewood/nodes/` (hub) — hostname/caps per identity (rebuildable by
  re-enrolling, but a backup avoids that).
- `/var/lib/greasewood/revoked.json` (hub).

`id_priv.pem` / `wg.key` on a node are **not** worth backing up — recover a lost
node by enrolling a fresh one (new identity).

---

## SOP: node identity compromised

The node's `id_priv` leaked. The attacker can impersonate *that node only*.

1. On the hub: `sudo gw revoke <id_pub_hex>`. This takes effect **live** — the
   hub immediately refuses its renew/publish and evicts it locally; other nodes
   drop it within one credential TTL as its credential expires.
2. (Optional) free its hostname: delete `/var/lib/greasewood/nodes/<id_pub_hex>.json`.
3. Re-provision a replacement with a **fresh identity** (`gw join <new-token>`).

`gw status` on the hub shows identities; `gw diagnose` confirms the peer drops.

## SOP: node lost / decommissioned (not compromised)

Either let it expire (do nothing — its credential lapses within one TTL and peers
remove it), or for immediate cleanup `sudo gw revoke <id_pub_hex>` and remove its
`nodes/<id>.json` to release the hostname.

## SOP: lost door key (`door.key`)

Outstanding join tokens embed the hub's door public key, so they break if the key
changes — but the door key is otherwise disposable.

1. `sudo rm /var/lib/greasewood/door.key`
2. The next `gw invite` regenerates it. **Re-issue every outstanding token** — old
   ones no longer work.

## SOP: move the CA to a new key (re-root)

Moving the hub/CA is a **re-root**: get the fleet to trust a new CA key,
re-issue every node under it, drop the old key. `trusted_pubs` is a *set*, so you
trust both during an overlap window and it's non-disruptive.

### Graceful migration (old CA still available) — hub A → hub B

The key requirement: **B must be a reachable mesh member and must trust A during
the overlap**, so existing nodes can renew against it over the overlay. That's
exactly what `hub-promote` gives you (promote an enrolled node — don't
`setup-hub` a fresh, unreachable host for this).

1. **Enroll B as an ordinary node** in the current mesh (`gw join …`) and start
   it. It now has an overlay address every node can reach.
2. **On B: `sudo gw hub-promote`.** It generates B's own CA, sets `role=hub`, and
   keeps trusting A (its `trusted_pubs` becomes `[A, B]`). Restart the daemon
   (`sudo gw run`) — B now serves the control plane on its overlay address. Note
   the printed **B CA pubkey** and **hub endpoint**.
3. **On every node** (Ansible): add B's CA pubkey to `[ca] trusted_pubs` (keep
   A's), and repoint `root_url` + `seeds` to B's overlay control URL. Restart the
   daemon. The fleet now trusts A *and* B — this is the overlap window.
4. **Nodes renew under B** on their next cycle. B never enrolled them, so it has
   no local `nodes/` info — but it **re-issues from each node's still-trusted
   directory record** (the hostname/caps are CA-attested in the credential), so
   there's nothing to copy. Renewal is at ~half the TTL, so plan the overlap to
   last **at least one credential TTL** for every node to migrate.
5. **Carry over revocations:** a fresh CA doesn't inherit A's revoke list. Re-run
   `gw revoke <id>` on B for anything revoked on A **before** dropping A (else the
   re-issue-from-record fallback would revive it).
6. Once every node holds a B-signed credential, **drop A's CA pubkey** from
   `trusted_pubs` fleet-wide, then decommission A.

### Emergency (old CA lost or compromised)

You can't rely on the old trust (lost), or must eject the old key fast
(compromised). Stand up a new CA (`gw setup-hub` fresh, or `hub-promote`), add
its key to `trusted_pubs` fleet-wide, and:

- **Compromised:** the attacker can mint valid creds until the old key is gone
  from *every* node's `trusted_pubs`, and `gw revoke` can't stop the CA itself.
  **Remove the compromised key immediately** — the overlap is the attacker's
  window, so make it short. Nodes whose creds already lapsed **re-join** under the
  new hub with fresh tokens (`gw join`).
- **Lost:** creds keep working until they expire; migrate (renew or re-join under
  the new hub) within one credential TTL.

Avoid the lost-key case entirely: **back up `ca.key` encrypted and offline** (then
a dead hub is a *restore*, not a re-root — see below), and keep `trusted_pubs` a
set so you always have an overlap path.

## SOP: hub host destroyed (disk gone)

- **You have a backup of the data dir + config:** on the replacement host,
  restore `/var/lib/greasewood/` (the whole dir — `ca.key`, `id_priv.pem`,
  `wg.key`, `nodes/`, `revoked.json`) and `/etc/greasewood.toml`, then `gw run`.
  This is a **restore, not a re-root**: same keys → same overlay address, same
  CA, same trust. Nodes reconnect on their next sync (~20s). Because the hub
  isn't in the data path, node↔node tunnels never went down; you just need to be
  back within one credential TTL so nothing expired.
- **No backup:** follow *CA key lost* (re-root).

> **Give the hub a DNS name.** The one thing that makes the restore seamless is
> the replacement being reachable **where the fleet expects it.** Set the hub's
> endpoint to a hostname at setup (`gw setup-hub --endpoint hub.example.com:51900`
> — `wg` accepts and re-resolves hostnames), so a hub move / hardware swap is
> just updating one DNS record. If instead the replacement lands on a **new IP**:
> inbound-reachable nodes self-heal (the hub dials them, WireGuard roaming fixes
> the path), but **outbound-only (`inbound=no`) nodes** only knew the old address
> and can't learn the new one on their own — re-join those few by hand. A stable
> DNS name avoids the whole problem.

Either way the data plane keeps running until credentials expire — the hub is not
in the data path.

## SOP: fleet-wide teardown ("everything disconnected at once")

Usually one of:

1. **Clock skew.** Symptoms: `gw diagnose` shows mass `credential EXPIRED` or
   renew "timestamp skew too large". Fix NTP/chrony on the affected hosts; trust
   recovers as records re-verify.
2. **Hub unreachable past one credential TTL.** Credentials lapse fleet-wide.
   Restore the hub (above); nodes recover on the next renewal.
3. **Botched re-root.** The old CA was dropped from `trusted_pubs` before every
   node had a new-CA credential. Re-add the old key fleet-wide to restore the
   overlap, let all nodes renew under the new CA, *then* drop the old key.

`gw diagnose` on a couple of nodes will tell you which of these it is.

## SOP: rotate a node's tunnel key (`wg_priv`)

Low urgency (the key is self-limiting). Regenerate `wg.key` and restart the
daemon; renewal carries the new `wg_pub` to the hub, and peers pick it up on
their next reconcile. No CA action needed — the address is anchored to `id_pub`,
not `wg_pub`, so it doesn't change.
