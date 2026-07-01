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
| `REJECTED` + "not from a trusted CA" | Succession not synced, or wrong fleet. | Confirm `[ca] trusted_pubs`; wait for trust sync; check the hub. |
| `REJECTED` + "node is REVOKED" | Intentionally revoked. | Expected, or un-revoke and re-issue. |
| `verified but NOT installed` | Daemon not reconciling / not root. | Ensure `gw run` (or the service) is up as root. |

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

## SOP: CA key compromised — *and you still have it*

Rotate via succession, no fleet-wide config edit, no downtime:

1. Stand up the new hub identity and CA: `sudo gw hub-promote` on node B.
2. From the **old** hub, endorse the successor:
   `sudo gw hub-endorse <B_ca_pub> --endpoint http://[<B-overlay>]:51902`.
3. Let it propagate; nodes re-credential under B on their next renewal.
4. From the old hub, retire the old CA **with a grace period** (default one
   credential TTL — never retire immediately): `sudo gw hub-retire <A_ca_pub>`.
5. After the grace window, destroy the old `ca.key`.

This is the normal §11 succession flow; see the README "Moving the hub" section.

## SOP: CA key **lost or compromised-and-gone** (you do *not* have it)

This is the worst case: you cannot sign a succession from a key you don't hold,
so transitive trust to a new CA is impossible. You must **re-root** the fleet.

1. On a hub, generate a new CA: `sudo gw hub-promote` (or `setup-hub` on a fresh
   host). Note the new CA public key it prints.
2. **Add the new CA pubkey to `[ca] trusted_pubs` on every node** and reload
   (config push — this is what Ansible is for). Keep the old key in the list only
   if it's lost-but-not-attacker-held; **remove it immediately if compromised.**
3. Nodes now trust the new CA. Re-issue/renew credentials under it
   (`gw join` with a fresh token, or let renewal target the new hub).
4. Old credentials expire on their own.

> If the key is in an attacker's hands, they can issue valid credentials until
> step 2 completes on every node — `gw revoke` cannot stop the CA itself. Treat
> this as an emergency re-root and prioritize pushing the new `trusted_pubs`.

The way to avoid ever being here: **back up `ca.key` encrypted and offline**, and
build `trusted_pubs` as a set from day one so you always have a succession path.

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
3. **Botched retirement.** A CA was retired without overlap. Re-endorse the
   intended active CA from a still-trusted key; never `hub-retire` without the
   default grace.

`gw diagnose` on a couple of nodes will tell you which of these it is.

## SOP: rotate a node's tunnel key (`wg_priv`)

Low urgency (the key is self-limiting). Regenerate `wg.key` and restart the
daemon; renewal carries the new `wg_pub` to the hub, and peers pick it up on
their next reconcile. No CA action needed — the address is anchored to `id_pub`,
not `wg_pub`, so it doesn't change.
