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

Whether the old key is compromised, lost, or you just want to migrate hubs, the
mechanism is the same **re-root**: get the fleet to trust a new CA key, re-issue
under it, drop the old key. Because `trusted_pubs` is a *set*, you can trust both
during the overlap, so it's non-disruptive when done gracefully.

1. On the new host, generate a CA: `sudo gw hub-promote` (or `setup-hub` on a
   fresh host). Note the new CA public key it prints.
2. **Add the new CA pubkey to `[ca] trusted_pubs` on every node** and restart
   their daemons (config push — this is what Ansible is for). The fleet now
   trusts old *and* new — this list is your overlap window.
3. Repoint nodes' `root_url` + `seeds` to the new hub (config push). Nodes
   re-credential under the new CA on their next renewal (or `gw join` fresh).
4. Once every node holds a new-CA credential, **remove the old key** from
   `trusted_pubs` fleet-wide. Then destroy the old `ca.key` / decommission A.

**Graceful (planned migration, or the old key is safely retired):** keep both
keys trusted through step 2–3, drop the old in step 4. Zero disruption.

**Emergency (old key in an attacker's hands):** the attacker can mint valid
credentials until the old key is gone from *every* node's `trusted_pubs`, and
`gw revoke` cannot stop the CA itself. So do step 1–2 with the **new** key, then
**immediately remove the compromised key** from `trusted_pubs` everywhere — the
overlap window is the attacker's window, so make it short. Prioritize the push.

The way to avoid the lost-key version entirely: **back up `ca.key` encrypted and
offline** (then a dead hub is a *restore*, not a re-root — see below), and keep
`trusted_pubs` a set so you always have an overlap path.

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
