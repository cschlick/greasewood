# Operations runbook

Disaster SOPs for a greasewood fleet. Commands assume the default
`/etc/greasewood_myfleet.toml` and data dir `/var/lib/greasewood`. Read
[SECURITY.md](SECURITY.md) for the trust model these procedures rest on.

## First, debug it: `gw diagnose`

Before any recovery, find out what's actually wrong. `gw diagnose` is a
**pairwise** tool: it lays up to two named nodes plus the hub side by side and
explains, per pair, whether a tunnel can form — and if not, which factor blocks
it. (Fleet-wide link state is `gw status`; diagnose is the focused deep-dive.)

```
sudo gw diagnose            # this host ↔ the hub
sudo gw diagnose db01       # this host ↔ db01   (+ hub as reference)
sudo gw diagnose db01 web1  # db01 ↔ web1        (+ hub as reference)
```

The comparison table shows each node's overlay/underlay addresses, inbound flag,
segments, credential, and firewall for the mesh UDP port. **Only this host's
firewall is directly known**; a peer's is *inferred `OPEN`* when a handshake has
been observed (packets flowing prove its whole inbound path — host firewall,
any router/NAT, and daemon), and shown `???` otherwise. Run it **on the node
that's misbehaving** (or on the hub, which has live handshakes to prove each
node's reachability).

The per-pair verdict reads out the **directionality** — who can dial whom — and
the live status. When a pair involves this host and there's no handshake, it
localizes the block, e.g.:

| Verdict says | Meaning | Likely fix |
|--------------|---------|------------|
| `● LINKED (handshake Ns ago)` | Healthy tunnel; the peer's firewall/router are inferred OPEN. | — |
| `no handshake` + "our host firewall OPEN … suspect an UPSTREAM router/NAT" | Our port is open locally but the peer can't reach us. | Check the upstream router/NAT port-forward for the mesh UDP port; confirm the peer's daemon/outbound. |
| `no handshake` + "our host firewall CLOSED … OPEN it" | This host's own firewall blocks the port. | Open the mesh UDP port (create/join printed the rule). |
| `no handshake` + "we can dial X but it isn't answering" | The remote isn't responding. | Check X's host firewall + upstream forward, and that its daemon is up (`gw diagnose` on X shows its own firewall). |
| `✗ no shared segment` | They won't peer by design. | Give them a common segment. |
| `✗ no dialable direction (both outbound-only)` | Neither accepts inbound. | Set `inbound=yes` on at least one (`gw set-inbound yes`). |
| credential `✗ EXPIRED` / `✗ untrusted CA` / `✗ REVOKED` | Bad credential. | Renewal/clock (expired); `[ca] trusted_pubs` after a re-root (untrusted); expected (revoked). |

A LINKED pair involving this host also gets a **path-MTU blackhole** check (small
pings pass but full-size packets are dropped — the "TLS hangs but ping works"
failure); it reports the fix if it fires.

## What to back up

**Use `sudo gw hub-backup` (hub only).** It writes ONE passphrase-encrypted
file (AES-GCM, scrypt-derived key) containing the whole hub state — the CA key,
the `nodes/` registry (hostname/caps per identity), `revoked.json`, the door
key, and the hub's own node identity (`id_priv.pem`/`wg.key`, so a restore keeps
the hub's overlay address). Move that file **offline**. The passphrase comes
from a prompt, or `$GW_BACKUP_PASSPHRASE` for a cron job:

```
sudo GW_BACKUP_PASSPHRASE=… gw hub-backup --out /secure/offline/hub.gwbk
```

Anyone with the file **and** the passphrase can impersonate your CA, so guard
both. The passphrase is the *single* factor protecting the CA key at rest — use
a long, high-entropy one (a diceware phrase); `gw hub-backup` warns on a short
one. Test-restore it (`gw hub-restore … --data-dir /tmp/verify`) before you rely
on it.

> **`GW_BACKUP_PASSPHRASE` in the environment is readable** by root and, on many
> systems, visible in `/proc/<pid>/environ` and process listings — and it may
> land in shell history or a CI log. Use it only for unattended/cron backups,
> and prefer sourcing it from a secrets manager rather than an inline
> assignment. For interactive backups, omit it and let `gw hub-backup` prompt.

The pieces, if you back up by hand instead:
- **`/var/lib/greasewood/ca.key`** (hub only) — the one irreplaceable secret;
  losing it means re-rooting the whole fleet.
- The CA public key / `[ca] trusted_pubs` — also kept in every node's config.
- `/var/lib/greasewood/nodes/` (hub) — hostname/caps per identity.
- `/var/lib/greasewood/revoked.json` and `/var/lib/greasewood/door.key` (hub).

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

> `gw renew-all` does **not** speed this up. Renewal refreshes each node's *own*
> credential and carries no information about *other* nodes — a peer drops the
> revoked node only when *its* credential expires (nodes hold no revoke list; only
> the hub does). Revocation is deliberately anchored to expiry, a property every
> verifier checks independently, rather than to a signal nodes must choose to act
> on — so it's guaranteed regardless of who is online or cooperating. Coupling it
> to `renew-all` would make it only as strong as the least-cooperative node. To
> tighten the window, shorten `credential_ttl`.

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
`create` a fresh, unreachable host for this).

1. **Enroll B as an ordinary node** in the current mesh (`gw join …`) and start
   it. It now has an overlay address every node can reach.
2. **On B: `sudo gw hub-promote`.** It generates B's own CA, sets `role=hub`, and
   keeps trusting A (its `trusted_pubs` becomes `[A, B]`). Restart the daemon
   (`sudo gw run`) — B now serves the control plane on its overlay address. Note
   the printed **B CA pubkey** and **hub endpoint**.
3. **On every node** (Ansible): add B's CA pubkey to `[ca] trusted_pubs` (keep
   A's), and repoint `root_url` + `seeds` to B's overlay control URL. Restart the
   daemon. The fleet now trusts A *and* B — this is the overlap window.
4. **Nodes renew under B.** B never enrolled them, so it has no local `nodes/`
   info — but it **re-issues from each node's still-trusted directory record** (the
   hostname/caps are CA-attested in the credential), so there's nothing to copy.
   Left alone, nodes renew at ~half the TTL, so the overlap would have to last
   **at least one credential TTL**. To compress that, run **`sudo gw renew-all` on
   B**: it advertises `renew_after=now`, and every cooperating node re-issues under
   B within a poll interval + jitter (the jitter window scales with fleet size, so
   size the overlap to comfortably exceed it). An offline node re-issues when it
   returns — so still confirm every node holds a B-signed credential before step 6.
5. **Carry over revocations:** a fresh CA doesn't inherit A's revoke list. Re-run
   `gw revoke <id>` on B for anything revoked on A **before** dropping A (else the
   re-issue-from-record fallback would revive it).
6. Once every node holds a B-signed credential, **drop A's CA pubkey** from
   `trusted_pubs` fleet-wide, then decommission A.

### Emergency (old CA lost or compromised)

You can't rely on the old trust (lost), or must eject the old key fast
(compromised). Stand up a new CA (`gw create` fresh, or `hub-promote`), add
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

## SOP: rename a mesh (`gw rename-mesh`)

A mesh's name is one thing everywhere: its domain (`<name>.internal`), and — on
each host — its config (`/etc/greasewood_<name>.toml`), data dir
(`/var/lib/greasewood_<name>`), interface (`gw_<name>`), and service
(`greasewood@<name>`). `gw rename-mesh <new>` moves all of them together, so
they never drift apart. It is **operator-driven on every host** — a rare,
deliberate fleet change, not something the daemon does to itself.

1. **On the hub:** `sudo gw rename-mesh <new-name>`. This migrates the hub's own
   artifacts, starts advertising the new domain in `GET /directory`, and starts
   a **grace window** (one credential TTL) during which the hub keeps resolving
   both old and new names.

2. **Each member, on its next directory poll**, notices the hub's domain no
   longer matches its own and records it — `gw status` then shows, loudly:
   `rename: ⚠ the hub renamed this mesh <old> → <new>. Migrate: sudo gw
   rename-mesh <new>`. (An un-migrated member keeps working — peering is by
   identity, not name — it's just naming-inconsistent with the fleet until you
   migrate it.)

3. **On each member:** `sudo gw rename-mesh <new-name>`. Same migration locally,
   plus its own grace window. Do them at your leisure inside the grace TTL; both
   names resolve and both verify in TLS throughout (the daemon issues dual-SAN
   certs and keeps a dual `/etc/hosts` block during grace).

4. **The one manual step nothing can automate:** update **client connection
   strings / app configs** from `<host>.<old>` to `<host>.<new>`. Do this
   *after* the cert has rolled to dual-SAN (check `gw cert-status`), any time
   inside the grace window — both names work until it ends.

5. **After grace**, old names stop resolving (a straggler dialing `<host>.<old>`
   fails at *name resolution*, cleanly, not with a cryptic cert error) and the
   next cert renewal drops the old SAN.

Notes: new join tokens carry the new name immediately, so nodes enrolled
mid-rename land on the new domain directly. `--interface` is the one artifact
that can collide after the 15-char kernel truncation for very long names —
`rename-mesh` refuses loudly and tells you to pass an explicit interface if so.

## SOP: hub host destroyed (disk gone)

- **You have a `gw hub-backup` archive:** on the replacement host,
  `sudo gw hub-restore hub.gwbk --data-dir /var/lib/greasewood`, write
  `/etc/greasewood_myfleet.toml` (role = hub, `ca_key_file` pointing at the restored
  `ca.key`), then `gw run`. This is a **restore, not a re-root**: same CA key →
  same trust, so existing nodes keep trusting it with no `trusted_pubs` change.
  The restore refuses to overwrite an existing `ca.key` unless you pass
  `--force`. Nodes reconnect on their next sync (~20s); because the hub isn't in
  the data path, node↔node tunnels never went down — you just need to be back
  within one credential TTL so nothing expired. (The backup includes the hub's
  own `id_priv`/`wg.key`, so the replacement comes up on the *same* overlay
  address — address-based `seeds`/`root_url` keep working with no edits.)
- **No backup:** follow *CA key lost* (re-root).

> **Give the hub a DNS name.** The one thing that makes the restore seamless is
> the replacement being reachable **where the fleet expects it.** Set the hub's
> endpoint to a hostname at setup (`gw create --endpoint hub.example.com:51900`
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

## SOP: TLS service certs (`gw cert-request`) + auto-renewal

`gw cert-request` gets an x509 leaf cert from the hub for a local service (e.g.
Postgres). The leaf key is generated locally and never leaves the node; the cert
is short-lived (`[hub] tls_cert_ttl`, default 7d). The node needs the `tls`
capability (grant it with `gw set-caps` on the hub).

Request once, with a reload hook so the service picks up rotations:

```
sudo gw cert-request --san db.myfleet.internal \
     --reload-cmd "systemctl reload postgresql"
# writes <data_dir>/tls/db.key, db.crt, ca.crt; point the service at them
```

The three files need not share a directory — override any of them with
`--key-out` / `--cert-out` / `--ca-out` (e.g. key under `/etc/ssl/private`, CA in
the system trust store).

**Three files, don't conflate them:**
- the **key/cert/ca** go wherever you point them (the `--*-out` flags, else
  `<data_dir>/tls/`);
- **`greasewood.toml`** is the daemon config — `cert-request` only *reads* it (for
  `data_dir` + the default SAN), never writes it; it lives wherever you pass
  `gw -c …`;
- **`<data_dir>/tls/managed.json`** is the **renewal source of truth** — it
  records each managed cert's three paths, and the daemon reads it to know where
  to re-issue. Its location follows `data_dir` (no separate flag). `cert-request`
  prints both the config and the manifest path so you know where the renewal
  record lives.

**Auto-renewal is automatic and lives in the daemon** — no cron, no extra unit.
The daemon re-issues each managed cert at ~half its TTL into its recorded paths,
then runs `--reload-cmd`. So the one systemd service that keeps the mesh
credential fresh keeps service certs fresh too.

- **Check state:** `gw cert-status` (shows each local cert + expiry). Renewals log
  to `journalctl -u greasewood` as `auto-renewed TLS cert` / `cert reload_cmd ran`.
- **Change SANs, paths, or the reload command:** just re-run `gw cert-request`
  with the new flags — the manifest entry is keyed by `--name`, so it's replaced
  in place. Changing the paths **relocates** it: the daemon renews into the new
  locations and `cert-request` flags the old files as orphaned (remove them once
  nothing reads them — greasewood won't delete key material for you).
- **One-shot (no auto-renewal):** `gw cert-request --no-auto-renew`, then renew by
  hand before expiry.

Troubleshooting:
- **Cert not renewing** (expiry creeping up in `gw cert-status`): the daemon must
  be running and the hub reachable over the overlay, and the node must still hold
  the `tls` cap. Check `journalctl -u greasewood` for `TLS cert auto-renewal
  for … failed`; run `gw diagnose` to confirm the link to the hub; confirm the cap
  with `gw status` on the hub. A renewal failure is retried on the next cycle.
- **Cert renewed but the service still serves the old one:** the reload hook
  didn't take. The new files *are* on disk — check `journalctl` for `cert
  reload_cmd … exited`, and test the command by hand (e.g. `systemctl reload
  postgresql`). The reload runs only after a successful renewal and is non-fatal,
  so a bad hook never blocks renewal; fix it and it runs next cycle (or reload
  the service manually now).
