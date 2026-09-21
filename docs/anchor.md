# The anchor file

There is no anchor *machine*. There is a file.

`<data_dir>/anchor.gwa` holds the mesh's two root secrets — the CA private
key (which signs credentials, membership statements, the grant table, and TLS
certs) and the door private key (whose public half is baked into every
invite). **Any node whose data dir holds this file performs anchor duties.**
Several can hold it at once and act independently — invites, revocations,
role changes, renewals, and departures can all be served or decided at any
holder, concurrently.

```
transfer    = copy the file        (gw anchor export → scp → gw anchor adopt)
redundancy  = keep it on several machines
de-anchor   = delete it            (gw anchor drop)
```

## Why several holders need no coordination

Two design moves make active/active coherent without any consensus protocol:

**The credential is the registry entry.** A node's hostname, caps, and expiry
all ride in its CA-signed credential, inside its NodeRecord, replicated to
every member by the directory gossip everyone already runs. So issuance —
enrollment, renewal — reads state every holder converges on, and a renewal
served at holder A is visible at holder B one sync pull later, because the
node's fresh record is. There is no private registry to hand over, which is
precisely what makes the authority portable.

**Membership decisions are replicated statements.** The three mutations a
credential can't express are CA-signed `AnchorStatement`s, carried in
`/directory` beside the records and merged order-free by every node and
holder:

| kind        | meaning                              | merge rule            |
|-------------|--------------------------------------|-----------------------|
| `revoke`    | permanent exclusion of an identity   | monotone — never lapses |
| `tombstone` | a membership ENDED (leave, sweep)    | latest ts wins; kills only credentials issued at or before it, so re-enrollment works |
| `setcaps`   | operator changed a node's caps       | latest ts wins; applied at the next renewal, by whichever holder serves it |

A statement is as unforgeable in transit as a credential, so any node can
relay one; verification against the trusted CA set gates every merge.

## The accepted races

Active/active with no consensus means a small set of races are *accepted and
made loud* rather than prevented:

- **Two holders enroll the same hostname at the same moment.** Both succeed;
  the collision is visible in every view (two records, one name); fix by
  re-running one join. Within one holder this can't happen (a lock plus the
  just-issued overlay).
- **A caps change races a renewal at a holder that hasn't synced it yet.**
  The renewal can bake the old caps for one cycle; re-apply. The statement
  gossip interval (~20s) keeps the window small.
- **Two holders decide about the same node concurrently.** Both decisions are
  authentic; the later timestamp prevails everywhere; both stay in the audit
  trail.

For a mesh operated by one person from several machines, these are the right
trade: every alternative buys consistency with an always-on quorum.

## Operations

```bash
sudo gw anchor init                  # legacy anchor → fold ca.key+door.key into the file
sudo gw anchor export /tmp/a.gwa    # write it for transfer (0600; refuses overwrite)
scp /tmp/a.gwa gp2:                  # YOUR channel — the root key never rides the mesh
sudo gw anchor adopt a.gwa           # on gp2: install, grant itself the anchor
                                     # roles (a replicated setcaps), restart
gw anchor status                     # holder state here + the fleet's holders
sudo gw anchor drop                  # shed the roles, delete this copy
```

Nodes need **no configuration** for any of this: they discover the anchor
set from the directory (records carrying the anchor roles under a trusted
CA), sync from the first live holder, renew against any of them, and `gw
leave` departs via whichever answers. `root_url`/`seeds` remain as pure
bootstrap. Holders sync from *each other* the same way — that is the whole
inter-holder protocol.

Invites are the one per-holder affair: a token opens the minting holder's
door and is redeemed there (door *windows* are local state, though the door
*key* rides in the file, so every holder's tokens verify the same trust).

## What deleting the file does — and doesn't — mean

`gw anchor drop` is the **cooperative** de-anchor: `gw leave`, for anchors.
The machine sheds its anchor roles (a replicated setcaps, minted while it
still holds the key) and deletes its copy. It proves nothing about other
copies — **knowledge can't be revoked**. A machine you no longer *trust*
needs the re-root: generate a fresh CA, walk `trusted_pubs` through the
overlap, retire the old key (see [operations](operations.md)).

Guard the file accordingly: it is the whole mesh's root authority, kept 0600
root, moved only over channels you control, wrapped in `gw anchor-backup`'s
encryption whenever it rests anywhere but a holder's data dir.

## Migration from a single-anchor mesh

1. Upgrade the fleet (holders first).
2. On the anchor: `sudo gw anchor init` — it keeps serving exactly as before
   (the legacy `role = anchor` config still counts; the file now travels).
3. `sudo gw anchor export` → copy → `sudo gw anchor adopt` on each additional
   machine you want to manage the mesh from.
4. Nothing else changes: nodes discover the new holders from the directory on
   their next pulls.

The old `nodes/` registry is simply ignored by current code (left on disk,
restored byte-for-byte from old backups); `revoked.json` remains a merged
source forever, so pre-statement revocations keep counting.
