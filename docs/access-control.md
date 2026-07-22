# Access control (roles & grants)

A fresh anchor ships **default-closed**: the grant table is a **secure star** —
the anchor (which holds `role:admin`) can SSH every node, nodes reach only the
anchor's control plane, and **nodes cannot reach each other at all**. You open
what you need by adding grants.

To control **who talks to whom, on what**, give nodes **roles** and write a
**grant table**. The mesh then *derives its tunnel topology from the policy*.
Three roles are built in:

| Role | Who holds it | Meaning |
|------|--------------|---------|
| `node` | every ordinary member (the default) | an ordinary fleet node |
| `anchor` | the anchor, and **only** the anchor | single-member reserved. Addressable in grants as `to = ["anchor"]` |
| `admin` | the anchor by default, tag any box | **terminal access** — SSH to every node.|

**Roles are CA-signed caps** (`role:<name>`), and crucially, the anchor
assigns them, a node cannot assert its own. However, the anchor can choose to
provide new nodes with a "menu" of available roles. This is helpful for auto-provisioning,
where multiple roles can join with a single standing token. 

```bash
# Fixed role — the invite decides; join takes what the token granted:
TOKEN=$(sudo gw invite --roles web)          # this token → a role:web node
sudo gw join "$TOKEN" --hostname web1

# ...or a MENU — one standing token, and the joiner picks a role from it:
MENU=$(sudo gw invite --self-roles web,worker,db)
#   ...or derive the menu from the policy itself — every role grants.toml
#   references, minus built-ins (*, anchor, node, admin):
# MENU=$(sudo gw invite --self-roles-from-grants)
sudo gw join "$MENU" --roles worker --hostname worker1   # anchor signs iff 'worker' is on the menu

# Change roles later without re-joining (effective at the node's next renewal):
`sudo gw set-roles web1 web,worker`
```

**Defaults for new nodes** live in the anchor's config — `[anchor]
default_roles` (`["node"]`) and `default_caps` (`["tls"]`). The default
`node` role is **sticky**: `gw set-roles` keeps it even when your list omits
it, and `gw invite --roles` adds it on top of the class you name — because
fleet grants (the shipped `admin → node : tcp/22`) target it, and losing it
by omission surfaces later as a "why can't admin SSH this box" mystery.
Dropping it is always explicit: `--exact` on either command (which prints
exactly which grants stop covering the host), or unchecking `node` in the
`gw watch` role editor (which warns on the review screen). A
plain `gw invite` uses them; the flags override per token; they're read fresh
at each invite, so editing the config changes future enrollments with no
restart.

### The grant table derives the topology (examples)

```toml
# <data_dir>/grants.toml on the anchor  (full reference: grants.toml.example)
[[grant]]
from  = ["web", "worker"]
to    = ["api"]
ports = ["tcp/8000"]
# why: the app tier calls the API; nothing else does.

[[grant]]
from  = ["metrics"]
to    = ["*"]
ports = ["tcp/9100"]
# why: prometheus scrapes everyone — hub-and-spoke tunnels, not a clique.
```

A single grant can be a whole service: `worker -> files : tcp/2049` is a
complete file share, with the grant table acting as the share's ACL — see the
[NFS worked example](nfs.md#worked-example-a-shared-directory-over-the-mesh-nfs).

### Declarative role assignments (`[assign]`)

Roles are assigned imperatively by default (`gw invite --roles`,
`gw set-roles`). Add an **optional `[assign]` table** to grants.toml and the
file also declares *who holds which roles* — making the one policy file a
complete, diffable description of the mesh: membership shape **and** topology:

```toml
[assign]
nas = ["nfs_srv"]
bb  = ["nfs_usr", "web"]
```

`gw policy apply` reconciles listed hosts' roles to the table — previewing
role diffs and the resulting tunnel delta exactly like a grant edit, then
sending one fleet renew hint so every change lands within a poll interval.
Listed hosts refuse `gw set-roles` (an imperative edit would silently drift
from the file), and the `gw watch` role editor **writes this table** rather
than the registry — the TUI is a hand on the file, never a bypass of it.
Unlisted hosts keep the imperative flow, so menu-invite auto-provisioning
composes untouched; a listed host that hasn't joined yet warns at apply and
reconciles automatically once it does. No `[assign]` section — no change at
all.

### Grants to specific machines (`host:`)

When a grant really means *this one box*, name it directly instead of minting
a single-member role:

```toml
[[grant]]
from  = ["host:bb"]
to    = ["host:nas"]
ports = ["tcp/2049"]
# why: exactly one workstation mounts the NAS — no role ceremony for a pair.
```

`host:<name>` matches the node's **CA-attested hostname** — the same signed
credential field behind `/etc/hosts` names and TLS CNs — so a host grant rides
the identical trust chain as a role: nothing self-asserted enters the policy.
(Mechanically it's a derived tag, computed from the credential at match time;
it is never stored and can never be assigned or spoofed as a cap.) Roles and
host entries mix freely in one grant: `from = ["worker", "host:laptop"]`.

**The one caveat: a host grant is only as strong as name assignment.** Roles
are always anchor-chosen, but by default a node *names itself* at join — so a
grant written for a name nobody currently holds (or a name freed by
decommissioning) would be inherited by whichever machine the anchor next
admits under it. `gw policy apply` warns on both cases (an unheld `host:` name,
and a granted node whose name is self-chosen), and the fix is one flag:
**pin any name you grant by** (`gw invite --hostname nas` — anchor-chosen,
un-renameable). Relatedly, the grant follows the *name*: `gw rename-node`
warns and asks before renaming a node out of its own grants (fail closed).

```bash
# the low-friction path — finds the file, opens your editor ($SUDO_EDITOR/
# $VISUAL/$EDITOR, else nano), validates on save, then offers the apply preview:
sudo gw policy edit

# or edit the anchor's <data_dir>/grants.toml by hand, then apply — with a preview:
sudo gw policy apply
#   this will change the policy: v1 → v2
#     - grant  * -> * : *
#     + grant  web -> api : tcp/8000     ← the rule change (X → Y)
#     - tunnel web1 ↔ web2               ← what actually connects/disconnects
#   apply? [y/N]
gw policy show              # on any node: the active table (flags unapplied edits)
```

**grants.toml is the source of truth.** `gw create`
writes it (the default-closed baseline — `admin -> anchor,node : tcp/22`) and signs it into the
distributed, CA-signed `policy.json` — the form nodes actually receive and
trust (a node can't trust a plaintext file from another host). To change
policy you edit grants.toml and run `gw policy apply`, which **previews the
change and asks you to confirm** before signing it: a policy change tears down
tunnels, so it is never applied silently by a stray file save. `gw policy show`
flags an edited-but-unapplied grants.toml so a forgotten apply is visible. A
joining node is handed the current signed policy at enrollment, so it enforces
the real table from its first run — the mesh never operates on an implicit
default.

With a policy applied, a tunnel exists between two nodes **only if some grant
connects their roles** (either direction — tunnels are symmetric; the grant's
direction is for port filtering). Tunnels are **minimal by construction**:
delete a grant and its tunnels are torn down on the next sync; peers,
keepalives, and handshake exposure all shrink to the grant graph. Two `web`
nodes have no tunnel unless someone writes `web -> web`, client and server
are roles that coexist without talking sideways.

**Segments are emergent, not configured.** There is no segment cap, flag, or
config key: a "segment" is the unnamed connected structure the grant graph
produces — `role:web` and `role:api` nodes granted an interface share one,
and it dissolves when the grant does. `gw watch --by-role` shows the groups
and flags **policy-expected links that are down** (a real fault) without
false-alarming on pairs the policy correctly keeps apart.

Properties to rely on:

- **Allow-only, by schema.** A flow passes iff some grant covers it; there's
  no deny rule (no action field) — grants are a set, not an ordered program,
  so no conflicts.
- **The anchor is hardwired beneath the table.** Every node always tunnels to
  the anchor (`role:*`), and no grant can prune it — the policy rides the
  directory sync, which rides the anchor tunnel, so the channel that carries
  the policy can't be severed *by* the policy.
- **Signed and replay-proof.** The table is CA-signed with a monotonic
  version; nodes adopt only newer, validly-signed tables and keep
  last-known-good on disk across reboots.
- **Anchor-assigned, mutually enforced.** A tunnel needs *both* ends to
  install each other, each reading the other's roles from its CA-signed
  credential — a node can't talk its way into a role it wasn't issued, nor be
  forced into a link it denies.

**Port enforcement is on by default.** The daemon realizes each grant's
`ports` in **greasewood's own** `table inet greasewood_<mesh>`, scoped to the
mesh interface: it default-denies mesh traffic and admits only the granted
flows (server-side inbound; a client's replies ride `ct established`, so the
asymmetry needs no rule). A fresh anchor ships **default-closed** — a secure
star where only `role:admin` (the anchor) can SSH nodes; you open services by
writing grants. Enforcement is a policy *state*, always installed, not a mode
you switch on.

It writes **only** its own table on `gw-<mesh>` — never your host firewall,
never a physical NIC — so it can only ever *tighten*, and it presupposes
you've admitted the overlay (`iifname "gw-<mesh>" accept`, or no host
firewall; `gw firewall` advises exactly that). The table **persists across
daemon restarts** (fail closed); `gw purge` removes it.

Because enforcement is on by default, **nftables must be usable** — the daemon
refuses to start rather than run silently unenforced. A host without it sets
`enforce_ports = false` under `[network]` (or a one-off `gw run
--no-enforce-ports`): grants still gate which *tunnels* exist, but port scopes
go advisory.

