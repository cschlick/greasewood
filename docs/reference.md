# Command & configuration reference

## Command reference

Bare **`gw`** is the dashboard, not a usage error: `sudo gw` in a terminal
opens the live watch view; without root (or piped) it prints the static
snapshot with an everyday-commands index below it; on an unconfigured or
multi-mesh host it tells you how to start (or which `-c`). `gw --help` keeps
the full reference.

| Command            | sudo? | What it does                                              |
|--------------------|-------|-----------------------------------------------------------|
| `create`        | yes   | One-shot anchor bootstrap: CA, door key, routing, self-cred. |
| `run`              | yes   | Start the daemon (WireGuard iface, control plane, loops). Port enforcement (grant port scopes, nftables) is on by default; `--no-enforce-ports` (or `enforce_ports=false`) disables it for an nft-less host. See [Access control](#access-control-roles--grants). |
| `invite`           | yes   | Open a 15-min door window, print a single-use join token. `--standing` opens a [standing door](#baked-images--autoscaling-the-standing-door) instead: one token, any number of enrollments, until `close-door`. |
| `close-door`       | yes   | Close the current door window — permanently invalidates its token (standing or single-use); enrolled nodes unaffected. |
| `join <token>`     | yes   | Enroll this machine using a token from `invite`.          |
| `watch`            | sudo  | **Live** mesh dashboard (redraws in place, so it needs sudo for live WireGuard state): the split roster + link state, per-second throughput, and a latency column that fills in as pings return. Ctrl-C to exit. **`--snapshot`** prints one static view and exits (no root; auto-used when piped); **`--json`** emits that snapshot as a stable, versioned schema for monitors/jq (add `sudo` for live WireGuard stats) — and the human roster is *rendered from that very JSON*, so the machine contract can't silently drift from what you see. **`--by-role`** groups by role and, per group, reports **connectivity** — connected components (the emergent segments), and policy-expected-but-down edges with a firewall/NAT hint — computed fleet-wide from each node's self-reported live links. Shows how fresh the view is (time since last sync) up top. |
| `config [key]`     | no    | Print resolved config facts machine-readably for scripting — `gw config interface` gives the mesh interface name (`gw-<mesh>`), no arg lists all as `key<TAB>value`. |
| `firewall`         | no    | Print the recommended firewall ruleset (a **suggestion** — greasewood never changes your firewall; nothing is applied). The same posture on every node; with `sudo` also flags anything that looks blocked. |
| `diagnose [A [B]]` | sudo  | Pairwise link diagnosis: compare up to two nodes + the anchor side by side and explain whether a tunnel can form (policy/roles, reachability, firewall directionality with `OPEN`-inferred-from-handshake and upstream-router localization). No args = this host ↔ anchor. |
| `revoke <node>`    | no    | Revoke a node on the anchor (denies renew/publish, evicts it, frees its hostname). `<node>` = hostname, `<host>.<mesh_domain>` mesh name, or 64-char id_pub hex. |
| `set-roles <node> <r>` | no | Change a node's roles (on the anchor; effective next renewal). |
| `policy`           | show: no · apply: sudo | The mesh's grant table (roles → roles : ports; derives which tunnels exist). `show` renders the active policy on any node; `apply` (anchor) validates `grants.toml`, previews the tunnel delta, signs with the CA key, publishes. See [Roles & the grant table](#roles--the-grant-table-gw-policy). |
| `set-caps <node> <caps>` | no | Change a node's full tag set (on the anchor; effective next renewal). |
| `anchor-promote`      | yes   | Turn this enrolled node into an anchor (generate its own CA key).  |
| `cert-request`     | no    | Get an x509 TLS cert from the anchor for a local service. The daemon auto-renews it at ~half its TTL; `--reload-cmd` runs a command after each renewal, `--no-auto-renew` opts out. **`--profile <name\|path>`** issues + places the key/cert/ca where the service wants them (right owner/mode) and re-places on every renewal; `--profile <name> --show` prints a bundled template to adapt. |
| `cert-profiles`    | no    | List the bundled cert profile templates (postgres, nginx, haproxy, redis, nats, minio, mosquitto) — starting points to copy and adapt. |
| `cert-remove <name>` | sudo | Stop managing a cert (drop it from auto-renewal + remove its profile snapshot). Leaves the placed files by default; `--delete-files` removes them too. |
| `cert-status`      | no    | Show every daemon-managed TLS cert (expiry, renewal state, SANs, placed files, profile) from the manifest — wherever the files live. |
| `narrate`          | no    | Translate the `ip`/`wg` command trail (`audit.log`) into a plain-English story of what greasewood did and why. Filters: `--since`, `--peer`, `--grep`, `--failures`, `--stats`, `--raw`. |
| `rename-node <name>` | yes | Change this node's mesh hostname (anchor-validated, no re-join; refused if the anchor pinned the name). |
| `rename-mesh <name>` | yes | Rename this mesh — domain, config, data dir, interface, and service move together. Run on the anchor, then on each member (surfaced in its `gw watch`). Old names resolve + verify in TLS through a one-TTL grace window. See the [RUNBOOK SOP](operations.md). |
| `renew`            | yes   | Force an immediate credential renewal for this node (applies an anchor-side `set-caps`/`set-roles` now, instead of at the ~half-TTL renewal). |
| `renew-all`        | no    | On the anchor: request a fleet-wide renewal (advertise `renew_after=now`; cooperating nodes renew, jittered so the anchor's rate stays ~constant with mesh size). |
| `anchor-backup`       | no    | On the anchor: write one passphrase-encrypted archive of the CA key, node registry, revoke list, door key, and anchor identity. Store it offline. |
| `anchor-restore`      | yes   | Restore a `anchor-backup` archive onto a replacement host (same CA key → a restore, not a re-root). |
| `anchor-transfer <host>` | yes | On the anchor: hand the anchor role to another host **over SSH** (same CA → no re-root; the CA never touches the mesh). Streams the encrypted state, copies the config, then stops here / starts there / verifies — rolling back if the target doesn't come up. See the [RUNBOOK SOP](operations.md). |
| `purge`            | yes   | Remove all greasewood state from this machine.            |

Global flags: `-c/--config FILE` (default: discovered — with one mesh on the host every command finds its config unaided; with several, gw lists them and asks for `-c`) and
`-v/--verbose`. Both must precede the subcommand (`gw -v run`, not `gw run -v`).

Enrollment is door-only: `invite` on the anchor, `join` on the node. There is no
manual credential-copy path.

## Configuration

`gw create` and `gw join` write `/etc/greasewood_<name>.toml` for you; see
`greasewood.toml.example` for the full annotated schema. Key fields:

```toml
[node]
hostname = "node01"
role     = "node"          # "anchor" | "node"
caps     = ["role:mesh"]     # role:<x> tags are the grant-table vocabulary; "tls" allows certs

[network]
interface  = "gw-myfleet"
listen_port = 51900
overlay_prefix = "fd8d:e5c1:db1a:7::"        # the fleet's overlay /64 (ULA)
seeds    = ["http://[<anchor-overlay>]:51902"]  # directory URLs to pull (the anchor)
root_url = "http://[<anchor-overlay>]:51902"    # where to publish / renew
hosts_sync  = true                           # manage /etc/hosts names (on by default)
mesh_domain = "myfleet.internal"             # the mesh's ONE domain (from create <name>)

[ca]
trusted_pubs = ["<hex Ed25519 CA pubkey>"]   # a set, to allow CA migration

[anchor]                        # anchor role only
ca_key_file    = "/var/lib/greasewood/ca.key"
control_listen = ":51902"
credential_ttl = "24h"
```

### Roles

- **anchor** — holds the CA private key; serves the control plane and the
  enrollment door; participates in the mesh.
- **node** — a plain mesh participant.

### One host on two meshes

The overlay `/64` is configurable (`[network] overlay_prefix`, set at
`create --overlay-prefix`; a node learns it from its credential at join). A
node learns and verifies addresses prefix-agnostically — the self-certifying
part is the host bits, `blake2s(id_pub)`, and the CA signature attests the
prefix — so **one host can be a plain node on two independent meshes at once**
(anchor-in-two-meshes is not supported). Joining a second mesh is just:

```bash
sudo gw join "$TOKEN_B"        # that's it
```

`join` routes by the token's **CA**: a token for a mesh you're already on
refreshes that membership; an unknown CA **auto-provisions the next membership
slot** — config `/etc/greasewood2.toml`, data `/var/lib/greasewood2`, interface
`gw-<name>`, UDP `51910` (then +10 each). The mesh's **name domain rides
in the token** (declared once at `gw create <name>` → `<name>.internal`), so
every member of a mesh, including multi-mesh hosts, mounts it under the SAME
suffix, and TLS names agree fleet-wide with no flags.

**Domain collisions**: a node cannot bridge two meshes with the
same domain — no local aliasing exists (a per-host alias would diverge from the
names in the mesh's TLS certs, a debugging trap; and rewriting is off the table
since names are CA-attested). The join refuses *before* the door dance (the
token is not consumed) and tells you the fix: rename one mesh on its anchor.
Requiring a mesh name at create (becomes subdomain) should makes this a rare coincidence.

Every derived value is still overridable — pass any of the explicit knobs and
the auto-slotting steps aside entirely:

```bash
sudo gw -c /etc/gw-b.toml join "$TOKEN_B" --data-dir /var/lib/gw-b \
    --interface gw-b --listen-port 51920 --mesh-domain beta
```

**The mesh domain must differ between the two, for the same reason the interface
name must** — both are flat, host-global namespaces with no scoping. The
`/etc/hosts` block is *keyed by* `mesh_domain`, so two meshes sharing one would
(a) clobber each other's block every reconcile, each daemon strips and rewrites
the same-tagged block, and (b) collide on the names themselves: both meshes'
`db.mymesh.internal` would claim the same name for two different addresses. 

