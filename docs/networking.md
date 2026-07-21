# Networking & names

## Firewall

**greasewood never modfies your external (underlay) firewall** Its control
plane (`51902/tcp`) and enrollment RPC (`51903/tcp`) bind only to the node's
overlay address and loopback *never* the underlay, so nothing it runs is
reachable off-mesh regardless of firewall policy. The only thing that must face
the underlay is WireGuard itself (UDP), which you open yourself like for any VPN.

greasewood uses **four ports**, one contiguous block — two WireGuard udp ports
on the underlay, and two TCP service ports on the overlay.

|         | UDP — WireGuard transport | TCP — service inside the tunnel |
|---------|---------------------------|---------------------------------|
| **mesh** | `51900` — overlay data plane | `51902` — control plane |
| **door** | `51901` — ephemeral join tunnel | `51903` — enroll exchange |

`create` and `join` **check** the local nftables ruleset and
loudly warn if a needed port looks blocked by a default-drop policy, printing the
exact rule to add. That's all greasewood does. You apply the printed rules yourself (put them in your nftables
config, or however you configure your firewall).

**No firewall at all? Then there's nothing to do — and nothing extra is
exposed.** greasewood binds nothing to the underlay except its WireGuard UDP
port(s): `51900` (mesh) on any node, plus `51901` (the enrollment door)
on the anchor. Those are WireGuard, which is designed to face the internet — it
silently drops any packet that isn't a valid handshake from a configured peer (no
reply, no info leak). Everything else — the control plane (`51902`) and the
enrollment exchange (`51903`) — binds to the overlay address or the door tunnel,
so it's *structurally* off the underlay whether or not you run a firewall. A
greasewood host with no firewall is therefore no more exposed than a plain
WireGuard host with no firewall. The rules below matter only on a host that runs
a **default-drop** policy and so must explicitly *allow* those ports through.

On a default-drop host, allow (nftables). With port enforcement on (the
default), greasewood's own nftables table filters the overlay interfaces
(control plane, enrollment + door lockdown, and the grant-derived ports), so
your firewall just opens the two underlay UDP ports and **admits** the overlay —
greasewood does the rest:

| Interface  | Rule                          | Purpose                              |
|------------|-------------------------------|--------------------------------------|
| underlay   | `udp dport 51900 accept`      | mesh WireGuard                       |
| underlay   | `udp dport 51901 accept`      | enrollment door (during join)        |
| `lo`       | `iifname "lo" accept`         | the host talks to itself (`::1:51902`)|
| `gw-*`     | `iifname "gw-*" accept`       | admit the overlay; greasewood's table filters the ports on it |

```
udp dport { 51900, 51901 } accept
iifname "lo" accept
iifname "gw-*" accept
```

That coarse `iifname "gw-*" accept` is required in a default drop context to allow
traffic to reach greasewood's overlay table (greasewood's table can only
*tighten* what your firewall admits, never open it). Greasewood's table then scopes the control plane to `gw-<mesh>`,
locks `gw-door` to enrollment only, and applies the grant table's port scopes.

**If you turn enforcement off** (`enforce_ports = false`), greasewood installs no
table. It's purpose is to enforce access control to ports on this machine from a central location
(the anchor), which requires cooperation from to enforce. It is opt-in. 

**Multi-user hosts:** the overlay is host-wide, *any* local user can use the
tunnel once it's up (identity is per-machine, not per-user). To restrict which
users may originate overlay traffic, add an nftables owner-match on the output
chain; see the "Multi-user hosts" section of [security.md](security.md).

### Reachability

WireGuard has no client/server roles. Both peers try to handshake and the
direction that physically works wins, then endpoint roaming pins it. So a link
forms as long as **at least one side is reachable**: a firewalled node dials an
open one, and the reply returns via the NAT hole it punched. Two fully-blocked
nodes can't pair (direct-or-fail — no relays). Greasewood inherits this semi-tolerance
of NAT/firewall issues from WireGuard directly, but it makes no serious effort to reason 
about the underlying network state and automatically just work (that is the domain of Tailscale, etc).
The best greasewood can do is to examine IP address and determine when a node obviously has no
externally reachable address (LAN NAT, CGNAT, etc) and print that in `gw diagnose`. 
So, when a reachability issue arise it is very likely to be that BOTH peers are behind a
NAT/Firewall that does not provide them an externally reachable endpoint. The only solution
in that case would be to try and make changes to the underlying network state. 

An **anchor** must be reachable (it serves the control plane), so in order for a node
to become the anchor, it must have a reachable external address. So
`anchor-promote` refuses on a node that knows it advertises no endpoint.


## Names

Every node has a stable overlay address, and `gw watch` shows each node's
resolvable name↔address map. Name resolution is **encouraged**: the daemon
keeps a marked `/etc/hosts` block mapping each node's address to
`<hostname>.<mesh>.internal` (e.g. `db.mymesh.internal`), built from the records that pass the reconcile loop's
full verification — the same gate that decides WireGuard peers, so a revoked or
expired node's name stops resolving on the same cycle its tunnel comes down.
It's re-checked each reconcile but *only rewritten when the block actually
changes* (a join, departure, revocation, or rename) — in steady state it never
touches the file, so it won't hammer `/etc/hosts`

```
# BEGIN greasewood — managed, do not edit
fd8d:e5c1:db1a:7:…  db.mymesh.internal
fd8d:e5c1:db1a:7:…  node01.mymesh.internal
# END greasewood
```

So `ping db.mymesh.internal`, `ssh db.mymesh.internal`, etc. just work — no DNS
server, and it keeps resolving even if the anchor is down (it's from the cache,
for as long as the cached credentials remain valid — one credential TTL, the
same horizon as the tunnels themselves). It
only ever touches the region between its markers; your own `/etc/hosts` lines are
left alone, and `--no-hosts-sync` (or `hosts_sync = false` + restart) or `gw
purge` removes the block.

A node can also publish extra **service names** under its own name via
`[network] aliases` (or automatically from a subdomain TLS cert) — a label `pg`
becomes an extra `pg.<hostname>.myfleet.internal` line pointing at that node. See the
TLS section for how this ties cert SANs to resolvable names.

**Who chooses the name.** By default a node names itself at `gw join` (defaulting
to its machine hostname) and can change it later with `gw rename-node`. If you'd rather
the anchor control it, **pin it at invite**: `gw invite --hostname db` fixes the name
at enrollment (the joiner's requested name is ignored) and marks the credential so
the node **can't `gw rename-node` itself** — to change a pinned name, re-invite with a
new `--hostname`. Either way the name is CA-attested; pinning just moves the
decision from the node to the anchor.

Two things make defaulting this on safe:
- **Names are CA-attested** (the hostname lives in the signed credential), so a
  member can't publish a record claiming another node's name to poison your hosts.
- **Names are namespaced** under the mesh's own `<name>.internal` label.

The domain is shared with TLS: `gw cert-request` with no `--san` defaults the
cert to this node's `<hostname>.myfleet.internal` **plus** its overlay address. So the
name a node is reached by is exactly the name its certificate is valid for —
resolve `db.myfleet.internal` → connect over WireGuard → TLS validates the
`db.myfleet.internal` SAN (Subject Alternative Name — the x509 field listing the
names a certificate is valid for).

A node's hostname defaults to the machine's own hostname at enrollment; change
it later with `sudo gw rename-node <newname>` (then restart the daemon). Rename goes
through the anchor, so it's uniqueness-checked and frees the old name. The keys and
overlay address don't change. (Editing `hostname` in the config directly is not
enough: the anchor wouldn't know, so always use `gw rename-node`.)

> Names are sanitized to a DNS-safe form (`ops@node01` → `ops-node01`) and must
> be **unique**. For a self-chosen name, uniqueness is checked at enrollment: a
> `join` whose (sanitized) name is already taken is refused. However, the token isn't
> immediately burned, so the joiner is told how many attempts remain and can retry with a
> different `--hostname` (a few tries per window). For a **anchor-pinned** name
> (`gw invite --hostname`), uniqueness is checked at *invite* instead, so a
> pinned name is guaranteed free before the token goes out and can't collide at
> enrollment (the joiner couldn't fix it anyway). Either way, a decommissioned
> node keeps its name until its `nodes/<id>.json` is removed on the anchor, which
> frees it for reuse.

