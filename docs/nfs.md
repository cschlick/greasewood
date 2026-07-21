# Worked example: a shared directory over the mesh (NFS)

greasewood doesn't ship a file-sharing feature, on purpose — it provides the
substrate (identity, addresses, names, per-port access control) and the
operator owns the service, same as with Postgres above. But the substrate does
almost all of the work here, so the recipe is short. What you get: any granted
node mounts `files01.mymesh.internal:/srv/workspace` and the mesh supplies the
encryption, the peer authentication, and the per-role firewall that NFS setups
usually bolt on by hand (Kerberos, per-host exports, firewall rules per pair).

**The one thing to understand: the grant table _is_ the share ACL.** NFSv4.1+
speaks on a single port (`tcp/2049` — no rpcbind/portmapper dance), and the
[port filter](access-control.md#access-control-roles--grants) already decides, per role, who can
reach that port over addresses that can't be spoofed (cryptokey routing pins
address ↔ key). So the NFS config below is **static — written once, never
edited as the fleet changes**. Export to the whole overlay /64 and let grants
do the gating: adding a node to `role:worker` grants it the share; revoking a
node revokes it, on the same reconcile cycle that tears down its tunnel. No
per-client exports lines, ever.

**On the file server** (say `files01`, holding `role:files`) — install the
server, make it NFSv4-only, and export to the overlay prefix (yours is
`overlay_prefix` in the config; the default is shown):

```bash
sudo apt install nfs-kernel-server        # Debian/Ubuntu; use your pkg mgr

# NFSv4-only: v3 off means no rpcbind, no mountd port — 2049 is the whole surface
printf '[nfsd]\nvers3=n\n' | sudo tee /etc/nfs.conf.d/greasewood.conf
sudo systemctl mask --now rpcbind.socket rpcbind.service

# a dedicated owner for the workspace tree
sudo adduser --system --group --uid 1500 workspace
sudo mkdir -p /srv/workspace && sudo chown workspace:workspace /srv/workspace
```

`/etc/exports` — one line, scoped to the mesh, and it never changes again:

```
/srv/workspace fd8d:e5c1:db1a:7::/64(rw,sync,no_subtree_check,all_squash,anonuid=1500,anongid=1500)
```

```bash
sudo exportfs -ra && sudo systemctl enable --now nfs-server
```

**Why `all_squash`.** WireGuard authenticates *hosts*, not users: over
`sec=sys` (plain NFS auth), root on any granted node can claim any UID. For a
shared workspace, don't fight that — squash every client to the `workspace`
user, so the share behaves like a common drop-box and UID games are moot. If
you instead need per-user ownership across nodes, you need matched UIDs
fleet-wide and `root_squash`, and you should know you're trusting every
granted host's root — that's inherent to NFS-without-Kerberos, not to the mesh.

**On the anchor** — open the one port, with the usual preview:

```toml
# append to <data_dir>/grants.toml
[[grant]]
from  = ["worker"]
to    = ["files"]
ports = ["tcp/2049"]
# why: workers mount the shared workspace; nothing else reaches NFS.
```

```bash
sudo gw policy apply     # shows the grant diff + tunnel delta, asks to confirm
```

**On each client** (any `role:worker` node) — one fstab line, using the mesh
name (from the managed [hosts block](networking.md#names), so it resolves anchor-down too):

```
# /etc/fstab
files01.mymesh.internal:/srv/workspace  /mnt/workspace  nfs4  vers=4.2,_netdev,noauto,x-systemd.automount,x-systemd.mount-timeout=30s,x-systemd.requires=greasewood@mymesh.service  0  0
```

```bash
sudo mkdir -p /mnt/workspace && sudo systemctl daemon-reload
sudo systemctl start mnt-workspace.automount
ls /mnt/workspace        # first touch mounts it through the tunnel
```

The automount is doing real work in that line: the path mounts on first access
instead of at boot (so boot never blocks on the mesh), and
`x-systemd.requires=` pins the ordering to this mesh's daemon.

**Honesty about failure.** NFS is the one place a mesh outage stops looking
like [direct-or-fail](concepts.md#direct-or-fail): a **hard mount** (the default above)
never errors — processes touching the path when the server is unreachable
block in uninterruptible sleep until it returns. That's the correct default
for a read-write workspace (`soft` can corrupt writes that were in flight),
but know the trade. If a share is read-mostly and you'd rather get I/O errors
than hangs, add `soft,timeo=100,retrans=3` to the options and accept the risk;
either way the `mount-timeout` above already keeps a *new* access from hanging
a service forever when the tunnel is down.

**The underlay is your job, as always.** greasewood [never touches your main
firewall](networking.md#firewall), and `nfsd` listens on all addresses — so whether
`tcp/2049` is reachable from the *underlay* is decided by your own host
firewall, exactly like SSH. Two things protect you meanwhile: the exports line
admits only the overlay /64 (an underlay client is refused the mount), and the
port filter admits only granted roles within the mesh. But scope your underlay
firewall as you would for any service.

> **What about NFS over TLS?** Linux 6.4+ can run NFS inside TLS (RPC-with-TLS,
> RFC 9289): `xprtsec=mtls` on the mount, `xprtsec=mtls` in the exports line,
> and the `tlshd` daemon (ktls-utils) on both ends — and `gw cert-request` can
> issue the certs, so the mesh CA drives it for free. *Inside* the mesh, skip
> it: it duplicates what WireGuard already provides (the tunnel encrypts; the
> address pins the host), costs a second encryption pass, adds a daemon whose
> failure mode is "mounts stop working" — and it does **not** fix the `sec=sys`
> caveat above, because certs authenticate the *machine* while UIDs stay
> client-asserted, so the `all_squash` guidance stands unchanged. It earns its
> keep only when a share must also be reachable from hosts *outside* the mesh,
> where there's no tunnel underneath — there, mTLS with mesh-issued certs is
> exactly the right tool.

