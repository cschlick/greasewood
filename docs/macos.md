# Worked example: run a node on macOS

greasewood has no macOS build, on purpose. The daemon drives kernel WireGuard,
`ip`, and `nft` directly — none of which exist on macOS the way they do on
Linux (its WireGuard is userspace behind the GUI app; there is no `nft`). A port
would be a whole second backend. So a Mac joins a mesh the same way any
appliance would: **a tiny Linux VM whose only job is to run one node.**

The tool for that is [Lima](https://lima-vm.io) — headless Linux VMs driven
entirely from the command line, no window to click around in. The config below
is stripped to barely-enough Linux; `limactl start` builds it, one `gw join`
enrolls it.

## Why a VM at all — and why NAT is fine

Two greasewood invariants decide the whole shape of this:

- **The overlay address is `hash(id_pub)`** — completely independent of the
  underlay. The node's mesh address survives DHCP changes, prefix renumbering,
  even rebuilding the VM (as long as you keep its keys). The VM is disposable;
  the identity isn't.
- **[Direct-or-fail](concepts.md)** — every granted pair needs a *direct*
  WireGuard tunnel. No relays, no hole-punch coordinator.

The second one usually forces a decision about VM networking (NAT vs bridged).
For a laptop it doesn't, because a laptop node's job is to **dial out** to a
reliable peer (your anchor, a server), never to be cold-dialed. greasewood pins
`PersistentKeepalive = 25` on healthy peers, so the outbound tunnel stays open
through NAT indefinitely and WireGuard roaming lets the peer reply. **NAT is
exactly right** — no bridging, no `socket_vmnet`, no `sudoers` entry.

One wrinkle inside that decision: use `vzNAT` (Apple's vmnet NAT), *not* Lima's
default user-mode network. The default carries **no IPv6 at all**, and on an
IPv6-first mesh many peers advertise v6-only endpoints — undialable from a
v4-only guest. The symptom is maddeningly quiet: `gw diagnose` shows the grant
fine and the endpoint fine, `gw watch` just says *no handshake*. `vzNAT` NATs
both families (NAT66 for v6) and needs no privileges either.

The one thing NAT can't do is reach *another* NAT'd node directly — two nodes
both behind NAT never handshake. As long as the peers this laptop talks to are
themselves directly reachable (a GUA'd server, your anchor), that never comes
up. If you genuinely need this node to be dialed *inbound*, you want bridged
networking instead — a different, heavier setup — but most laptop clients don't.

!!! note "The firewall is scoped to the VM"
    On Linux, greasewood's per-role nftables filter governs the whole host. Here
    it governs only the VM's interface, not macOS. For a laptop that normally
    runs no firewall at all, that's a reasonable trade — the node is sealed, the
    Mac is untouched.

## Set it up

The short way — Homebrew installs the whole Mac side (Lima, the `gw` and
`gw-mac` commands, and the VM recipes), and `gw-mac` creates the VM on first
run:

```bash
brew install cschlick/tap/greasewood
gw-mac            # creates the VM, prints the invite/join steps
```

The rest of this section is the same setup by hand — read it to know what the
formula is doing for you, or to customize the VM.

Install Lima (`brew install lima`), then drop in
[`greasewood-node.yaml`](examples/greasewood-node.yaml):

```yaml
--8<-- "examples/greasewood-node.yaml"
```

```bash
limactl start greasewood-node.yaml     # download image, boot, install greasewood
```

The choices that make it an appliance rather than a dev box:

| Setting | Why |
|---------|-----|
| `networks: [vzNAT]` | The NAT-is-fine decision — but Apple's NAT, not Lima's default user-mode net, which has no IPv6 and silently strands v6-only peer endpoints. |
| `containerd: {system: false, user: false}` | Lima installs containerd/nerdctl by default; a node wants none of it. This is most of the "not a dev box" difference. |
| `mounts: []` | The node is sealed — your Mac's files aren't exposed to a root daemon. Also a faster boot. |
| `vmType: vz` | Apple's native hypervisor, no QEMU emulation. Fast on Apple Silicon *and* Intel. |
| the `command -v gw && exit 0` guard | Provisioning is idempotent, so reboots skip apt and the VM comes back in seconds. |
| Debian, not Alpine | Both work — `gw join` installs a systemd unit on Debian, an OpenRC service on Alpine. Debian is the default here because systemd gives the daemon a kernel-enforced exec sandbox (`CAP_NET_ADMIN` bounding, `ProtectSystem`, syscall filters) that OpenRC can't; on Alpine the daemon runs as unconfined root. For the leaner, sandbox-free Alpine build see [below](#leaner-alternative-alpine-openrc). |
| `PIPX_BIN_DIR=/usr/local/bin` | Lands `gw` where the unit's `ExecStart` looks for it, on old pipx or new (no reliance on `pipx install --global`). |

## Join the mesh

The VM is now running greasewood but hasn't joined anything. Tokens are
short-lived and seed-bound, so you mint one on the anchor and paste it once —
never bake it into the YAML.

```bash
# on your anchor
sudo gw invite --hostname macbook

# then, on the Mac
limactl shell greasewood-node sudo gw join <token>
```

`gw join` enrolls the node **and** enables `greasewood@<mesh>` to start at boot
— nothing else to configure. Confirm it:

```bash
limactl shell greasewood-node sudo gw watch --snapshot
```

## Day-to-day

- **Start/stop the node:** `limactl start greasewood-node` /
  `limactl stop greasewood-node`. The VM disk (including `/var/lib/greasewood`)
  persists across stops, so the node keeps its identity and credential — no
  re-join on reboot.
- **A shell in it:** `limactl shell greasewood-node` (then any `gw` command with
  `sudo`).
- **Or skip the shell entirely:** install [`gw-shim.sh`](examples/gw-shim.sh)
  as a Mac command (`install -m 755 gw-shim.sh /opt/homebrew/bin/gw`) and
  `gw watch`, `gw diagnose <peer>`, … work straight from the Mac terminal — no
  `limactl shell`, no `sudo` (commands run as root inside the VM; typing
  `sudo gw …` out of habit is handled — the shim drops the Lima leg back to
  your user, since instances are per-user).
- **Rebuild from scratch:** `limactl delete greasewood-node` then
  `limactl start greasewood-node.yaml` again. This is a *new* node — new keys,
  new overlay address; revoke the old one on the anchor and join fresh. To keep
  the *same* identity across a rebuild, back up the VM's `/var/lib/greasewood`
  and `/etc/greasewood_<mesh>.toml` first and restore them before re-joining.

!!! warning "Don't lose `/var/lib/greasewood`"
    The node's directory lives there. Deleting the VM without backing it up is a
    full re-enrollment — the same [directory-loss caveat](operations.md) as any
    node, just easier to trigger with a throwaway VM. `limactl stop` is safe;
    `limactl delete` is not.

## Reach a peer from a Mac app

`limactl shell` covers the command line, but a GUI app — a remote desktop
client, a database browser — can't type that. It also can't dial overlay
addresses directly: the mesh terminates inside the VM, macOS has no route to
it, and [direct-or-fail](concepts.md) means nothing will relay for it.

The missing piece is Lima itself: **any port the guest listens on is
auto-forwarded to `127.0.0.1` on the Mac** (ports ≥1024 — Lima can't bind
privileged ports on the host). So a small relay inside the VM puts a peer's
service on localhost, where any Mac app can reach it.

Ad-hoc — an ssh tunnel via Lima's own ssh config (`sshd` inside the VM
resolves the mesh name, so the [hosts block](networking.md#names) works here
too). RDP to a peer named `desktop`:

```bash
ssh -F ~/.lima/greasewood-node/ssh.config lima-greasewood-node \
    -N -L 3389:desktop.mymesh.internal:3389
```

Persistent — a `socat` unit inside the VM (socat ships in the genericcloud
image); Lima picks up the listener the moment it appears:

```bash
limactl shell greasewood-node -- sudo systemd-run --unit rdp-desktop \
    socat TCP6-LISTEN:3389,fork,reuseaddr TCP6:desktop.mymesh.internal:3389
```

Point the app at `localhost:3389` either way. The Mac leg never leaves
loopback; the peer leg is this node's ordinary WireGuard tunnel, so the relay
reaches exactly what the node's grants allow — it widens nothing. A hang here
is almost always a grant, not the relay: the peer must grant this node's role
that port. Stop the unit with `sudo systemctl stop rdp-desktop`; `systemd-run`
units are transient, so a VM restart clears them — re-run it, or promote it to
a real unit file if a relay should survive reboots.

## Route the whole Mac into the overlay

The relay is the right default: one port, one peer, nothing widened. But if
you want overlay addresses and mesh names to work from *every* Mac app with no
per-service setup, the VM can be the Mac's **gateway into the mesh** — no
bridged networking, no `socket_vmnet`; the `vzNAT` link already carries
host↔guest traffic both ways.

The trick is NAT66, and it's load-bearing: WireGuard's cryptokey routing means
every peer accepts exactly one source address from this node — its own
overlay `/128`. Routing the Mac's traffic in *unmasqueraded* would be silently
dropped by every peer's WireGuard, and "fixing" that fleet-wide would mean a
subnet-routes concept that collides with the `addr = hash(id_pub)` invariant.
Masquerading to the node's own address sidesteps all of it: **to the fleet,
the Mac is this node** — same identity, same grants, enforced at each
receiving peer's input filter exactly as before.

Three small files inside the VM (forwarding + NAT66 + MSS clamp for the
1500→1420 MTU step — and note `accept_ra=2`, without which enabling forwarding
would silently kill the VM's own SLAAC underlay):

```nft
--8<-- "examples/gw-mac-gateway.nft"
```

```ini
--8<-- "examples/gw-mac-gateway.sysctl.conf"
```

```ini
--8<-- "examples/gw-mac-gateway.service"
```

Install once (`gw-mac` does this automatically when it creates the VM — this
is the manual path for a VM you built yourself):

```bash
limactl cp gw-mac-gateway.nft gw-mac-gateway.sysctl.conf gw-mac-gateway.service greasewood-node:/tmp/
limactl shell greasewood-node -- sudo sh -c '
  mv /tmp/gw-mac-gateway.nft /etc/ &&
  mv /tmp/gw-mac-gateway.sysctl.conf /etc/sysctl.d/99-gw-mac-gateway.conf &&
  mv /tmp/gw-mac-gateway.service /etc/systemd/system/ &&
  chown root:root /etc/gw-mac-gateway.nft /etc/sysctl.d/99-gw-mac-gateway.conf /etc/systemd/system/gw-mac-gateway.service &&
  sysctl --system >/dev/null && systemctl daemon-reload && systemctl enable --now gw-mac-gateway'
```

Then on the Mac, install [`gw-mac-net.sh`](examples/gw-mac-net.sh) as a
command:

```bash
install -m 755 gw-mac-net.sh /opt/homebrew/bin/gw-mac
```

`gw-mac` (short for `gw-mac up`) starts the VM if it's stopped, installs the
mesh `/64` route via the VM, and syncs the VM's managed hosts block into the
Mac's `/etc/hosts` — idempotent, and it only asks for sudo when something
actually needs changing. The VM half of the setup is permanent, but macOS
routes are not files: the route dies with a Mac reboot or VM stop. So the
whole day-to-day is:

```bash
gw-mac                   # after a reboot, or anytime — safe to re-run
ssh gp2.mymesh.internal  # any app, any port the node's grants allow
```

`gw-mac down` removes the route and stops the VM; `gw-mac status` shows both
layers at a glance.

Or stop thinking about it entirely — `up` is an idempotent reconciler, so it
can run on a timer (brew install only):

```bash
sudo gw-mac install-autostart   # once: root helper + scoped sudoers rule
brew services start greasewood  # runs 'gw-mac up' every 2 minutes at login
```

Root operations (the route, `/etc/hosts`) don't prompt after that: they go
through a small audited helper installed root-owned at
`/usr/local/libexec/gw-mac-priv` — outside the user-writable brew prefix, so
the NOPASSWD rule covers exactly that file and nothing a non-root process can
rewrite. The trade: your user can adjust the mesh route and hosts block
without a password. `sudo gw-mac uninstall-autostart` undoes both.

Know what you're trading:

- **Per-port becomes whole-node.** The relay exposed one port; this hands
  every Mac process the node's full identity and grant set. For a personal
  laptop that's the same trust shape as any mesh VPN client on the host — but
  it's a real widening; that's why the relay stays the default recipe.
- **Outbound only.** NAT66 has no inbound mappings — the Mac still can't be
  dialed from the mesh, which is the laptop posture anyway.
- **Names go stale on the Mac.** The VM's hosts block updates every reconcile;
  the Mac's copy updates when you run `gw-mac`. Rerun it after joins,
  departures, or renames (resolution only — reachability and revocation are
  still enforced live, at the peers).

## Leaner alternative: Alpine (OpenRC)

If you're counting resources — an old Mac, a small SSD, or several node VMs —
Alpine is the featherweight option. `gw join` installs an **OpenRC** service
there just as automatically as it installs a systemd unit on Debian, so the
workflow is identical; only the base OS and the service commands change.

What it actually saves, and what it costs:

- **Disk:** ~0.8 GB less (Alpine + Python + `cryptography` is ~400–500 MB used,
  vs Debian's ~1.2–1.4 GB). Most of what remains is Python + `cryptography`,
  which is the same on both — you can't shrink below that floor.
- **RAM:** inside the guest, an Alpine node idles around ~100 MB used vs
  Debian's ~250 MB — systemd + journald + page cache Alpine simply doesn't
  carry. What Activity Monitor shows on the Mac is a different (larger) number:
  the VM process's footprint tracks the high-water mark of guest pages ever
  touched, so it creeps toward the configured ceiling and doesn't come back
  down (no memory balloon). The ceiling is the real lever, and Alpine's is a
  quarter: 256 MiB vs 1 GiB. What makes 256 safe is the recipe's in-guest
  swapfile — pip's install-time bursts (the VM's only hungry moment) spill to
  the virtual disk instead of needing RAM ceiling held in reserve for them.
- **The cost:** OpenRC can't apply the systemd unit's exec sandbox
  (`CAP_NET_ADMIN` bounding, `ProtectSystem`, syscall filters), so **the daemon
  runs as unconfined root.** For a laptop that normally runs no firewall this is
  a reasonable trade; it's still a real downgrade to weigh.

Use [`greasewood-node-alpine.yaml`](examples/greasewood-node-alpine.yaml):

```yaml
--8<-- "examples/greasewood-node-alpine.yaml"
```

```bash
limactl start greasewood-node-alpine.yaml
# on your anchor:  sudo gw invite --hostname macbook
limactl shell greasewood-node-alpine sudo gw join <token>
```

The only day-to-day difference is the service command — `rc-service
greasewood.<mesh> {status,restart}` instead of `systemctl`/`journalctl`, and
logs land in `/var/log/greasewood.<mesh>.log`. Everything else (identity
survives rebuilds, `limactl stop` safe / `delete` not, the directory-loss
caveat) is the same.

!!! note "One image-line chore"
    The YAML pins the official Alpine cloud images at the point-release Lima
    itself currently pins (Lima ≥2.0 uses these, not the old alpine-lima ISOs).
    Alpine point-releases move over time; refresh the `images:` block from
    Lima's current pin with `limactl template copy template:_images/alpine-3.23 -`
    and paste it in (digests included) before `limactl start`.

!!! note "The Mac-app sections above work here too"
    *Route the whole Mac* carries over as-is: `gw-mac` detects the guest's
    init system and installs the gateway as an OpenRC service
    ([`gw-mac-gateway.initd`](examples/gw-mac-gateway.initd)) instead of a
    systemd unit. Only the *Reach a peer* transient relay needs adapting —
    `systemd-run` has no OpenRC analog, so write a small
    `/etc/init.d/` script (the same shape `gw` itself installs) or run
    `socat` under `nohup` for a one-off.
