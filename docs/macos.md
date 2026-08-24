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
networking instead — a heavier setup, described in
[Make the node dialable](#make-the-node-dialable-bridged) — but most laptop
clients don't.

!!! note "The firewall is scoped to the VM"
    On Linux, greasewood's per-role nftables filter governs the whole host. Here
    it governs only the VM's interface, not macOS. For a laptop that normally
    runs no firewall at all, that's a reasonable trade — the node is sealed, the
    Mac is untouched.

    Note what "sealed" is doing there: under NAT the VM is unreachable, so its
    listeners (sshd, mDNS) are closed by construction rather than by a rule.
    Give the VM a real NIC and that stops being true, which is why `gw-mac`
    installs the [LAN seal](#the-lan-seal) into every VM it creates.

## Set it up

The short way — Homebrew installs the whole Mac side (Lima, the `gw` and
`gw-mac` commands, and the VM recipes), and `gw-mac` creates the VM on first
run:

```bash
brew install cschlick/tap/greasewood
gw-mac            # creates the VM, prints the invite/join steps
```

!!! note "No Xcode command-line tools required"
    The Mac side of greasewood is just the `gw` shell shim and the `gw-mac`
    helpers. They use standard `/usr/bin` tools (`sh`, `awk`, `sed`, `route`,
    `netstat`) plus `lima` from Homebrew. The helper scripts no longer call
    `python3`, so a fresh macOS install with no Xcode/CLT disk space will not
    get `xcode-select` prompts from `gw-mac` itself.

    As of v0.4.0 the Homebrew formula also ships a prebuilt Apple Silicon bottle
    (`cellar :any_skip_relocation`), so `brew install` can pour the bottle
    without treating `greasewood` as a source build. If `brew install` still
    pops the CLT prompt for any reason, see the [No CLT?](#no-clt) fallback.

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

## No CLT?

As of greasewood 0.4.0, the Homebrew formula ships a prebuilt Apple Silicon
bottle with `cellar :any_skip_relocation`, so `brew install cschlick/tap/greasewood`
no longer needs the Xcode Command Line Tools:

```bash
brew update
HOMEBREW_NO_REQUIRE_TAP_TRUST=1 brew install cschlick/tap/greasewood
sudo gw-mac install-autostart
brew services start greasewood
```

(Third-party taps require explicit trust in recent Homebrew; run
`brew trust cschlick/tap` once instead of the `HOMEBREW_NO_REQUIRE_TAP_TRUST`
workaround if you prefer.)

On older Apple Silicon macOS releases, the `arm64_sequoia` bottle will be used
via Homebrew's bottle fallback. If you are on an unsupported combination or
`brew install` still prompts for CLT, the manual path below gives the same
files:

```bash
# Clone just the release you want
GIT=/opt/homebrew/bin/git
TAG=v0.4.0
REPO=https://github.com/cschlick/greasewood.git
CLONE=/tmp/greasewood-$TAG
rm -rf "$CLONE"
"$GIT" clone --depth 1 --branch "$TAG" "$REPO" "$CLONE"

# Put the commands and recipes where brew would put them
sudo install -m 755 "$CLONE/docs/examples/gw-shim.sh" /opt/homebrew/bin/gw
sudo install -m 755 "$CLONE/docs/examples/gw-mac-net.sh" /opt/homebrew/bin/gw-mac
sudo mkdir -p /opt/homebrew/share/greasewood
sudo install -m 644 \
    "$CLONE/docs/examples/gw-mac-gateway.nft" \
    "$CLONE/docs/examples/gw-mac-gateway.sysctl.conf" \
    "$CLONE/docs/examples/gw-mac-gateway.service" \
    "$CLONE/docs/examples/gw-mac-gateway.initd" \
    "$CLONE/docs/examples/gw-mac-priv.sh" \
    "$CLONE/docs/examples/greasewood-node.yaml" \
    "$CLONE/docs/examples/greasewood-node-alpine.yaml" \
    /opt/homebrew/share/greasewood/

# Install the root helper and sudoers rule
sudo /opt/homebrew/bin/gw-mac install-autostart

# Start the 2-minute timer manually if you didn't install via brew services
/opt/homebrew/bin/gw-mac up
(crontab -l 2>/dev/null; echo "*/2 * * * * /opt/homebrew/bin/gw-mac up >/tmp/gw-mac.log 2>&1") | crontab -
```

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

(With the brew-installed `gw` shim, plain `gw join <token>` also names the
node like Linux would — it claims the **Mac's** hostname, not the VM's
Lima-internal one, unless you pass `--hostname` or the invite pinned a name.)

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
it, and [direct-or-fail](concepts.md) means nothing will forward for it.

The missing piece is Lima itself: **any port the guest listens on is
auto-forwarded to `127.0.0.1` on the Mac** (ports ≥1024 — Lima can't bind
privileged ports on the host). So a small local forward inside the VM puts a peer's
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
loopback; the peer leg is this node's ordinary WireGuard tunnel, so the forward
reaches exactly what the node's grants allow — it widens nothing. A hang here
is almost always a grant, not the forward: the peer must grant this node's role
that port. Stop the unit with `sudo systemctl stop rdp-desktop`; `systemd-run`
units are transient, so a VM restart clears them — re-run it, or promote it to
a real unit file if the forward should survive reboots.

## Route the whole Mac into the overlay

A per-port forward is the right default: one port, one peer, nothing widened. But if
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

Four small files inside the VM: the NAT66 + MSS clamp for the 1500→1420 MTU
step, `forwarding=1`, the gateway unit (which also pins the VM's side of the
transfer address `gw-mac` routes through (explained with the `gw-mac`
command below)), and a networkd drop-in that keeps RA autoconfiguration alive on the
vzNAT link — `forwarding=1` makes the kernel ignore RAs, and the per-interface
`accept_ra` sysctl that would counter it silently loses a race with interface
renaming at boot (the sysctl file's comment has the details; on OpenRC the
gateway script applies it at start instead):

```nft
--8<-- "examples/gw-mac-gateway.nft"
```

```ini
--8<-- "examples/gw-mac-gateway.sysctl.conf"
```

```ini
--8<-- "examples/gw-mac-gateway.service"
```

```ini
--8<-- "examples/gw-mac-gateway.network.conf"
```

Install once (`gw-mac` does this automatically when it creates the VM — this
is the manual path for a VM you built yourself):

```bash
limactl cp gw-mac-gateway.nft gw-mac-gateway.sysctl.conf gw-mac-gateway.service gw-mac-gateway.network.conf greasewood-node:/tmp/
limactl shell greasewood-node -- sudo sh -c '
  mv /tmp/gw-mac-gateway.nft /etc/ &&
  mv /tmp/gw-mac-gateway.sysctl.conf /etc/sysctl.d/99-gw-mac-gateway.conf &&
  mv /tmp/gw-mac-gateway.service /etc/systemd/system/ &&
  NETFILE=$(networkctl status lima0 | grep "Network File:" | tr -d " " | cut -d: -f2) &&
  mkdir -p /etc/systemd/network/$(basename "$NETFILE").d &&
  mv /tmp/gw-mac-gateway.network.conf /etc/systemd/network/$(basename "$NETFILE").d/gw-mac-gateway.conf &&
  chown -R root:root /etc/gw-mac-gateway.nft /etc/sysctl.d/99-gw-mac-gateway.conf /etc/systemd/system/gw-mac-gateway.service /etc/systemd/network/ &&
  sysctl --system >/dev/null && networkctl reload && systemctl daemon-reload && systemctl enable --now gw-mac-gateway'
```

Then on the Mac, install [`gw-mac-net.sh`](examples/gw-mac-net.sh) as a
command:

```bash
install -m 755 gw-mac-net.sh /opt/homebrew/bin/gw-mac
```

`gw-mac` (short for `gw-mac up`) starts the VM if it's stopped, installs the
mesh `/64` route via the VM, and syncs the VM's managed hosts block into the
Mac's `/etc/hosts` — idempotent, and it only asks for sudo when something
actually needs changing. Under the hood it gives both ends of the `vzNAT` link
a fixed *transfer address* (`fd6d:6163::1` on the Mac, `::2` in the VM): the
route's next hop, and — the part that matters — the source macOS picks for
mesh-bound traffic, so the VM's replies come back over the `vzNAT` link
regardless of where its default route points. (A
[bridged](#make-the-node-dialable-bridged) VM's default route points at the
bridged link, which is host-blind — without the transfer net, replies to the
Mac die there.) The VM half of the setup is permanent, but macOS
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

- **Per-port becomes whole-node.** The per-port forward exposed one port; this hands
  every Mac process the node's full identity and grant set. For a personal
  laptop that's the same trust shape as any mesh VPN client on the host — but
  it's a real widening; that's why the per-port forward stays the default recipe.
- **Outbound only.** NAT66 has no inbound mappings — the Mac still can't be
  dialed from the mesh, which is the laptop posture anyway.
- **Names go stale on the Mac.** The VM's hosts block updates every reconcile;
  the Mac's copy updates when you run `gw-mac`. Rerun it after joins,
  departures, or renames (resolution only — reachability and revocation are
  still enforced live, at the peers).

## Make the node dialable (bridged)

Everything above assumes the laptop posture: this node dials out, and never
needs to be called. A Mac that lives on one desk — a clamshell machine used as a
desktop, a mini acting as a small server — may need the opposite, and two
outbound-only nodes never link at all:

```
panda ↔ melvin
  panda → melvin: can't — melvin is outbound-only / advertises no endpoint
  melvin → panda: can't — panda is outbound-only / advertises no endpoint
  ✗ no dialable direction — the link can't form (both outbound-only)
```

The Mac has a GUA; the node doesn't. greasewood runs *inside the VM*, whose only
global address under `vzNAT` is Apple's NAT66 ULA (`fd…`), and
[endpoint detection](networking.md#reachability) correctly refuses to advertise
a ULA — nothing could dial it. The GUA is on the Mac's `en0`, on the far side of
that NAT.

Fixing it means giving the VM its own NIC on your LAN, so it gets a GUA from
your router's RA directly and `endpoint_auto` picks it up on its next cycle.
That last part is the reason to prefer bridging over pinning an endpoint by
hand: a residential prefix rotates, and only the node that can *see* its own
address can follow it.

Lima does this with `socket_vmnet`, which runs as root — so unlike everything
else on this page, it costs a sudoers rule. Install the binary somewhere the
user cannot rewrite (Homebrew's prefix is user-writable, which is exactly why
Lima refuses to run it from there):

```bash
brew install socket_vmnet && sudo install -o root -g wheel -m 0755 -d /opt/socket_vmnet/bin && sudo install -o root -g wheel -m 0555 "$(brew --prefix)/opt/socket_vmnet/bin/socket_vmnet" "$(brew --prefix)/opt/socket_vmnet/bin/socket_vmnet_client" /opt/socket_vmnet/bin/
```

Then the sudoers rule — generated by Lima, validated before install so a bad
file can't lock you out of `sudo`, and left world-readable because `limactl`
insists on reading it back (`sudo` only objects to a sudoers file being
*writable*):

```bash
limactl sudoers > /tmp/lima.sudoers && sudo visudo -cf /tmp/lima.sudoers && sudo install -o root -g wheel -m 0444 /tmp/lima.sudoers /etc/sudoers.d/lima
```

Now add the NIC. Add it **alongside** `vzNAT`, never replacing it. This is not
bookkeeping: Apple's bridged vmnet carries **no host↔guest traffic at all** —
the Mac gets no L3 presence on that bridge, so while every *other* machine on
the LAN can dial the VM's new address, the Mac itself cannot. `limactl shell`
survives regardless (Lima reaches the guest over vsock), but whole-Mac overlay
routing needs an IP path to the VM, and `vzNAT` is the only one:

```bash
limactl stop greasewood-node && limactl edit greasewood-node --network lima:bridged && limactl start greasewood-node
```

The node should pick up a GUA within a minute and republish itself:

```
advertised endpoint(s) changed: (none) → ['[2601:db8:…:54e7]:51900'] — re-advertising
```

Confirm with `gw diagnose <peer>`, which should now show `reachable: yes
(advertises endpoint)` and a dialable direction for the pair that had none.

!!! warning "Bridging over Wi-Fi is the uncertain part"
    Bridged mode puts a second MAC behind one 802.11 association. Apple's vmnet
    handles this with MAC translation (`bridge100` gains `en0` as a member with
    a `MACNAT` flag) and it works on plenty of access points — but some drop the
    frames, and that is a property of your AP, not of this setup. It costs five
    minutes to find out, and adding the NIC alongside `vzNAT` means a failure
    changes nothing: delete the line and you are back where you started.

    Lima's bridged mode also pins one host interface (`interface: en0` in
    `~/.lima/_config/networks.yaml`). Stationary machines don't care; a laptop
    that moves between Wi-Fi, a dock, and tethering does.

If your peers are outside the LAN, they reach the VM's GUA through your router's
IPv6 firewall, which needs a rule permitting inbound UDP on the node's port —
there is no NAT to forward. Peers on the same `/64` need nothing: that traffic
is neighbour discovery on the local link and never touches the router.

### The LAN seal

A bridged VM is on your network for real, and the listeners that NAT used to
hide — sshd, mDNS, LLMNR — now face the LAN, and the internet too if the router
forwards to them. greasewood's own table governs the mesh interfaces only; it
never touches the rest of the host, by design. So `gw-mac` installs a small
default-closed ruleset into every VM it creates, and retro-fits it to an
existing VM the next time you run `gw-mac`:

```nft
--8<-- "examples/gw-mac-lan.nft"
```

It closes everything that isn't loopback or the mesh, then reopens exactly what
a node needs: established flows, ICMP (IPv6 does not work without it), DHCP,
inbound WireGuard, and Lima's own host→guest ssh scoped to the RFC1918 ranges
Lima's NATs use. Sealing by *exclusion* rather than by interface name is
deliberate: which of `lima0`/`lima1` is the bridged one depends on the order of
`networks:` in the recipe, and a NIC added later should be closed the day it
appears rather than silently exposed.

If your node listens on something other than the default 51900, `gw-mac`
substitutes the configured port when it installs the seal. Installing the file
by hand instead means editing the `define wg_port` line yourself.

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
  carry. What Activity Monitor shows on the Mac is a different (larger) number,
  and it's the least meaningful one: the "Memory" column is *physical
  footprint*, which tracks the high-water mark of guest pages ever touched —
  Linux fills its RAM with page cache during boot alone, so the figure sits
  pinned at the configured ceiling forever and never comes back down. It does
  **not** mean that much of your RAM is occupied. Guest RAM under
  Virtualization.framework is ordinary pageable memory, and macOS's compressor
  quietly reclaims the cold pages (a running node typically has a third or more
  of its writable pages compressed or swapped out — check with
  `vmmap --summary <pid>`); footprint counts those reclaimed pages as if they
  were still resident. There's no memory balloon in the Lima/vz stack and none
  is needed — the compressor already does that job, guest cooperation not
  required. Real steady-state cost is on the order of 100–150 MB, less under
  host memory pressure. The ceiling is still the real lever, and Alpine's is a
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
    systemd unit. Only the *Reach a peer* transient port forward needs adapting —
    `systemd-run` has no OpenRC analog, so write a small
    `/etc/init.d/` script (the same shape `gw` itself installs) or run
    `socat` under `nohup` for a one-off.
