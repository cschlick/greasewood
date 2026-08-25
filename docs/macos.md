# macOS: run a node natively

greasewood runs natively on macOS. The control plane, crypto, directory,
enrollment, and policy layers are byte-identical to Linux; only the
OS-touching pieces differ, behind [one seam](concepts.md#platforms):

| | Linux | macOS |
|---|---|---|
| WireGuard | in-kernel | [wireguard-go](https://git.zx2c4.com/wireguard-go/about/) (userspace) on a `utun` |
| iface tools | `ip` (iproute2) | `ifconfig` / `route` |
| supervisor | systemd (or OpenRC) | launchd (`com.greasewood.<mesh>`) |
| port enforcement | nftables, on by default | **not yet** — a pf backend is planned; ports run advisory |

The last row is the one honest gap: the grant table still fully decides
*which tunnels exist* (that check is in the reconcile loop, not the packet
filter), but the finer per-port layer inside those tunnels isn't enforced on
macOS until the pf backend lands. `gw watch` and the config say so plainly.

## Install

```bash
brew install cschlick/tap/greasewood
```

The formula brings `wireguard-go`, `wireguard-tools`, and its own Python — no
Xcode command-line tools, no Rust (`cryptography` installs as a wheel). Or,
anywhere Python 3.11+ lives: `pipx install greasewood` plus
`brew install wireguard-go wireguard-tools`.

## Join (or create) a mesh

Same ceremony as Linux — the door, not SSH:

```bash
# on your anchor:
sudo gw invite --hostname mymac

# on the Mac:
sudo gw join <token>
```

`join` (and `create`) installs a **launchd daemon** that starts at boot and
restarts on any exit — deliberately stronger than the Linux unit's
on-failure-only, because a Mac that sleeps and roams needs the daemon back
every time without asking. The only intentional stop is unloading the job.

Day-to-day:

```bash
gw watch                                              # same dashboard as anywhere
sudo launchctl kickstart -k system/com.greasewood.<mesh>   # restart the daemon
tail -f /var/log/greasewood/<mesh>.log                # its logs (no journal here)
sudo gw service disable                               # stop + remove from boot
```

Every Mac app gets the mesh natively: the overlay address lives on a real
interface, peers' `/128`s are real routes, and with `hosts_sync` on, mesh
names resolve from `/etc/hosts` like anywhere else. `ssh db.mymesh.internal`
from Terminal, a GUI database client, a browser — no forwarding, no gateway,
no per-port relays. The Mac *is* the node.

## Platform notes

- **The interface name is logical.** `gw-<mesh>` in every config and command;
  the OS device is a dynamically numbered `utunN` run by wireguard-go
  (`/var/run/wireguard/gw-<mesh>.name` records which). `wg show`, `gw watch`,
  and `gw diagnose` all resolve it for you.
- **Door isolation without policy routing.** On Linux the enrollment door is
  isolated by a source-scoped blackhole; macOS has no policy routing without
  pf — and needs none: the guest can't transit an anchor that doesn't forward,
  and greasewood asserts `net.inet6.ip6.forwarding` is off (warning loudly if
  something like Internet Sharing turned it on).
- **Firewall posture.** macOS runs no packet filter by default and greasewood
  never edits one. If you enable the application firewall or your own pf
  config, allow inbound `udp/51900` (and `udp/51820`'s door sibling on an
  anchor — `gw create` prints the exact ports).
- **Laptops behave like laptops.** A Mac without a public address is
  outbound-only — it dials peers, keepalives hold the path, and
  `endpoint_auto` re-advertises if it gains one. Nothing to configure.

## Migrating a node out of the Lima VM

Before v0.5.0 a Mac joined the mesh through a Linux VM (the Lima appliance —
preserved at repo tag `lima-era-archive`, rationale below). The node's
identity is two small directories, so it moves out of the VM intact — same
keys, same overlay address, same credential; the fleet never notices.

With the VM still running:

```bash
limactl shell greasewood-node -- sudo tar czf - /var/lib/greasewood_<mesh> /etc/greasewood_<mesh>.toml > node-backup.tgz
```

Stop the VM's daemon **before** the native one starts — two daemons must
never share one identity:

```bash
limactl shell greasewood-node -- sudo systemctl disable --now greasewood@<mesh>
```

Clean up the old Mac-side machinery *while its tooling is still installed*
(the upgrade removes `gw-mac`):

```bash
brew services stop greasewood 2>/dev/null; sudo gw-mac uninstall-autostart 2>/dev/null; sudo route -n delete -inet6 $(netstat -rn -f inet6 | awk '/^fd.*:\/64/ {print $1; exit}') 2>/dev/null; true
```

Then install the native package and restore:

```bash
brew upgrade greasewood   # or: brew install cschlick/tap/greasewood
```

```bash
mkdir -p /tmp/gwmig && tar xzf node-backup.tgz -C /tmp/gwmig && sudo cp -a /tmp/gwmig/var/lib/greasewood_<mesh> /var/lib/ && sudo cp /tmp/gwmig/etc/greasewood_<mesh>.toml /etc/
```

macOS has no nftables, so the port filter must go advisory or the daemon
will refuse to start:

```bash
sudo sed -i '' 's/^enforce_ports = true/enforce_ports = false/' /etc/greasewood_<mesh>.toml
```

Adopt the config — this writes and starts the launchd daemon:

```bash
sudo gw service enable
```

`gw watch` should show the same node, same address, peers relinking within a
reconcile cycle or two. Then retire the VM:

```bash
limactl delete greasewood-node
```

(`socket_vmnet`, its sudoers entry at `/etc/sudoers.d/lima`, and Lima itself
can go too if nothing else uses them: `brew uninstall lima socket_vmnet` and
`sudo rm -f /etc/sudoers.d/lima /etc/sudoers.d/gw-mac /usr/local/libexec/gw-mac-priv`.)

## Why the VM era ended

The Lima appliance was chosen so greasewood could stay single-platform — and
for a laptop that only dials out, it genuinely was simple. What ended it was
everything the VM *boundary* demanded once a Mac node had real work to do:
Apple's vmnet silently dropped IPv6 fragments, its NAT66 router died without
notice, bridged mode carried no host↔guest traffic at all, TSO frames arrived
unsegmentable, and every one of those was discovered empirically against a
closed, undocumented layer — then papered over with another layer of shell
(a transfer net, an MSS clamp, a firewall seal, sysctl reconcilers). Against
this project's first value — *easy to reason about* — wireguard-go and
launchd, both open and documented, win. The full accounting lives in the
`lima-era-archive` tag message; the machinery itself is one
`git checkout lima-era-archive -- docs/examples` away if you ever want it.
