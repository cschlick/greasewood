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
through NAT indefinitely and WireGuard roaming lets the peer reply. **Lima's
default user-mode NAT is exactly right** — no bridging, no `socket_vmnet`, no
`sudoers` entry.

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
| `networks: []` | The NAT-is-fine decision, encoded as *doing nothing*. |
| `containerd: {system: false, user: false}` | Lima installs containerd/nerdctl by default; a node wants none of it. This is most of the "not a dev box" difference. |
| `mounts: []` | The node is sealed — your Mac's files aren't exposed to a root daemon. Also a faster boot. |
| `vmType: vz` | Apple's native hypervisor, no QEMU emulation. Fast on Apple Silicon *and* Intel. |
| the `command -v gw && exit 0` guard | Provisioning is idempotent, so reboots skip apt and the VM comes back in seconds. |
| Debian, not Alpine | Alpine is smaller but it's OpenRC; the `greasewood@` unit is systemd. Debian genericcloud is the smallest thing that keeps systemd + kernel WireGuard. |
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
