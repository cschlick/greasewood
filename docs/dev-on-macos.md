# Developing greasewood on macOS

greasewood is a Linux tool — it drives the in-kernel WireGuard module, `ip`,
`nftables`, and systemd, none of which exist on macOS. So "run it on my Mac"
means **run it inside Linux on the Mac**: a Linux VM or Linux containers. The
Linux-only package then runs completely unmodified — no macOS special-casing,
which is exactly the point.

Nested/virtualized WireGuard is slower than bare metal, but for development that
doesn't matter. None of this is a supported *deployment* path; it's for hacking
on greasewood and testing meshes without a fleet of Linux boxes.

Two shapes, by what you're doing:

| You want to…                                   | Use                        |
|------------------------------------------------|----------------------------|
| run a real node / test the full service + reboot lifecycle | a **Linux VM** (§1) |
| iterate on the code, run the test suite, throw up a local mesh | **containers** (§2) |

---

## 1. A Linux VM — a standing "dev box"

A lightweight Linux VM runs the package like any real host: `install.sh` works
as-is, the daemon runs under real systemd, the kernel provides WireGuard. Best
when you want a persistent node that joins a mesh or when you're testing the
install / service / reboot path itself.

[Lima](https://lima-vm.org/) is the least-friction option (a headless Linux VM
that shares your Mac home dir):

```bash
brew install lima
limactl start --name=gw --yes template:default     # Ubuntu VM with systemd
limactl shell gw                                    # a shell inside it
```

(`--yes` skips Lima's interactive "Proceed / Exit" prompt — without it, and with
older `template://…` syntax, `limactl` drops into a menu. `start` both creates
and starts, so no separate `limactl create` is needed. If your Lima rejects
`--yes`, use `--tty=false`.)

Then, inside the VM, install and use greasewood exactly as on any Linux host:

```bash
git clone https://gitlab.com/cschlick/greasewood.git   # or use the shared mount, below
cd greasewood
sudo ./install.sh
sudo gw create devmesh        # this VM as the anchor…
#   …or join an existing mesh:
sudo gw join <token>
```

### The dev pipeline (editable — updates every commit, no tags)

For iterating, install **editable** so the running code tracks your checkout:

```bash
sudo ./install.sh --dev        # pip install -e: /opt/greasewood points AT this tree
```

From then on, updating to the latest commit is just a pull and a restart — no
reinstall, no version tag:

```bash
git pull
sudo systemctl restart 'greasewood@*'      # or restart your `gw run`
```

The daemon runs `<interpreter> -m greasewood`, which executes the working tree
directly, so a `git pull` *is* the update. Re-run `install.sh --dev` only when
dependencies change (rare — greasewood has one). For the tightest loop, run the
daemon by hand instead of via systemd: `sudo gw -c /etc/greasewood_devmesh.toml
run`, then Ctrl-C / edit / re-run.

Two caveats for `--dev`:
- **Clone inside the VM.** An editable install writes `*.egg-info` into the
  checkout, and Lima mounts your Mac home *read-only* — so `--dev` against the
  mounted path fails. Clone in the VM (as above), or make the mount writable
  (`limactl edit gw` → `mounts: [{ location: "~", writable: true }]`) and then
  point `install.sh --dev` at the mounted checkout to edit on the Mac.
- **`gw --version` stays frozen** at the pyproject version — it reads packaged
  metadata, set at install time, not the source. The *code* is live; only that
  version string lags until you bump it and reinstall.

`multipass` (`brew install multipass`) or a UTM/QEMU VM work the same way; Lima is
just the quickest to a shell.

## 2. Containers — the test harness and local meshes

The integration suite already builds a Linux image from the repo `Containerfile`
and runs **multi-node meshes in privileged containers**. On macOS that runs
inside `podman machine`'s Linux VM:

```bash
brew install podman
podman machine init && podman machine start
python -m pytest tests/integration/          # spins up whole test meshes on your Mac
```

For a manual playground mesh (an anchor + a node you can poke at), the same
primitives the harness uses:

```bash
podman build -t greasewood .
podman network create --ipv6 --subnet fd00:dev::/64 gwdev

# anchor
podman run -d --privileged --network gwdev --name anchor greasewood sleep infinity
podman exec anchor gw create devmesh
podman exec -d anchor sh -c 'gw run >> /tmp/gw.log 2>&1'
sleep 2                                        # let the anchor daemon come up
TOKEN=$(podman exec anchor gw invite --hostname node1 -q)

# node
podman run -d --privileged --network gwdev --name node1 greasewood sleep infinity
podman exec node1 gw join "$TOKEN"
podman exec -d node1 sh -c 'gw run >> /tmp/gw.log 2>&1'

podman exec node1 gw watch --snapshot        # see the mesh
```

Containers run the daemon by hand (`gw run`), not under systemd — systemd-in-a-
container is fiddly and not worth it for dev. So this is the path for **testing
the mesh and the code**, not for exercising the systemd service (use a VM, §1,
for that).

---

## Networking notes ("fast networking not necessary")

- **A self-contained dev mesh** (anchor + nodes all in local VMs/containers)
  needs *zero* external networking — everything talks over the Mac's internal
  virtual network. This is the common case and it's trivial.
- **Joining the real mesh** from a VM works for *outbound* WireGuard: the VM
  dials the anchor and peers out through the Mac's connection (NAT). The node
  ends up **outbound-only** — behind the Mac + your home NAT, peers can't dial
  *in* to it — but greasewood's direct-or-fail model handles that: it dials out,
  keepalive holds the tunnel open, and the link is bidirectional once
  established. It just won't be a *dialable* peer for others (advertise no
  endpoint, or expect `○ no handshake` from nodes that can only reach it inbound).

## Troubleshooting

- **`ip link add … type wireguard` fails / no WireGuard.** The VM kernel needs
  the module. Check inside the VM/container: `sudo modprobe wireguard && wg
  --version`. Lima's Ubuntu image and podman's Fedora CoreOS both ship it; a bare
  container gets it from the *host* VM's kernel, so it's the `podman machine` /
  Lima kernel that matters, not the image.
- **Permission denied creating the interface.** The daemon needs
  `CAP_NET_ADMIN`. In a VM, run it as root (`sudo`). In a container, use
  `--privileged` (as above) or at least `--cap-add NET_ADMIN --device
  /dev/net/tun`.
- **`gw` not found under `sudo`.** `install.sh` symlinks `/usr/local/bin/gw`
  (on root's PATH); if you installed some other way, use the full path or
  `sudo $(command -v gw) …`.
