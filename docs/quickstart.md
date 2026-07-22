# Quickstart


### 1. Bootstrap the anchor

On the machine that will hold the CA and serve enrollment:

```bash
sudo gw create mymesh          # names live under *.mymesh.internal
```

`create` generates the CA, the persistent door key, the policy routing for
the enrollment door, and the anchor's own credential, then writes
`/etc/greasewood_mymesh.toml`. By default `create` also starts the daemon: it brings up the `gw-mymesh`
WireGuard interface, serves the control plane, and watches for door windows.

The anchor takes this machine's hostname like any other node. 
You tell which node is the anchor from `role: anchor` in
`gw watch`, not from its name. (Pass `--hostname <name>` to override the default.)

### 2. Enroll a node

Enrollment uses a transient WireGuard "door". This provides a mechanism to allow new nodes
onto the mesh that is much lower trust than, for example, relying on ssh. Also since wireguard doesn't
respond to connections without a recognized credential, it is a much cleaner external profile than, for
example, running an http server for configuration on the underlay. To add a new node to the mesh, create an 
invite token on the anchor:

```bash
sudo gw invite # prints token
```

Deliver that token to the new machine (any channel) and redeem it:

```bash
sudo gw join <token>
```

`join` derives a throwaway guest key from the token, stands up a temporary
`gw-door` tunnel to the anchor, receives a CA-signed credential over it, tears the
door down, and writes the node's config, then the anchor brings the node into the
mesh.

**Why a door — why can't the token just contain everything to peer over
your mesh interface?** Because WireGuard peering is *mutual*: to bring up a tunnel to the
anchor over any interface, the anchor must already have **your** public key in its peer
list. At invite time your real keys don't exist yet (they're generated locally
at `join`, and private keys never travel) so the anchor cannot pre-authorize your
real identity key. 

What the token *can* do is carry a 32-byte seed that **both sides expand (HKDF)
into the same throwaway door keypair + PSK**. The anchor derives that throwaway
pubkey from the seed it minted and pre-installs it as a peer; you derive the
matching private key — so now a tunnel can actually form. But it forms under a
**disposable, credential-less key, not your identity**. That's why the door is a
*separate* interface:

- it runs on its own **dedicated door subnet** (`fd8d:…:d::/64`) — not a
  throwaway address squatting on the real overlay (which would break the
  self-certifying `address = hash(identity)`)
- it reaches **only the enroll daemon** (not the directory/control plane, not
  other peers) A token-holder can do exactly one thing: request a credential;
- it's **torn down** the moment your credential is issued.

So the door bootstraps joining the mesh with your real identity. You bring up the 
mesh interface, with your *real* key and its self-certifying address, only
once you hold that credential. Running the throwaway peering over the mesh interface
instead would drop a credential-less stranger onto the live mesh with a fake
address and expose the whole control plane. The door is a temporary quarantine.

### 3. Check it

```bash
sudo gw watch              # a live ( or --snapshot) view of the mesh peers
sudo wg show gw-mymesh     # wg show works normally, showing each tunnel
```

`gw diagnose` is the tool to reach for when a peer won't connect. It's
**pairwise**: it lays up to two named nodes plus the anchor side by side and
explains, per pair, whether a tunnel can form — policy (roles/grants), reachability, and the
firewall/routing directionality that's usually the real question. (`gw watch`
is the fleet-wide link overview; diagnose is the focused deep-dive.)

```bash
sudo gw diagnose            # this host ↔ the anchor
sudo gw diagnose db01       # this host ↔ db01   (+ anchor as reference)
sudo gw diagnose db01 web1  # db01 ↔ web1        (+ anchor as reference)
```

The comparison table shows each node's addresses, reachability, roles,
credential, and firewall for the mesh UDP port. 

## Running as a service

On a systemd host the daemon is managed for you — **`create` and `join` install
the service and start it**, no extra command. A single **template unit** serves
every mesh as its own instance `greasewood@<name>` (survives reboots, restarts
on failure, logs to the journal), so the whole workflow is just:

```bash
sudo gw create mymesh                 # anchor  → greasewood@myfleet installed + running
sudo gw join "$TOKEN" --hostname n01  # node → greasewood@<mesh> installed + running
journalctl -u greasewood@mymesh  -f   # watch a mesh's daemon
systemctl status 'greasewood@*'       # all of them
```

There is no separate install/uninstall step: the service lifecycle rides on the
mesh lifecycle. **`gw purge`** removes a mesh's instance (and the shared
template when it's the last mesh) providing a from-scratch reset in one command.

- **On OpenRC (Alpine)** it's the same one-command story — `create`/`join`
  install `/etc/init.d/greasewood`, symlink this mesh's instance
  (`greasewood.<name>`), add it to the boot runlevel and start it under
  `supervise-daemon`. Manage it with `rc-service greasewood.<name> {status,restart}`.
  One caveat: OpenRC can't apply the systemd unit's exec sandbox
  (`CAP_NET_ADMIN` bounding, `ProtectSystem`, syscall filters), so the OpenRC
  daemon runs as unconfined root.
- **Neither systemd nor OpenRC, or want to run it yourself?** Pass `--no-service`
  to `create`/`join`; they print the `sudo gw -c <config> run` line instead and
  touch no init system. (A host with no supported init auto-falls-back to this
  even without the flag.)
- Instances run `gw run` as root (they manage WireGuard interfaces and
  routing). Don't also run `gw run` by hand while an instance is up,  both
  would fight over the interface.
- A **config-changing re-join** (new anchor, etc) isn't auto-detected — the
  daemon reads its config at startup, so run `sudo systemctl restart greasewood@<name>`
  afterward.

## Provisioning many nodes

Enrollment tokens are **initiated by the anchor, never by nodes**. A node
cannot request admission; you (or an orchestrator acting on the anchor) decide to
admit a machine, run `gw invite`, and deliver the token out of band. The node
only redeems what it was handed. The door is **single-slot by construction**:
each invite opens one enrollment window, and the anchor closes it the instant that
node finishes joining. To persist a door over multiple joins (reuse a token, useful for 
provisioning many instances at once), use the `--standing` flag:

On the anchor:

```bash
sudo gw invite               # prints a one-time token
sudo gw invite --standing    # prints a multi-use token
```

Joining is the same either way

```bash
sudo gw join <token>
```

