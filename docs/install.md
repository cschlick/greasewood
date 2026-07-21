# Install

Requires Python 3.11+, the WireGuard userspace tools (`wireguard-tools`/`wg`),
and `iproute2` (`ip`). The kernel WireGuard module is built into Linux 5.6+ and
autoloads on first use.

Two ways to install on a host that will run the daemon; both set up the managed
systemd service.

**With pipx (recommended on Linux)** — the standard way to install a Python
application in its own isolated environment, straight from PyPI:

```bash
sudo apt install pipx wireguard-tools    # Debian/Ubuntu; use your distro's pkg mgr
sudo pipx install --global greasewood
```

`--global` puts `gw` on root's `PATH` so `sudo gw …` resolves, and the daemon
service launches as `<interpreter> -m greasewood`, so it stays valid wherever
pipx put the package. pipx manages only the Python side — install the WireGuard
tools separately with your distro's package manager (shown above). Upgrade with
`sudo pipx upgrade greasewood`.

Prefer **uv**? `sudo UV_TOOL_BIN_DIR=/usr/local/bin uv tool install greasewood`
is the faster equivalent (`uv tool` is uv's app installer). uv has no `--global`
flag, so point its bin dir at a spot already on root's `PATH` yourself, as shown.

To run an **unreleased commit** instead of the latest release, point pipx at the
git URL — it builds the default branch directly, no clone needed:

```bash
sudo pipx install --global "git+https://github.com/cschlick/greasewood.git"
```

(For a git install, pull newer commits with `sudo pipx reinstall greasewood` — a
clean re-pull; plain `pipx upgrade` can skip a git install when the version
string hasn't moved.)

**With the bundled installer** — a self-contained alternative that also installs
the WireGuard deps and pins a fixed venv at `/opt/greasewood`. Re-run any time
(after a `git pull`) to upgrade in place:

```bash
git clone https://github.com/cschlick/greasewood.git
cd greasewood
sudo ./install.sh
```

**Distro packages** — `.deb` and `.rpm` are attached to each [GitHub
release](https://github.com/cschlick/greasewood/releases); they bundle their own
Python, so they need nothing but glibc (and pull in `wireguard-tools`,
`iproute2`, `nftables`):

```bash
sudo apt install ./greasewood_<ver>_amd64.deb     # Debian/Ubuntu
sudo dnf install ./greasewood-<ver>.x86_64.rpm    # Fedora/RHEL
```

On Arch it's on the AUR: `yay -S greasewood`. See [packaging/](https://github.com/cschlick/greasewood/tree/main/packaging) for
how these are built.

Either way you get the `gw` command (and `man gw`), and `gw create`/`join`
install + enable the systemd service. Most subcommands need sudo/root (they
create WireGuard interfaces and edit routing); `gw watch` does not. For plain
library/dev use, `pip install greasewood` (or `pip install '.[test]'` from a
checkout for pytest).

After install the workflow is just setup/join → the daemon runs as a managed
systemd service that `gw create`/`gw join` set up for you — see [Running as a
service](#running-as-a-service). The Quickstart below
runs it by hand with `gw run` to show the moving parts.

### First-run pitfalls

Every one of these comes from a real fleet coming up; each has a one-command
fix.

- **`sudo: gw: command not found` after a plain `pipx install`.** A per-user
  install lands in `~/.local/bin`, which sudo's `secure_path` never searches.
  And "fixing" it with `sudo pipx install` (no `--global`) is the same trap
  one home directory over: it lands in `/root/.local/bin`, on *nobody's* PATH.
  The `--global` flag isn't cosmetic — the daemon is a root service, so its
  venv must live somewhere root-owned and stable, not inside a login account's
  home. Uninstall the stray one (`pipx uninstall greasewood`, with `sudo` if
  it went to root's home) and reinstall with `--global`.

- **`pipx: error: unrecognized arguments: --global`.** The distro's pipx
  predates 1.5 (Ubuntu 24.04 ships 1.4.3). Set by hand exactly what
  `--global` sets:

  ```bash
  sudo PIPX_HOME=/opt/pipx PIPX_BIN_DIR=/usr/local/bin pipx install greasewood
  ```

  Upgrades on that host need the same env vars (a plain `sudo pipx upgrade`
  looks in `/root/.local` and finds nothing). Or skip pipx and use the
  bundled `install.sh`, which pins its own venv at `/opt/greasewood`.

- **`FileNotFoundError: ... 'wg'` at join.** pipx installs only the Python
  side; the WireGuard tools come from your distro (`sudo apt install
  wireguard-tools`). Don't be fooled by the join getting partway: the kernel
  module being present (`ip link add … type wireguard` succeeds) says nothing
  about the `wg` *binary* being installed. The distro `.deb`/`.rpm` packages
  pull it in for you; pipx cannot.

- **`credential verification failed: no trusted CA signature found` at join —
  even with a fresh token.** If the anchor was re-created (`gw create
  --force`) after its daemon started, the daemon keeps signing with the old
  CA it loaded at startup while every new invite embeds the new on-disk CA:
  the join's door tunnel comes up (the door key survives a re-create) and
  then the credential is rightly refused. Restart the anchor daemon so it
  re-reads the key, then mint a fresh invite:

  ```bash
  sudo systemctl restart greasewood@<mesh>   # on the anchor
  sudo gw invite                             # token minted AFTER the restart
  ```

