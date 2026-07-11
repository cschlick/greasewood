#!/usr/bin/env bash
#
# greasewood installer — idempotent (Linux).
#
# Installs the `gw` binary at a STABLE path and nothing more: the daemon service
# itself is self-managed — `gw create` / `gw join` write the systemd unit and
# enable it for you. This script only makes `gw` exist and stay put, which is the
# piece an Ansible role or a by-hand `pip install` was doing inconsistently:
#
#   1. runtime deps — wireguard-tools (`wg`) + nftables
#   2. a self-contained venv at /opt/greasewood built from THIS checkout
#   3. /usr/local/bin/gw symlinked at it
#
# Why a fixed venv + symlink rather than a bare `pip install`: the service's
# ExecStart resolves `gw` to an absolute path once, at
# create/join time. If a later upgrade moves the binary (a new venv, a different
# Python), the service execs a path that no longer exists and crash-loops
# (systemd 203/EXEC). Pinning the venv at /opt/greasewood and pointing the
# symlink there means an upgrade rewrites the SAME paths — the service never
# drifts. (These are the locations the Ansible role already uses:
# greasewood_venv=/opt/greasewood, /usr/local/bin/gw.)
#
# Idempotent: re-run any time to upgrade in place. The venv is reused, the
# package is upgraded from this checkout, existing meshes/configs/services are
# left untouched. To pick up new code afterward, restart the daemon(s) — the
# script prints how at the end.
#
# Usage:  sudo ./install.sh
#         sudo GREASEWOOD_VENV=/opt/greasewood ./install.sh   # override the venv path

set -euo pipefail

VENV="${GREASEWOOD_VENV:-/opt/greasewood}"      # matches the Ansible role's greasewood_venv
BIN_LINK="${GREASEWOOD_BIN:-/usr/local/bin/gw}"
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

say()  { printf '\033[1m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[33mwarning:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }

# --dev: editable install (pip install -e), for development. site-packages
# points at this checkout, so `git pull` + a daemon restart runs the new commit
# with NO reinstall and no version tag — re-run install.sh --dev only if the
# dependencies change. (Needs a WRITABLE checkout: pip writes *.egg-info into it.
# On a Lima read-only home mount, clone inside the VM instead.)
DEV=0
for arg in "$@"; do
    case "$arg" in
        --dev|-e|--editable) DEV=1 ;;
        -h|--help)
            printf 'usage: sudo ./install.sh [--dev]\n\n'
            printf '  --dev   editable install: the running code tracks this checkout, so\n'
            printf "          'git pull' + a daemon restart picks up every commit, no reinstall.\n"
            exit 0 ;;
        *) die "unknown option '$arg' (see --help)" ;;
    esac
done

[ "$(id -u)" -eq 0 ] || die "run as root (it writes $VENV and $BIN_LINK): sudo $0"
[ "$(uname -s)" = "Linux" ] || die "greasewood is a Linux-only tool (this host is $(uname -s))."

# --- a Python >= 3.11 to build the venv from -------------------------------
find_python() {
    local c
    for c in python3.13 python3.12 python3.11 python3; do
        command -v "$c" >/dev/null 2>&1 || continue
        "$c" - <<'PY' >/dev/null 2>&1 || continue
import sys
sys.exit(0 if sys.version_info[:2] >= (3, 11) else 1)
PY
        command -v "$c"
        return 0
    done
    return 1
}

# --- runtime dependencies (idempotent: only act on what's missing) ---------
install_deps_linux() {
    local need_wg=1 need_venv=1 pyver
    pyver=$("$PY" -c 'import sys; print("%d.%d" % sys.version_info[:2])')
    command -v wg >/dev/null 2>&1 && need_wg=0
    # Probe ENSUREPIP, not `venv --help`: on Debian `python3 -m venv --help`
    # works without the python3-venv package, but actually CREATING a venv then
    # fails ("ensurepip is not available"). ensurepip is what venv needs to
    # bootstrap pip, and what python3-venv provides — so it's the honest check.
    "$PY" -c "import ensurepip" >/dev/null 2>&1 && need_venv=0
    [ "$need_wg" -eq 0 ] && [ "$need_venv" -eq 0 ] && { say "runtime deps present (wg, venv)"; return; }

    say "installing runtime deps (wireguard-tools, nftables, python venv)"
    if command -v apt-get >/dev/null 2>&1; then
        apt-get update -qq
        apt-get install -y wireguard-tools nftables python3-venv
        # $PY may be a NON-default interpreter (find_python prefers python3.13…)
        # whose venv/ensurepip lives in a version-specific package that
        # python3-venv doesn't pull. Best-effort — the name may not exist.
        apt-get install -y "python${pyver}-venv" 2>/dev/null || true
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y wireguard-tools nftables
    elif command -v yum >/dev/null 2>&1; then
        yum install -y wireguard-tools nftables
    elif command -v pacman >/dev/null 2>&1; then
        pacman -Sy --noconfirm wireguard-tools nftables
    elif command -v zypper >/dev/null 2>&1; then
        zypper --non-interactive install wireguard-tools nftables
    else
        warn "no known package manager — install 'wireguard-tools' (and a"
        warn "python3 with venv) yourself, then re-run."
    fi
    command -v wg >/dev/null 2>&1 || die "'wg' still not found after dep install — install wireguard-tools manually"
    "$PY" -c "import ensurepip" >/dev/null 2>&1 || die \
        "python venv still unavailable for $PY after install — install the venv
   package for it (python3-venv, or python${pyver}-venv on Debian) and re-run."
}

# ---------------------------------------------------------------------------
say "greasewood installer — from $REPO_DIR"

PY="$(find_python)" || die "need Python >= 3.11 (found none). Install it and re-run."
say "using $("$PY" --version 2>&1) at $PY"

install_deps_linux

# --- the venv + package ----------------------------------------------------
say "building venv at $VENV"
mkdir -p "$(dirname "$VENV")"
"$PY" -m venv "$VENV"                 # idempotent: reuses an existing venv
"$VENV/bin/pip" install --quiet --upgrade pip
if [ "$DEV" -eq 1 ]; then
    say "installing greasewood (editable/dev) from $REPO_DIR"
    "$VENV/bin/pip" install --quiet --upgrade -e "$REPO_DIR"
else
    say "installing greasewood from $REPO_DIR"
    "$VENV/bin/pip" install --quiet --upgrade "$REPO_DIR"
fi

# --- the stable symlink ----------------------------------------------------
ln -sfn "$VENV/bin/gw" "$BIN_LINK"
say "linked $BIN_LINK -> $VENV/bin/gw"

# --- verify it actually runs (a broken exec here is a create/join failure) --
VER="$("$BIN_LINK" --version 2>/dev/null)" || die "gw is installed but won't run — see: $BIN_LINK --version"

cat <<EOF

$(say "$VER installed")
  venv   : $VENV
  binary : $BIN_LINK

next steps
  anchor : sudo gw create <mesh-name>
  node   : sudo gw join <token>
  status : sudo gw -c /etc/greasewood_<name>.toml watch
  (create/join install + enable the systemd service for you)

upgrading an existing install? you just did — now restart the daemon(s) to run
the new code:
  sudo systemctl restart 'greasewood@*'
EOF
if [ "$DEV" -eq 1 ]; then
    echo
    echo "dev (editable) install: the code tracks $REPO_DIR live. To run a new"
    echo "commit, 'git pull' there and restart the daemon — NO reinstall. Re-run"
    echo "install.sh --dev only when dependencies change."
    # An editable install under a home dir is INVISIBLE to the hardened systemd
    # unit (ProtectHome=yes), so the SERVICE crashes with 'No module named
    # greasewood' even though interactive `gw` works. Warn + give the one-liner.
    case "$REPO_DIR" in
        /home/*|/root/*)
            echo
            warn "$REPO_DIR is under a home dir, which the systemd unit hides"
            warn "(ProtectHome=yes) — so 'systemctl start greasewood@<mesh>' will fail"
            warn "with 'No module named greasewood'. Run 'sudo gw run' in the"
            warn "foreground, OR let the service read your checkout:"
            echo "    d=/etc/systemd/system/greasewood@<mesh>.service.d; sudo mkdir -p \$d"
            echo "    printf '[Service]\\nProtectHome=read-only\\n' | sudo tee \$d/dev.conf"
            echo "    sudo systemctl daemon-reload && sudo systemctl restart greasewood@<mesh>"
            ;;
    esac
fi
