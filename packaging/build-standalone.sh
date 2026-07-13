#!/usr/bin/env bash
#
# Build a SELF-CONTAINED greasewood tree for .deb/.rpm packaging.
#
# The package can't just depend on the distro's python3: greasewood needs
# Python >= 3.11 (older stables ship less), and — critically — the self-managed
# systemd unit runs `{sys.executable} -m greasewood` (see cli._service_exec), so
# whatever `gw` resolves to must be a Python that can import greasewood. A
# zipapp (shiv/pex) can't satisfy that; a host-python venv isn't portable across
# machines. So we bundle a relocatable python-build-standalone interpreter at
# /opt/greasewood/python and pip-install greasewood into it. The result depends
# on nothing but glibc — `sys.executable` is the bundled python, and
# `-m greasewood` finds the package in its own site-packages.
#
# Mirrors install.sh's model (a fixed prefix + a /usr/bin/gw entry), so the
# service's ExecStart path never drifts across upgrades.
#
# Output: a staged filesystem under $DESTDIR with final runtime paths, ready to
# hand to nfpm (packaging/nfpm.yaml) — or to dpkg-deb for a smoke test.
#
#   PREFIX=/opt/greasewood DESTDIR=./stage ARCH=x86_64 \
#     GREASEWOOD_SPEC=greasewood==0.1.1 ./packaging/build-standalone.sh
#
set -euo pipefail

PY_VERSION="${PY_VERSION:-3.12.13}"      # cpython in the bundle
PBS_TAG="${PBS_TAG:-20260623}"           # python-build-standalone release tag
ARCH="${ARCH:-x86_64}"                    # x86_64 | aarch64
PREFIX="${PREFIX:-/opt/greasewood}"
DESTDIR="${DESTDIR:-$PWD/stage}"
# What to install: a PyPI spec ("greasewood==0.1.1") or a local wheel/path.
GREASEWOOD_SPEC="${GREASEWOOD_SPEC:-greasewood}"
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

say() { printf '\033[1m==>\033[0m %s\n' "$*"; }

triple="${ARCH}-unknown-linux-gnu"
# install_only_stripped: pbs strips debug symbols the SAFE way (preserving
# dynamic-symbol versioning). Stripping libpython ourselves corrupts it — the
# interpreter then dies with "no version information available". So take pbs's.
asset="cpython-${PY_VERSION}+${PBS_TAG}-${triple}-install_only_stripped.tar.gz"
url="https://github.com/astral-sh/python-build-standalone/releases/download/${PBS_TAG}/${asset}"

work="$(mktemp -d)"; trap 'rm -rf "$work"' EXIT

say "fetching relocatable python: $asset"
curl -fSL --retry 3 "$url" -o "$work/py.tgz"
tar -xzf "$work/py.tgz" -C "$work"        # unpacks to $work/python

pyroot="$DESTDIR$PREFIX/python"
mkdir -p "$(dirname "$pyroot")"
rm -rf "$pyroot"
mv "$work/python" "$pyroot"
py="$pyroot/bin/python3"

say "installing greasewood ($GREASEWOOD_SPEC) into the bundle"
"$py" -m pip install --quiet --upgrade pip
"$py" -m pip install --quiet "$GREASEWOOD_SPEC"

# The `gw` console script's shebang is the BUILD path of the interpreter
# ($DESTDIR$PREFIX/...). It lives at $PREFIX/... at runtime, so pin the shebang
# to the runtime path (harmless when DESTDIR is empty).
gwbin="$pyroot/bin/gw"
sed -i "1s|^#!.*|#!${PREFIX}/python/bin/python3|" "$gwbin"

# Prune dev cruft greasewood never touches. The interpreter is already stripped
# (install_only_stripped); we only DELETE whole dirs here — never rewrite ELF —
# so symbol versioning stays intact. Takes the tree to ~40M (~15M compressed).
pyver_mm="${PY_VERSION%.*}"                       # 3.12.13 -> 3.12
pylib="$pyroot/lib/python${pyver_mm}"
say "trimming the bundle (drop unused stdlib)"
# headers, python's own docs/man, and stdlib pieces a network daemon never uses
rm -rf "$pyroot/include" "$pyroot/share" \
       "$pylib/test" "$pylib/idlelib" "$pylib/tkinter" "$pylib/turtledemo" \
       "$pylib/lib2to3" "$pylib/ensurepip" 2>/dev/null || true
# tk/tcl shared libs (only tkinter used them) — keep sqlite/other stdlib libs
rm -rf "$pyroot"/lib/libtcl* "$pyroot"/lib/libtk* "$pyroot"/lib/tcl* \
       "$pyroot"/lib/tk* "$pyroot"/lib/itcl* "$pyroot"/lib/thread*.so 2>/dev/null || true
# runtime needs neither pip nor setuptools (greasewood is already installed)
rm -rf "$pylib"/site-packages/pip "$pylib"/site-packages/pip-* \
       "$pylib"/site-packages/setuptools "$pylib"/site-packages/setuptools-* \
       "$pylib"/site-packages/pkg_resources \
       "$pylib"/site-packages/wheel "$pylib"/site-packages/wheel-* 2>/dev/null || true
find "$pyroot" -type d -name __pycache__ -prune -exec rm -rf {} + 2>/dev/null || true

# man page (committed, generated from the CLI parser), gzipped.
say "staging man page + docs"
install -d "$DESTDIR/usr/share/man/man1"
gzip -9 -c "$REPO_DIR/man/gw.1" > "$DESTDIR/usr/share/man/man1/gw.1.gz"

# examples + reference docs
install -d "$DESTDIR/usr/share/doc/greasewood"
install -m644 \
    "$REPO_DIR/greasewood.toml.example" \
    "$REPO_DIR/grants.toml.example" \
    "$REPO_DIR/README.md" "$REPO_DIR/SECURITY.md" "$REPO_DIR/RUNBOOK.md" \
    "$REPO_DIR/LICENSE" \
    "$DESTDIR/usr/share/doc/greasewood/"

# Sanity: the bundle runs, AND `python -m greasewood` works (the service path).
# Invoke through the staged interpreter explicitly — $gwbin's shebang now points
# at the RUNTIME path ($PREFIX/...), which doesn't exist until the package is
# installed, so we can't exec it directly here.
say "verifying the bundle"
ver="$("$py" "$gwbin" --version)"
"$py" -m greasewood --version >/dev/null
say "built $ver  →  $DESTDIR$PREFIX  (python $PY_VERSION, arch $ARCH)"
