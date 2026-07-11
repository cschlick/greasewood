#!/bin/sh
# CI helper: bootstrap a bare distro image with just enough to run install.sh
# and the unit suite — a Python >= 3.11 interpreter, git, and TLS roots.
#
# It DELIBERATELY does not install wireguard-tools or python3-venv: those are
# exactly what install.sh must provide per-distro, and the matrix exists to test
# that. Keep this to the pre-reqs only.
set -eu

if command -v apt-get >/dev/null 2>&1; then          # Debian, Ubuntu
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y python3 git ca-certificates
elif command -v dnf >/dev/null 2>&1; then            # Fedora, RHEL/Rocky/Alma
    # RHEL 9 clones default to python3.9 (< 3.11) — pull a modern one alongside;
    # on Fedora the plain python3 (3.13) is already fine, hence the fallback.
    dnf install -y python3.12 git || dnf install -y python3 git
elif command -v pacman >/dev/null 2>&1; then         # Arch
    pacman -Sy --noconfirm python git
elif command -v zypper >/dev/null 2>&1; then         # openSUSE
    zypper --non-interactive install python3 git
elif command -v apk >/dev/null 2>&1; then            # Alpine (install.sh needs apk support)
    apk add --no-cache python3 git bash
else
    echo "ci-bootstrap: no known package manager in this image" >&2
    exit 1
fi

python3 --version
