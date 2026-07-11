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
    # Always install `python3` — Fedora 41's minimal base ships none (dnf5 is
    # C++), so it must be pulled in. RHEL 9's python3 is 3.9 (< 3.11), so also
    # grab python3.12 (best-effort; harmless on Fedora, where find_python just
    # prefers the newest interpreter present).
    dnf install -y python3 git
    dnf install -y python3.12 2>/dev/null || true
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
