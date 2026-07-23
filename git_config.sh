#!/usr/bin/env bash
# One-time dev-machine setup: commit identity + the GitHub remote.
# GitHub is the single source of truth; nodes install over IPv6 via pipx.
set -euo pipefail

git config --global user.name "cschlick"
git config --global user.email "16112328+cschlick@users.noreply.github.com"

git remote set-url origin git@github.com:cschlick/greasewood.git
git config --unset-all remote.origin.pushurl || true   # drop any stale dual-push URLs

git remote -v
