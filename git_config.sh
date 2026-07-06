#!/usr/bin/env bash
# One-time dev-machine setup: commit identity + dual-push remotes.
# GitHub is the source of truth (dev, issues); GitLab is the IPv6 mirror the
# fleet installs from (pip install git+https://gitlab.com/...). A single
# `git push` updates both — instantly, unlike the pull mirror, which stays
# configured as the safety net for web-UI merges.
set -euo pipefail

git config --global user.name "cschlick"
git config --global user.email "16112328+cschlick@users.noreply.github.com"

# Fetch from GitHub; push atomically to GitHub AND the GitLab mirror.
# (Setting any explicit push URL disables the implicit fetch-URL push,
# so BOTH must be added. Idempotent: clear existing push URLs first.)
git remote set-url origin git@github.com:cschlick/greasewood.git
git config --unset-all remote.origin.pushurl || true
git remote set-url --add --push origin git@github.com:cschlick/greasewood.git
git remote set-url --add --push origin git@gitlab.com:cschlick/greasewood.git

git remote -v
