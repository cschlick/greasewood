#!/bin/sh
# release-brew.sh — sync the Homebrew tap to the current tagged release.
#
# The tap (cschlick/homebrew-tap) is what `brew upgrade` reads; a git tag
# alone changes nothing for brew users. This makes the sync one command,
# run from the repo root after tagging:
#
#   git tag v$(version) && git push origin main v$(version)
#   sh scripts/release-brew.sh
#
# It reads the version from pyproject.toml, downloads THAT tag's tarball from
# GitHub (failing loudly if the tag isn't pushed), pins its sha256 into
# packaging/brew/greasewood.rb, copies the formula into the locally-tapped
# repo, and commits + pushes the tap. Idempotent: already in sync = no-op.
set -eu

cd "$(dirname "$0")/.."
FORMULA=packaging/brew/greasewood.rb

VERSION=$(sed -n 's/^version = "\(.*\)"/\1/p' pyproject.toml)
[ -n "$VERSION" ] || { echo "release-brew: no version in pyproject.toml" >&2; exit 1; }
URL="https://github.com/cschlick/greasewood/archive/refs/tags/v${VERSION}.tar.gz"

echo "release-brew: v${VERSION} — fetching ${URL}"
SHA=$(curl -fsL "$URL" | shasum -a 256 | cut -d' ' -f1) \
    || { echo "release-brew: download failed — is tag v${VERSION} pushed to GitHub?" >&2; exit 1; }

sed -i '' \
    -e "s|url \".*/archive/refs/tags/v.*\.tar\.gz\"|url \"${URL}\"|" \
    -e "s|sha256 \".*\"|sha256 \"${SHA}\"|" "$FORMULA"

TAP=$(brew --repository 2>/dev/null)/Library/Taps/cschlick/homebrew-tap
[ -d "$TAP" ] || { echo "release-brew: tap not installed — brew tap cschlick/tap" >&2; exit 1; }
cp "$FORMULA" "$TAP/Formula/greasewood.rb"

if git -C "$TAP" diff --quiet -- Formula/greasewood.rb; then
    echo "release-brew: tap already at v${VERSION} (sha ${SHA}) — nothing to do"
else
    git -C "$TAP" add Formula/greasewood.rb
    git -C "$TAP" commit -m "greasewood ${VERSION}"
    git -C "$TAP" push
    echo "release-brew: tap updated to v${VERSION} — brew users get it on 'brew update'"
fi

git diff --quiet -- "$FORMULA" \
    || echo "release-brew: note — $FORMULA changed here too; commit it (git add $FORMULA)"
