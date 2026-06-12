#!/usr/bin/env bash
# curl -fsSL https://raw.githubusercontent.com/nirapod-labs/simenclave/main/scripts/install.sh | sh
#
# Build SimEnclave from source on this Mac and install it: the menu bar helper to /Applications and
# the simenclavectl CLI to ~/.local/bin. Building locally keeps the binaries off the Gatekeeper
# quarantine path, and the Secure Enclave works under the ad-hoc signature.
#
# The source is cloned at a release tag (the latest release, or SIMENCLAVE_REF=<tag>). The tag is
# validated to be a version tag before use, so the clone follows a published release, not a branch.
set -euo pipefail

REPO="nirapod-labs/simenclave"
REF="${SIMENCLAVE_REF:-}" # a tag like v1.0.0; default is the latest release
APPS="/Applications"
BIN="${HOME}/.local/bin"
die() { echo "install: $1" >&2; exit 1; }

command -v git >/dev/null || die "git is required"
command -v xcrun >/dev/null || die "the Xcode command line tools are required: xcode-select --install"

if [ -z "$REF" ]; then
  # Resolve the release tag from VERSION on the default branch over raw.githubusercontent, the same
  # host this script was fetched from, so the install does not depend on the rate-limited GitHub API
  # (60 unauthenticated requests per hour) and does not care whether the release is a prerelease.
  ver="$(curl -fsSL "https://raw.githubusercontent.com/$REPO/main/VERSION" 2>/dev/null | tr -d '[:space:]' || true)"
  [ -n "$ver" ] || die "could not read the latest version; pass SIMENCLAVE_REF=<tag> to build a specific tag"
  REF="v$ver"
fi

# Only follow a version tag (vX.Y.Z, optionally -prerelease). git clone --branch resolves a branch
# or a tag, so this guard keeps the install pinned to a published release, not a moving branch.
printf '%s' "$REF" | grep -qE '^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$' \
  || die "refusing to build '$REF': not a version tag (expected vX.Y.Z)"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
echo "install: cloning $REPO at $REF"
git clone --depth 1 --branch "$REF" "https://github.com/$REPO.git" "$WORK/src" >/dev/null 2>&1 \
  || die "could not clone $REPO at $REF"
cd "$WORK/src"

echo "install: building from source (ad-hoc signed, never quarantined)"
SIGN_ID="-" bash scripts/build-menubar-app.sh
( cd tools/simenclavectl && xcrun swift build -c release )

mkdir -p "$BIN"
rm -rf "$APPS/SimEnclave.app"
cp -R dist/SimEnclave.app "$APPS/SimEnclave.app" \
  || die "could not write to $APPS (try: sudo, or set APPS=\$HOME/Applications)"
cp tools/simenclavectl/.build/release/simenclavectl "$BIN/simenclavectl"

echo "install: installed $APPS/SimEnclave.app and $BIN/simenclavectl"
echo "install: open it with  open \"$APPS/SimEnclave.app\"   (ensure $BIN is on PATH for the CLI)"
