#!/usr/bin/env bash
# curl -fsSL https://raw.githubusercontent.com/nirapod-labs/simenclave/main/scripts/install.sh | sh
#
# Build SimEnclave from source on this Mac and install it. Building locally means the binaries are
# never quarantined (no Gatekeeper wall), and the Secure Enclave works under the ad-hoc signature.
# Homebrew users get the same build from source: brew install nirapod-labs/simenclave/simenclave.
#
# The source is cloned at a pinned tag (the latest release, or SIMENCLAVE_REF=<tag>); this script is
# the only thing fetched over the network unpinned, and it pins everything it builds.
set -euo pipefail

REPO="nirapod-labs/simenclave"
REF="${SIMENCLAVE_REF:-}" # a tag like v1.0.0; default is the latest release
APPS="/Applications"
BIN="${HOME}/.local/bin"
die() { echo "install: $1" >&2; exit 1; }

command -v git >/dev/null || die "git is required"
command -v xcrun >/dev/null || die "the Xcode command line tools are required: xcode-select --install"

if [ -z "$REF" ]; then
  REF="$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" \
    | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -1)"
  [ -n "$REF" ] || die "no published release yet; pass SIMENCLAVE_REF=<tag> to build a specific tag"
fi

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
