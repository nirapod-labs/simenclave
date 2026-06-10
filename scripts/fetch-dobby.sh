#!/usr/bin/env bash
# Fetch and build Dobby (jmpews/Dobby, Apache-2.0), the default inline-hook
# backend, into packages/interpose/vendor/dobby for both the macOS host and the
# iphonesimulator slices. Pinned to a known commit. The tree is gitignored, so a
# fresh checkout runs this once.
set -euo pipefail

PIN="5dfc8546954ce3b3198132ab13fddb89ee92cdd7"
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIR="$REPO/packages/interpose/vendor/dobby"
export DEVELOPER_DIR="${DEVELOPER_DIR:-/Applications/Xcode.app/Contents/Developer}"

if [ ! -d "$DIR/.git" ]; then
  git clone https://github.com/jmpews/Dobby.git "$DIR"
fi
git -C "$DIR" fetch origin "$PIN" --depth 1 2>/dev/null || git -C "$DIR" fetch origin
git -C "$DIR" checkout -q "$PIN"

common=(-DCMAKE_BUILD_TYPE=Release -DDOBBY_BUILD_EXAMPLE=OFF -DDOBBY_BUILD_TEST=OFF -DCMAKE_OSX_ARCHITECTURES=arm64)

echo "building Dobby for the macOS host slice..."
cmake -S "$DIR" -B "$DIR/build" "${common[@]}" >/dev/null
cmake --build "$DIR/build" -j4 >/dev/null

echo "building Dobby for the iphonesimulator slice..."
SIMSDK="$(xcrun --sdk iphonesimulator --show-sdk-path)"
TARGET="arm64-apple-ios15.0-simulator"
cmake -S "$DIR" -B "$DIR/build-sim" "${common[@]}" \
  -DCMAKE_OSX_SYSROOT="$SIMSDK" \
  -DCMAKE_C_FLAGS="-target $TARGET" -DCMAKE_CXX_FLAGS="-target $TARGET" >/dev/null
cmake --build "$DIR/build-sim" -j4 >/dev/null

echo "Dobby ready at $DIR (host: build/, simulator: build-sim/)"
