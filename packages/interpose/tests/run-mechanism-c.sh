#!/usr/bin/env bash
# Mechanism C: the interposer hooks, installed in a host process, route a
# standard SecKey key-generate, public-key, and sign to the helper, and the
# signature verifies. The native binary comes from the CMake host tree; this
# script only orchestrates the run (start the helper, point the harness at it).
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
export DEVELOPER_DIR="${DEVELOPER_DIR:-/Applications/Xcode.app/Contents/Developer}"
HARNESS="$REPO/build/bin/mechanism_c"

[ -f "$REPO/build/CMakeCache.txt" ] || make -C "$REPO" configure
cmake --build "$REPO/build" --target mechanism_c -j >/dev/null || { echo "harness build failed"; exit 1; }
( cd "$REPO/apps/helper" && xcrun swift build ) >/dev/null 2>&1 || { echo "helper build failed"; exit 1; }
HELPER="$REPO/apps/helper/.build/debug/simenclave-helper"

OUT="$(mktemp)"
"$HELPER" >"$OUT" 2>&1 &
HELPER_PID=$!
trap 'kill "$HELPER_PID" 2>/dev/null' EXIT

PORT=""
for _ in $(seq 1 100); do
  PORT="$(grep -o '"port":[0-9]*' "$OUT" 2>/dev/null | grep -o '[0-9]*' | head -1)"
  [ -n "$PORT" ] && break
  sleep 0.05
done
[ -z "$PORT" ] && { echo "helper did not start"; cat "$OUT"; exit 1; }
echo "helper on 127.0.0.1:$PORT"

SIMENCLAVE_PORT="$PORT" "$HARNESS"
