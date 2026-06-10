#!/usr/bin/env bash
# Mechanism C driver: build and start the helper, compile the interposer sources
# into a host harness, run it against the helper, and report. No simulator.
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
INTERPOSE="$REPO/packages/interpose"
PROTO="$REPO/packages/protocol/c"
export DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer

[ -f "$INTERPOSE/vendor/dobby/build/libdobby.dylib" ] || bash "$REPO/scripts/fetch-dobby.sh"

echo "building helper..."
( cd "$REPO/apps/helper" && xcrun swift build ) || { echo "helper build failed"; exit 1; }
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
if [ -z "$PORT" ]; then echo "helper did not report a port:"; cat "$OUT"; exit 1; fi
echo "helper listening on 127.0.0.1:$PORT"

echo "compiling harness..."
clang -O0 -arch arm64 \
  "$INTERPOSE/tests/mechanism_c.c" \
  "$INTERPOSE/src/hooks/sec_key_hooks.c" \
  "$INTERPOSE/src/registry/shadow_ref.c" \
  "$INTERPOSE/src/transport/client.c" \
  "$INTERPOSE/src/backend/dobby_backend.c" \
  "$PROTO/src/se_protocol.c" \
  "$PROTO/src/se_framing.c" \
  -I"$INTERPOSE/include" -I"$PROTO/include" -I"$INTERPOSE/vendor/dobby/include" \
  -L"$INTERPOSE/vendor/dobby/build" -ldobby -Wl,-rpath,"$INTERPOSE/vendor/dobby/build" \
  -framework Security -framework CoreFoundation \
  -o /tmp/se_mechanism_c || { echo "harness compile failed"; exit 1; }

echo "running harness against the helper..."
SIMENCLAVE_PORT="$PORT" /tmp/se_mechanism_c
