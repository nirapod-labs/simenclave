#!/usr/bin/env bash
# Mechanism D, the M0 exit criterion: a hooked SecKeyCreateSignature in a
# simulator app returns a Mac-SEP signature that verifies. The demo links no
# interposer; it is injected at spawn. The control run (no injection) must fail,
# proving the simulator has no SEP and the demo really depends on the bridge.
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
INTERPOSE="$REPO/packages/interpose"
PROTO="$REPO/packages/protocol/c"
export DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer
SIMSDK="$(xcrun --sdk iphonesimulator --show-sdk-path)"
TARGET="arm64-apple-ios15.0-simulator"
DOBBY_SIM="$INTERPOSE/vendor/dobby/build-sim"
DYLIB=/tmp/simenclave-interpose.dylib
DEMO=/tmp/sim_demo

[ -f "$DOBBY_SIM/libdobby.a" ] || bash "$REPO/scripts/fetch-dobby.sh"

echo "building interposer dylib and demo (simulator slice)..."
clang -dynamiclib -target "$TARGET" -isysroot "$SIMSDK" -O0 \
  "$INTERPOSE/src/entry.c" "$INTERPOSE/src/hooks/sec_key_hooks.c" \
  "$INTERPOSE/src/registry/shadow_ref.c" "$INTERPOSE/src/transport/client.c" \
  "$INTERPOSE/src/backend/dobby_backend.c" \
  "$PROTO/src/se_protocol.c" "$PROTO/src/se_framing.c" \
  -I"$INTERPOSE/include" -I"$PROTO/include" -I"$INTERPOSE/vendor/dobby/include" \
  $(find "$DOBBY_SIM" -name '*.a') -lc++ \
  -framework Security -framework CoreFoundation -o "$DYLIB" 2>/dev/null || { echo "dylib build failed"; exit 1; }
clang -target "$TARGET" -isysroot "$SIMSDK" -O0 "$INTERPOSE/tests/sim_demo.c" \
  -framework Security -framework CoreFoundation -o "$DEMO" || { echo "demo build failed"; exit 1; }

echo "building helper..."
( cd "$REPO/apps/helper" && xcrun swift build ) >/dev/null 2>&1 || { echo "helper build failed"; exit 1; }
HELPER="$REPO/apps/helper/.build/debug/simenclave-helper"

DEVICE="$(xcrun simctl list devices available | grep -A30 'iOS 26' | grep -oE '[0-9A-F-]{36}' | head -1)"
[ -z "$DEVICE" ] && { echo "no iOS simulator device available"; exit 1; }
echo "device: $DEVICE"
xcrun simctl boot "$DEVICE" 2>/dev/null
xcrun simctl bootstatus "$DEVICE" >/dev/null 2>&1

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

echo ""
echo "--- control: spawn in the simulator with NO interposer (must fail) ---"
xcrun simctl spawn "$DEVICE" "$DEMO"
echo "control exit: $?"

echo ""
echo "--- mechanism D: spawn with the interposer injected ---"
SIMCTL_CHILD_DYLD_INSERT_LIBRARIES="$DYLIB" \
SIMCTL_CHILD_SIMENCLAVE_PORT="$PORT" \
xcrun simctl spawn "$DEVICE" "$DEMO"
RC=$?
echo "injected exit: $RC"
exit $RC
