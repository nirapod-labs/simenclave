#!/usr/bin/env bash
# Mechanism D on watchOS: a hooked SecKeyCreateSignature in a watchOS Simulator app returns a
# Mac-SEP signature that verifies. Same proof as run-mechanism-d.sh, on the watch slice: the
# watchos-simulator dylib and demo come from the build-watchsim CMake tree, the demo links no
# interposer (it is injected at spawn), and the control run (no injection) must fail, proving the
# watch simulator has no SEP and the demo really depends on the bridge.
#
# Needs the watchOS Simulator runtime installed (xcodebuild -downloadPlatform watchOS); without it
# there is no watch device to boot and the run exits early.
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
export DEVELOPER_DIR="${DEVELOPER_DIR:-/Applications/Xcode.app/Contents/Developer}"
DYLIB="$REPO/build-watchsim/bin/simenclave-interpose-watchos.dylib"
DEMO="$REPO/build-watchsim/bin/sim_demo"

[ -f "$REPO/build-watchsim/CMakeCache.txt" ] || make -C "$REPO" configure
cmake --build "$REPO/build-watchsim" -j >/dev/null || { echo "watch simulator build failed"; exit 1; }
( cd "$REPO/apps/helper" && xcrun swift build ) >/dev/null 2>&1 || { echo "helper build failed"; exit 1; }
HELPER="$REPO/apps/helper/.build/debug/simenclave-helper"

DEVICE="$(xcrun simctl list devices available | grep -A30 'watchOS' | grep -oE '[0-9A-F-]{36}' | head -1)"
[ -z "$DEVICE" ] && { echo "no watchOS simulator device available (install the runtime: xcodebuild -downloadPlatform watchOS)"; exit 1; }
echo "device: $DEVICE"
xcrun simctl boot "$DEVICE" 2>/dev/null
xcrun simctl bootstatus "$DEVICE" >/dev/null 2>&1

SIM_HOME="$(mktemp -d)"
OUT="$(mktemp)"
SIMENCLAVE_HOME="$SIM_HOME" "$HELPER" >"$OUT" 2>&1 &
HELPER_PID=$!
trap 'kill "$HELPER_PID" 2>/dev/null; rm -rf "$SIM_HOME"' EXIT
PORT=""
for _ in $(seq 1 100); do
  PORT="$(grep -o '"port":[0-9]*' "$OUT" 2>/dev/null | grep -o '[0-9]*' | head -1)"
  [ -n "$PORT" ] && break
  sleep 0.05
done
[ -z "$PORT" ] && { echo "helper did not start"; cat "$OUT"; exit 1; }
echo "helper on 127.0.0.1:$PORT"

TOKEN="$(cat "$SIM_HOME/token" 2>/dev/null)"
[ -z "$TOKEN" ] && { echo "no token file"; cat "$OUT"; exit 1; }

# The demo exits 2 on the stock no-SEP create failure and 0 on a full verify. Three legs, all
# asserted: the control (no interposer) and the fence leg (interposer injected but unconfigured)
# must both show the identical stock failure, and the configured injection must verify. The fence
# leg is the runtime fence proof: a stray injection without a wired scheme behaves exactly like no
# injection at all.
STOCK_FAILURE=2

echo ""
echo "--- control: spawn in the watch simulator with NO interposer (must fail) ---"
xcrun simctl spawn "$DEVICE" "$DEMO"
CONTROL_RC=$?
echo "control exit: $CONTROL_RC"

echo ""
echo "--- fence: interposer injected but unconfigured (must match the control) ---"
SIMCTL_CHILD_DYLD_INSERT_LIBRARIES="$DYLIB" \
xcrun simctl spawn "$DEVICE" "$DEMO"
INERT_RC=$?
echo "unconfigured exit: $INERT_RC"

echo ""
echo "--- mechanism D: spawn with the interposer injected ---"
SIMCTL_CHILD_DYLD_INSERT_LIBRARIES="$DYLIB" \
SIMCTL_CHILD_SIMENCLAVE_PORT="$PORT" \
SIMCTL_CHILD_SIMENCLAVE_TOKEN="$TOKEN" \
xcrun simctl spawn "$DEVICE" "$DEMO"
RC=$?
echo "injected exit: $RC"

echo ""
FAIL=0
[ "$CONTROL_RC" -eq "$STOCK_FAILURE" ] \
  || { echo "FENCE FAIL: control expected the stock create failure ($STOCK_FAILURE), got $CONTROL_RC"; FAIL=1; }
[ "$INERT_RC" -eq "$STOCK_FAILURE" ] \
  || { echo "FENCE FAIL: unconfigured injection must match the stock failure ($STOCK_FAILURE), got $INERT_RC"; FAIL=1; }
[ "$RC" -eq 0 ] \
  || { echo "MECHANISM D FAIL: injected run exit $RC"; FAIL=1; }
[ "$FAIL" -eq 0 ] && echo "MECHANISM D + FENCE (watchOS): ok"
exit $FAIL
