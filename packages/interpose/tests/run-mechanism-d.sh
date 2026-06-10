#!/usr/bin/env bash
# Mechanism D, the M0 exit criterion: a hooked SecKeyCreateSignature in a
# simulator app returns a Mac-SEP signature that verifies. The dylib and the demo
# come from the CMake simulator tree; the demo links no interposer, it is injected
# at spawn. The control run (no injection) must fail, proving the simulator has no
# SEP and the demo really depends on the bridge.
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
export DEVELOPER_DIR="${DEVELOPER_DIR:-/Applications/Xcode.app/Contents/Developer}"
DYLIB="$REPO/build-sim/bin/simenclave-interpose.dylib"
DEMO="$REPO/build-sim/bin/sim_demo"

[ -f "$REPO/build-sim/CMakeCache.txt" ] || make -C "$REPO" configure
cmake --build "$REPO/build-sim" -j >/dev/null || { echo "simulator build failed"; exit 1; }
( cd "$REPO/apps/helper" && xcrun swift build ) >/dev/null 2>&1 || { echo "helper build failed"; exit 1; }
HELPER="$REPO/apps/helper/.build/debug/simenclave-helper"

DEVICE="$(xcrun simctl list devices available | grep -A30 'iOS 26' | grep -oE '[0-9A-F-]{36}' | head -1)"
[ -z "$DEVICE" ] && { echo "no iOS simulator device available"; exit 1; }
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

# The demo exits 2 on the stock no-SEP create failure and 0 on a full verify.
# Three legs, all asserted: the control (no interposer) and the fence leg
# (interposer injected but unconfigured) must both show the identical stock
# failure, and the configured injection must verify. The fence leg is the
# runtime fence proof: a stray injection without a wired scheme behaves exactly
# like no injection at all.
STOCK_FAILURE=2

echo ""
echo "--- control: spawn in the simulator with NO interposer (must fail) ---"
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
[ "$FAIL" -eq 0 ] && echo "MECHANISM D + FENCE: ok"
exit $FAIL
