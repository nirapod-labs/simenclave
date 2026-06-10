#!/usr/bin/env bash
# A probe of CryptoKit's SecureEnclave.P256 in the simulator. This is NOT a bridge
# proof; it documents a limitation. On a modern simulator CryptoKit's SecureEnclave
# verifies even with no interposer, and even injected against a dead helper port,
# which shows it falls back to a software key instead of bottoming out in the hooked
# SecKey Secure Enclave path. So SimEnclave does not bridge CryptoKit's
# SecureEnclave; the supported real-hardware path is the SecKey C API, proven by
# run-mechanism-d.sh. This script makes that finding reproducible.
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
export DEVELOPER_DIR="${DEVELOPER_DIR:-/Applications/Xcode.app/Contents/Developer}"
DYLIB="$REPO/build-sim/bin/simenclave-interpose.dylib"
WORK="$(mktemp -d)"
DEMO="$WORK/crypto_demo"
trap 'rm -rf "$WORK"' EXIT

[ -f "$DYLIB" ] || { echo "build the sim slice first: make build"; exit 1; }
xcrun -sdk iphonesimulator swiftc -target arm64-apple-ios15.0-simulator \
  "$REPO/packages/interpose/tests/crypto_demo.swift" -o "$DEMO" || { echo "swiftc failed"; exit 1; }

DEVICE="$(xcrun simctl list devices available | grep -A30 'iOS 26' | grep -oE '[0-9A-F-]{36}' | head -1)"
[ -z "$DEVICE" ] && { echo "no iOS simulator device available"; exit 1; }
xcrun simctl boot "$DEVICE" 2>/dev/null
xcrun simctl bootstatus "$DEVICE" >/dev/null 2>&1

echo "--- CryptoKit SecureEnclave, NO interposer (a software key still verifies) ---"
xcrun simctl spawn "$DEVICE" "$DEMO"
echo "exit: $?"

echo ""
echo "--- CryptoKit SecureEnclave, injected, DEAD helper port (not routed, still verifies) ---"
SIMCTL_CHILD_DYLD_INSERT_LIBRARIES="$DYLIB" \
SIMCTL_CHILD_SIMENCLAVE_PORT="1" \
SIMCTL_CHILD_SIMENCLAVE_TOKEN="00000000000000000000000000000000000000000000000000000000000000ab" \
xcrun simctl spawn "$DEVICE" "$DEMO"
echo "exit: $?"

echo ""
echo "Finding: CryptoKit's SecureEnclave.P256 verifies in both runs, so it uses a"
echo "software fallback in the simulator and is not bridged by the interposer. Use"
echo "the SecKey C API for a real-hardware test path (run-mechanism-d.sh)."
