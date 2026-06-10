#!/usr/bin/env bash
# Emit the three environment variables a debug Simulator scheme needs to load the
# interposer and reach a running helper: the injected dylib, the helper's port, and
# the capability token. Paste them into the scheme's EnvironmentVariables in Xcode,
# or, for `xcrun simctl spawn`, prefix each name with SIMCTL_CHILD_ (as the
# mechanism scripts do). The token is read from the helper's 0600 file; it is a
# per-session secret, so never commit it or paste it anywhere durable.
#
# The polished `simenclavectl init`, which writes these into a real app's scheme and
# runs a doctor handshake, is M5. This is the precursor a developer can use now.
#
# Usage: set-scheme-env.sh <helper-port> [token-dir]
#   <helper-port>  the port the helper printed in its {"ready":...} line
#   [token-dir]    where the helper wrote its token (default: the per-user path,
#                  or pass the SIMENCLAVE_HOME a helper was started with)
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PORT="${1:-}"
TOKEN_DIR="${2:-$HOME/Library/Application Support/SimEnclave}"
DYLIB="$REPO/build-sim/bin/simenclave-interpose.dylib"

if [ -z "$PORT" ]; then
  echo "usage: set-scheme-env.sh <helper-port> [token-dir]" >&2
  exit 2
fi
if [ ! -f "$DYLIB" ]; then
  echo "interposer not built: run 'make build' first ($DYLIB)" >&2
  exit 1
fi
TOKEN="$(cat "$TOKEN_DIR/token" 2>/dev/null)"
if [ -z "$TOKEN" ]; then
  echo "no token at $TOKEN_DIR/token; is the helper running?" >&2
  exit 1
fi

cat <<ENV
DYLD_INSERT_LIBRARIES=$DYLIB
SIMENCLAVE_PORT=$PORT
SIMENCLAVE_TOKEN=$TOKEN
ENV
