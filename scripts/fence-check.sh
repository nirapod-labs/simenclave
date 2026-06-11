#!/usr/bin/env bash
# The static fence assertions. The fence: a release build sets no
# DYLD_INSERT_LIBRARIES and bundles no interposer dylib, so SimEnclave cannot
# ship inside an app. This script asserts the repo side of that on every PR;
# the runtime side (an unconfigured or uninjected app shows the stock
# failing-SE behavior) is asserted by run-mechanism-d.sh on a Mac with a
# simulator.
#
# Rules over tracked files:
#   1. Any .xcscheme that carries DYLD_INSERT_LIBRARIES must launch the Debug
#      build configuration. Any .xcconfig that sets it must be a debug config.
#   2. No Xcode project artifact (project.yml, *.pbxproj, *.xcconfig, any
#      Info.plist) references the interposer dylib. Bundling it is never
#      legitimate, debug or release.
#   3. DYLD_INSERT_LIBRARIES appears only in the allowlist below. A new
#      reference fails until it is consciously added here, in review.
#
# Bundle mode, for the release workflow once M5 builds a helper .app:
#   fence-check.sh --bundle <path.app>
#   Fails if the bundle contains an interposer dylib or sets the variable in
#   its Info.plist LSEnvironment.
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"

DYLIB_NAME="simenclave-interpose"
VAR="DYLD_INSERT_LIBRARIES"
FAIL=0

fail() {
  echo "FENCE FAIL: $1" >&2
  FAIL=1
}

# --- bundle mode -----------------------------------------------------------
if [ "${1:-}" = "--bundle" ]; then
  BUNDLE="${2:-}"
  [ -d "$BUNDLE" ] || { echo "usage: fence-check.sh --bundle <path.app>" >&2; exit 2; }
  # PlistBuddy is the LSEnvironment check. It is macOS-only; refuse rather than
  # silently skip a fence assertion, which would read as "checked" when it was not.
  # The release workflow that builds the .app runs on macOS, so this holds there.
  [ -x /usr/libexec/PlistBuddy ] || { echo "FENCE FAIL: --bundle needs PlistBuddy (run on macOS)" >&2; exit 2; }
  HITS="$(find "$BUNDLE" -name "*${DYLIB_NAME}*" 2>/dev/null)"
  [ -z "$HITS" ] || fail "interposer dylib inside the bundle: $HITS"
  PLIST="$BUNDLE/Contents/Info.plist"
  if [ -f "$PLIST" ] && /usr/libexec/PlistBuddy -c "Print :LSEnvironment" "$PLIST" 2>/dev/null | grep -q "$VAR"; then
    fail "$VAR set in $PLIST LSEnvironment"
  fi
  [ "$FAIL" -eq 0 ] && echo "FENCE (bundle): ok"
  exit "$FAIL"
fi

# --- rule 1: injection is debug-scheme-only --------------------------------
git ls-files '*.xcscheme' | while read -r scheme; do
  grep -q "$VAR" "$scheme" || continue
  # The LaunchAction is the configuration the env vars ride.
  launch_cfg="$(sed -n '/<LaunchAction/,/>/p' "$scheme" | grep -o 'buildConfiguration = "[^"]*"' | head -1)"
  case "$launch_cfg" in
    *'"Debug"'*) ;;
    *) echo "FENCE FAIL: $scheme carries $VAR outside a Debug launch configuration ($launch_cfg)" >&2
       touch .fence-violation ;;
  esac
done

git ls-files '*.xcconfig' | while read -r cfg; do
  grep -q "^[[:space:]]*$VAR" "$cfg" || continue
  case "$(basename "$cfg" | tr '[:upper:]' '[:lower:]')" in
    *debug*) ;;
    *) echo "FENCE FAIL: $cfg sets $VAR and is not a debug xcconfig" >&2
       touch .fence-violation ;;
  esac
done

# --- rule 2: the dylib is never a project artifact -------------------------
HITS="$(git ls-files 'project.yml' '*/project.yml' '*.pbxproj' '*.xcconfig' '*Info.plist' \
        | xargs grep -l "$DYLIB_NAME" 2>/dev/null || true)"
[ -z "$HITS" ] || fail "interposer dylib referenced by a project artifact: $HITS"

# --- rule 3: the injection variable stays inside the allowlist -------------
# scripts/set-scheme-env.sh   the developer-facing injection precursor
# scripts/fence-check.sh      this script
# scripts/fence-selftest.sh   the bundle-fence self-test; builds violation fixtures
#   (an Info.plist that sets the variable) in a temp dir to prove the fence catches
#   them. Never a real artifact; rule 2 still forbids bundling the dylib.
# packages/interpose/tests/   the mechanism harnesses and probes
# packages/interpose/src/entry.c  the load-path comment
# apps/helper/Sources/simenclave-menubar/HelperModel.swift  the menubar arms the
#   booted simulators (the SimCam model): it sets the variable in the simulator's
#   launchd environment so a launched app inherits the interposer. Dev-tool only,
#   never a shipped app; the same role as set-scheme-env.sh. Rule 2 still forbids
#   bundling the dylib, so this does not weaken the fence.
# .github/workflows/          the fence and CI definitions
# *.md and docs/              prose
# *.xcscheme and *.xcconfig   governed by rule 1 (debug-only), not this list
allowed() {
  case "$1" in
    scripts/set-scheme-env.sh) return 0 ;;
    scripts/fence-check.sh) return 0 ;;
    scripts/fence-selftest.sh) return 0 ;;
    packages/interpose/tests/*) return 0 ;;
    packages/interpose/src/entry.c) return 0 ;;
    apps/helper/Sources/simenclave-menubar/HelperModel.swift) return 0 ;;
    .github/workflows/*) return 0 ;;
    *.md | docs/*) return 0 ;;
    *.xcscheme | *.xcconfig) return 0 ;;
  esac
  return 1
}

git grep -l "$VAR" -- . | while read -r f; do
  allowed "$f" && continue
  echo "FENCE FAIL: $VAR referenced outside the fence allowlist: $f" >&2
  touch .fence-violation
done

# Subshell rules signal through a marker file; fold it into the exit code.
if [ -e .fence-violation ]; then
  rm -f .fence-violation
  FAIL=1
fi

[ "$FAIL" -eq 0 ] && echo "FENCE (static): ok"
exit "$FAIL"
