#!/usr/bin/env bash
# Self-test for the bundle-mode fence (scripts/fence-check.sh --bundle), the gate
# the release workflow runs on the built .app. It plants each violation a shipped
# app must never carry and asserts the fence FAILS, then a clean bundle and asserts
# it PASSES. A fence that only ever passes proves nothing; this proves it catches a
# bundled interposer and an injection-setting Info.plist.
#
# macOS only: the LSEnvironment assertion needs PlistBuddy, and the release lane
# that runs the bundle fence is macOS.
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FENCE="$REPO/scripts/fence-check.sh"

if [ ! -x /usr/libexec/PlistBuddy ]; then
  echo "fence-selftest: needs PlistBuddy (run on macOS)" >&2
  exit 2
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
fails=0

# expect <wanted-exit> <label> -- <fence args...>
expect() {
  local want="$1" label="$2"
  shift 3
  bash "$FENCE" "$@" >/dev/null 2>&1
  local got=$?
  if [ "$got" -ne "$want" ]; then
    echo "SELFTEST FAIL: $label (wanted exit $want, got $got)" >&2
    fails=1
  else
    echo "ok: $label (exit $got)"
  fi
}

# A minimal valid bundle: just a CFBundleName Info.plist, no violations.
write_clean_plist() {
  cat >"$1" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>CFBundleName</key><string>Fixture</string></dict></plist>
PLIST
}

# 1. A clean bundle passes.
clean="$TMP/Clean.app/Contents"
mkdir -p "$clean"
write_clean_plist "$clean/Info.plist"
expect 0 "clean bundle passes" -- --bundle "$TMP/Clean.app"

# 2. A bundle carrying the interposer dylib fails (rule 2 in bundle form).
dylib="$TMP/Dylib.app/Contents"
mkdir -p "$dylib/Frameworks"
write_clean_plist "$dylib/Info.plist"
touch "$dylib/Frameworks/simenclave-interpose.dylib"
expect 1 "bundled interposer dylib fails" -- --bundle "$TMP/Dylib.app"

# 3. A bundle whose Info.plist sets the injection variable fails (rule 1 in bundle form).
inject="$TMP/Inject.app/Contents"
mkdir -p "$inject"
cat >"$inject/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleName</key><string>Fixture</string>
  <key>LSEnvironment</key>
  <dict><key>DYLD_INSERT_LIBRARIES</key><string>anything.dylib</string></dict>
</dict></plist>
PLIST
expect 1 "injection in Info.plist LSEnvironment fails" -- --bundle "$TMP/Inject.app"

# 4. A nonexistent bundle is a usage error, not a silent pass.
expect 2 "missing bundle is a usage error" -- --bundle "$TMP/Nope.app"

if [ "$fails" -eq 0 ]; then
  echo "FENCE SELFTEST: ok"
fi
exit "$fails"
