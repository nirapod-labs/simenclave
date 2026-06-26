#!/usr/bin/env bash
# Self-test for the fence bundle modes (scripts/fence-check.sh --bundle and --helper), the gates the
# release workflow runs on built bundles. For --bundle (a shipped consuming app) it plants each
# violation the app must never carry and asserts the fence FAILS, then a clean bundle PASSES. For
# --helper (the tool) it asserts a bundle with no interposer or a non-simulator-slice payload FAILS,
# and the real simulator-slice interposer PASSES. A fence that only ever passes proves nothing.
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

# 5. Helper mode: a bundle with no interposer cannot inject, so it fails.
nohelper="$TMP/NoInterposer.app/Contents"
mkdir -p "$nohelper/Resources"
write_clean_plist "$nohelper/Info.plist"
expect 1 "helper bundle without an interposer fails" -- --helper "$TMP/NoInterposer.app"

# 6. Helper mode rejects a payload it cannot prove is simulator-slice (here, a non-Mach-O file).
fakehelper="$TMP/FakeInterposer.app/Contents"
mkdir -p "$fakehelper/Resources"
write_clean_plist "$fakehelper/Info.plist"
echo "not a mach-o" >"$fakehelper/Resources/simenclave-interpose.dylib"
expect 1 "helper bundle with a non-simulator-slice interposer fails" -- --helper "$TMP/FakeInterposer.app"

# 7. Helper mode passes with the real simulator-slice interposer. Needs the built dylib
#    (make dylib / make build); skipped if it has not been built yet.
real="$REPO/build-sim/bin/simenclave-interpose.dylib"
if [ -f "$real" ]; then
  okhelper="$TMP/Helper.app/Contents"
  mkdir -p "$okhelper/Resources"
  write_clean_plist "$okhelper/Info.plist"
  cp "$real" "$okhelper/Resources/simenclave-interpose.dylib"
  expect 0 "helper bundle with the simulator-slice interposer passes" -- --helper "$TMP/Helper.app"
else
  echo "skip: helper-mode pass case (build the interposer with 'make dylib' to cover it)"
fi

# 8. Helper mode passes with the watchos simulator slice, and with both slices together: every
#    platform in the bundle is a simulator slice. Needs the watchos slice (make dylib / make build).
realwatch="$REPO/build-watchsim/bin/simenclave-interpose-watchos.dylib"
if [ -f "$realwatch" ]; then
  watchapp="$TMP/Watch.app/Contents"
  mkdir -p "$watchapp/Resources"
  write_clean_plist "$watchapp/Info.plist"
  cp "$realwatch" "$watchapp/Resources/simenclave-interpose-watchos.dylib"
  expect 0 "helper bundle with the watchos simulator slice passes" -- --helper "$TMP/Watch.app"
fi
if [ -f "$real" ] && [ -f "$realwatch" ]; then
  bothapp="$TMP/Both.app/Contents"
  mkdir -p "$bothapp/Resources"
  write_clean_plist "$bothapp/Info.plist"
  cp "$real" "$bothapp/Resources/simenclave-interpose.dylib"
  cp "$realwatch" "$bothapp/Resources/simenclave-interpose-watchos.dylib"
  expect 0 "helper bundle with both simulator slices passes" -- --helper "$TMP/Both.app"
fi

# 9. Helper mode rejects a real Mach-O whose platform is a device platform, not a simulator slice.
#    vtool rewrites the sim slice's build version to macos to synthesize a device-platform file.
if [ -f "$real" ] && command -v vtool >/dev/null; then
  devapp="$TMP/Device.app/Contents"
  mkdir -p "$devapp/Resources"
  write_clean_plist "$devapp/Info.plist"
  vtool -arch arm64 -set-build-version macos 14.0 14.0 -replace \
    -output "$devapp/Resources/simenclave-interpose.dylib" "$real" >/dev/null 2>&1
  expect 1 "helper bundle with a device-platform interposer fails" -- --helper "$TMP/Device.app"

  # 10. A bundle mixing a good simulator slice with a device-platform slice still fails: the check
  #     covers every slice, not just the first one found.
  mixedapp="$TMP/Mixed.app/Contents"
  mkdir -p "$mixedapp/Resources"
  write_clean_plist "$mixedapp/Info.plist"
  cp "$real" "$mixedapp/Resources/simenclave-interpose.dylib"
  vtool -arch arm64 -set-build-version macos 14.0 14.0 -replace \
    -output "$mixedapp/Resources/simenclave-interpose-bad.dylib" "$real" >/dev/null 2>&1
  expect 1 "helper bundle mixing a device-platform slice fails" -- --helper "$TMP/Mixed.app"
fi

if [ "$fails" -eq 0 ]; then
  echo "FENCE SELFTEST: ok"
fi
exit "$fails"
