#!/usr/bin/env bash
# Assemble the menubar helper into a real SimEnclave.app bundle and sign it. A bundle (not
# a bare executable) is what MenuBarExtra needs to render reliably and what SMAppService
# needs for launch at login. SIGN_ID defaults to ad-hoc; pass a keychain identity for a
# named local build. The notarized, distributable bundle is M5; this is the dev bundle.
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export DEVELOPER_DIR="${DEVELOPER_DIR:-/Applications/Xcode.app/Contents/Developer}"
SIGN_ID="${SIGN_ID:--}"
APP="$REPO/dist/SimEnclave.app"

echo "building simenclave-menubar (release)..."
( cd "$REPO/apps/helper" && xcrun swift build -c release --product simenclave-menubar ) || exit 1
BIN="$REPO/apps/helper/.build/release/simenclave-menubar"

rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp "$BIN" "$APP/Contents/MacOS/SimEnclave"

cat > "$APP/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleIdentifier</key><string>dev.simenclave.menubar</string>
  <key>CFBundleName</key><string>SimEnclave</string>
  <key>CFBundleDisplayName</key><string>SimEnclave</string>
  <key>CFBundleExecutable</key><string>SimEnclave</string>
  <key>CFBundleIconFile</key><string>simenclave</string>
  <key>CFBundleIconName</key><string>simenclave</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>1.0</string>
  <key>CFBundleVersion</key><string>1</string>
  <key>LSMinimumSystemVersion</key><string>14.0</string>
  <key>LSUIElement</key><true/>
</dict>
</plist>
PLIST

# Compile the regular app icon (the Icon Composer .icon) into the bundle: actool emits the
# Assets.car the modern renderer reads, the simenclave.icns the Dock and Finder fall back to, and
# a partial plist whose icon-name keys are already in the Info.plist above.
ICON_PARTIAL="$(mktemp)"
xcrun actool "$REPO/assets/simenclave.icon" --compile "$APP/Contents/Resources" \
  --app-icon simenclave --platform macosx --minimum-deployment-target 14.0 \
  --output-partial-info-plist "$ICON_PARTIAL" >/dev/null 2>&1 \
  || { echo "actool failed to compile the app icon"; rm -f "$ICON_PARTIAL"; exit 1; }
rm -f "$ICON_PARTIAL"

# The menu-bar status icon: the Template variants AppKit auto-tints to the menu bar (black on a
# light bar, white on a dark one). NSImage(named:) resolves @1x/@2x from these two files.
cp "$REPO/assets/menubar/menubar-iconTemplate-18.png" "$APP/Contents/Resources/MenuBarIcon.png"
cp "$REPO/assets/menubar/menubar-iconTemplate-36-2x.png" "$APP/Contents/Resources/MenuBarIcon@2x.png"

codesign -s "$SIGN_ID" --force --timestamp=none "$APP" >/dev/null 2>&1 \
  || { echo "codesign failed for identity '$SIGN_ID'"; exit 1; }

echo "built $APP (signed: $SIGN_ID)"
echo "run it:   open \"$APP\""
