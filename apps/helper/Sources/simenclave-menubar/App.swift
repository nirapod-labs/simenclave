// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

// The helper as a menubar app. It runs the same loopback signing service as the CLI
// (SimEnclaveHelperKit) behind a SwiftUI MenuBarExtra: an on/off toggle, the bound port and
// SEP status, one-click "copy scheme environment", and the simulator apps using the SEP this
// session. Settings cover a pinned port and launch at login. It is an accessory app (no dock
// icon, set by LSUIElement in the bundle's Info.plist). The Secure Enclave works ad-hoc; a
// notarized, distributable bundle is M5.

import AppKit
import SwiftUI

@main
struct SimEnclaveMenubarApp: App {
    @State private var model = HelperModel()

    var body: some Scene {
        MenuBarExtra {
            MenubarView(model: model)
        } label: {
            menuBarLabel
        }
        .menuBarExtraStyle(.window)

        Settings {
            SettingsView(model: model)
        }
    }

    /// The status-bar glyph: the SimEnclave mark (a template image the menu bar tints to match
    /// the bar), dimmed while the helper is stopped so the on/off state still reads at a glance.
    /// A missing Secure Enclave keeps the warning triangle, and an un-bundled `swift run` with no
    /// copied resource falls back to the symbol so dev runs still show something.
    @ViewBuilder
    private var menuBarLabel: some View {
        if !model.secureEnclaveAvailable {
            Image(systemName: "exclamationmark.triangle")
        } else if let icon = Self.markIcon {
            Image(nsImage: icon).opacity(model.running ? 1 : 0.45)
        } else {
            Image(systemName: model.iconName)
        }
    }

    /// The menu-bar mark, loaded once from the bundle and marked as a template so AppKit tints it.
    private static let markIcon: NSImage? = {
        guard let image = NSImage(named: "MenuBarIcon") else { return nil }
        image.isTemplate = true
        return image
    }()
}
