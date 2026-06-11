// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

import SwiftUI

/// The settings pane: a pinned port so the scheme environment stays stable across restarts,
/// and a launch-at-login switch.
struct SettingsView: View {
    @Bindable var model: HelperModel
    @State private var portText = ""

    var body: some View {
        Form {
            Section {
                Toggle("Launch SimEnclave at login", isOn: $model.launchAtLogin)
            }

            Section {
                LabeledContent("Port") {
                    HStack {
                        TextField("Auto", text: $portText)
                            .frame(width: 90)
                            .onSubmit(applyPort)
                        Button("Apply", action: applyPort)
                    }
                }
            } header: {
                Text("Fixed port")
            } footer: {
                Text("Pin a port so the scheme environment stays the same every run. "
                    + "Leave blank for an automatic port. Takes effect on the next on/off toggle.")
                    .font(.caption).foregroundStyle(.secondary)
            }
        }
        .formStyle(.grouped)
        .frame(width: 380, height: 240)
        .onAppear { portText = model.fixedPort == 0 ? "" : String(model.fixedPort) }
    }

    private func applyPort() {
        model.fixedPort = Int(portText) ?? 0
        portText = model.fixedPort == 0 ? "" : String(model.fixedPort)
    }
}
