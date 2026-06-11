// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

import SwiftUI

/// The settings window, presented through the native `Settings` scene with the standard tab
/// toolbar: a General tab for configuration (launch at login, a pinned port) and a Status tab for
/// the helper's live state, version, and the data directory with a key reset.
struct SettingsView: View {
    @Bindable var model: HelperModel

    var body: some View {
        TabView {
            GeneralSettings(model: model)
                .tabItem { Label("General", systemImage: "gearshape") }
            StatusSettings(model: model)
                .tabItem { Label("Status", systemImage: "info.circle") }
        }
        .frame(width: 440)
    }
}

/// Configuration: the two things a developer actually sets.
private struct GeneralSettings: View {
    @Bindable var model: HelperModel
    @State private var portText = ""

    var body: some View {
        Form {
            Section {
                Toggle("Launch SimEnclave at login", isOn: $model.launchAtLogin)
            }

            Section {
                LabeledContent("Fixed port") {
                    HStack(spacing: 8) {
                        TextField("Auto", text: $portText)
                            .frame(width: 90)
                            .multilineTextAlignment(.trailing)
                            .onSubmit(applyPort)
                        Button("Apply", action: applyPort)
                    }
                }
            } footer: {
                Text("Pin a port so the scheme environment stays the same every run. Leave blank "
                    + "for an automatic port. Takes effect on the next on/off toggle.")
            }
        }
        .formStyle(.grouped)
        .onAppear { portText = model.fixedPort == 0 ? "" : String(model.fixedPort) }
    }

    private func applyPort() {
        model.fixedPort = Int(portText) ?? 0
        portText = model.fixedPort == 0 ? "" : String(model.fixedPort)
    }
}

/// The helper's live state, version, and the data directory with a reset.
private struct StatusSettings: View {
    @Bindable var model: HelperModel
    @State private var confirmingReset = false

    var body: some View {
        Form {
            Section {
                LabeledContent("Helper") {
                    // Interpolate the port as a String, not the integer: a Text built from a
                    // LocalizedStringKey number-groups an Int (it would read "65,176").
                    Text(model.running ? "Running on port \(String(model.port))" : "Stopped")
                        .foregroundStyle(model.running ? Color.green : Color.secondary)
                }
                if model.running, let started = model.startedAt {
                    LabeledContent("Uptime") {
                        TimelineView(.periodic(from: started, by: 1)) { context in
                            Text(Self.uptime(from: started, to: context.date)).monospacedDigit()
                        }
                    }
                }
                LabeledContent(
                    "Secure Enclave",
                    value: model.secureEnclaveAvailable ? "Available" : "Not available")
                LabeledContent("Keys", value: model.totalKeys == 1 ? "1 key" : "\(model.totalKeys) keys")
                LabeledContent("Version", value: model.appVersion)
            }

            Section {
                Button("Open data directory") { model.openDataDirectory() }
                Button("Reset all keys", role: .destructive) { confirmingReset = true }
            } footer: {
                Text("The token and port live in the data directory. Resetting drops every key the "
                    + "helper holds; a connected app must generate again.")
            }
        }
        .formStyle(.grouped)
        .confirmationDialog("Reset all keys?", isPresented: $confirmingReset) {
            Button("Reset all keys", role: .destructive) { model.resetAllKeys() }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("Every key the helper holds is dropped. This cannot be undone.")
        }
    }

    /// Format elapsed time compactly: "1h 05m", "5m 23s", or "12s".
    private static func uptime(from start: Date, to now: Date) -> String {
        let total = max(0, Int(now.timeIntervalSince(start)))
        let hours = total / 3600, minutes = (total % 3600) / 60, seconds = total % 60
        if hours > 0 { return String(format: "%dh %02dm", hours, minutes) }
        if minutes > 0 { return String(format: "%dm %02ds", minutes, seconds) }
        return "\(seconds)s"
    }
}
