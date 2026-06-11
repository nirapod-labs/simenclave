// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

import SwiftUI

/// The settings pane: helper status and a live uptime, a pinned port so the scheme environment
/// stays stable across restarts, launch-at-login, and the data directory with a reset for the keys.
struct SettingsView: View {
    @Bindable var model: HelperModel
    @State private var portText = ""
    @State private var confirmingReset = false

    var body: some View {
        Form {
            Section("Status") {
                LabeledContent("Helper") {
                    Text(model.running ? "Running on port \(model.port)" : "Stopped")
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
                LabeledContent("Keys", value: "\(model.totalKeys) across \(model.apps.count) apps")
                LabeledContent("Version", value: model.appVersion)
            }

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

            Section {
                Button("Open data directory") { model.openDataDirectory() }
                Button("Reset all keys", role: .destructive) { confirmingReset = true }
            } header: {
                Text("Data")
            } footer: {
                Text("The token and port live in the data directory. Resetting drops every key the "
                    + "helper holds; a connected app must generate again.")
                    .font(.caption).foregroundStyle(.secondary)
            }
        }
        .formStyle(.grouped)
        .frame(width: 380, height: 470)
        .onAppear { portText = model.fixedPort == 0 ? "" : String(model.fixedPort) }
        .confirmationDialog("Reset all keys?", isPresented: $confirmingReset) {
            Button("Reset all keys", role: .destructive) { model.resetAllKeys() }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("Every key the helper holds is dropped. This cannot be undone.")
        }
    }

    private func applyPort() {
        model.fixedPort = Int(portText) ?? 0
        portText = model.fixedPort == 0 ? "" : String(model.fixedPort)
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
