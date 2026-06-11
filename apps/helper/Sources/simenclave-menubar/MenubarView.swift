// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

import AppKit
import SwiftUI

/// The MenuBarExtra popover: the on/off toggle, status, copy-scheme-environment, the
/// connected simulator apps, and the footer actions.
struct MenubarView: View {
    @Bindable var model: HelperModel
    @State private var copied = false
    @Environment(\.openSettings) private var openSettings

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header
            Divider()
            if model.secureEnclaveAvailable {
                status
                copyButton
                Divider()
                connectedApps
            } else {
                Label("No Secure Enclave on this Mac", systemImage: "exclamationmark.triangle")
                    .font(.callout).foregroundStyle(.secondary).padding(12)
            }
            Divider()
            footer
        }
        .frame(width: 300)
    }

    private var header: some View {
        HStack {
            SimEnclaveWordmark(size: 17)
            Spacer()
            Toggle("", isOn: Binding(get: { model.running }, set: { _ in model.toggle() }))
                .toggleStyle(.switch)
                .labelsHidden()
                .disabled(!model.secureEnclaveAvailable)
        }
        .padding(12)
    }

    private var status: some View {
        HStack(spacing: 8) {
            Circle().fill(model.running ? Color.green : Color.secondary).frame(width: 8, height: 8)
            if model.running {
                Text("Running").font(.callout)
                Text("127.0.0.1:\(String(model.port))")
                    .font(.system(.callout, design: .monospaced)).foregroundStyle(.secondary)
            } else {
                Text("Off").font(.callout).foregroundStyle(.secondary)
            }
            Spacer()
        }
        .padding(.horizontal, 12).padding(.vertical, 8)
    }

    private var copyButton: some View {
        Button {
            if let env = model.schemeEnvironment() {
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(env, forType: .string)
                withAnimation { copied = true }
            }
        } label: {
            Label(copied ? "Copied" : "Copy scheme environment",
                  systemImage: copied ? "checkmark" : "doc.on.clipboard")
                .frame(maxWidth: .infinity)
        }
        .controlSize(.large)
        .disabled(!model.running)
        .padding(.horizontal, 12).padding(.bottom, 10)
        .task(id: copied) {
            if copied {
                try? await Task.sleep(for: .seconds(1.5))
                withAnimation { copied = false }
            }
        }
    }

    private var connectedApps: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Connected apps").font(.caption).foregroundStyle(.secondary)
            if model.apps.isEmpty {
                Text("No simulator app has connected yet.")
                    .font(.caption).foregroundStyle(.tertiary)
            } else {
                ForEach(model.apps) { app in
                    HStack(spacing: 10) {
                        Image(systemName: "iphone").foregroundStyle(.tint).frame(width: 20)
                        VStack(alignment: .leading, spacing: 1) {
                            Text(app.name ?? app.id)
                                .font(.caption.weight(.medium)).lineLimit(1).truncationMode(.middle)
                            Text("\(app.keys) key\(app.keys == 1 ? "" : "s") · \(app.lastSeen, style: .relative)")
                                .font(.caption2).foregroundStyle(.secondary)
                        }
                    }
                }
            }
        }
        .padding(12)
    }

    private var footer: some View {
        HStack(spacing: 0) {
            Button("Settings…") { openSettings() }
                .frame(maxWidth: .infinity)
            Divider().frame(height: 16)
            Button("Quit") { model.clearInjection(); NSApp.terminate(nil) }
                .frame(maxWidth: .infinity)
        }
        .buttonStyle(.borderless)
        .padding(.vertical, 8)
    }
}
