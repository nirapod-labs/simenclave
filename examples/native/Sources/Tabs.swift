// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 SimEnclave Contributors

import SwiftUI

/// Create keys and manage the set of keys minted this session. Each key is a row; tap to
/// select, swipe to delete. The selected key is what the Sign and Keychain tabs act on.
struct KeyTab: View {
    @Environment(SEConsole.self) private var console
    @State private var gate: KeyGate = .silent
    @State private var protection: Protection = .whenUnlockedThisDevice

    var body: some View {
        @Bindable var console = console
        NavigationStack {
            List {
                Section {
                    Picker("Access gate", selection: $gate) {
                        ForEach(KeyGate.allCases) { Text($0.rawValue).tag($0) }
                    }
                    .pickerStyle(.segmented)
                    Picker("Protection", selection: $protection) {
                        ForEach(Protection.allCases) { Text($0.rawValue).tag($0) }
                    }
                    .pickerStyle(.menu)
                    Toggle(isOn: $console.persist) {
                        Label("Store in keychain", systemImage: "internaldrive")
                    }
                    Button {
                        console.generate(gate: gate, protection: protection)
                    } label: {
                        Label("Generate hardware key", systemImage: "key.fill")
                            .frame(maxWidth: .infinity)
                            .fontWeight(.semibold)
                    }
                    .buttonStyle(.borderedProminent)
                } header: {
                    Text("Create a key")
                } footer: {
                    Text(console.persist
                        ? "A stored key persists in the keychain and reloads next launch, like a real app's signing key."
                        : "An ephemeral key lives only while the app is open.")
                }

                Section {
                    if console.keys.isEmpty {
                        Text("No keys yet. Generate one above.")
                            .foregroundStyle(.secondary)
                    } else {
                        ForEach(console.keys) { key in
                            Button {
                                withAnimation(.snappy) { console.select(key.id) }
                            } label: {
                                KeyListRow(key: key, selected: key.id == console.selectedID)
                            }
                            .buttonStyle(.plain)
                            .swipeActions {
                                Button(role: .destructive) {
                                    withAnimation(.snappy) { console.deleteKey(key.id) }
                                } label: {
                                    Label("Delete", systemImage: "trash")
                                }
                            }
                        }
                    }
                } header: {
                    Text(console.keys.isEmpty ? "Keys" : "Keys (\(console.keys.count))")
                }
            }
            .brandHeader()
        }
    }
}

/// Sign a message with the selected key and verify it. The signature comes back as a card with
/// a verified badge.
struct SignTab: View {
    @Environment(SEConsole.self) private var console
    @State private var message = "hello secure enclave"
    @State private var mode: SignMode = .digest
    @FocusState private var editing: Bool

    var body: some View {
        NavigationStack {
            List {
                if let key = console.selectedKey {
                    Section { SelectedKeyRow(key: key) }

                    Section {
                        TextField("Message to sign", text: $message, axis: .vertical)
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                            .lineLimit(1 ... 4)
                            .focused($editing)
                        Picker("Mode", selection: $mode) {
                            ForEach(SignMode.allCases) { Text($0.rawValue).tag($0) }
                        }
                        .pickerStyle(.segmented)
                        Button {
                            editing = false
                            console.sign(message: message, mode: mode)
                        } label: {
                            Label("Sign message", systemImage: "signature")
                                .frame(maxWidth: .infinity)
                                .fontWeight(.semibold)
                        }
                        .buttonStyle(.borderedProminent)
                        .disabled(message.isEmpty)
                    } header: {
                        Text("Message")
                    } footer: {
                        Text(mode == .digest
                            ? "Digest mode signs the SHA-256 of your message."
                            : "Message mode hands the raw message to the SEP to hash and sign.")
                    }

                    if let signature = console.signature {
                        Section("Signature") {
                            SignatureCard(signature: signature)
                        }
                    }
                } else {
                    Section {
                        ContentUnavailableView("No key selected", systemImage: "key.slash",
                                               description: Text("Generate or select a key on the Key tab."))
                    }
                }
            }
            .animation(.snappy, value: console.signature)
            .scrollDismissesKeyboard(.interactively)
            .brandHeader()
            .toolbar {
                ToolbarItemGroup(placement: .keyboard) {
                    Spacer()
                    Button("Done") { editing = false }
                }
            }
        }
    }
}

/// Persist, find, and delete a key by application tag through SecItem.
struct KeychainTab: View {
    @Environment(SEConsole.self) private var console
    @State private var tag = "my.app.key"
    @FocusState private var editing: Bool

    var body: some View {
        NavigationStack {
            List {
                if let key = console.selectedKey {
                    Section { SelectedKeyRow(key: key) }
                }

                Section {
                    TextField("Application tag", text: $tag)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .submitLabel(.done)
                        .focused($editing)
                    Button {
                        editing = false
                        console.keychainAdd(tag: tag)
                    } label: {
                        Label("Save current key", systemImage: "tray.and.arrow.down")
                    }
                    .disabled(!console.hasKey)
                    Button {
                        editing = false
                        console.keychainFind(tag: tag)
                    } label: {
                        Label("Find key by tag", systemImage: "magnifyingglass")
                    }
                    Button(role: .destructive) {
                        editing = false
                        console.keychainDelete(tag: tag)
                    } label: {
                        Label("Delete key by tag", systemImage: "trash")
                    }
                } header: {
                    Text("Keychain by tag")
                } footer: {
                    Text("SecItem stores and finds the key under this tag for the session. Durable storage across helper restarts is on the roadmap.")
                }
            }
            .scrollDismissesKeyboard(.interactively)
            .brandHeader()
            .toolbar {
                ToolbarItemGroup(placement: .keyboard) {
                    Spacer()
                    Button("Done") { editing = false }
                }
            }
        }
    }
}

/// The full trail of operations, newest first, as a plain grouped list.
struct HistoryTab: View {
    @Environment(SEConsole.self) private var console

    var body: some View {
        NavigationStack {
            List {
                if console.history.isEmpty {
                    Section {
                        ContentUnavailableView("No activity yet", systemImage: "clock.arrow.circlepath",
                                               description: Text("Run an operation and it shows up here."))
                    }
                } else {
                    ForEach(console.history) { line in
                        HStack(alignment: .top, spacing: 12) {
                            Image(systemName: icon(line.ok)).foregroundStyle(color(line.ok))
                            VStack(alignment: .leading, spacing: 2) {
                                Text(line.text).font(.callout)
                                Text(line.time, style: .time)
                                    .font(.caption2).foregroundStyle(.secondary)
                            }
                        }
                    }
                }
            }
            .brandHeader()
            .toolbar {
                if !console.history.isEmpty {
                    ToolbarItem(placement: .topBarTrailing) {
                        Button("Clear", role: .destructive) {
                            withAnimation(.snappy) { console.clearHistory() }
                        }
                    }
                }
            }
        }
    }

    private func icon(_ ok: Bool?) -> String {
        ok == true ? "checkmark.circle.fill" : ok == false ? "xmark.circle.fill" : "info.circle.fill"
    }
    private func color(_ ok: Bool?) -> Color {
        ok == true ? .green : ok == false ? .red : .blue
    }
}

/// A signature shown as a card: the DER in monospace, a verified badge, copy and verify.
struct SignatureCard: View {
    let signature: SignatureInfo
    @Environment(SEConsole.self) private var console

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Text("\(signature.bytes) B · DER · \(signature.mode.rawValue)")
                    .font(.caption).foregroundStyle(.secondary)
                Spacer()
                verifiedBadge.contentTransition(.symbolEffect(.replace))
            }
            Text(grouped(signature.derHex))
                .font(.system(.caption, design: .monospaced))
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(12)
                .background(Color(.tertiarySystemFill), in: RoundedRectangle(cornerRadius: 10))
            HStack(spacing: 12) {
                CopyButton(value: signature.derHex, label: "signature")
                Spacer()
                Button {
                    console.verify(tamper: false)
                } label: {
                    Label("Verify", systemImage: "checkmark.seal")
                }
                .buttonStyle(.bordered)
                Button {
                    console.verify(tamper: true)
                } label: {
                    Label("Tamper", systemImage: "exclamationmark.triangle")
                }
                .buttonStyle(.bordered)
                .tint(.orange)
            }
            .font(.subheadline)
        }
        .padding(.vertical, 4)
    }

    @ViewBuilder private var verifiedBadge: some View {
        switch signature.verified {
        case .some(true):
            Label("Verified", systemImage: "checkmark.seal.fill")
                .font(.caption.weight(.semibold)).foregroundStyle(.green)
        case .some(false):
            Label("Failed", systemImage: "xmark.seal.fill")
                .font(.caption.weight(.semibold)).foregroundStyle(.red)
        case .none:
            Label("Not verified", systemImage: "seal").font(.caption).foregroundStyle(.secondary)
        }
    }

    private func grouped(_ hex: String) -> String {
        stride(from: 0, to: hex.count, by: 2).map {
            let start = hex.index(hex.startIndex, offsetBy: $0)
            let end = hex.index(start, offsetBy: 2, limitedBy: hex.endIndex) ?? hex.endIndex
            return String(hex[start ..< end])
        }.joined(separator: " ")
    }
}

