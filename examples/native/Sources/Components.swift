// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

import SwiftUI
import UIKit

/// The selected key's status as a standard grouped row: hardware-backed (green) or software
/// (orange), with the gate on the trailing edge. Used at the top of Sign and Keychain.
struct SelectedKeyRow: View {
    let key: KeyInfo

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: key.hardwareBacked ? "checkmark.shield.fill" : "exclamationmark.triangle.fill")
                .font(.title2)
                .foregroundStyle(key.hardwareBacked ? .green : .orange)
                .symbolEffect(.bounce, value: key.id)
            VStack(alignment: .leading, spacing: 2) {
                Text(key.hardwareBacked ? "Hardware Secure Enclave" : "Software fallback")
                    .font(.subheadline.weight(.semibold))
                Text("\(key.label) · \(key.gate.rawValue) · \(key.protection.short)")
                    .font(.caption).foregroundStyle(.secondary)
            }
            Spacer()
            Image(systemName: key.gate.symbol)
                .foregroundStyle(key.gate.color)
                .symbolRenderingMode(.hierarchical)
        }
    }
}

/// The public key in monospace with a copy button. A standard row.
struct PublicKeyRow: View {
    let key: KeyInfo

    var body: some View {
        HStack(spacing: 10) {
            Text(key.publicKeyHex.prefix(28) + "…")
                .font(.system(.footnote, design: .monospaced))
                .lineLimit(1).truncationMode(.tail)
                .foregroundStyle(.secondary)
            Spacer()
            CopyButton(value: key.publicKeyHex, label: "public key")
        }
    }
}

/// One row in the keys list: the gate icon, the label and a short fingerprint, and a checkmark
/// when this is the selected key.
struct KeyListRow: View {
    let key: KeyInfo
    let selected: Bool

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: key.gate.symbol)
                .font(.body)
                .foregroundStyle(key.gate.color)
                .frame(width: 28)
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 5) {
                    Text(key.label).font(.body)
                    if key.persistent {
                        Image(systemName: "internaldrive")
                            .font(.caption2).foregroundStyle(.secondary)
                    }
                }
                Text("\(key.gate.rawValue) · \(key.publicKeyHex.prefix(12))…")
                    .font(.caption).foregroundStyle(.secondary)
            }
            Spacer()
            if selected {
                Image(systemName: "checkmark.circle.fill").foregroundStyle(.tint)
            }
        }
        .contentShape(Rectangle())
    }
}

/// A copy-to-clipboard button that confirms with a toast through the environment.
struct CopyButton: View {
    let value: String
    let label: String
    @Environment(SEConsole.self) private var console

    var body: some View {
        Button {
            UIPasteboard.general.string = value
            console.toast = Toast(kind: .info, text: "Copied \(label)")
        } label: {
            Image(systemName: "doc.on.doc").font(.subheadline)
        }
        .buttonStyle(.borderless)
    }
}

/// A transient toast pinned to the top, auto-dismissing.
struct ToastView: View {
    let toast: Toast

    var body: some View {
        Label(toast.text, systemImage: symbol)
            .font(.subheadline.weight(.medium))
            .foregroundStyle(tint)
            .padding(.horizontal, 16).padding(.vertical, 11)
            .background(.regularMaterial, in: Capsule())
            .overlay(Capsule().strokeBorder(tint.opacity(0.25)))
            .shadow(color: .black.opacity(0.12), radius: 10, y: 3)
            .padding(.top, 8)
    }

    private var symbol: String {
        switch toast.kind {
        case .success: return "checkmark.circle.fill"
        case .error: return "xmark.octagon.fill"
        case .info: return "info.circle.fill"
        }
    }
    private var tint: Color {
        switch toast.kind {
        case .success: return .green
        case .error: return .red
        case .info: return .blue
        }
    }
}

extension View {
    /// Overlays an auto-dismissing toast bound to `toast`.
    func toast(_ toast: Binding<Toast?>) -> some View {
        overlay(alignment: .top) {
            if let value = toast.wrappedValue {
                ToastView(toast: value)
                    .transition(.move(edge: .top).combined(with: .opacity))
                    .task(id: value.id) {
                        try? await Task.sleep(for: .seconds(1.9))
                        withAnimation(.snappy) { toast.wrappedValue = nil }
                    }
            }
        }
        .animation(.snappy, value: toast.wrappedValue)
    }
}
