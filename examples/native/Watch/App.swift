// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

import SwiftUI

/// The watchOS face of the example. It drives the same `SEConsole` the iOS app does, so the
/// Secure Enclave code is shared across both platforms and only the UI differs for the watch
/// screen. On an Apple Watch it signs in the device Secure Enclave; in the watchOS Simulator with
/// SimEnclave injected, against the host Mac's Secure Enclave.
@main
struct SecureEnclaveWatchApp: App {
    var body: some Scene {
        WindowGroup { WatchRootView() }
    }
}

struct WatchRootView: View {
    @State private var console = SEConsole()

    var body: some View {
        ScrollView {
            VStack(spacing: 10) {
                Image(systemName: symbol)
                    .font(.title2)
                    .foregroundStyle(tint)
                Text(console.history.first?.text ?? "Generate a key and sign in the Secure Enclave")
                    .font(.footnote)
                    .multilineTextAlignment(.center)
                Button("Generate + sign") { run() }
                    .buttonStyle(.borderedProminent)
                if let signature = console.signature {
                    Text("\(signature.bytes) B \(signature.verified == true ? "verified" : "signature")")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
            }
            .padding()
        }
    }

    private var symbol: String {
        switch console.signature?.verified {
        case true: return "checkmark.seal.fill"
        case false: return "xmark.seal.fill"
        default: return "lock.shield"
        }
    }

    private var tint: Color {
        switch console.signature?.verified {
        case true: return .green
        case false: return .red
        default: return .blue
        }
    }

    /// Generate a silent key (the watch has no biometry to prompt at sign time), sign a message
    /// digest, and verify it, all through the shared `SEConsole` the iOS app uses.
    private func run() {
        console.generate(gate: .silent, protection: .whenUnlockedThisDevice)
        console.sign(message: "hello from the watch", mode: .digest)
        console.verify(tamper: false)
    }
}
