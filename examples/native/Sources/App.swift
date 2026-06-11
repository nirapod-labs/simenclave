// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 SimEnclave Contributors

import SwiftUI

/// An interactive Secure Enclave console. Every operation is a control you drive, results
/// land as cards with haptic and toast feedback, and the keys you mint stay in a list you can
/// select among. Each call is the real native one, so the same actions run unchanged on a
/// device and, in the Simulator with SimEnclave injected, against the host Mac's Secure Enclave.
@main
struct SecureEnclaveExampleApp: App {
    var body: some Scene {
        WindowGroup { RootView() }
    }
}

struct RootView: View {
    @State private var console = SEConsole()
    @State private var tab = Self.initialTab

    var body: some View {
        @Bindable var console = console
        TabView(selection: $tab) {
            KeyTab().tag(0).tabItem { Label("Key", systemImage: "key") }
            SignTab().tag(1).tabItem { Label("Sign", systemImage: "signature") }
            KeychainTab().tag(2).tabItem { Label("Keychain", systemImage: "key.viewfinder") }
            HistoryTab().tag(3).tabItem { Label("History", systemImage: "clock.arrow.circlepath") }
        }
        .tint(.blue)
        .environment(console)
        .toast($console.toast)
        .sensoryFeedback(.success, trigger: console.successTick)
        .sensoryFeedback(.error, trigger: console.errorTick)
        .task {
            console.loadKeys()
            if ProcessInfo.processInfo.environment["SE_DEMO_SEED"] == "1", console.keys.isEmpty {
                console.seedDemo()
            }
        }
    }

    private static var initialTab: Int {
        switch ProcessInfo.processInfo.environment["SE_DEMO_TAB"] {
        case "sign": return 1
        case "keychain": return 2
        case "history": return 3
        default: return 0
        }
    }
}
