// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 SimEnclave Contributors

import SwiftUI

/// The SimEnclave lockup (mark + wordmark) from the shipped brand asset, which already carries the
/// mark and the "SimEnclave" wordmark and switches light and dark. Used as the navigation title.
struct SimEnclaveLockup: View {
    var height: CGFloat = 22

    var body: some View {
        Image("simenclave-wordmark")
            .resizable()
            .scaledToFit()
            .frame(height: height)
            .accessibilityLabel("SimEnclave")
    }
}

/// The brand navigation header: the Swift badge on the left, the SimEnclave lockup centered as the
/// title, and an About button on the right that presents the About sheet. Applied to every tab so
/// the bar is consistent, the way the React Native example's header is.
private struct BrandHeader: ViewModifier {
    @State private var showAbout = false

    func body(content: Content) -> some View {
        content
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarLeading) {
                    Image(systemName: "swift")
                        .foregroundStyle(Color(red: 0.941, green: 0.318, blue: 0.220))
                        .accessibilityLabel("Swift")
                }
                ToolbarItem(placement: .principal) {
                    SimEnclaveLockup()
                }
                ToolbarItem(placement: .topBarTrailing) {
                    Button {
                        showAbout = true
                    } label: {
                        Image(systemName: "info.circle")
                    }
                    .accessibilityLabel("About SimEnclave")
                }
            }
            .sheet(isPresented: $showAbout) { AboutSheet() }
    }
}

extension View {
    /// Adds the SimEnclave brand navigation header (Swift badge, lockup, About button).
    func brandHeader() -> some View { modifier(BrandHeader()) }
}

/// The About panel, presented as a sheet from the header: what the project is, that this is the
/// native example, and the Nirapod Labs credit and license.
struct AboutSheet: View {
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            List {
                Section {
                    VStack(alignment: .leading, spacing: 8) {
                        SimEnclaveLockup(height: 34)
                        Text("Real hardware Secure Enclave for the iOS Simulator.")
                            .font(.subheadline).foregroundStyle(.secondary)
                    }
                    .padding(.vertical, 4)
                }

                Section("About") {
                    Text("SimEnclave injects a small interposer into a simulated app, catches its SecKey calls, and routes the Secure Enclave ones to your Mac's real SEP over an authenticated loopback channel. The app signs with genuine hardware P-256. No mock, no software key.")
                }

                Section("This example") {
                    Text("Native SwiftUI. The same console as the React Native example, reaching the same host Secure Enclave, so the bridge is framework-agnostic.")
                }

                Section {
                    LabeledContent("Built by", value: "Nirapod Labs")
                    LabeledContent("License", value: "Apache-2.0")
                    LabeledContent("Status", value: "Early")
                } footer: {
                    Text("© 2026 Nirapod Labs")
                }
            }
        }
        .presentationDetents([.medium, .large])
        .presentationDragIndicator(.visible)
    }
}
