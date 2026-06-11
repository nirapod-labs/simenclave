// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

import SwiftUI

/// The SimEnclave wordmark, drawn as live text in the brand face.
///
/// "Sim" is set in DM Sans Medium in the muted grey, "Enclave" in DM Sans Bold
/// in the ink colour, on one baseline with the brand's negative tracking. Both
/// colours track the light and dark appearance.
///
/// DM Sans ships in the packaged app's `Resources` and is registered at launch
/// through `ATSApplicationFontsPath` (see `scripts/build-menubar-app.sh`).
/// Outside that bundle, for example under `swift run`, the custom face is not
/// registered and `Font.custom` falls back to the system font, so the wordmark
/// still renders, just not in DM Sans.
struct SimEnclaveWordmark: View {
    /// Point size of the wordmark. The brand minimum is 13; below that the mark
    /// alone should be used instead.
    var size: CGFloat = 17

    @Environment(\.colorScheme) private var scheme

    /// The "Sim" grey: `#86868B` in light, `#8E95A3` in dark.
    private var simColor: Color {
        scheme == .dark
            ? Color(red: 0.557, green: 0.584, blue: 0.639)
            : Color(red: 0.525, green: 0.525, blue: 0.545)
    }

    /// The "Enclave" ink: `#1D1D1F` in light, `#F5F5F7` in dark.
    private var inkColor: Color {
        scheme == .dark
            ? Color(red: 0.961, green: 0.961, blue: 0.969)
            : Color(red: 0.114, green: 0.114, blue: 0.122)
    }

    var body: some View {
        (
            Text("Sim")
                .font(.custom("DMSans-Medium", size: size))
                .foregroundColor(simColor)
                + Text("Enclave")
                .font(.custom("DMSans-Bold", size: size))
                .foregroundColor(inkColor)
        )
        // The brand tracking is -0.035em, applied in points to both parts.
        .tracking(-0.035 * size)
        .fixedSize()
        .accessibilityLabel("SimEnclave")
    }
}
