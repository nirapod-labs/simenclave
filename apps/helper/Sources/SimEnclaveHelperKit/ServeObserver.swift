// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

import Foundation

/// Sees each request the router serves, reported after the op is handled. The menubar uses it
/// to show live activity. It is called from connection threads, possibly several at once, so an
/// implementation must be thread-safe. It receives the op name, the guest-reported app id, the
/// guest-reported display name and icon (both sanitized and validated by the router), and the key
/// handle the op created or removed (the minted handle on a GENERATE, the deleted handle on a
/// DELETE, else nil), which lets the UI keep a live per-app key count. It never receives the token
/// or any key material.
public protocol ServeObserver: Sendable {
    func served(op: String, appID: String?, displayName: String?, iconPNG: Data?, handle: Data?)
}
