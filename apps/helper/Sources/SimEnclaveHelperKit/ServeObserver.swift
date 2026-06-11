// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

import Foundation

/// Sees each request the router serves, after the token gate passes. The menubar uses it
/// to show live activity. It is called from connection threads, possibly several at once,
/// so an implementation must be thread-safe. It receives the op name, the guest-reported app
/// id, and the guest-reported display name (sanitized by the router), never the token or any
/// key bytes.
public protocol ServeObserver: Sendable {
    func served(op: String, appID: String?, displayName: String?)
}
