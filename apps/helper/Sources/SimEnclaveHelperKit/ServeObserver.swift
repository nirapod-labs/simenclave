// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 SimEnclave Contributors

import Foundation

/// Sees each request the router serves, after the token gate passes. The menubar uses it
/// to show live activity. It is called from connection threads, possibly several at once,
/// so an implementation must be thread-safe. It receives only the op name and the
/// guest-reported app id, never the token or any key bytes.
public protocol ServeObserver: Sendable {
    func served(op: String, appID: String?)
}
