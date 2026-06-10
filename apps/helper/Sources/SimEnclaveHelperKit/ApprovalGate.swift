// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 SimEnclave Contributors

import Foundation
import SimEnclaveHostCore

/// The in-session approval set behind the per-app prompt. A known app proceeds; a new app
/// prompts once through the approver and is remembered for the session; a denial does not
/// proceed.
///
/// This is a convenience, not an access boundary: the capability token is the boundary,
/// and the app id is guest-reported. The CLI helper installs no approver, so a request
/// there proceeds. Durable, cross-session approval is deferred past M3.
public final class ApprovalGate: @unchecked Sendable {
    private let approver: AppApprover
    private var approved: Set<String> = []
    private let lock = NSLock()

    /// Build the gate around the approver that presents the prompt.
    public init(approver: AppApprover) {
        self.approver = approver
    }

    /// Whether to proceed for this app id. A second, concurrent first-use of the same new
    /// app may prompt twice, which is a harmless convenience race, not a correctness or a
    /// security issue.
    func proceed(appID: String) -> Bool {
        lock.lock()
        let known = approved.contains(appID)
        lock.unlock()
        if known { return true }
        let allowed = approver.approve(appID: appID)
        if allowed {
            lock.lock()
            approved.insert(appID)
            lock.unlock()
        }
        return allowed
    }
}
