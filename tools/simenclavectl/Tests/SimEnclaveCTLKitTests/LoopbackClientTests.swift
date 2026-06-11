// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

import Foundation
import SimEnclaveProtocol
import XCTest

@testable import SimEnclaveCTLKit

final class LoopbackClientTests: XCTestCase {
    func testConnectionRefusedOnDeadPort() {
        // Nothing listens on loopback port 1; the client must fail fast as refused
        // rather than hang or surface a generic error, so `doctor` can report it.
        let client = LoopbackClient(port: 1, token: Data(repeating: 0, count: 32), timeout: 2)
        XCTAssertThrowsError(try client.send(.hello(version: Wire.version1))) { error in
            XCTAssertEqual(error as? LoopbackClient.ClientError, .connectionRefused)
        }
    }
}
