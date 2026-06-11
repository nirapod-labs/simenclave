// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

import Foundation
import XCTest

import SimEnclaveHostCore
import SimEnclaveProtocol
@testable import SimEnclaveHelperKit

/// The router is the helper's front door for hostile bytes from an injected app.
/// Whatever arrives, it must answer with a failure Response and never crash. None
/// of these reach the Secure Enclave, so they run without one.
final class RouterRobustnessTests: XCTestCase {
    func testHostilePayloadsYieldFailuresNotCrashes() {
        let router = RequestRouter(
            service: SecureEnclaveService(), gate: AuthGate(session: CapabilityToken()))
        let hostile: [(String, Data)] = [
            ("empty", Data()),
            ("not cbor", Data([0xFF, 0xFF, 0xFF, 0xFF])),
            ("truncated map", Data([0xA1, 0x00])),
            ("text-header run", Data(repeating: 0x61, count: 64)),
        ]
        for (name, payload) in hostile {
            guard case .failure = router.respond(toPayload: payload) else {
                return XCTFail("hostile payload '\(name)' must yield a failure")
            }
        }
    }

    func testValidTokenWithUnknownOpFailsCleanly() {
        // The right token but op 99: it passes the gate, then the decoder rejects the
        // op, so the helper returns a failure rather than crashing or misdispatching.
        let session = CapabilityToken()
        let router = RequestRouter(service: SecureEnclaveService(), gate: AuthGate(session: session))
        // { 0: 99, 7: <32-byte token> } in canonical CBOR.
        var payload = Data([0xA2, 0x00, 0x18, 0x63, 0x07, 0x58, 0x20])
        payload.append(session.bytes)
        guard case let .failure(code, _, _) = router.respond(toPayload: payload) else {
            return XCTFail("an unknown op must come back as a failure")
        }
        XCTAssertEqual(code, OSStatusCode.internalError)
    }
}
