// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

import SimEnclaveProtocol
import XCTest

@testable import SimEnclaveHelperKit

/// The guest-reported display name is hostile input. These pin the router's sanitizer, the only
/// security boundary the apps-list identity feature has, so a refactor cannot silently weaken it.
final class IdentityValidationTests: XCTestCase {
    func testDisplayNameStripsControlAndFormatChars() {
        // A newline, the RTL override, and an escape must not reach the UI.
        XCTAssertEqual(RequestRouter.sanitizedDisplayName("My\u{0A}App\u{202E}\u{1B}"), "MyApp")
    }

    func testDisplayNameClampsZalgo() {
        // One base char with 5000 combining marks is a single grapheme but 5001 scalars; the
        // scalar clamp must bound it regardless of how it clusters.
        let zalgo = "a" + String(repeating: "\u{0301}", count: 5000)
        let result = RequestRouter.sanitizedDisplayName(zalgo)
        XCTAssertNotNil(result)
        XCTAssertLessThanOrEqual(result!.unicodeScalars.count, Wire.maxAppDisplayNameScalars + 1)
    }

    func testDisplayNameEmptyOrAllControlIsNil() {
        XCTAssertNil(RequestRouter.sanitizedDisplayName(nil))
        XCTAssertNil(RequestRouter.sanitizedDisplayName(""))
        XCTAssertNil(RequestRouter.sanitizedDisplayName("   "))
        XCTAssertNil(RequestRouter.sanitizedDisplayName("\u{0A}\u{202E}"))
    }

    func testDisplayNameOrdinaryNamePassesThrough() {
        XCTAssertEqual(RequestRouter.sanitizedDisplayName("SimEnclave RN"), "SimEnclave RN")
    }
}
