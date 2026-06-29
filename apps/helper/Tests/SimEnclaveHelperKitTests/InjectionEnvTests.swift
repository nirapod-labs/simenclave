// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

import XCTest
@testable import SimEnclaveHelperKit

final class InjectionEnvTests: XCTestCase {
    let mine = "/tools/simenclave-interpose.dylib"
    let other = "/tools/simble-interpose.dylib"

    func testComposedAddsToEmpty() {
        XCTAssertEqual(InjectionEnv.composed(current: nil, adding: mine), mine)
        XCTAssertEqual(InjectionEnv.composed(current: "", adding: mine), mine)
    }

    func testComposedKeepsAnotherToolsEntry() {
        // The coexistence case: a peer (SimBLE) armed first; our arm must not drop it.
        XCTAssertEqual(InjectionEnv.composed(current: other, adding: mine), "\(other):\(mine)")
    }

    func testComposedIsIdempotent() {
        let once = InjectionEnv.composed(current: other, adding: mine)
        XCTAssertEqual(InjectionEnv.composed(current: once, adding: mine), once)
    }

    func testComposedDeduplicates() {
        XCTAssertEqual(
            InjectionEnv.composed(current: "\(mine):\(other):\(mine)", adding: mine),
            "\(other):\(mine)")
    }

    func testRemovedDropsOnlyOwnEntry() {
        XCTAssertEqual(InjectionEnv.removed(current: "\(other):\(mine)", removing: mine), other)
    }

    func testRemovedLeavesEmptyWhenSole() {
        XCTAssertEqual(InjectionEnv.removed(current: mine, removing: mine), "")
    }

    func testRemovedToleratesMissing() {
        XCTAssertEqual(InjectionEnv.removed(current: other, removing: mine), other)
        XCTAssertEqual(InjectionEnv.removed(current: nil, removing: mine), "")
    }
}
