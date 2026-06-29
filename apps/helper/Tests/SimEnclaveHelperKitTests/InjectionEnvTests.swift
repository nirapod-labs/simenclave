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

    func testRemovedMatchesByFileNameAfterPathMoved() {
        // The stale-entry case: armed at one path, the slice has since moved; matching on the
        // file name still strips our entry.
        let moved = "/old/build/simenclave-interpose.dylib"
        XCTAssertEqual(InjectionEnv.removed(current: moved, removing: mine), "")
        XCTAssertEqual(InjectionEnv.removed(current: "\(other):\(moved)", removing: mine), other)
    }

    func testRemovedByBareCanonicalName() {
        // Teardown passes the platform's canonical slice name, no resolved path, and still removes
        // our entry: the locator-independent disarm path.
        let name = "simenclave-interpose.dylib"
        XCTAssertEqual(InjectionEnv.removed(current: mine, removing: name), "")
        XCTAssertEqual(InjectionEnv.removed(current: "\(other):\(mine)", removing: name), other)
    }

    func testComposedReplacesMovedEntry() {
        // Re-arming after the slice relocated replaces the stale-path entry instead of
        // doubling ours.
        let moved = "/old/build/simenclave-interpose.dylib"
        XCTAssertEqual(InjectionEnv.composed(current: moved, adding: mine), mine)
        XCTAssertEqual(
            InjectionEnv.composed(current: "\(other):\(moved)", adding: mine),
            "\(other):\(mine)")
    }
}
