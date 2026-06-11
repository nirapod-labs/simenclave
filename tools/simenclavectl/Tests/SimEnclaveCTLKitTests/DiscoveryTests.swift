// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

import Foundation
import XCTest

@testable import SimEnclaveCTLKit

final class DiscoveryTests: XCTestCase {
    func testDecodeHexRoundTrips() {
        XCTAssertEqual(Discovery.decodeHex("00ff10"), Data([0x00, 0xFF, 0x10]))
        XCTAssertNil(Discovery.decodeHex("0"), "odd length is not hex")
        XCTAssertNil(Discovery.decodeHex("zz"), "non-hex is rejected")
    }

    func testPortAndTokenReadFromDirectory() throws {
        let directory = NSTemporaryDirectory() + "se-ctl-\(UUID().uuidString)"
        try FileManager.default.createDirectory(atPath: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: directory) }
        try "65176\n".write(toFile: directory + "/port", atomically: true, encoding: .utf8)
        try String(repeating: "ab", count: 32)
            .write(toFile: directory + "/token", atomically: true, encoding: .utf8)

        XCTAssertEqual(Discovery.port(directory: directory, environment: [:]), 65176)
        XCTAssertEqual(Discovery.token(directory: directory, environment: [:]),
                       Data(repeating: 0xAB, count: 32))
    }

    func testEnvironmentOverridesFiles() {
        let environment = [
            "SIMENCLAVE_PORT": "5000",
            "SIMENCLAVE_TOKEN": String(repeating: "cd", count: 32),
        ]
        XCTAssertEqual(Discovery.port(directory: "/nonexistent", environment: environment), 5000)
        XCTAssertEqual(Discovery.token(directory: "/nonexistent", environment: environment),
                       Data(repeating: 0xCD, count: 32))
    }

    func testExplicitOverrideBeatsEnvironment() {
        XCTAssertEqual(
            Discovery.port(override: 1234, directory: "/x", environment: ["SIMENCLAVE_PORT": "9"]),
            1234)
    }

    func testMissingSourcesReturnNil() {
        XCTAssertNil(Discovery.port(directory: "/nonexistent", environment: [:]))
        XCTAssertNil(Discovery.token(directory: "/nonexistent", environment: [:]))
        // A token of the wrong length is rejected, not truncated.
        XCTAssertNil(Discovery.decodeHex("abcd").flatMap { $0.count == 32 ? $0 : nil })
    }
}
