// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

import XCTest

@testable import SimEnclaveCTLKit

final class JSONValueTests: XCTestCase {
    func testObjectKeepsKeyOrderAndTypes() {
        let value = JSONValue.object([
            ("port", .int(65176)),
            ("token_found", .bool(true)),
            ("version", .null),
            ("name", .string("SE")),
        ])
        XCTAssertEqual(
            value.encoded(),
            #"{"port": 65176, "token_found": true, "version": null, "name": "SE"}"#)
    }

    func testStringEscaping() {
        XCTAssertEqual(JSONValue.string("a\"b\\c\nd").encoded(), #""a\"b\\c\nd""#)
    }

    func testArrayEncodesNestedValues() {
        let value = JSONValue.object([
            ("count", .int(2)),
            ("keys", .array([.string("a"), .object([("handle", .string("b"))])])),
        ])
        XCTAssertEqual(value.encoded(), #"{"count": 2, "keys": ["a", {"handle": "b"}]}"#)
    }

    func testControlCharactersAreUnicodeEscaped() {
        // A raw control character must come back as a \u00XX escape, never literal.
        let encoded = JSONValue.string("\u{01}").encoded()
        XCTAssertTrue(encoded.hasPrefix("\"\\u00"), "got \(encoded)")
        XCTAssertEqual(encoded.count, 8)
    }
}
