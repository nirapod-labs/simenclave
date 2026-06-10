// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 SimEnclave Contributors

import XCTest

@testable import SimEnclaveProtocol

final class CBORTests: XCTestCase {
    func testUintShortestForm() {
        XCTAssertEqual(write { $0.uint(0) }, Data([0x00]))
        XCTAssertEqual(write { $0.uint(23) }, Data([0x17]))
        XCTAssertEqual(write { $0.uint(24) }, Data([0x18, 0x18]))
        XCTAssertEqual(write { $0.uint(255) }, Data([0x18, 0xFF]))
        XCTAssertEqual(write { $0.uint(256) }, Data([0x19, 0x01, 0x00]))
        XCTAssertEqual(write { $0.uint(0x1_0000) }, Data([0x1A, 0x00, 0x01, 0x00, 0x00]))
    }

    func testByteAndTextHeaders() {
        XCTAssertEqual(write { $0.bytes(Data([0xAA, 0xBB])) }, Data([0x42, 0xAA, 0xBB]))
        XCTAssertEqual(write { $0.text("ok") }, Data([0x62, 0x6F, 0x6B]))
    }

    func testMapRoundTripsAndIsOrderIndependentToRead() throws {
        var writer = CBORWriter()
        writer.mapHeader(2)
        writer.uint(0); writer.uint(4)
        writer.uint(2); writer.bytes(Data([1, 2, 3]))
        let map = try CBORMap(decoding: writer.data)
        XCTAssertEqual(try map.uint(0), 4)
        XCTAssertEqual(try map.bytes(2), Data([1, 2, 3]))
    }

    func testTruncatedByteStringThrows() {
        // bstr of length 4, but only two bytes follow.
        XCTAssertThrowsError(try CBORMap(decoding: Data([0xA1, 0x00, 0x44, 0x01, 0x02]))) { error in
            XCTAssertEqual(error as? ProtocolError, .truncated)
        }
    }

    func testTypeMismatchOnWrongAccessor() throws {
        var writer = CBORWriter()
        writer.mapHeader(1)
        writer.uint(0); writer.uint(2)
        let map = try CBORMap(decoding: writer.data)
        XCTAssertThrowsError(try map.bytes(0)) { error in
            XCTAssertEqual(error as? ProtocolError, .missingField(0))
        }
    }

    func testRejectsDuplicateKey() {
        // map(2) { 0: 2, 0: 3 } repeats key 0.
        XCTAssertThrowsError(try CBORMap(decoding: Data([0xA2, 0x00, 0x02, 0x00, 0x03]))) { error in
            XCTAssertEqual(error as? ProtocolError, .duplicateKey(0))
        }
    }

    func testRejectsNonCanonicalInteger() {
        // value 5 in the 1-byte form (0x18 0x05) instead of inline.
        XCTAssertThrowsError(try CBORMap(decoding: Data([0xA1, 0x00, 0x18, 0x05]))) { error in
            XCTAssertEqual(error as? ProtocolError, .nonCanonical)
        }
    }

    func testRejectsTrailingBytes() {
        // map(1) { 0: 2 } followed by a stray byte.
        XCTAssertThrowsError(try CBORMap(decoding: Data([0xA1, 0x00, 0x02, 0xFF]))) { error in
            XCTAssertEqual(error as? ProtocolError, .trailingBytes)
        }
    }

    // The pre-auth crash class from the M4 security review: a hostile 64-bit
    // length or count argument must throw, never trap, because the decoder runs
    // on unauthenticated bytes before the token gate.

    func testHostileByteLengthThrowsInsteadOfTrapping() {
        // map(1) { 7: bytes(len 2^64 - 1) }: head 0x5B then eight 0xFF.
        let payload = Data([0xA1, 0x07, 0x5B] + [UInt8](repeating: 0xFF, count: 8))
        XCTAssertThrowsError(try CBORMap(decoding: payload)) { error in
            XCTAssertEqual(error as? ProtocolError, .truncated)
        }
        // The Int.max edge: the checked offset + count addition must not trap either.
        let intMax = Data([0xA1, 0x07, 0x5B, 0x7F] + [UInt8](repeating: 0xFF, count: 7))
        XCTAssertThrowsError(try CBORMap(decoding: intMax)) { error in
            XCTAssertEqual(error as? ProtocolError, .truncated)
        }
    }

    func testHostileMapCountThrowsInsteadOfTrapping() {
        // map(2^64 - 1): head 0xBB then eight 0xFF.
        let payload = Data([0xBB] + [UInt8](repeating: 0xFF, count: 8))
        XCTAssertThrowsError(try CBORMap(decoding: payload)) { error in
            XCTAssertEqual(error as? ProtocolError, .truncated)
        }
    }

    func testHostileIntegerOutsideInt64Throws() throws {
        // map(1) { 10: uint(2^64 - 1) }: above Int64.max, must throw, not trap.
        let big = try CBORMap(decoding: Data([0xA1, 0x0A, 0x1B] + [UInt8](repeating: 0xFF, count: 8)))
        XCTAssertThrowsError(try big.int(10)) { error in
            XCTAssertEqual(error as? ProtocolError, .malformed)
        }
        // map(1) { 10: negint(argument 2^64 - 1) }: encodes -2^64, below Int64.min.
        let bigNeg = try CBORMap(decoding: Data([0xA1, 0x0A, 0x3B] + [UInt8](repeating: 0xFF, count: 8)))
        XCTAssertThrowsError(try bigNeg.int(10)) { error in
            XCTAssertEqual(error as? ProtocolError, .malformed)
        }
    }

    private func write(_ body: (inout CBORWriter) -> Void) -> Data {
        var writer = CBORWriter()
        body(&writer)
        return writer.data
    }
}
