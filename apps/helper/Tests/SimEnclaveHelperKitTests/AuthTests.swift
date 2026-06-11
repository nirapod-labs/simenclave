// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

import XCTest

@testable import SimEnclaveHelperKit

final class AuthTests: XCTestCase {
    // MARK: token

    func testMintIs32Bytes() {
        XCTAssertEqual(CapabilityToken().bytes.count, 32)
    }

    func testTwoMintsDiffer() {
        XCTAssertNotEqual(CapabilityToken().bytes, CapabilityToken().bytes)
    }

    func testHexRoundTrips() {
        let token = CapabilityToken()
        XCTAssertEqual(token.hex.count, 64)
        XCTAssertEqual(CapabilityToken(hex: token.hex), token)
    }

    func testHexRejectsBadInput() {
        XCTAssertNil(CapabilityToken(hex: "xyz"))
        XCTAssertNil(CapabilityToken(hex: String(repeating: "0", count: 63)))
        XCTAssertNil(CapabilityToken(hex: String(repeating: "g", count: 64)))
    }

    func testBytesRejectsWrongLength() {
        XCTAssertNil(CapabilityToken(bytes: Data(repeating: 0, count: 31)))
    }

    // MARK: gate

    func testGateAcceptsSameRejectsDifferent() {
        let token = CapabilityToken()
        let gate = AuthGate(session: token)
        XCTAssertTrue(gate.accepts(CapabilityToken(bytes: token.bytes)!))
        var flipped = Data(token.bytes)
        flipped[flipped.startIndex] ^= 0x01
        XCTAssertFalse(gate.accepts(CapabilityToken(bytes: flipped)!))
        var lastFlipped = Data(token.bytes)
        lastFlipped[lastFlipped.index(before: lastFlipped.endIndex)] ^= 0x80
        XCTAssertFalse(gate.accepts(CapabilityToken(bytes: lastFlipped)!))
    }

    // MARK: file

    func testFileWriteThenReadRoundTrips() throws {
        let dir = tempDir()
        defer { try? FileManager.default.removeItem(atPath: dir) }
        let token = CapabilityToken()
        let written = try TokenFile.write(token, toDirectory: dir)
        XCTAssertEqual(TokenFile.path(inDirectory: dir), written)
        XCTAssertEqual(try TokenFile.read(fromDirectory: dir), token)
    }

    func testFileIsOwnerOnly() throws {
        let dir = tempDir()
        defer { try? FileManager.default.removeItem(atPath: dir) }
        let written = try TokenFile.write(CapabilityToken(), toDirectory: dir)
        let mode = try FileManager.default.attributesOfItem(atPath: written)[.posixPermissions] as? Int
        XCTAssertEqual(mode, 0o600)
    }

    func testSecondWriteRefusesRatherThanTruncate() throws {
        let dir = tempDir()
        defer { try? FileManager.default.removeItem(atPath: dir) }
        try TokenFile.write(CapabilityToken(), toDirectory: dir)
        XCTAssertThrowsError(try TokenFile.write(CapabilityToken(), toDirectory: dir)) { error in
            guard case TokenFile.TokenFileError.alreadyExists = error else {
                return XCTFail("expected alreadyExists, got \(error)")
            }
        }
    }

    func testRejectsWorldWritableDirectory() throws {
        let dir = tempDir()
        defer { try? FileManager.default.removeItem(atPath: dir) }
        try FileManager.default.createDirectory(
            atPath: dir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o777])
        XCTAssertThrowsError(try TokenFile.write(CapabilityToken(), toDirectory: dir)) { error in
            guard case TokenFile.TokenFileError.directoryUnsafe = error else {
                return XCTFail("expected directoryUnsafe, got \(error)")
            }
        }
    }

    func testRejectsSymlinkDirectory() throws {
        let base = tempDir()
        defer { try? FileManager.default.removeItem(atPath: base) }
        let real = base + "/real"
        let link = base + "/link"
        try FileManager.default.createDirectory(atPath: real, withIntermediateDirectories: true)
        try FileManager.default.createSymbolicLink(atPath: link, withDestinationPath: real)
        XCTAssertThrowsError(try TokenFile.write(CapabilityToken(), toDirectory: link)) { error in
            guard case TokenFile.TokenFileError.directoryUnsafe = error else {
                return XCTFail("expected directoryUnsafe, got \(error)")
            }
        }
    }

    private func tempDir() -> String {
        NSTemporaryDirectory() + "simenclave-test-" + UUID().uuidString
    }
}
