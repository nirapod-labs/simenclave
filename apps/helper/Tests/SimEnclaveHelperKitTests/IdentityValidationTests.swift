// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

import AppKit
import SimEnclaveProtocol
import XCTest

@testable import SimEnclaveHelperKit

/// The guest-reported display name and icon are hostile input. These pin the router's two
/// validators, the only security boundary the apps-list identity feature has, so a refactor
/// cannot silently weaken them.
final class IdentityValidationTests: XCTestCase {
    // MARK: display name

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

    // MARK: icon

    func testValidPNGIconAccepted() {
        let png = Self.png(width: 64, height: 64)
        XCTAssertEqual(RequestRouter.validatedIcon(png), png)
    }

    func testNonPNGIconRejected() {
        XCTAssertNil(RequestRouter.validatedIcon(Self.jpeg(width: 64, height: 64)))
        XCTAssertNil(RequestRouter.validatedIcon(Data([0x00, 0x01, 0x02, 0x03])))
        XCTAssertNil(RequestRouter.validatedIcon(Data()))
        XCTAssertNil(RequestRouter.validatedIcon(nil))
    }

    func testOversizedDimensionsRejected() {
        // A valid PNG, but larger than the 256px cap: a decompression-bomb guard.
        XCTAssertNil(RequestRouter.validatedIcon(Self.png(width: 257, height: 257)))
    }

    func testOversizedBytesRejected() {
        // Past the byte cap, rejected before any decode.
        XCTAssertNil(
            RequestRouter.validatedIcon(Data(repeating: 0, count: Wire.maxAppIconBytes + 1)))
    }

    // MARK: fixtures

    private static func png(width: Int, height: Int) -> Data {
        bitmap(width: width, height: height).representation(using: .png, properties: [:])!
    }

    private static func jpeg(width: Int, height: Int) -> Data {
        bitmap(width: width, height: height).representation(using: .jpeg, properties: [:])!
    }

    private static func bitmap(width: Int, height: Int) -> NSBitmapImageRep {
        let rep = NSBitmapImageRep(
            bitmapDataPlanes: nil, pixelsWide: width, pixelsHigh: height, bitsPerSample: 8,
            samplesPerPixel: 4, hasAlpha: true, isPlanar: false, colorSpaceName: .deviceRGB,
            bytesPerRow: 0, bitsPerPixel: 0)!
        NSGraphicsContext.saveGraphicsState()
        NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: rep)
        NSColor.systemBlue.setFill()
        NSRect(x: 0, y: 0, width: width, height: height).fill()
        NSGraphicsContext.restoreGraphicsState()
        return rep
    }
}
