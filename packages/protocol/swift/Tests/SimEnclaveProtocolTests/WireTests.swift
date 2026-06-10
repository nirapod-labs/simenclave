import XCTest

@testable import SimEnclaveProtocol

final class WireTests: XCTestCase {
    func testGenerateRequestRoundTrips() throws {
        let payload = Wire.encode(.generate)
        XCTAssertEqual(payload, Data([0xA1, 0x00, 0x02]))
        XCTAssertEqual(try Wire.decodeRequest(payload), .generate)
    }

    func testSignRequestRoundTrips() throws {
        let handle = Data((0 ..< 16).map { UInt8($0) })
        let digest = Data(repeating: 0x5A, count: 32)
        let request = Request.sign(handle: handle, digest: digest)
        XCTAssertEqual(try Wire.decodeRequest(Wire.encode(request)), request)
    }

    func testGeneratedResponseRoundTrips() throws {
        let handle = Data(repeating: 0xAB, count: 16)
        let publicKey = Data([0x04] + (0 ..< 64).map { UInt8($0) })
        let response = Response.generated(handle: handle, publicKey: publicKey)
        XCTAssertEqual(try Wire.decodeResponse(Wire.encode(response)), response)
    }

    func testSignedResponseRoundTrips() throws {
        let response = Response.signed(signature: Data(repeating: 0x30, count: 71))
        XCTAssertEqual(try Wire.decodeResponse(Wire.encode(response)), response)
    }

    func testFailureResponseRoundTrips() throws {
        let response = Response.failure("no secure enclave on this host")
        XCTAssertEqual(try Wire.decodeResponse(Wire.encode(response)), response)
    }

    func testUnknownOpcodeRejected() {
        // A map { 0: 9 } with op = 9.
        XCTAssertThrowsError(try Wire.decodeRequest(Data([0xA1, 0x00, 0x09]))) { error in
            XCTAssertEqual(error as? ProtocolError, .badOpcode(9))
        }
    }

    func testFrameCarriesBigEndianLength() {
        let framed = Framing.frame(Data([0xDE, 0xAD, 0xBE, 0xEF]))
        XCTAssertEqual(framed, Data([0, 0, 0, 4, 0xDE, 0xAD, 0xBE, 0xEF]))
    }

    func testPayloadLengthParses() throws {
        XCTAssertEqual(try Framing.payloadLength(Data([0, 0, 1, 0])), 256)
    }

    func testOversizeFrameRejected() {
        let tooBig = Data([0x00, 0x20, 0x00, 0x01]) // 0x200001 > 1 MiB
        XCTAssertThrowsError(try Framing.payloadLength(tooBig)) { error in
            XCTAssertEqual(error as? ProtocolError, .frameTooLarge(0x20_0001))
        }
    }
}
