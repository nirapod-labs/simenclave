import XCTest

@testable import SimEnclaveProtocol

final class WireTests: XCTestCase {
    func testGenerateRequestRoundTrips() throws {
        let token = Data(repeating: 0xAB, count: 32)
        let payload = Wire.encode(.generate(keyClass: .silent), token: token)
        // A silent GENERATE is map(2) { 0: 2, 7: bstr(32) }, with no key 9.
        XCTAssertEqual(payload.prefix(6), Data([0xA2, 0x00, 0x02, 0x07, 0x58, 0x20]))
        XCTAssertEqual(try Wire.decodeRequest(payload), .generate(keyClass: .silent))
        XCTAssertEqual(try Wire.token(in: payload), token)
    }

    func testBiometryGenerateCarriesKeyClass() throws {
        let token = Data(repeating: 0xAB, count: 32)
        let payload = Wire.encode(.generate(keyClass: .biometry), token: token)
        // A biometry GENERATE is map(3) and ends with key 9 = 1.
        XCTAssertEqual(payload.prefix(3), Data([0xA3, 0x00, 0x02]))
        XCTAssertEqual(payload.suffix(2), Data([0x09, 0x01]))
        XCTAssertEqual(try Wire.decodeRequest(payload), .generate(keyClass: .biometry))
    }

    func testSignRequestRoundTrips() throws {
        let handle = Data((0 ..< 16).map { UInt8($0) })
        let digest = Data(repeating: 0x5A, count: 32)
        let token = Data(repeating: 0xCD, count: 32)
        let request = Request.sign(handle: handle, digest: digest)
        let payload = Wire.encode(request, token: token)
        XCTAssertEqual(try Wire.decodeRequest(payload), request)
        XCTAssertEqual(try Wire.token(in: payload), token)
    }

    func testGetPublicKeyAndDeleteRequestsRoundTrip() throws {
        let handle = Data(repeating: 0x11, count: 16)
        let token = Data(repeating: 0xAB, count: 32)
        for request in [Request.getPublicKey(handle: handle), .delete(handle: handle)] {
            let payload = Wire.encode(request, token: token)
            XCTAssertEqual(try Wire.decodeRequest(payload), request)
            XCTAssertEqual(try Wire.token(in: payload), token)
        }
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

    func testPublicKeyAndDeletedResponsesRoundTrip() throws {
        let publicKey = Data([0x04] + (0 ..< 64).map { UInt8($0) })
        for response in [Response.publicKey(publicKey), .deleted] {
            XCTAssertEqual(try Wire.decodeResponse(Wire.encode(response)), response)
        }
    }

    func testFailureResponseRoundTrips() throws {
        let response = Response.failure(code: -25293, message: "invalid capability token")
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
