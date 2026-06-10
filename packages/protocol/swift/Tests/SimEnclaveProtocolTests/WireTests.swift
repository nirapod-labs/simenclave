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

    func testGenerateWithAccessControlRoundTrips() throws {
        let token = Data(repeating: 0xAB, count: 32)
        let ac = AccessControl(flags: 5, protection: "ak")
        let request = Request.generate(keyClass: .biometry, accessControl: ac)
        let payload = Wire.encode(request, token: token)
        // map(5) { 0:2, 7:token, 9:1, 11:flags, 12:protection }, ending 0B 05 0C 62 'a' 'k'.
        XCTAssertEqual(payload.first, 0xA5)
        XCTAssertEqual(payload.suffix(6), Data([0x0B, 0x05, 0x0C, 0x62, 0x61, 0x6B]))
        XCTAssertEqual(try Wire.decodeRequest(payload), request)
        // A silent key with an access control omits key 9: map(4).
        let silent = Request.generate(keyClass: .silent, accessControl: ac)
        XCTAssertEqual(Wire.encode(silent, token: token).first, 0xA4)
        XCTAssertEqual(try Wire.decodeRequest(Wire.encode(silent, token: token)), silent)
    }

    func testGenerateCarriesAppID() throws {
        let token = Data(repeating: 0xAB, count: 32)
        let payload = Wire.encode(.generate(keyClass: .silent), token: token, appID: "hi")
        // map(3) { 0:2, 7:token, 14:"hi" }, ending 0E 62 'h' 'i'.
        XCTAssertEqual(payload.first, 0xA3)
        XCTAssertEqual(payload.suffix(4), Data([0x0E, 0x62, 0x68, 0x69]))
        XCTAssertEqual(Wire.appID(in: payload), "hi")
        // No app id keeps the bare bytes and a nil app id.
        let bare = Wire.encode(.generate(keyClass: .silent), token: token)
        XCTAssertEqual(bare.first, 0xA2)
        XCTAssertNil(Wire.appID(in: bare))
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

    func testFindByTagRequestRoundTrips() throws {
        let token = Data(repeating: 0xAB, count: 32)
        let appTag = Data("app.example.key".utf8)
        let udid = "11111111-2222-3333-4444-555555555555"
        let request = Request.findByTag(appTag: appTag, udid: udid)
        let payload = Wire.encode(request, token: token)
        // map(4) { 0: 6, 7: token, 15: udid, 16: appTag }, keys ascending.
        XCTAssertEqual(payload.prefix(3), Data([0xA4, 0x00, 0x06]))
        XCTAssertEqual(try Wire.decodeRequest(payload), request)
        XCTAssertEqual(try Wire.token(in: payload), token)
    }

    func testFoundResponseRoundTrips() throws {
        let handle = Data(repeating: 0xCD, count: 16)
        let publicKey = Data([0x04] + (0 ..< 64).map { UInt8($0) })
        let response = Response.found(handle: handle, publicKey: publicKey)
        // A found response echoes op 6, so it is distinct from a generated response.
        XCTAssertEqual(Wire.encode(response).prefix(3), Data([0xA4, 0x00, 0x06]))
        XCTAssertEqual(try Wire.decodeResponse(Wire.encode(response)), response)
    }

    func testFailureCarriesErrorDomain() throws {
        // The OSStatus domain is the default and omits key 13: a 4-entry map, the
        // same bytes as before M3.
        let osStatus = Response.failure(code: -25293, message: "auth")
        XCTAssertEqual(Wire.encode(osStatus).first, 0xA4)
        XCTAssertEqual(try Wire.decodeResponse(Wire.encode(osStatus)), osStatus)
        // A LocalAuthentication-domain failure adds key 13: a 5-entry map that round-trips.
        let laError = Response.failure(code: -2, message: "cancelled", domain: Wire.domainLAError)
        XCTAssertEqual(Wire.encode(laError).first, 0xA5)
        XCTAssertEqual(try Wire.decodeResponse(Wire.encode(laError)), laError)
        XCTAssertNotEqual(osStatus, laError)
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
