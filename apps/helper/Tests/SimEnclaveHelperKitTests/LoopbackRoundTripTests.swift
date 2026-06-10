import CryptoKit
import Foundation
import Security
import XCTest

import SimEnclaveHostCore
import SimEnclaveProtocol
@testable import SimEnclaveHelperKit

// Mechanism B, now authenticated. The protocol, the loopback transport, the
// capability token, and the host SEP, proven together on one machine with no
// simulator: present the token, generate, sign, verify, and reject a wrong token.
final class LoopbackRoundTripTests: XCTestCase {
    func testGenerateThenSignOverLoopbackVerifies() throws {
        let service = SecureEnclaveService()
        try XCTSkipUnless(service.isAvailable, "no Secure Enclave on this host")

        let token = CapabilityToken()
        let listener = LoopbackListener(router: RequestRouter(service: service, gate: AuthGate(session: token)))
        try listener.start()
        defer { listener.stop() }
        XCTAssertGreaterThan(listener.port, 0)

        let client = LoopbackClient(port: listener.port)

        guard case let .generated(handle, x963) = try client.send(.generate, token: token) else {
            return XCTFail("expected a generated response")
        }
        XCTAssertEqual(x963.count, 65)
        XCTAssertEqual(x963.first, 0x04)

        let digest = Data(SHA256.hash(data: Data("loopback mechanism B".utf8)))
        let signResponse = try client.send(.sign(handle: handle, digest: digest), token: token)
        guard case let .signed(signature) = signResponse else {
            return XCTFail("expected a signed response")
        }

        XCTAssertTrue(
            verifies(digest: digest, signature: signature, x963: x963),
            "a loopback signature must verify under the host public key"
        )
    }

    func testWrongTokenIsRejected() throws {
        // No SEP needed: the gate rejects before the service is ever touched.
        let token = CapabilityToken()
        let listener = LoopbackListener(
            router: RequestRouter(service: SecureEnclaveService(), gate: AuthGate(session: token)))
        try listener.start()
        defer { listener.stop() }

        let client = LoopbackClient(port: listener.port)
        guard case let .failure(code, _) = try client.send(.generate, token: CapabilityToken()) else {
            return XCTFail("a wrong token must come back as a failure")
        }
        XCTAssertEqual(code, -25293) // errSecAuthFailed
    }

    func testSignWithUnknownHandleReturnsFailure() throws {
        let service = SecureEnclaveService()
        try XCTSkipUnless(service.isAvailable, "no Secure Enclave on this host")

        let token = CapabilityToken()
        let listener = LoopbackListener(router: RequestRouter(service: service, gate: AuthGate(session: token)))
        try listener.start()
        defer { listener.stop() }

        let client = LoopbackClient(port: listener.port)
        let response = try client.send(
            .sign(handle: Data([9, 9, 9, 9]), digest: Data(repeating: 0, count: 32)), token: token)
        guard case .failure = response else {
            return XCTFail("an unknown handle must come back as a failure response")
        }
    }

    private func verifies(digest: Data, signature: Data, x963: Data) -> Bool {
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
            kSecAttrKeySizeInBits as String: 256,
        ]
        var error: Unmanaged<CFError>?
        guard let publicKey = SecKeyCreateWithData(x963 as CFData, attributes as CFDictionary, &error) else {
            return false
        }
        return SecKeyVerifySignature(
            publicKey,
            .ecdsaSignatureDigestX962SHA256,
            digest as CFData,
            signature as CFData,
            &error
        )
    }
}
