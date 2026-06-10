import CryptoKit
import Foundation
import Security
import XCTest

import SimEnclaveHostCore
import SimEnclaveProtocol
@testable import SimEnclaveHelperKit

// Mechanism B. The protocol, the loopback transport, and the host SEP, proven
// together on one machine with no simulator: connect, generate, sign, verify.
final class LoopbackRoundTripTests: XCTestCase {
    func testGenerateThenSignOverLoopbackVerifies() throws {
        let service = SecureEnclaveService()
        try XCTSkipUnless(service.isAvailable, "no Secure Enclave on this host")

        let listener = LoopbackListener(router: RequestRouter(service: service))
        try listener.start()
        defer { listener.stop() }
        XCTAssertGreaterThan(listener.port, 0)

        let client = LoopbackClient(port: listener.port)

        guard case let .generated(handle, x963) = try client.send(.generate) else {
            return XCTFail("expected a generated response")
        }
        XCTAssertEqual(x963.count, 65)
        XCTAssertEqual(x963.first, 0x04)

        let digest = Data(SHA256.hash(data: Data("loopback mechanism B".utf8)))
        guard case let .signed(signature) = try client.send(.sign(handle: handle, digest: digest)) else {
            return XCTFail("expected a signed response")
        }

        XCTAssertTrue(
            verifies(digest: digest, signature: signature, x963: x963),
            "a loopback signature must verify under the host public key"
        )
    }

    func testSignWithUnknownHandleReturnsFailure() throws {
        let service = SecureEnclaveService()
        try XCTSkipUnless(service.isAvailable, "no Secure Enclave on this host")

        let listener = LoopbackListener(router: RequestRouter(service: service))
        try listener.start()
        defer { listener.stop() }

        let client = LoopbackClient(port: listener.port)
        let response = try client.send(.sign(handle: Data([9, 9, 9, 9]), digest: Data(repeating: 0, count: 32)))
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
