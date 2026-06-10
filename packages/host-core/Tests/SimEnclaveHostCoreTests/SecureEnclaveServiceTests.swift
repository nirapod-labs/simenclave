import CryptoKit
import Foundation
import Security
import XCTest

@testable import SimEnclaveHostCore

/// These run only on a Mac with a real Secure Enclave (Apple Silicon or T2). On a
/// hosted CI VM with no SEP they skip, so the suite is green everywhere and
/// actually exercises hardware on a self-hosted runner or a developer Mac.
final class SecureEnclaveServiceTests: XCTestCase {
    func testGeneratedSignatureVerifiesUnderExportedKey() throws {
        let service = SecureEnclaveService()
        try XCTSkipUnless(service.isAvailable, "no Secure Enclave on this host")

        let (handle, x963) = try service.generate()
        XCTAssertEqual(x963.count, 65, "X9.63 uncompressed P-256 public key is 65 bytes")
        XCTAssertEqual(x963.first, 0x04, "X9.63 uncompressed lead byte")

        let digest = Data(SHA256.hash(data: Data("simenclave round-trip".utf8)))
        XCTAssertEqual(digest.count, 32)

        let signature = try service.sign(handle: handle, digest: digest)
        XCTAssertTrue(
            verifies(digest: digest, signature: signature, x963: x963),
            "the DER signature must verify under the exported public key, digest mode"
        )
    }

    func testPublicKeyIsStableForAHandle() throws {
        let service = SecureEnclaveService()
        try XCTSkipUnless(service.isAvailable, "no Secure Enclave on this host")

        let (handle, x963) = try service.generate()
        XCTAssertEqual(try service.publicKey(for: handle), x963)
    }

    func testUnknownHandleIsRejected() throws {
        let service = SecureEnclaveService()
        try XCTSkipUnless(service.isAvailable, "no Secure Enclave on this host")

        XCTAssertThrowsError(
            try service.sign(handle: Data([0, 1, 2, 3]), digest: Data(repeating: 0, count: 32))
        ) { error in
            XCTAssertEqual(error as? SecureEnclaveService.Failure, .unknownHandle)
        }
    }

    /// Verify a DER ECDSA signature over a digest using the public key the service
    /// exported, through the same Security-framework verify path a device uses.
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
