import CryptoKit
import Foundation
import Security
import XCTest

@testable import SimEnclaveHostCore

/// The host half of the M4 parity gate: a SimEnclave signature must be accepted by any
/// P-256 verifier exactly as a device signature is. Every other test in the suite
/// verifies through `SecKeyVerifySignature`, the same framework that produced the
/// signature, so it cannot catch a defect the framework is symmetric about. CryptoKit is
/// an independent implementation with its own DER parser and its own verify path, which
/// makes it the second, disagreeing-by-construction verifier parity needs.
///
/// The device half, the same assertions run against a signature captured on real
/// hardware, is the docs/parity.md capture run and cannot execute here.
final class ParityTests: XCTestCase {
    /// The service signs in digest mode, exactly as a device's
    /// `kSecKeyAlgorithmECDSASignatureDigestX962SHA256` does, so a signature over
    /// SHA256(m) must verify under a verifier that hashes m itself. CryptoKit's
    /// `isValidSignature(_:for:)` recomputes SHA-256 over the message, so a pass proves
    /// three things at once: the DER parses under an independent parser, the digest the
    /// helper signed is the digest a verifier derives, and the curve math agrees.
    func testSignatureVerifiesUnderCryptoKit() throws {
        let service = SecureEnclaveService()
        try XCTSkipUnless(service.isAvailable, "no Secure Enclave on this host")

        let message = Data("simenclave parity: cross-verifier".utf8)
        let digest = Data(SHA256.hash(data: message))

        let (handle, x963) = try service.generate()
        let signature = try service.sign(handle: handle, digest: digest)

        let publicKey = try P256.Signing.PublicKey(x963Representation: x963)
        let parsed = try P256.Signing.ECDSASignature(derRepresentation: signature)
        XCTAssertTrue(
            publicKey.isValidSignature(parsed, for: message),
            "a Mac-SEP digest-mode signature must verify under CryptoKit over the message"
        )
    }

    /// A device SE signature is DER whose r and s each fit 32 bytes; CryptoKit's raw
    /// form is exactly r || s. A 64-byte raw representation proves the DER carries
    /// nothing beyond the two scalars, the same shape a device emits.
    func testSignatureRawFormIsTwoScalars() throws {
        let service = SecureEnclaveService()
        try XCTSkipUnless(service.isAvailable, "no Secure Enclave on this host")

        let (handle, _) = try service.generate()
        let signature = try service.sign(handle: handle, digest: Data(repeating: 0x5A, count: 32))

        let parsed = try P256.Signing.ECDSASignature(derRepresentation: signature)
        XCTAssertEqual(parsed.rawRepresentation.count, 64, "raw ECDSA P-256 is r || s, 32 + 32")
    }

    /// The exported public key must import into an independent implementation: a device
    /// app that hands the X9.63 bytes to CryptoKit, a server, or another library gets a
    /// working verification key, not just one `SecKeyCreateWithData` tolerates.
    func testPublicKeyImportsIntoCryptoKit() throws {
        let service = SecureEnclaveService()
        try XCTSkipUnless(service.isAvailable, "no Secure Enclave on this host")

        let (_, x963) = try service.generate()
        XCTAssertNoThrow(try P256.Signing.PublicKey(x963Representation: x963))
    }
}
