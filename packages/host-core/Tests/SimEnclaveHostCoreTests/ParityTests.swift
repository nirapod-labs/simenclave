// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

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
/// hardware, is the device-capture parity run and cannot execute here.
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
        let algorithm = SecKeyAlgorithm.ecdsaSignatureDigestX962SHA256.rawValue as String
        let signature = try service.sign(handle: handle, algorithm: algorithm, input: digest)

        let publicKey = try P256.Signing.PublicKey(x963Representation: x963)
        let parsed = try P256.Signing.ECDSASignature(derRepresentation: signature)
        XCTAssertTrue(
            publicKey.isValidSignature(parsed, for: message),
            "a Mac-SEP digest-mode signature must verify under CryptoKit over the message"
        )
    }

    /// The service signs under whatever SecKeyAlgorithm the caller passes, not a fixed
    /// SHA-256 digest. Each SHA size the Secure Enclave supports must produce a signature
    /// that an independent verifier accepts over the matching digest, proving the algorithm
    /// is relayed to the real key rather than reduced to one hard-coded pair.
    func testSignsUnderEveryShaSizeTheEnclaveSupports() throws {
        let service = SecureEnclaveService()
        try XCTSkipUnless(service.isAvailable, "no Secure Enclave on this host")

        let message = Data("simenclave: every sha size signs and verifies".utf8)
        let (handle, x963) = try service.generate()
        let publicKey = try P256.Signing.PublicKey(x963Representation: x963)

        // Digest mode: the service signs the digest as given, so a CryptoKit verify over the
        // same Digest (which checks r, s against the digest scalar directly) must accept it.
        func checkDigest(_ algorithm: SecKeyAlgorithm, _ digest: some Digest) throws {
            let signature = try service.sign(
                handle: handle, algorithm: algorithm.rawValue as String, input: Data(digest))
            let parsed = try P256.Signing.ECDSASignature(derRepresentation: signature)
            XCTAssertTrue(
                publicKey.isValidSignature(parsed, for: digest),
                "a \(algorithm) signature must verify under the exported key")
        }
        try checkDigest(.ecdsaSignatureDigestX962SHA256, SHA256.hash(data: message))
        try checkDigest(.ecdsaSignatureDigestX962SHA384, SHA384.hash(data: message))
        try checkDigest(.ecdsaSignatureDigestX962SHA512, SHA512.hash(data: message))

        // Message mode: the service hashes the raw message itself under the algorithm, the
        // path an app that hands bytes (not a digest) to SecKeyCreateSignature takes.
        let messageSignature = try service.sign(
            handle: handle,
            algorithm: SecKeyAlgorithm.ecdsaSignatureMessageX962SHA512.rawValue as String,
            input: message)
        let parsedMessage = try P256.Signing.ECDSASignature(derRepresentation: messageSignature)
        XCTAssertTrue(
            publicKey.isValidSignature(parsedMessage, for: SHA512.hash(data: message)),
            "a message-mode SHA-512 signature must verify over SHA-512(message)")
    }

    /// A device SE signature is DER whose r and s each fit 32 bytes; CryptoKit's raw
    /// form is exactly r || s. A 64-byte raw representation proves the DER carries
    /// nothing beyond the two scalars, the same shape a device emits.
    func testSignatureRawFormIsTwoScalars() throws {
        let service = SecureEnclaveService()
        try XCTSkipUnless(service.isAvailable, "no Secure Enclave on this host")

        let (handle, _) = try service.generate()
        let algorithm = SecKeyAlgorithm.ecdsaSignatureDigestX962SHA256.rawValue as String
        let signature = try service.sign(
            handle: handle, algorithm: algorithm, input: Data(repeating: 0x5A, count: 32))

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

    /// ECDH agreement on the SEP key must match an independent CryptoKit peer, for both a raw
    /// agreement and a KDF variant whose requested size travels in `parameters`. The KDF case is
    /// the proof the exchange parameters reach the real key: with no parameters relayed it would
    /// fail for want of a requested size, and a wrong size would not match CryptoKit's output.
    func testKeyAgreementMatchesAndKdfParametersAreRelayed() throws {
        let service = SecureEnclaveService()
        try XCTSkipUnless(service.isAvailable, "no Secure Enclave on this host")

        let (handle, seX963) = try service.generate()
        let sePublic = try P256.KeyAgreement.PublicKey(x963Representation: seX963)
        let peer = P256.KeyAgreement.PrivateKey()
        let peerX963 = peer.publicKey.x963Representation
        let peerShared = try peer.sharedSecretFromKeyAgreement(with: sePublic)

        // Raw agreement: the SEP returns the x-coordinate, which equals CryptoKit's shared secret.
        let rawSecret = try service.keyExchange(
            handle: handle,
            algorithm: SecKeyAlgorithm.ecdhKeyExchangeStandard.rawValue as String,
            peerPublicKey: peerX963, parameters: Data())
        XCTAssertEqual(rawSecret, peerShared.withUnsafeBytes { Data($0) },
                       "raw ECDH must match the CryptoKit peer")

        // KDF variant: the requested size travels in parameters; the X9.63 KDF output must match.
        let parameters = try PropertyListSerialization.data(
            fromPropertyList: [SecKeyKeyExchangeParameter.requestedSize.rawValue as String: 32],
            format: .binary, options: 0)
        let derived = try service.keyExchange(
            handle: handle,
            algorithm: SecKeyAlgorithm.ecdhKeyExchangeStandardX963SHA256.rawValue as String,
            peerPublicKey: peerX963, parameters: parameters)
        let peerDerived = peerShared.x963DerivedSymmetricKey(
            using: SHA256.self, sharedInfo: Data(), outputByteCount: 32)
        XCTAssertEqual(derived, peerDerived.withUnsafeBytes { Data($0) },
                       "the KDF output must match, so the relayed requested size reached the real key")
    }
}
