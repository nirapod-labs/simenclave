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

    /// A user-presence access control: a prompted key that needs no specific biometric
    /// hardware to create, so these run on any Mac with a Secure Enclave.
    private static let promptFlags = UInt(
        SecAccessControlCreateFlags([.privateKeyUsage, .userPresence]).rawValue)

    func testPromptedSignRoutesThroughTheGate() throws {
        let canned = Data(repeating: 0x30, count: 70)
        let gate = MockBiometricGate(.authorize(canned))
        let service = SecureEnclaveService(biometricGate: gate)
        try XCTSkipUnless(service.isAvailable, "no Secure Enclave on this host")
        let (handle, _) = try service.generate(requiresBiometry: true, accessFlags: Self.promptFlags)
        let signature = try service.sign(handle: handle, digest: Data(repeating: 0x5A, count: 32))
        XCTAssertEqual(signature, canned, "a prompted sign is delegated to the gate")
        XCTAssertEqual(gate.callCount, 1)
    }

    func testPromptedSignDenialIsAFailure() throws {
        let gate = MockBiometricGate(.deny)
        let service = SecureEnclaveService(biometricGate: gate)
        try XCTSkipUnless(service.isAvailable, "no Secure Enclave on this host")
        let (handle, _) = try service.generate(requiresBiometry: true, accessFlags: Self.promptFlags)
        XCTAssertThrowsError(try service.sign(handle: handle, digest: Data(repeating: 0x5A, count: 32)))
    }

    func testPromptedSignWithoutGateFailsClosed() throws {
        let service = SecureEnclaveService() // no gate, as the CLI helper installs none
        try XCTSkipUnless(service.isAvailable, "no Secure Enclave on this host")
        let (handle, _) = try service.generate(requiresBiometry: true, accessFlags: Self.promptFlags)
        XCTAssertThrowsError(
            try service.sign(handle: handle, digest: Data(repeating: 0x5A, count: 32))
        ) { error in
            XCTAssertEqual(error as? SecureEnclaveService.Failure, .biometryUnavailable)
        }
    }

    func testSilentSignNeverTouchesTheGate() throws {
        let gate = MockBiometricGate(.deny) // would throw if a silent sign reached it
        let service = SecureEnclaveService(biometricGate: gate)
        try XCTSkipUnless(service.isAvailable, "no Secure Enclave on this host")
        let (handle, x963) = try service.generate() // silent
        let digest = Data(SHA256.hash(data: Data("silent skips the gate".utf8)))
        let signature = try service.sign(handle: handle, digest: digest)
        XCTAssertEqual(gate.callCount, 0, "a silent sign must not reach the gate")
        XCTAssertTrue(verifies(digest: digest, signature: signature, x963: x963))
    }

    func testFlagsForceThePromptEvenWhenTheClassIsSilent() throws {
        // A silent class but presence flags: the helper derives requiresPrompt from the
        // flags it built, so the prompt route is taken regardless of the class bit.
        let gate = MockBiometricGate(.deny)
        let service = SecureEnclaveService(biometricGate: gate)
        try XCTSkipUnless(service.isAvailable, "no Secure Enclave on this host")
        let (handle, _) = try service.generate(requiresBiometry: false, accessFlags: Self.promptFlags)
        XCTAssertThrowsError(try service.sign(handle: handle, digest: Data(repeating: 0x5A, count: 32)))
        XCTAssertEqual(gate.callCount, 1, "presence flags route through the gate regardless of the class")
    }

    func testPromptsSerialize() throws {
        let gate = ConcurrencyRecordingGate()
        let service = SecureEnclaveService(biometricGate: gate)
        try XCTSkipUnless(service.isAvailable, "no Secure Enclave on this host")
        let (handle, _) = try service.generate(requiresBiometry: true, accessFlags: Self.promptFlags)
        let group = DispatchGroup()
        for _ in 0 ..< 4 {
            group.enter()
            DispatchQueue.global().async {
                _ = try? service.sign(handle: handle, digest: Data(repeating: 0x5A, count: 32))
                group.leave()
            }
        }
        group.wait()
        XCTAssertEqual(gate.maxConcurrent, 1, "prompts must serialize through one presenter")
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

/// A biometric gate for tests: it returns canned bytes (authorized) or throws (denied)
/// without a real prompt, so the routing is exercised headlessly. A silent sign must
/// never reach it, which the call count proves.
final class MockBiometricGate: BiometricGate, @unchecked Sendable {
    enum Behavior { case authorize(Data); case deny }
    private let behavior: Behavior
    private let lock = NSLock()
    private var calls = 0

    init(_ behavior: Behavior) { self.behavior = behavior }

    var callCount: Int {
        lock.lock(); defer { lock.unlock() }
        return calls
    }

    func promptedSign(key _: SecKey, digest _: Data, reason _: String) throws -> Data {
        lock.lock(); calls += 1; lock.unlock()
        switch behavior {
        case let .authorize(bytes): return bytes
        case .deny: throw SecureEnclaveService.Failure.signing("denied (mock)")
        }
    }
}

/// A gate that records the peak number of concurrent prompts, to prove the service
/// serializes them. It sleeps briefly, so a missing serializer would show overlap.
final class ConcurrencyRecordingGate: BiometricGate, @unchecked Sendable {
    private let lock = NSLock()
    private var active = 0
    private var peak = 0

    var maxConcurrent: Int {
        lock.lock(); defer { lock.unlock() }
        return peak
    }

    func promptedSign(key _: SecKey, digest _: Data, reason _: String) throws -> Data {
        lock.lock(); active += 1; peak = max(peak, active); lock.unlock()
        Thread.sleep(forTimeInterval: 0.05)
        lock.lock(); active -= 1; lock.unlock()
        return Data(repeating: 0x30, count: 70)
    }
}
