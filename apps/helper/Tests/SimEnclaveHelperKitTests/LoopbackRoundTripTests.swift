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

        guard case let .generated(handle, x963) = try client.send(.generate(keyClass: .silent), token: token) else {
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
        guard case let .failure(code, _, _) = try client.send(.generate(keyClass: .silent), token: CapabilityToken()) else {
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

    func testGetPublicKeyMatchesAndDeleteRevokes() throws {
        let service = SecureEnclaveService()
        try XCTSkipUnless(service.isAvailable, "no Secure Enclave on this host")

        let token = CapabilityToken()
        let listener = LoopbackListener(router: RequestRouter(service: service, gate: AuthGate(session: token)))
        try listener.start()
        defer { listener.stop() }
        let client = LoopbackClient(port: listener.port)

        guard case let .generated(handle, x963) = try client.send(.generate(keyClass: .silent), token: token) else {
            return XCTFail("expected a generated response")
        }
        guard case let .publicKey(fetched) = try client.send(.getPublicKey(handle: handle), token: token) else {
            return XCTFail("expected a publicKey response")
        }
        XCTAssertEqual(fetched, x963, "GET_PUBKEY must return the key GENERATE handed back")

        guard case .deleted = try client.send(.delete(handle: handle), token: token) else {
            return XCTFail("expected a deleted response")
        }
        // After delete the handle is gone: errSecItemNotFound.
        guard case let .failure(code, _, _) = try client.send(.getPublicKey(handle: handle), token: token) else {
            return XCTFail("a deleted handle must fail")
        }
        XCTAssertEqual(code, -25300) // errSecItemNotFound
    }

    func testBiometryKeyGeneration() throws {
        let service = SecureEnclaveService()
        try XCTSkipUnless(service.isAvailable, "no Secure Enclave on this host")

        let token = CapabilityToken()
        let listener = LoopbackListener(router: RequestRouter(service: service, gate: AuthGate(session: token)))
        try listener.start()
        defer { listener.stop() }
        let client = LoopbackClient(port: listener.port)

        switch try client.send(.generate(keyClass: .biometry), token: token) {
        case let .generated(_, x963):
            // A biometry key generated: its public key is an ordinary P-256 point.
            // The prompt at sign time and the error parity are M3.
            XCTAssertEqual(x963.count, 65)
            XCTAssertEqual(x963.first, 0x04)
        case let .failure(_, message, _):
            throw XCTSkip("biometry key generation not available here: \(message)")
        default:
            return XCTFail("unexpected response to a biometry generate")
        }
    }

    // BLOCKER-1 proof: a biometry sign parked on the human prompt must block only its own
    // connection. A user-presence key (builds on any Mac) is signed on one connection,
    // which parks in a gate; while it is parked, a silent generate and sign on other
    // connections must complete. The proof is deterministic: it waits on a semaphore the
    // gate signals when parked, not on a timing margin.
    func testParkedBiometrySignDoesNotStallOtherConnections() throws {
        let parked = DispatchSemaphore(value: 0)
        let release = DispatchSemaphore(value: 0)
        let gate = ParkingGate(parked: parked, release: release, signature: Data(repeating: 0x30, count: 70))
        let service = SecureEnclaveService(biometricGate: gate)
        try XCTSkipUnless(service.isAvailable, "no Secure Enclave on this host")

        let token = CapabilityToken()
        let listener = LoopbackListener(router: RequestRouter(service: service, gate: AuthGate(session: token)))
        try listener.start()
        defer { release.signal(); listener.stop() }
        let port = listener.port

        let ac = AccessControl(
            flags: UInt64(SecAccessControlCreateFlags([.privateKeyUsage, .userPresence]).rawValue),
            protection: kSecAttrAccessibleWhenUnlockedThisDeviceOnly as String)
        guard case let .generated(promptedHandle, _) = try LoopbackClient(port: port).send(
            .generate(keyClass: .biometry, accessControl: ac), token: token)
        else { return XCTFail("expected a generated biometry key") }

        // Connection A: sign the prompted key; it parks in the gate.
        DispatchQueue.global().async {
            _ = try? LoopbackClient(port: port).send(
                .sign(handle: promptedHandle, digest: Data(repeating: 0x5A, count: 32)), token: token)
        }
        XCTAssertEqual(parked.wait(timeout: .now() + 5), .success, "the biometry sign should park in the gate")

        // While A is parked, a silent generate and sign on other connections must complete.
        guard case let .generated(silentHandle, x963) = try LoopbackClient(port: port).send(
            .generate(keyClass: .silent), token: token)
        else { return XCTFail("a silent generate must complete while a biometry sign is parked") }
        let digest = Data(SHA256.hash(data: Data("unblocked".utf8)))
        guard case let .signed(signature) = try LoopbackClient(port: port).send(
            .sign(handle: silentHandle, digest: digest), token: token)
        else { return XCTFail("a silent sign must complete while a biometry sign is parked") }
        XCTAssertTrue(verifies(digest: digest, signature: signature, x963: x963))
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

/// A gate that parks the calling connection's sign until released, signaling when it
/// parks. It stands in for a human at the Touch ID sheet, so a test can prove a parked
/// biometry sign holds only its own connection.
final class ParkingGate: BiometricGate, @unchecked Sendable {
    private let parked: DispatchSemaphore
    private let release: DispatchSemaphore
    private let signature: Data

    init(parked: DispatchSemaphore, release: DispatchSemaphore, signature: Data) {
        self.parked = parked
        self.release = release
        self.signature = signature
    }

    func promptedSign(key _: SecKey, digest _: Data, reason _: String) throws -> Data {
        parked.signal()
        release.wait()
        return signature
    }
}
