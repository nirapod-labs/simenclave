import CryptoKit
import Foundation
import Security

/// Drives the Mac's Secure Enclave for the SimEnclave helper.
///
/// Every private key is generated inside the SEP and never leaves it. Callers
/// hold only an opaque handle, the public key, and signatures. This is the host
/// half of the bridge: the simulator's hooked `SecKey` calls land here over
/// loopback, and this service answers them with the exact same Security-framework
/// path a real device runs (`SecKeyCreateRandomKey` with the SE token,
/// `SecKeyCreateSignature` in digest mode), so what it returns is byte-shaped like
/// the device API. It adds no canonicalization of its own.
///
/// M0 holds keys in memory for the helper's lifetime, keyed by an opaque handle.
/// Keychain-tag persistence across helper restarts is M3; the handle is already
/// opaque so that swap does not change the wire.
public final class SecureEnclaveService: @unchecked Sendable {
    public enum Failure: Error, Equatable {
        case unavailable
        case keyGeneration(String)
        case unknownHandle
        case signing(String)
        case publicKeyExport(String)
    }

    private let lock = NSLock()
    private var keys: [Data: SecKey] = [:]

    public init() {}

    /// True on T2 and Apple Silicon Macs. The whole tool is a no-op without it.
    public var isAvailable: Bool { SecureEnclave.isAvailable }

    /// Generate a silent P-256 signing key in the SEP.
    ///
    /// Returns an opaque handle and the public key in X9.63 form (65 bytes, a
    /// `0x04` lead byte then the two 32-byte coordinates), which is what the device
    /// returns from `SecKeyCopyExternalRepresentation`. The biometry-gated key
    /// class is M3.
    public func generate() throws -> (handle: Data, publicKey: Data) {
        guard SecureEnclave.isAvailable else { throw Failure.unavailable }

        var accessError: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.privateKeyUsage],
            &accessError
        ) else {
            throw Failure.keyGeneration(Self.message(accessError))
        }

        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: false,
                kSecAttrAccessControl as String: access,
            ],
        ]

        var keyError: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &keyError) else {
            throw Failure.keyGeneration(Self.message(keyError))
        }

        let publicKey = try exportPublicKey(of: privateKey)
        let handle = Self.randomHandle()
        lock.lock()
        keys[handle] = privateKey
        lock.unlock()
        return (handle, publicKey)
    }

    /// The X9.63 public key for the SEP key named by `handle`.
    public func publicKey(for handle: Data) throws -> Data {
        try exportPublicKey(of: try lookup(handle))
    }

    /// Sign a 32-byte SHA-256 `digest` with the SEP key named by `handle`,
    /// returning the X9.62 DER ECDSA signature `SecKeyCreateSignature` produces on
    /// a device. The digest is signed as given; no hashing and no `s`
    /// normalization happen here. Whatever an app does on top of an SE signature
    /// is the app's step, run unchanged against this faithful output.
    public func sign(handle: Data, digest: Data) throws -> Data {
        let key = try lookup(handle)
        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(
            key,
            .ecdsaSignatureDigestX962SHA256,
            digest as CFData,
            &error
        ) as Data? else {
            throw Failure.signing(Self.message(error))
        }
        return signature
    }

    /// Remove the SEP key named by `handle`. The key is non-permanent, so
    /// dropping the only reference frees it from the Secure Enclave.
    public func delete(handle: Data) throws {
        lock.lock()
        defer { lock.unlock() }
        guard keys.removeValue(forKey: handle) != nil else { throw Failure.unknownHandle }
    }

    private func exportPublicKey(of privateKey: SecKey) throws -> Data {
        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            throw Failure.publicKeyExport("SecKeyCopyPublicKey returned nil")
        }
        var error: Unmanaged<CFError>?
        guard let x963 = SecKeyCopyExternalRepresentation(publicKey, &error) as Data? else {
            throw Failure.publicKeyExport(Self.message(error))
        }
        return x963
    }

    private func lookup(_ handle: Data) throws -> SecKey {
        lock.lock()
        defer { lock.unlock() }
        guard let key = keys[handle] else { throw Failure.unknownHandle }
        return key
    }

    private static func randomHandle() -> Data {
        var bytes = [UInt8](repeating: 0, count: 16)
        _ = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        return Data(bytes)
    }

    private static func message(_ error: Unmanaged<CFError>?) -> String {
        guard let error = error?.takeRetainedValue() else { return "unknown error" }
        return (CFErrorCopyDescription(error) as String?) ?? "unknown error"
    }
}
