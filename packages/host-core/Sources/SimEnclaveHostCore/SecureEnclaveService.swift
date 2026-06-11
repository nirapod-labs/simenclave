// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

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
/// Keys live in memory for the helper's lifetime, keyed by an opaque handle.
/// Durable keychain persistence across helper restarts is M5 work (it needs a
/// signed helper); the handle is already opaque so that swap will not change
/// the wire.
public final class SecureEnclaveService: @unchecked Sendable {
    /// Why a service operation failed.
    public enum Failure: Error, Equatable {
        /// This host has no usable Secure Enclave.
        case unavailable
        /// The SEP refused to mint the key; the message carries the OSStatus text.
        case keyGeneration(String)
        /// No key is stored under the presented handle.
        case unknownHandle
        /// The SEP refused to sign; the message carries the OSStatus text.
        case signing(String)
        /// The public key could not be exported to X9.63 bytes.
        case publicKeyExport(String)
        /// A prompted sign was requested but no biometric gate is installed;
        /// the headless helper fails closed rather than prompting nowhere.
        case biometryUnavailable
    }

    /// A stored SEP key and whether its use requires a prompt (a biometry or
    /// user-presence key). The flag is set at generate, so sign can route a prompted key
    /// through the biometric gate without re-reading its access control.
    private struct StoredKey {
        let key: SecKey
        let requiresPrompt: Bool
    }

    /// A permanent key's handle and the tag it is stored under, keyed by the (udid, tag)
    /// namespace. The tag is kept so an enumeration can report it without reversing the key.
    private struct TagRecord { let handle: Data; let appTag: Data }

    private let lock = NSLock()
    private var keys: [Data: StoredKey] = [:]
    // A permanent key's (udid, tag) namespace -> record, so a relaunched app finds the key
    // again by tag the way a device retrieves a keychain-stored key, and can enumerate every
    // key for the simulator. Helper-lifetime: it survives an app relaunch while the helper
    // runs. Durable across helper restarts and Mac reboot (a write into the Mac keychain) is
    // M5, and needs the signed helper.
    private var tags: [String: TagRecord] = [:]
    private let biometricGate: BiometricGate?
    // Serializes prompts so two prompted signs never raise two sheets at once. Held only
    // around the gate call, never together with the handle-store lock, so it cannot
    // deadlock or serialize a silent sign.
    private let promptLock = NSLock()

    /// The access-control flags that make a key require a prompt: any biometric or
    /// user-presence constraint. requiresPrompt is derived from the flags the helper
    /// actually built, not from the class bit, so the two cannot desync helper-side.
    private static let promptFlagMask = UInt(
        SecAccessControlCreateFlags([.userPresence, .biometryAny, .biometryCurrentSet,
                                     .devicePasscode]).rawValue)

    /// The biometric gate drives the prompt for a prompted key. The menubar app installs
    /// the real one; the CLI helper installs none, so a prompted sign there fails closed;
    /// tests inject a mock. A silent key never touches it.
    public init(biometricGate: BiometricGate? = nil) {
        self.biometricGate = biometricGate
    }

    /// True on T2 and Apple Silicon Macs. The whole tool is a no-op without it.
    public var isAvailable: Bool { SecureEnclave.isAvailable }

    /// Generate a P-256 signing key in the SEP. A silent key is usable without
    /// user presence; a biometry key requires Touch ID to use the private key.
    ///
    /// Returns an opaque handle and the public key in X9.63 form (65 bytes, a
    /// `0x04` lead byte then the two 32-byte coordinates), which is what the device
    /// returns from `SecKeyCopyExternalRepresentation`. The biometric prompt at
    /// sign time and its error parity are M3.
    public func generate(requiresBiometry: Bool = false, accessFlags: UInt? = nil,
                         protection: String? = nil, persistentTag: Data? = nil,
                         udid: String? = nil, appID: String? = nil, keyType: String? = nil,
                         keySizeInBits: UInt? = nil) throws -> (handle: Data, publicKey: Data) {
        guard SecureEnclave.isAvailable else { throw Failure.unavailable }

        var accessError: Unmanaged<CFError>?
        let access: SecAccessControl
        if let accessFlags {
            // Rebuild the app's gate from the relayed flags and protection, verbatim, so
            // the SEP enforces exactly what the app asked for. Fail closed if the host
            // rejects the flag set rather than build a weaker gate than was asked.
            let protectionClass: CFString = protection.map { $0 as CFString }
                ?? kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            guard let built = SecAccessControlCreateWithFlags(
                kCFAllocatorDefault,
                protectionClass,
                SecAccessControlCreateFlags(rawValue: CFOptionFlags(accessFlags)),
                &accessError
            ) else { throw Failure.keyGeneration(Self.message(accessError)) }
            access = built
        } else {
            let flags: SecAccessControlCreateFlags = requiresBiometry
                ? [.privateKeyUsage, .biometryCurrentSet]
                : [.privateKeyUsage]
            guard let built = SecAccessControlCreateWithFlags(
                kCFAllocatorDefault,
                kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                flags,
                &accessError
            ) else { throw Failure.keyGeneration(Self.message(accessError)) }
            access = built
        }

        // Use the app's requested type and size when the interposer relayed them, so the real
        // SecKeyCreateRandomKey rejects a type or size the SEP does not support with its own
        // error. Absent (nil) keeps the P-256 default a created SE key has always had.
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: keyType.map { $0 as CFString } ?? kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: keySizeInBits ?? 256,
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
        // Derive the prompt flag from the gate that was built, not the class bit, so a
        // relayed flag set with a presence constraint always prompts even if the class
        // somehow said silent.
        let requiresPrompt = accessFlags.map { ($0 & Self.promptFlagMask) != 0 } ?? requiresBiometry
        lock.lock()
        keys[handle] = StoredKey(key: privateKey, requiresPrompt: requiresPrompt)
        // A permanent key (tag + udid both present) is registered for find-by-tag and enumerate,
        // namespaced by the calling app so two apps on one simulator stay isolated like a device.
        if let persistentTag, let udid {
            tags[Self.tagKey(udid: udid, appID: appID, appTag: persistentTag)] =
                TagRecord(handle: handle, appTag: persistentTag)
        }
        lock.unlock()
        return (handle, publicKey)
    }

    /// The handle and X9.63 public key of the permanent key stored under `appTag` for
    /// `udid`, or `unknownHandle` if no such key is in this helper's session. This is how a
    /// relaunched app finds a key it created on a previous run, while the helper stays up.
    public func findByTag(appTag: Data, udid: String, appID: String? = nil) throws
        -> (handle: Data, publicKey: Data) {
        lock.lock()
        let handle = tags[Self.tagKey(udid: udid, appID: appID, appTag: appTag)]?.handle
        lock.unlock()
        guard let handle else { throw Failure.unknownHandle }
        return (handle, try publicKey(for: handle))
    }

    /// Every permanent key registered for `udid`: its handle, X9.63 public key, and tag. This
    /// is what backs an app's `SecItemCopyMatching` with `kSecMatchLimitAll`, so the keychain
    /// is enumerated natively rather than the app remembering its own tags.
    public func listKeys(udid: String, appID: String? = nil)
        -> [(handle: Data, publicKey: Data, appTag: Data)] {
        lock.lock()
        let records = tags.filter { $0.key.hasPrefix("\(udid)|\(appID ?? "")|") }.values
        lock.unlock()
        return records.compactMap { record in
            (try? publicKey(for: record.handle)).map { (record.handle, $0, record.appTag) }
        }
    }

    private static func tagKey(udid: String, appID: String?, appTag: Data) -> String {
        "\(udid)|\(appID ?? "")|" + appTag.map { String(format: "%02x", $0) }.joined()
    }

    /// The X9.63 public key for the SEP key named by `handle`.
    public func publicKey(for handle: Data) throws -> Data {
        try exportPublicKey(of: try lookup(handle).key)
    }

    /// Whether the real SEP key behind `handle` supports `(operation, algorithm)`, asked of the
    /// real key with `SecKeyIsAlgorithmSupported`. This is what makes the shadow report the
    /// private key's support matrix (sign yes, verify no) instead of the public carrier's.
    /// An unknown operation raw value is unsupported, the same as the framework would treat it.
    public func isAlgorithmSupported(handle: Data, operation: UInt, algorithm: String) throws -> Bool {
        let key = try lookup(handle).key
        guard let type = SecKeyOperationType(rawValue: Int(operation)) else { return false }
        return SecKeyIsAlgorithmSupported(key, type, SecKeyAlgorithm(rawValue: algorithm as CFString))
    }

    /// The real key's `SecKeyCopyAttributes` dictionary, serialized as a binary property list,
    /// so the shadow can report the SEP key's own attributes (the application label, the
    /// capability flags, the sizes) rather than a stub. Only property-list-serializable values
    /// cross the wire; an opaque `SecAccessControlRef` cannot be serialized and is dropped.
    public func copyAttributes(handle: Data) throws -> Data {
        let key = try lookup(handle).key
        guard let raw = SecKeyCopyAttributes(key) as? [String: Any] else { return Data() }
        var plist: [String: Any] = [:]
        for (attrKey, value) in raw
            where PropertyListSerialization.propertyList(value, isValidFor: .binary) {
            plist[attrKey] = value
        }
        return (try? PropertyListSerialization.data(
            fromPropertyList: plist, format: .binary, options: 0)) ?? Data()
    }

    /// Decrypt `ciphertext` with the real SEP key under `algorithm` (ECIES). The real
    /// `SecKeyCreateDecryptedData` runs on the real private key, so the plaintext (or the
    /// SEP's real refusal) is what a device returns.
    public func decrypt(handle: Data, algorithm: String, ciphertext: Data) throws -> Data {
        let key = try lookup(handle).key
        var error: Unmanaged<CFError>?
        guard let plaintext = SecKeyCreateDecryptedData(
            key, SecKeyAlgorithm(rawValue: algorithm as CFString), ciphertext as CFData, &error)
            as Data? else {
            throw Failure.signing(Self.message(error))
        }
        return plaintext
    }

    /// Derive an ECDH shared secret between the real SEP key and `peerPublicKey` (X9.63 bytes)
    /// under `algorithm`. The real `SecKeyCopyKeyExchangeResult` runs on the real private key.
    /// `parameters` is the caller's exchange-parameters dictionary serialized as a plist (empty
    /// for a raw agreement); it is rebuilt and passed through, so a KDF variant's requested size
    /// and shared info are the ones a device would use, not a stand-in's.
    public func keyExchange(handle: Data, algorithm: String, peerPublicKey: Data,
                            parameters: Data) throws -> Data {
        let key = try lookup(handle).key
        var error: Unmanaged<CFError>?
        let peerAttributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
        ]
        guard let peer = SecKeyCreateWithData(
            peerPublicKey as CFData, peerAttributes as CFDictionary, &error) else {
            throw Failure.signing(Self.message(error))
        }
        var exchangeParameters: [String: Any] = [:]
        if !parameters.isEmpty,
           let decoded = try? PropertyListSerialization.propertyList(
               from: parameters, options: [], format: nil) as? [String: Any] {
            exchangeParameters = decoded
        }
        guard let secret = SecKeyCopyKeyExchangeResult(
            key, SecKeyAlgorithm(rawValue: algorithm as CFString), peer,
            exchangeParameters as CFDictionary, &error) as Data? else {
            throw Failure.signing(Self.message(error))
        }
        return secret
    }

    /// Sign `input` with the SEP key named by `handle` under `algorithm` (a
    /// `SecKeyAlgorithm` raw string), returning whatever `SecKeyCreateSignature`
    /// produces on a device. Digest-mode algorithms sign `input` as given; message-mode
    /// algorithms hash it first. The algorithm is passed straight to the real key, so the
    /// SEP's own support set decides what works, not a fixed SHA-256 digest. No `s`
    /// normalization happens here; whatever an app does on top of an SE signature is the
    /// app's step, run unchanged against this output.
    public func sign(handle: Data, algorithm: String, input: Data) throws -> Data {
        let stored = try lookup(handle)
        guard stored.requiresPrompt else {
            return try Self.signDirectly(stored.key, algorithm: algorithm, input: input)
        }
        // A prompted key signs only through the biometric gate, which foregrounds and
        // runs Touch ID. Without a gate (the CLI helper) the sign fails closed rather
        // than prompting in a process that cannot present, or signing silently.
        guard let biometricGate else { throw Failure.biometryUnavailable }
        // Serialize prompts through one presenter: a second prompted sign waits its turn
        // rather than racing a second sheet. The handle-store lock is already released.
        promptLock.lock()
        defer { promptLock.unlock() }
        return try biometricGate.promptedSign(
            key: stored.key, algorithm: algorithm, input: input,
            reason: "Sign with the Secure Enclave")
    }

    private static func signDirectly(_ key: SecKey, algorithm: String, input: Data) throws -> Data {
        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(
            key,
            SecKeyAlgorithm(rawValue: algorithm as CFString),
            input as CFData,
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
        // Drop any tag that pointed at this handle, so a find-by-tag after a delete misses.
        tags = tags.filter { $0.value.handle != handle }
    }

    /// Re-tag the key named by `handle` to `appTag` for `udid`, so find-by-tag and enumerate
    /// follow a `SecItemUpdate` that renames a key's application tag. Unknown handles fail closed.
    public func updateTag(handle: Data, appTag: Data, udid: String, appID: String? = nil) throws {
        lock.lock()
        defer { lock.unlock() }
        guard keys[handle] != nil else { throw Failure.unknownHandle }
        // Drop any tag record pointing at this handle, then register the new one, so an old-tag
        // lookup misses and a new-tag lookup hits, exactly as a renamed keychain item behaves.
        tags = tags.filter { $0.value.handle != handle }
        tags[Self.tagKey(udid: udid, appID: appID, appTag: appTag)] =
            TagRecord(handle: handle, appTag: appTag)
    }

    /// Drop every key and tag the helper holds. The keys are in-session (created with
    /// `isPermanent: false`), so releasing the references is the whole reset; nothing lingers in
    /// the chip. This backs the menubar's "reset all keys". A handle from before the reset is now
    /// unknown, which a sign or lookup surfaces as the device's item-not-found.
    public func reset() {
        lock.lock()
        keys.removeAll()
        tags.removeAll()
        lock.unlock()
    }

    /// How many keys the helper currently holds. Read straight from the store, so it counts every
    /// key, including ones whose app is no longer in the menubar's connected-apps view.
    public var keyCount: Int {
        lock.lock()
        defer { lock.unlock() }
        return keys.count
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

    private func lookup(_ handle: Data) throws -> StoredKey {
        lock.lock()
        defer { lock.unlock() }
        guard let stored = keys[handle] else { throw Failure.unknownHandle }
        return stored
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
