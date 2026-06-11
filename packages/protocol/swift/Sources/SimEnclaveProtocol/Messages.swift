// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

import Foundation

/// The class of a generated key. A silent key is usable without user presence; a
/// biometry key requires Touch ID to use the private key. M1 creates the key with
/// the right access control; the biometric prompt and its error parity are M3.
public enum KeyClass: UInt64, Sendable {
    case silent = 0
    case biometry = 1
}

/// The access control an app attached to a Secure Enclave key, captured by the
/// interposer and relayed verbatim so the helper rebuilds the same gate. `flags` is the
/// raw `SecAccessControlCreateFlags` bit set; `protection` is the `kSecAttrAccessible`
/// constant carried as its own string.
public struct AccessControl: Equatable, Sendable {
    /// The raw `SecAccessControlCreateFlags` bit set, exactly as captured.
    public let flags: UInt64
    /// The `kSecAttrAccessible` constant, carried verbatim as text.
    public let protection: String
    /// Wrap a captured `(flags, protection)` pair.
    public init(flags: UInt64, protection: String) {
        self.flags = flags
        self.protection = protection
    }
}

/// The persistence descriptor a permanent key carries: the application tag the app
/// stored it under and the simulator UDID that namespaces tags per device. When a
/// `generate` carries one, the helper keeps the key findable by tag for its lifetime,
/// so a relaunched app reloads it the way a device retrieves a keychain-stored key.
public struct PersistentTag: Equatable, Sendable {
    /// The `kSecAttrApplicationTag` bytes the app named the key with.
    public let appTag: Data
    /// The simulator UDID, namespacing tags per device (hygiene, not a boundary).
    public let udid: String
    /// Wrap a captured `(appTag, udid)` pair.
    public init(appTag: Data, udid: String) {
        self.appTag = appTag
        self.udid = udid
    }
}

/// One persisted key as the helper reports it for an enumeration: the handle, the X9.63
/// public key, and the application tag it is stored under.
public struct KeyEntry: Equatable, Sendable {
    public let handle: Data
    public let publicKey: Data
    public let appTag: Data
    public init(handle: Data, publicKey: Data, appTag: Data) {
        self.handle = handle
        self.publicKey = publicKey
        self.appTag = appTag
    }
}

/// A request from the interposer to the helper.
public enum Request: Equatable {
    /// Version negotiation; the helper answers with the version it speaks.
    case hello(version: UInt64)
    /// Mint a key in the host SEP, optionally relaying a captured access control and,
    /// for a permanent key, the tag that makes it findable on a later relaunch. `keyType` and
    /// `keySizeInBits` carry the app's requested `kSecAttrKeyType`/`kSecAttrKeySizeInBits` (nil
    /// keeps the helper's P-256 default), relayed so the SEP rejects a type or size it does not
    /// support rather than the interposer silently making a P-256 key.
    case generate(keyClass: KeyClass, accessControl: AccessControl?, persistent: PersistentTag?,
                  keyType: String?, keySizeInBits: UInt64?)
    /// Fetch the public key for a handle without signing anything.
    case getPublicKey(handle: Data)
    /// Sign `input` with the key behind a handle under `algorithm`, the
    /// `SecKeyAlgorithm` raw string. Digest variants carry the caller's digest,
    /// message variants the raw message; the helper hands both to the real key,
    /// so every algorithm the SEP supports works rather than a fixed SHA-256 digest.
    case sign(handle: Data, algorithm: String, input: Data)
    /// Remove the key behind a handle.
    case delete(handle: Data)
    /// Look up a persisted key by application tag; the UDID namespaces per
    /// simulator as hygiene, not a boundary.
    case findByTag(appTag: Data, udid: String)
    /// Enumerate every persisted key for a simulator, so an app's
    /// `SecItemCopyMatching` with `kSecMatchLimitAll` reads the keychain natively
    /// instead of the app remembering its own tags.
    case listKeys(udid: String)
    /// Ask whether the real key behind `handle` supports an `(operation, algorithm)`,
    /// so `SecKeyIsAlgorithmSupported` on the shadow returns the real SEP key's answer,
    /// not the public carrier's. `operation` is a `SecKeyOperationType`; `algorithm` is the
    /// `SecKeyAlgorithm` constant carried as its own string.
    case isAlgorithmSupported(handle: Data, operation: UInt64, algorithm: String)
    /// Fetch the real key's `SecKeyCopyAttributes` dictionary, serialized, so the shadow
    /// reports the SEP key's real attributes (application label, the capability flags, sizes)
    /// instead of a stub.
    case copyAttributes(handle: Data)
    /// Decrypt `ciphertext` with the real key under `algorithm` (ECIES), so an app that
    /// encrypts to the public key and decrypts with the shadow gets the real SEP result.
    case decrypt(handle: Data, algorithm: String, ciphertext: Data)
    /// Derive an ECDH shared secret between the real key and `peerPublicKey` under
    /// `algorithm`, so key agreement on the shadow uses the real SEP key. `parameters` is the
    /// caller's exchange-parameters dictionary serialized as a plist (empty for a raw agreement),
    /// carried whole so a KDF variant's requested size and shared info reach the real key.
    case keyExchange(handle: Data, algorithm: String, peerPublicKey: Data, parameters: Data)
    /// Re-tag the key behind `handle` to `appTag` (namespaced by `udid`), so an app's
    /// `SecItemUpdate` renaming a key's application tag is reflected in find-by-tag and enumerate.
    case updateTag(handle: Data, appTag: Data, udid: String)
}

public extension Request {
    /// A generate with no relayed access control: the helper applies its default for
    /// the key class. Keeps the pre-M3 call sites unchanged.
    static func generate(keyClass: KeyClass) -> Request {
        .generate(keyClass: keyClass, accessControl: nil, persistent: nil, keyType: nil,
                  keySizeInBits: nil)
    }

    /// A generate relaying an access control but no persistence tag (an ephemeral key).
    /// Keeps the M3 two-argument call sites unchanged.
    static func generate(keyClass: KeyClass, accessControl: AccessControl?) -> Request {
        .generate(keyClass: keyClass, accessControl: accessControl, persistent: nil, keyType: nil,
                  keySizeInBits: nil)
    }
}

/// A reply from the helper to the interposer.
public enum Response: Equatable {
    /// The version the helper speaks.
    case hello(version: UInt64)
    /// A minted key: its handle and X9.63 public key.
    case generated(handle: Data, publicKey: Data)
    /// The public key for a queried handle.
    case publicKey(Data)
    /// A DER ECDSA signature, exactly as the SEP returned it.
    case signed(signature: Data)
    /// The handle's key is gone.
    case deleted
    /// The key was re-tagged.
    case updated
    /// An error: a device-shaped `(code, domain)` plus a human-readable message
    /// that is never load-bearing.
    case failure(code: Int64, message: String, domain: UInt64)
    /// A persisted key matched the tag: its handle and X9.63 public key.
    case found(handle: Data, publicKey: Data)
    /// Every persisted key for the queried simulator, for a native enumeration.
    case listed(keys: [KeyEntry])
    /// Whether the real key supports the queried `(operation, algorithm)`, as the SEP reports.
    case supported(Bool)
    /// The real key's attribute dictionary, serialized as a binary property list.
    case attributes(Data)
    /// The plaintext from an ECIES decrypt with the real key.
    case decrypted(Data)
    /// The shared secret from an ECDH key agreement with the real key.
    case derived(Data)
}

public extension Response {
    /// A failure in the OSStatus domain, the common case before M3. The domain
    /// argument defaults here so the helper's existing call sites stay unchanged;
    /// a LocalAuthentication-domain failure passes the domain explicitly.
    static func failure(code: Int64, message: String) -> Response {
        .failure(code: code, message: message, domain: Wire.domainOSStatus)
    }
}

/// The version-1 message codec: a CBOR map in and out (see `SPEC.md`). Socket
/// I/O and framing live elsewhere; this is the pure payload layer.
public enum Wire {
    static let opHello: UInt64 = 1
    static let opGenerate: UInt64 = 2
    static let opGetPublicKey: UInt64 = 3
    static let opSign: UInt64 = 4
    static let opDelete: UInt64 = 5
    static let opFindByTag: UInt64 = 6
    static let opListKeys: UInt64 = 7
    static let opIsAlgorithmSupported: UInt64 = 8
    static let opCopyAttributes: UInt64 = 9
    static let opDecrypt: UInt64 = 10
    static let opKeyExchange: UInt64 = 11
    static let opUpdate: UInt64 = 12
    static let statusOK: UInt64 = 0
    static let statusError: UInt64 = 1
    /// The protocol version this codec implements.
    public static let version1: UInt64 = 1

    static let keyOp: UInt64 = 0
    static let keyStatus: UInt64 = 1
    static let keyHandle: UInt64 = 2
    static let keyPublicKey: UInt64 = 3
    static let keyDigest: UInt64 = 4
    static let keySignature: UInt64 = 5
    static let keyError: UInt64 = 6
    static let keyToken: UInt64 = 7
    static let keyVersion: UInt64 = 8
    static let keyClassKey: UInt64 = 9
    static let keyErrorCode: UInt64 = 10
    static let keyAccessFlags: UInt64 = 11
    static let keyProtection: UInt64 = 12
    static let keyErrorDomain: UInt64 = 13
    static let keyAppID: UInt64 = 14
    static let keyUDID: UInt64 = 15
    static let keyAppTag: UInt64 = 16
    /// A packed list of key entries (count, then handle/pubkey/tag each), carried as one
    /// byte string so the map codec needs no array support. The interposer unpacks it.
    static let keyEntries: UInt64 = 17
    static let keyOperation: UInt64 = 18
    static let keyAlgorithm: UInt64 = 19
    static let keyFlag: UInt64 = 20
    static let keyAttributes: UInt64 = 21
    static let keyCiphertext: UInt64 = 22
    static let keyPeerKey: UInt64 = 23
    static let keyResult: UInt64 = 24
    static let keyParameters: UInt64 = 25
    static let keyKeyType: UInt64 = 26
    static let keyKeySize: UInt64 = 27
    /// The guest app's display name (HELLO, key 28), guest-reported and untrusted: the
    /// helper clamps and sanitizes it before showing it. Names the app, gates nothing.
    static let keyAppDisplayName: UInt64 = 28
    /// The guest app's icon as PNG bytes (HELLO, key 29), guest-reported and untrusted: the
    /// helper validates it as a bounded PNG before showing it, or falls back to a placeholder.
    static let keyAppIcon: UInt64 = 29

    /// The largest app-icon the helper accepts on the wire, in bytes. A real app icon
    /// rendered to PNG is a few KB; this cap rejects an app trying to flood the channel.
    public static let maxAppIconBytes = 64 * 1024
    /// The most Unicode scalars the helper keeps from a guest display name. Clamping scalars, not
    /// graphemes, bounds the rendered width even when a name stacks unbounded combining marks.
    public static let maxAppDisplayNameScalars = 64

    /// The OSStatus error domain, the default for key 13; an OSStatus-domain
    /// failure omits the key entirely, keeping the pre-M3 bytes.
    public static let domainOSStatus: UInt64 = 0
    /// The LocalAuthentication error domain for key 13, carried by biometric
    /// failures so the interposer rebuilds the LAError a device returns.
    public static let domainLAError: UInt64 = 1

    /// Encode a request, carrying the capability token in key 7. The token rides
    /// every request; the helper validates it before interpreting the op.
    public static func encode(_ request: Request, token: Data, appID: String? = nil,
                              displayName: String? = nil, appIcon: Data? = nil) -> Data {
        var writer = CBORWriter()
        switch request {
        case let .hello(version):
            // HELLO carries the session identity once: op, token, version, then the optional
            // app id (14), display name (28), and icon (29) in ascending key order. An interposer
            // that sends none of the three encodes the original three-field HELLO byte for byte.
            var count = 3
            if appID != nil { count += 1 }
            if displayName != nil { count += 1 }
            if appIcon != nil { count += 1 }
            writer.mapHeader(count)
            writer.uint(keyOp); writer.uint(opHello)
            writer.uint(keyToken); writer.bytes(token)
            writer.uint(keyVersion); writer.uint(version)
            if let appID { writer.uint(keyAppID); writer.text(appID) }
            if let displayName { writer.uint(keyAppDisplayName); writer.text(displayName) }
            if let appIcon { writer.uint(keyAppIcon); writer.bytes(appIcon) }
        case let .generate(keyClass, accessControl, persistent, keyType, keySizeInBits):
            // op and token, then key 9 if biometry, the access control (11, 12) if
            // present, the app id (14) if present, the persistence udid + tag (15, 16)
            // if the key is permanent, and the requested key type + size (26, 27) if relayed,
            // all keys ascending. The no-app-id, no-tag, no-type shapes keep the exact bytes
            // the M0 through M2 interposer sends.
            let biometry = keyClass == .biometry
            var count = 2
            if biometry { count += 1 }
            if accessControl != nil { count += 2 }
            if appID != nil { count += 1 }
            if persistent != nil { count += 2 }
            if keyType != nil { count += 2 }
            writer.mapHeader(count)
            writer.uint(keyOp); writer.uint(opGenerate)
            writer.uint(keyToken); writer.bytes(token)
            if biometry { writer.uint(keyClassKey); writer.uint(KeyClass.biometry.rawValue) }
            if let ac = accessControl {
                writer.uint(keyAccessFlags); writer.uint(ac.flags)
                writer.uint(keyProtection); writer.text(ac.protection)
            }
            if let appID { writer.uint(keyAppID); writer.text(appID) }
            if let persistent {
                writer.uint(keyUDID); writer.text(persistent.udid)
                writer.uint(keyAppTag); writer.bytes(persistent.appTag)
            }
            if let keyType {
                writer.uint(keyKeyType); writer.text(keyType)
                writer.uint(keyKeySize); writer.uint(keySizeInBits ?? 256)
            }
        case let .getPublicKey(handle):
            writer.mapHeader(3)
            writer.uint(keyOp); writer.uint(opGetPublicKey)
            writer.uint(keyHandle); writer.bytes(handle)
            writer.uint(keyToken); writer.bytes(token)
        case let .sign(handle, algorithm, input):
            // map(5) { 0: 4, 2: handle, 4: input, 7: token, 19: algorithm }, keys ascending.
            writer.mapHeader(5)
            writer.uint(keyOp); writer.uint(opSign)
            writer.uint(keyHandle); writer.bytes(handle)
            writer.uint(keyDigest); writer.bytes(input)
            writer.uint(keyToken); writer.bytes(token)
            writer.uint(keyAlgorithm); writer.text(algorithm)
        case let .delete(handle):
            writer.mapHeader(3)
            writer.uint(keyOp); writer.uint(opDelete)
            writer.uint(keyHandle); writer.bytes(handle)
            writer.uint(keyToken); writer.bytes(token)
        case let .findByTag(appTag, udid):
            // map(4) { 0: 6, 7: token, 15: udid, 16: appTag }, keys ascending.
            writer.mapHeader(4)
            writer.uint(keyOp); writer.uint(opFindByTag)
            writer.uint(keyToken); writer.bytes(token)
            writer.uint(keyUDID); writer.text(udid)
            writer.uint(keyAppTag); writer.bytes(appTag)
        case let .listKeys(udid):
            // map(3) { 0: 7, 7: token, 15: udid }, keys ascending.
            writer.mapHeader(3)
            writer.uint(keyOp); writer.uint(opListKeys)
            writer.uint(keyToken); writer.bytes(token)
            writer.uint(keyUDID); writer.text(udid)
        case let .isAlgorithmSupported(handle, operation, algorithm):
            // map(5) { 0: 8, 2: handle, 7: token, 18: operation, 19: algorithm }, keys ascending.
            writer.mapHeader(5)
            writer.uint(keyOp); writer.uint(opIsAlgorithmSupported)
            writer.uint(keyHandle); writer.bytes(handle)
            writer.uint(keyToken); writer.bytes(token)
            writer.uint(keyOperation); writer.uint(operation)
            writer.uint(keyAlgorithm); writer.text(algorithm)
        case let .copyAttributes(handle):
            // map(3) { 0: 9, 2: handle, 7: token }, keys ascending.
            writer.mapHeader(3)
            writer.uint(keyOp); writer.uint(opCopyAttributes)
            writer.uint(keyHandle); writer.bytes(handle)
            writer.uint(keyToken); writer.bytes(token)
        case let .decrypt(handle, algorithm, ciphertext):
            // map(5) { 0: 10, 2: handle, 7: token, 19: algorithm, 22: ciphertext }, ascending.
            writer.mapHeader(5)
            writer.uint(keyOp); writer.uint(opDecrypt)
            writer.uint(keyHandle); writer.bytes(handle)
            writer.uint(keyToken); writer.bytes(token)
            writer.uint(keyAlgorithm); writer.text(algorithm)
            writer.uint(keyCiphertext); writer.bytes(ciphertext)
        case let .keyExchange(handle, algorithm, peerPublicKey, parameters):
            // map(6) { 0: 11, 2: handle, 7: token, 19: algorithm, 23: peer key, 25: params }, ascending.
            writer.mapHeader(6)
            writer.uint(keyOp); writer.uint(opKeyExchange)
            writer.uint(keyHandle); writer.bytes(handle)
            writer.uint(keyToken); writer.bytes(token)
            writer.uint(keyAlgorithm); writer.text(algorithm)
            writer.uint(keyPeerKey); writer.bytes(peerPublicKey)
            writer.uint(keyParameters); writer.bytes(parameters)
        case let .updateTag(handle, appTag, udid):
            // map(5) { 0: 12, 2: handle, 7: token, 15: udid, 16: appTag }, keys ascending.
            writer.mapHeader(5)
            writer.uint(keyOp); writer.uint(opUpdate)
            writer.uint(keyHandle); writer.bytes(handle)
            writer.uint(keyToken); writer.bytes(token)
            writer.uint(keyUDID); writer.text(udid)
            writer.uint(keyAppTag); writer.bytes(appTag)
        }
        return writer.data
    }

    /// Pack key entries into one byte string: a 2-byte count, then for each a 1-byte
    /// handle length and handle, a 1-byte public-key length and key, and a 2-byte tag
    /// length and tag, all big-endian. Both codecs agree on this layout byte for byte.
    static func packEntries(_ entries: [KeyEntry]) -> Data {
        var d = Data()
        d.append(UInt8(truncatingIfNeeded: entries.count >> 8))
        d.append(UInt8(truncatingIfNeeded: entries.count))
        for e in entries {
            d.append(UInt8(e.handle.count)); d.append(e.handle)
            d.append(UInt8(e.publicKey.count)); d.append(e.publicKey)
            d.append(UInt8(truncatingIfNeeded: e.appTag.count >> 8))
            d.append(UInt8(truncatingIfNeeded: e.appTag.count)); d.append(e.appTag)
        }
        return d
    }

    /// Inverse of `packEntries`. Throws on a truncated or inconsistent blob.
    static func unpackEntries(_ blob: Data) throws -> [KeyEntry] {
        let b = [UInt8](blob)
        var i = 0
        func u8() throws -> Int {
            guard i < b.count else { throw ProtocolError.truncated }
            defer { i += 1 }
            return Int(b[i])
        }
        func take(_ n: Int) throws -> Data {
            guard n >= 0, b.count - i >= n else { throw ProtocolError.truncated }
            defer { i += n }
            return Data(b[i ..< i + n])
        }
        let count = (try u8() << 8) | (try u8())
        var entries: [KeyEntry] = []
        for _ in 0 ..< count {
            let handle = try take(try u8())
            let publicKey = try take(try u8())
            let tagLen = (try u8() << 8) | (try u8())
            entries.append(KeyEntry(handle: handle, publicKey: publicKey, appTag: try take(tagLen)))
        }
        guard i == b.count else { throw ProtocolError.trailingBytes }
        return entries
    }

    /// The capability token from a request, key 7. Read before the op so the
    /// AuthGate can reject without interpreting the operation.
    public static func token(in payload: Data) throws -> Data {
        try CBORMap(decoding: payload).bytes(keyToken)
    }

    /// The interposer-reported app id from a request, key 14, if present. Read alongside
    /// the token to drive the approval prompt; it is guest-reported, so it names the app
    /// but gates nothing.
    public static func appID(in payload: Data) -> String? {
        (try? CBORMap(decoding: payload))?.optionalText(keyAppID)
    }

    /// The guest-reported display name from a HELLO, key 28, if present. Guest-reported and
    /// untrusted: the caller clamps and sanitizes it before display, and it gates nothing.
    public static func appDisplayName(in payload: Data) -> String? {
        (try? CBORMap(decoding: payload))?.optionalText(keyAppDisplayName)
    }

    /// The guest-reported app icon from a HELLO, key 29, as raw bytes, if present. Guest-reported
    /// and untrusted: the caller validates it as a bounded PNG before display.
    public static func appIcon(in payload: Data) -> Data? {
        (try? CBORMap(decoding: payload))?.optionalBytes(keyAppIcon)
    }

    /// Decode a request payload, dispatching on the op in key 0.
    ///
    /// - Throws: `ProtocolError` when the bytes are not canonical CBOR, a
    ///   required field is absent, or the op is unknown.
    public static func decodeRequest(_ payload: Data) throws -> Request {
        let map = try CBORMap(decoding: payload)
        switch try map.uint(keyOp) {
        case opHello:
            return .hello(version: try map.uint(keyVersion))
        case opGenerate:
            let keyClass = KeyClass(rawValue: map.optionalUint(keyClassKey) ?? 0) ?? .silent
            let accessControl = try map.optionalUint(keyAccessFlags).map {
                AccessControl(flags: $0, protection: try map.text(keyProtection))
            }
            // A permanent key carries both the udid (15) and the tag (16); the udid's
            // presence gates reading the tag, so an ephemeral generate is unchanged.
            let persistent = try map.optionalText(keyUDID).map {
                PersistentTag(appTag: try map.bytes(keyAppTag), udid: $0)
            }
            // The requested type (26) and size (27): present only when the interposer relayed
            // a non-default request; absent keeps the helper's P-256 default.
            let keyType = map.optionalText(keyKeyType)
            let keySizeInBits = map.optionalUint(keyKeySize)
            return .generate(keyClass: keyClass, accessControl: accessControl, persistent: persistent,
                             keyType: keyType, keySizeInBits: keySizeInBits)
        case opGetPublicKey:
            return .getPublicKey(handle: try map.bytes(keyHandle))
        case opSign:
            return .sign(handle: try map.bytes(keyHandle), algorithm: try map.text(keyAlgorithm),
                         input: try map.bytes(keyDigest))
        case opDelete:
            return .delete(handle: try map.bytes(keyHandle))
        case opFindByTag:
            return .findByTag(appTag: try map.bytes(keyAppTag), udid: try map.text(keyUDID))
        case opListKeys:
            return .listKeys(udid: try map.text(keyUDID))
        case opIsAlgorithmSupported:
            return .isAlgorithmSupported(handle: try map.bytes(keyHandle),
                                         operation: try map.uint(keyOperation),
                                         algorithm: try map.text(keyAlgorithm))
        case opCopyAttributes:
            return .copyAttributes(handle: try map.bytes(keyHandle))
        case opDecrypt:
            return .decrypt(handle: try map.bytes(keyHandle), algorithm: try map.text(keyAlgorithm),
                            ciphertext: try map.bytes(keyCiphertext))
        case opKeyExchange:
            return .keyExchange(handle: try map.bytes(keyHandle),
                                algorithm: try map.text(keyAlgorithm),
                                peerPublicKey: try map.bytes(keyPeerKey),
                                parameters: try map.bytes(keyParameters))
        case opUpdate:
            return .updateTag(handle: try map.bytes(keyHandle), appTag: try map.bytes(keyAppTag),
                              udid: try map.text(keyUDID))
        case let other:
            throw ProtocolError.badOpcode(other)
        }
    }

    /// Encode a response. Responses never carry the token.
    public static func encode(_ response: Response) -> Data {
        var writer = CBORWriter()
        switch response {
        case let .hello(version):
            writer.mapHeader(3)
            writer.uint(keyOp); writer.uint(opHello)
            writer.uint(keyStatus); writer.uint(statusOK)
            writer.uint(keyVersion); writer.uint(version)
        case let .generated(handle, publicKey):
            writer.mapHeader(4)
            writer.uint(keyOp); writer.uint(opGenerate)
            writer.uint(keyStatus); writer.uint(statusOK)
            writer.uint(keyHandle); writer.bytes(handle)
            writer.uint(keyPublicKey); writer.bytes(publicKey)
        case let .publicKey(publicKey):
            writer.mapHeader(3)
            writer.uint(keyOp); writer.uint(opGetPublicKey)
            writer.uint(keyStatus); writer.uint(statusOK)
            writer.uint(keyPublicKey); writer.bytes(publicKey)
        case let .signed(signature):
            writer.mapHeader(3)
            writer.uint(keyOp); writer.uint(opSign)
            writer.uint(keyStatus); writer.uint(statusOK)
            writer.uint(keySignature); writer.bytes(signature)
        case .deleted:
            writer.mapHeader(2)
            writer.uint(keyOp); writer.uint(opDelete)
            writer.uint(keyStatus); writer.uint(statusOK)
        case .updated:
            writer.mapHeader(2)
            writer.uint(keyOp); writer.uint(opUpdate)
            writer.uint(keyStatus); writer.uint(statusOK)
        case let .found(handle, publicKey):
            writer.mapHeader(4)
            writer.uint(keyOp); writer.uint(opFindByTag)
            writer.uint(keyStatus); writer.uint(statusOK)
            writer.uint(keyHandle); writer.bytes(handle)
            writer.uint(keyPublicKey); writer.bytes(publicKey)
        case let .listed(keys):
            writer.mapHeader(3)
            writer.uint(keyOp); writer.uint(opListKeys)
            writer.uint(keyStatus); writer.uint(statusOK)
            writer.uint(keyEntries); writer.bytes(packEntries(keys))
        case let .supported(flag):
            writer.mapHeader(3)
            writer.uint(keyOp); writer.uint(opIsAlgorithmSupported)
            writer.uint(keyStatus); writer.uint(statusOK)
            writer.uint(keyFlag); writer.uint(flag ? 1 : 0)
        case let .attributes(blob):
            writer.mapHeader(3)
            writer.uint(keyOp); writer.uint(opCopyAttributes)
            writer.uint(keyStatus); writer.uint(statusOK)
            writer.uint(keyAttributes); writer.bytes(blob)
        case let .decrypted(plaintext):
            writer.mapHeader(3)
            writer.uint(keyOp); writer.uint(opDecrypt)
            writer.uint(keyStatus); writer.uint(statusOK)
            writer.uint(keyResult); writer.bytes(plaintext)
        case let .derived(secret):
            writer.mapHeader(3)
            writer.uint(keyOp); writer.uint(opKeyExchange)
            writer.uint(keyStatus); writer.uint(statusOK)
            writer.uint(keyResult); writer.bytes(secret)
        case let .failure(code, message, domain):
            // The OSStatus domain is the default and omits key 13, keeping the M2
            // failure bytes; a non-default domain (LocalAuthentication) adds it.
            let includeDomain = domain != domainOSStatus
            writer.mapHeader(includeDomain ? 5 : 4)
            writer.uint(keyOp); writer.uint(opGenerate)
            writer.uint(keyStatus); writer.uint(statusError)
            writer.uint(keyError); writer.text(message)
            writer.uint(keyErrorCode); writer.int(code)
            if includeDomain { writer.uint(keyErrorDomain); writer.uint(domain) }
        }
        return writer.data
    }

    /// Decode a response payload, dispatching on status then op.
    ///
    /// - Throws: `ProtocolError` when the bytes are not canonical CBOR, a
    ///   required field is absent, or the op or status is unknown.
    public static func decodeResponse(_ payload: Data) throws -> Response {
        let map = try CBORMap(decoding: payload)
        let status = try map.uint(keyStatus)
        if status == statusError {
            return .failure(code: try map.int(keyErrorCode), message: try map.text(keyError),
                            domain: map.optionalUint(keyErrorDomain) ?? domainOSStatus)
        }
        guard status == statusOK else { throw ProtocolError.badStatus(status) }
        switch try map.uint(keyOp) {
        case opHello:
            return .hello(version: try map.uint(keyVersion))
        case opGenerate:
            return .generated(handle: try map.bytes(keyHandle), publicKey: try map.bytes(keyPublicKey))
        case opGetPublicKey:
            return .publicKey(try map.bytes(keyPublicKey))
        case opSign:
            return .signed(signature: try map.bytes(keySignature))
        case opDelete:
            return .deleted
        case opUpdate:
            return .updated
        case opFindByTag:
            return .found(handle: try map.bytes(keyHandle), publicKey: try map.bytes(keyPublicKey))
        case opListKeys:
            return .listed(keys: try unpackEntries(try map.bytes(keyEntries)))
        case opIsAlgorithmSupported:
            return .supported(try map.uint(keyFlag) != 0)
        case opCopyAttributes:
            return .attributes(try map.bytes(keyAttributes))
        case opDecrypt:
            return .decrypted(try map.bytes(keyResult))
        case opKeyExchange:
            return .derived(try map.bytes(keyResult))
        case let other:
            throw ProtocolError.badOpcode(other)
        }
    }
}
