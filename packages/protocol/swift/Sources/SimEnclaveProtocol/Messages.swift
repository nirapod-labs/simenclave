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
    public let flags: UInt64
    public let protection: String
    public init(flags: UInt64, protection: String) {
        self.flags = flags
        self.protection = protection
    }
}

/// A request from the interposer to the helper.
public enum Request: Equatable {
    case hello(version: UInt64)
    case generate(keyClass: KeyClass, accessControl: AccessControl?)
    case getPublicKey(handle: Data)
    case sign(handle: Data, digest: Data)
    case delete(handle: Data)
    case findByTag(appTag: Data, udid: String)
}

public extension Request {
    /// A generate with no relayed access control: the helper applies its default for
    /// the key class. Keeps the pre-M3 call sites unchanged.
    static func generate(keyClass: KeyClass) -> Request {
        .generate(keyClass: keyClass, accessControl: nil)
    }
}

/// A reply from the helper to the interposer.
public enum Response: Equatable {
    case hello(version: UInt64)
    case generated(handle: Data, publicKey: Data)
    case publicKey(Data)
    case signed(signature: Data)
    case deleted
    case failure(code: Int64, message: String, domain: UInt64)
    case found(handle: Data, publicKey: Data)
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
    static let statusOK: UInt64 = 0
    static let statusError: UInt64 = 1
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

    /// Error-domain selectors for key 13. The default is the OSStatus domain used
    /// before M3; the LocalAuthentication domain arrives with the biometry work.
    public static let domainOSStatus: UInt64 = 0
    public static let domainLAError: UInt64 = 1

    /// Encode a request, carrying the capability token in key 7. The token rides
    /// every request; the helper validates it before interpreting the op.
    public static func encode(_ request: Request, token: Data, appID: String? = nil) -> Data {
        var writer = CBORWriter()
        switch request {
        case let .hello(version):
            writer.mapHeader(3)
            writer.uint(keyOp); writer.uint(opHello)
            writer.uint(keyToken); writer.bytes(token)
            writer.uint(keyVersion); writer.uint(version)
        case let .generate(keyClass, accessControl):
            // op and token, then key 9 if biometry, the access control (11, 12) if
            // present, and the app id (14) if present, all keys ascending. The no-app-id
            // shapes keep the exact bytes the M0 through M2 interposer sends.
            let biometry = keyClass == .biometry
            var count = 2
            if biometry { count += 1 }
            if accessControl != nil { count += 2 }
            if appID != nil { count += 1 }
            writer.mapHeader(count)
            writer.uint(keyOp); writer.uint(opGenerate)
            writer.uint(keyToken); writer.bytes(token)
            if biometry { writer.uint(keyClassKey); writer.uint(KeyClass.biometry.rawValue) }
            if let ac = accessControl {
                writer.uint(keyAccessFlags); writer.uint(ac.flags)
                writer.uint(keyProtection); writer.text(ac.protection)
            }
            if let appID { writer.uint(keyAppID); writer.text(appID) }
        case let .getPublicKey(handle):
            writer.mapHeader(3)
            writer.uint(keyOp); writer.uint(opGetPublicKey)
            writer.uint(keyHandle); writer.bytes(handle)
            writer.uint(keyToken); writer.bytes(token)
        case let .sign(handle, digest):
            writer.mapHeader(4)
            writer.uint(keyOp); writer.uint(opSign)
            writer.uint(keyHandle); writer.bytes(handle)
            writer.uint(keyDigest); writer.bytes(digest)
            writer.uint(keyToken); writer.bytes(token)
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
        }
        return writer.data
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
            return .generate(keyClass: keyClass, accessControl: accessControl)
        case opGetPublicKey:
            return .getPublicKey(handle: try map.bytes(keyHandle))
        case opSign:
            return .sign(handle: try map.bytes(keyHandle), digest: try map.bytes(keyDigest))
        case opDelete:
            return .delete(handle: try map.bytes(keyHandle))
        case opFindByTag:
            return .findByTag(appTag: try map.bytes(keyAppTag), udid: try map.text(keyUDID))
        case let other:
            throw ProtocolError.badOpcode(other)
        }
    }

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
        case let .found(handle, publicKey):
            writer.mapHeader(4)
            writer.uint(keyOp); writer.uint(opFindByTag)
            writer.uint(keyStatus); writer.uint(statusOK)
            writer.uint(keyHandle); writer.bytes(handle)
            writer.uint(keyPublicKey); writer.bytes(publicKey)
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
        case opFindByTag:
            return .found(handle: try map.bytes(keyHandle), publicKey: try map.bytes(keyPublicKey))
        case let other:
            throw ProtocolError.badOpcode(other)
        }
    }
}
