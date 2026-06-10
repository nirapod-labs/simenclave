import Foundation

/// A request from the interposer to the helper.
public enum Request: Equatable {
    case generate
    case getPublicKey(handle: Data)
    case sign(handle: Data, digest: Data)
    case delete(handle: Data)
}

/// A reply from the helper to the interposer.
public enum Response: Equatable {
    case generated(handle: Data, publicKey: Data)
    case publicKey(Data)
    case signed(signature: Data)
    case deleted
    case failure(code: Int64, message: String)
}

/// The version-1 message codec: a CBOR map in and out (see `SPEC.md`). Socket
/// I/O and framing live elsewhere; this is the pure payload layer.
public enum Wire {
    static let opGenerate: UInt64 = 2
    static let opGetPublicKey: UInt64 = 3
    static let opSign: UInt64 = 4
    static let opDelete: UInt64 = 5
    static let statusOK: UInt64 = 0
    static let statusError: UInt64 = 1

    static let keyOp: UInt64 = 0
    static let keyStatus: UInt64 = 1
    static let keyHandle: UInt64 = 2
    static let keyPublicKey: UInt64 = 3
    static let keyDigest: UInt64 = 4
    static let keySignature: UInt64 = 5
    static let keyError: UInt64 = 6
    static let keyToken: UInt64 = 7
    static let keyErrorCode: UInt64 = 10

    /// Encode a request, carrying the capability token in key 7. The token rides
    /// every request; the helper validates it before interpreting the op.
    public static func encode(_ request: Request, token: Data) -> Data {
        var writer = CBORWriter()
        switch request {
        case .generate:
            writer.mapHeader(2)
            writer.uint(keyOp); writer.uint(opGenerate)
            writer.uint(keyToken); writer.bytes(token)
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
        }
        return writer.data
    }

    /// The capability token from a request, key 7. Read before the op so the
    /// AuthGate can reject without interpreting the operation.
    public static func token(in payload: Data) throws -> Data {
        try CBORMap(decoding: payload).bytes(keyToken)
    }

    public static func decodeRequest(_ payload: Data) throws -> Request {
        let map = try CBORMap(decoding: payload)
        switch try map.uint(keyOp) {
        case opGenerate:
            return .generate
        case opGetPublicKey:
            return .getPublicKey(handle: try map.bytes(keyHandle))
        case opSign:
            return .sign(handle: try map.bytes(keyHandle), digest: try map.bytes(keyDigest))
        case opDelete:
            return .delete(handle: try map.bytes(keyHandle))
        case let other:
            throw ProtocolError.badOpcode(other)
        }
    }

    public static func encode(_ response: Response) -> Data {
        var writer = CBORWriter()
        switch response {
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
        case let .failure(code, message):
            writer.mapHeader(4)
            writer.uint(keyOp); writer.uint(opGenerate)
            writer.uint(keyStatus); writer.uint(statusError)
            writer.uint(keyError); writer.text(message)
            writer.uint(keyErrorCode); writer.int(code)
        }
        return writer.data
    }

    public static func decodeResponse(_ payload: Data) throws -> Response {
        let map = try CBORMap(decoding: payload)
        let status = try map.uint(keyStatus)
        if status == statusError {
            return .failure(code: try map.int(keyErrorCode), message: try map.text(keyError))
        }
        guard status == statusOK else { throw ProtocolError.badStatus(status) }
        switch try map.uint(keyOp) {
        case opGenerate:
            return .generated(handle: try map.bytes(keyHandle), publicKey: try map.bytes(keyPublicKey))
        case opGetPublicKey:
            return .publicKey(try map.bytes(keyPublicKey))
        case opSign:
            return .signed(signature: try map.bytes(keySignature))
        case opDelete:
            return .deleted
        case let other:
            throw ProtocolError.badOpcode(other)
        }
    }
}
