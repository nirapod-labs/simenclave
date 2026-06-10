import Foundation

/// A request from the interposer to the helper.
public enum Request: Equatable {
    case generate
    case sign(handle: Data, digest: Data)
}

/// A reply from the helper to the interposer.
public enum Response: Equatable {
    case generated(handle: Data, publicKey: Data)
    case signed(signature: Data)
    case failure(String)
}

/// The version-1 message codec: a CBOR map in and out (see `SPEC.md`). Socket
/// I/O and framing live elsewhere; this is the pure payload layer.
public enum Wire {
    static let opGenerate: UInt64 = 2
    static let opSign: UInt64 = 4
    static let statusOK: UInt64 = 0
    static let statusError: UInt64 = 1

    static let keyOp: UInt64 = 0
    static let keyStatus: UInt64 = 1
    static let keyHandle: UInt64 = 2
    static let keyPublicKey: UInt64 = 3
    static let keyDigest: UInt64 = 4
    static let keySignature: UInt64 = 5
    static let keyError: UInt64 = 6

    public static func encode(_ request: Request) -> Data {
        var writer = CBORWriter()
        switch request {
        case .generate:
            writer.mapHeader(1)
            writer.uint(keyOp); writer.uint(opGenerate)
        case let .sign(handle, digest):
            writer.mapHeader(3)
            writer.uint(keyOp); writer.uint(opSign)
            writer.uint(keyHandle); writer.bytes(handle)
            writer.uint(keyDigest); writer.bytes(digest)
        }
        return writer.data
    }

    public static func decodeRequest(_ payload: Data) throws -> Request {
        let map = try CBORMap(decoding: payload)
        switch try map.uint(keyOp) {
        case opGenerate:
            return .generate
        case opSign:
            return .sign(handle: try map.bytes(keyHandle), digest: try map.bytes(keyDigest))
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
        case let .signed(signature):
            writer.mapHeader(3)
            writer.uint(keyOp); writer.uint(opSign)
            writer.uint(keyStatus); writer.uint(statusOK)
            writer.uint(keySignature); writer.bytes(signature)
        case let .failure(message):
            writer.mapHeader(3)
            writer.uint(keyOp); writer.uint(opGenerate)
            writer.uint(keyStatus); writer.uint(statusError)
            writer.uint(keyError); writer.text(message)
        }
        return writer.data
    }

    public static func decodeResponse(_ payload: Data) throws -> Response {
        let map = try CBORMap(decoding: payload)
        let status = try map.uint(keyStatus)
        if status == statusError {
            return .failure(try map.text(keyError))
        }
        guard status == statusOK else { throw ProtocolError.badStatus(status) }
        switch try map.uint(keyOp) {
        case opGenerate:
            return .generated(handle: try map.bytes(keyHandle), publicKey: try map.bytes(keyPublicKey))
        case opSign:
            return .signed(signature: try map.bytes(keySignature))
        case let other:
            throw ProtocolError.badOpcode(other)
        }
    }
}
