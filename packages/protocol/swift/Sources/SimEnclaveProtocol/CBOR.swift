import Foundation

/// The subset of CBOR (RFC 8949) the protocol uses: unsigned integers, byte
/// strings, text strings, and definite-length maps keyed by unsigned integers.
/// Hand-written rather than pulled from a dependency because the surface is this
/// small and both ends, this codec and the C one, must agree byte for byte.
enum CBORValue: Equatable {
    case uint(UInt64)
    case bytes(Data)
    case text(String)
}

struct CBORWriter {
    private(set) var data = Data()

    mutating func mapHeader(_ count: Int) { writeHead(major: 5, value: UInt64(count)) }
    mutating func uint(_ value: UInt64) { writeHead(major: 0, value: value) }

    mutating func bytes(_ value: Data) {
        writeHead(major: 2, value: UInt64(value.count))
        data.append(value)
    }

    mutating func text(_ value: String) {
        let utf8 = Data(value.utf8)
        writeHead(major: 3, value: UInt64(utf8.count))
        data.append(utf8)
    }

    /// Emit a major type and an argument in the shortest form, which is what
    /// canonical CBOR requires.
    private mutating func writeHead(major: UInt8, value: UInt64) {
        let tag = major << 5
        switch value {
        case 0 ..< 24:
            data.append(tag | UInt8(value))
        case 24 ..< 0x100:
            data.append(tag | 24)
            data.append(UInt8(value))
        case 0x100 ..< 0x1_0000:
            data.append(tag | 25)
            appendBigEndian(value, bytes: 2)
        case 0x1_0000 ..< 0x1_0000_0000:
            data.append(tag | 26)
            appendBigEndian(value, bytes: 4)
        default:
            data.append(tag | 27)
            appendBigEndian(value, bytes: 8)
        }
    }

    private mutating func appendBigEndian(_ value: UInt64, bytes: Int) {
        for shift in stride(from: (bytes - 1) * 8, through: 0, by: -8) {
            data.append(UInt8((value >> UInt64(shift)) & 0xFF))
        }
    }
}

struct CBORReader {
    private let data: Data
    private var offset: Int

    init(_ data: Data) {
        self.data = data
        offset = 0
    }

    var isAtEnd: Bool { offset == data.count }

    func expectEnd() throws {
        guard isAtEnd else { throw ProtocolError.trailingBytes }
    }

    mutating func mapHeader() throws -> Int {
        let head = try byte()
        guard head >> 5 == 5 else { throw ProtocolError.typeMismatch }
        return Int(try argument(head & 0x1F))
    }

    mutating func uint() throws -> UInt64 {
        let head = try byte()
        guard head >> 5 == 0 else { throw ProtocolError.typeMismatch }
        return try argument(head & 0x1F)
    }

    /// Read one value of whichever supported type comes next.
    mutating func value() throws -> CBORValue {
        let head = try byte()
        let major = head >> 5
        let additional = head & 0x1F
        switch major {
        case 0:
            return .uint(try argument(additional))
        case 2:
            return .bytes(try take(Int(try argument(additional))))
        case 3:
            return .text(String(decoding: try take(Int(try argument(additional))), as: UTF8.self))
        default:
            throw ProtocolError.typeMismatch
        }
    }

    private mutating func byte() throws -> UInt8 {
        guard offset < data.count else { throw ProtocolError.truncated }
        let value = data[data.startIndex + offset]
        offset += 1
        return value
    }

    private mutating func take(_ count: Int) throws -> Data {
        guard count >= 0, offset + count <= data.count else { throw ProtocolError.truncated }
        let start = data.startIndex + offset
        let slice = data[start ..< start + count]
        offset += count
        return Data(slice)
    }

    /// Decode the argument that follows a head byte. Indefinite length and the
    /// reserved additional-info values are rejected.
    private mutating func argument(_ additional: UInt8) throws -> UInt64 {
        switch additional {
        case 0 ..< 24:
            return UInt64(additional)
        case 24:
            let value = UInt64(try byte())
            guard value >= 24 else { throw ProtocolError.nonCanonical }
            return value
        case 25:
            let value = try bigEndian(2)
            guard value > 0xFF else { throw ProtocolError.nonCanonical }
            return value
        case 26:
            let value = try bigEndian(4)
            guard value > 0xFFFF else { throw ProtocolError.nonCanonical }
            return value
        case 27:
            let value = try bigEndian(8)
            guard value > 0xFFFF_FFFF else { throw ProtocolError.nonCanonical }
            return value
        default:
            throw ProtocolError.malformed
        }
    }

    private mutating func bigEndian(_ count: Int) throws -> UInt64 {
        var value: UInt64 = 0
        for byte in try take(count) { value = (value << 8) | UInt64(byte) }
        return value
    }
}

/// A decoded message map, with type-checked accessors per key.
struct CBORMap {
    private let entries: [UInt64: CBORValue]

    /// Read a definite-length map of `uint => value` pairs, with no bytes left
    /// over.
    init(decoding payload: Data) throws {
        var reader = CBORReader(payload)
        let count = try reader.mapHeader()
        var entries: [UInt64: CBORValue] = [:]
        for _ in 0 ..< count {
            let key = try reader.uint()
            guard entries[key] == nil else { throw ProtocolError.duplicateKey(key) }
            entries[key] = try reader.value()
        }
        try reader.expectEnd()
        self.entries = entries
    }

    func uint(_ key: UInt64) throws -> UInt64 {
        guard case let .uint(value)? = entries[key] else { throw ProtocolError.missingField(key) }
        return value
    }

    func bytes(_ key: UInt64) throws -> Data {
        guard case let .bytes(value)? = entries[key] else { throw ProtocolError.missingField(key) }
        return value
    }

    func text(_ key: UInt64) throws -> String {
        guard case let .text(value)? = entries[key] else { throw ProtocolError.missingField(key) }
        return value
    }
}
