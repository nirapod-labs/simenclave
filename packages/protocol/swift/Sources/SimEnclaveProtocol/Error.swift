import Foundation

/// A decode that failed because the bytes did not match the wire format in
/// `SPEC.md`. Encoding never fails.
public enum ProtocolError: Error, Equatable {
    /// A field or frame ran past the end of the buffer.
    case truncated
    /// A CBOR item used an encoding this codec does not accept (indefinite
    /// length, an unsupported major type, a reserved additional-info value).
    case malformed
    /// A CBOR item was a different major type than the field required.
    case typeMismatch
    /// Bytes remained after a complete message was decoded.
    case trailingBytes
    /// The `op` field held a value this version does not define.
    case badOpcode(UInt64)
    /// The `status` field held a value other than OK or ERROR.
    case badStatus(UInt64)
    /// A required map key was absent.
    case missingField(UInt64)
    /// A frame's length prefix exceeded `Framing.maxFrame`.
    case frameTooLarge(Int)
}
