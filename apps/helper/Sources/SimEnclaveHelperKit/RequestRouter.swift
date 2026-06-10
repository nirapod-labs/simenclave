import Foundation
import SimEnclaveHostCore
import SimEnclaveProtocol

/// The OSStatus codes the helper returns. M1 lands the auth failure and a
/// generic failure; the full device-to-code table is M3.
enum OSStatusCode {
    static let authFailed: Int64 = -25293 // errSecAuthFailed
    static let itemNotFound: Int64 = -25300 // errSecItemNotFound
    static let internalError: Int64 = -2070 // errSecInternalComponent
}

/// Turns a request into a response by driving the Mac Secure Enclave, behind the
/// capability-token gate. One `SecureEnclaveService` is shared across every
/// connection, so a key from a `GENERATE` on one connection is signable by a
/// `SIGN` on the next.
public struct RequestRouter: Sendable {
    private let service: SecureEnclaveService
    private let gate: AuthGate

    public init(service: SecureEnclaveService, gate: AuthGate) {
        self.service = service
        self.gate = gate
    }

    /// Validate the token, then dispatch. The gate runs before the operation is
    /// interpreted, so a caller without the token learns nothing about the op
    /// surface beyond the auth failure.
    public func respond(toPayload payload: Data) -> Response {
        guard let presented = (try? Wire.token(in: payload)).flatMap(CapabilityToken.init(bytes:)),
              gate.accepts(presented)
        else {
            return .failure(code: OSStatusCode.authFailed, message: "invalid capability token")
        }
        do {
            return handle(try Wire.decodeRequest(payload))
        } catch {
            return .failure(code: OSStatusCode.internalError, message: String(describing: error))
        }
    }

    func handle(_ request: Request) -> Response {
        do {
            switch request {
            case let .hello(version):
                return version == Wire.version1
                    ? .hello(version: Wire.version1)
                    : .failure(code: OSStatusCode.internalError,
                               message: "unsupported protocol version \(version)")
            case let .generate(keyClass):
                let (handle, publicKey) = try service.generate(requiresBiometry: keyClass == .biometry)
                return .generated(handle: handle, publicKey: publicKey)
            case let .getPublicKey(handle):
                return .publicKey(try service.publicKey(for: handle))
            case let .sign(handle, digest):
                return .signed(signature: try service.sign(handle: handle, digest: digest))
            case let .delete(handle):
                try service.delete(handle: handle)
                return .deleted
            case .findByTag:
                // The durable keychain lookup is M3 slice 5; until the helper keeps a
                // persistent store, a find by tag always misses.
                return .failure(code: OSStatusCode.itemNotFound, message: "no persisted key")
            }
        } catch SecureEnclaveService.Failure.unknownHandle {
            return .failure(code: OSStatusCode.itemNotFound, message: "unknown handle")
        } catch {
            return .failure(code: OSStatusCode.internalError, message: String(describing: error))
        }
    }
}
