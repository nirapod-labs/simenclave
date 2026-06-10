import Foundation
import SimEnclaveHostCore
import SimEnclaveProtocol

/// Turns a decoded request into a response by driving the Mac Secure Enclave.
/// One `SecureEnclaveService` is shared across every connection, so a key from a
/// `GENERATE` on one connection is signable by a `SIGN` on the next.
public struct RequestRouter: Sendable {
    private let service: SecureEnclaveService

    public init(service: SecureEnclaveService) {
        self.service = service
    }

    public func handle(_ request: Request) -> Response {
        do {
            switch request {
            case .generate:
                let (handle, publicKey) = try service.generate()
                return .generated(handle: handle, publicKey: publicKey)
            case let .sign(handle, digest):
                return .signed(signature: try service.sign(handle: handle, digest: digest))
            }
        } catch {
            return .failure(String(describing: error))
        }
    }
}
