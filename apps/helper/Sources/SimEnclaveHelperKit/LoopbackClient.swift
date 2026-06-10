import Foundation
import SimEnclaveProtocol

#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

/// A one-shot loopback client: connect, send one request, read one response,
/// close. The interposer's C transport mirrors this; the helper's own tests and
/// `simenclavectl` use this Swift one.
public struct LoopbackClient: Sendable {
    public let port: UInt16

    public init(port: UInt16) {
        self.port = port
    }

    public func send(_ request: Request, token: CapabilityToken, appID: String? = nil) throws -> Response {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { throw SocketError.system("socket: \(errnoText())") }
        defer { close(fd) }

        var address = sockaddr_in()
        address.sin_family = sa_family_t(AF_INET)
        address.sin_port = port.bigEndian
        address.sin_addr.s_addr = inet_addr("127.0.0.1")

        let connected = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard connected == 0 else { throw SocketError.system("connect: \(errnoText())") }

        // A receive timeout, so a stalled helper surfaces as a clean error rather than a
        // hung caller: a regressed accept loop would otherwise block this read forever.
        var timeout = timeval(tv_sec: 10, tv_usec: 0)
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))

        try writeFrame(fd, Wire.encode(request, token: token.bytes, appID: appID))
        return try Wire.decodeResponse(readFrame(fd))
    }
}
