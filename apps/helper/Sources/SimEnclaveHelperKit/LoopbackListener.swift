import Foundation
import SimEnclaveProtocol

#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

/// A loopback TCP server bound to `127.0.0.1`. It accepts connections on a
/// background thread and serves framed CBOR requests through the router until the
/// peer closes. M0 has no authentication; the capability token is M1.
///
/// Loopback TCP, not a Unix socket, because the simulator shares the host network
/// stack but virtualizes its filesystem, so a host socket file is not reachable
/// from a simulated app.
public final class LoopbackListener: @unchecked Sendable {
    private let router: RequestRouter
    private var listenFD: Int32 = -1
    private var worker: Thread?
    private var running = false

    /// The bound port, valid after `start`. Zero before then.
    public private(set) var port: UInt16 = 0

    public init(router: RequestRouter) {
        self.router = router
    }

    /// Bind, listen, and start accepting. Pass `0` to take an ephemeral port,
    /// then read the chosen port from `port`.
    public func start(port requestedPort: UInt16 = 0) throws {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { throw SocketError.system("socket: \(errnoText())") }

        var reuse: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, socklen_t(MemoryLayout<Int32>.size))

        var address = sockaddr_in()
        address.sin_family = sa_family_t(AF_INET)
        address.sin_port = requestedPort.bigEndian
        address.sin_addr.s_addr = inet_addr("127.0.0.1")

        let bound = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard bound == 0 else { close(fd); throw SocketError.system("bind: \(errnoText())") }
        guard listen(fd, 16) == 0 else { close(fd); throw SocketError.system("listen: \(errnoText())") }

        port = boundPort(fd)
        listenFD = fd
        running = true

        let worker = Thread { [weak self] in self?.acceptLoop() }
        worker.stackSize = 1 << 20
        worker.name = "simenclave.loopback"
        self.worker = worker
        worker.start()
    }

    /// Stop accepting and close the listening socket.
    public func stop() {
        running = false
        if listenFD >= 0 {
            close(listenFD)
            listenFD = -1
        }
    }

    private func acceptLoop() {
        while running {
            let client = accept(listenFD, nil, nil)
            if client < 0 {
                if running { continue }
                break
            }
            serve(client)
        }
    }

    private func serve(_ fd: Int32) {
        defer { close(fd) }
        while true {
            do {
                let request = try Wire.decodeRequest(readFrame(fd))
                try writeFrame(fd, Wire.encode(router.handle(request)))
            } catch {
                // Peer closed, or a malformed frame: drop this connection.
                return
            }
        }
    }

    private func boundPort(_ fd: Int32) -> UInt16 {
        var address = sockaddr_in()
        var length = socklen_t(MemoryLayout<sockaddr_in>.size)
        withUnsafeMutablePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                _ = getsockname(fd, $0, &length)
            }
        }
        return UInt16(bigEndian: address.sin_port)
    }
}

func errnoText() -> String { String(cString: strerror(errno)) }
