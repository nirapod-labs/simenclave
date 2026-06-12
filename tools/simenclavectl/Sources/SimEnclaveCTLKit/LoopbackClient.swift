// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

import Foundation
import SimEnclaveProtocol

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

/// A synchronous loopback client to a running helper. It connects to 127.0.0.1 on
/// the helper's port, frames a token-authenticated request, and decodes the reply,
/// mirroring the wire the interposer's C client speaks: a big-endian `u32` length
/// prefix then a CBOR payload, in both directions. One exchange per connection,
/// because the helper handles one request per accepted socket.
public struct LoopbackClient {
    public enum ClientError: Error, Equatable {
        /// Nothing is listening on the port; the helper is not running.
        case connectionRefused
        /// The socket read or write timed out.
        case timedOut
        /// The peer closed the connection before a full frame arrived.
        case closedEarly
        /// A system call failed; the string is the `errno` description.
        case system(String)
    }

    let port: UInt16
    let token: Data
    let timeout: TimeInterval

    /// - Parameters:
    ///   - port: the helper's loopback port.
    ///   - token: the 32-byte capability token the helper expects.
    ///   - timeout: per-read and per-write timeout in seconds, so a hung helper
    ///     never blocks the CLI forever.
    public init(port: UInt16, token: Data, timeout: TimeInterval = 5) {
        self.port = port
        self.token = token
        self.timeout = timeout
    }

    /// Send one request and return the decoded response, opening and closing a
    /// fresh connection for the exchange. `appID` scopes the ops that namespace by
    /// app (list-keys, find-by-tag), the way an injected app's bundle id does.
    public func send(_ request: Request, appID: String? = nil) throws -> Response {
        let descriptor = try openConnection()
        defer { close(descriptor) }
        try writeAll(descriptor, Framing.frame(Wire.encode(request, token: token, appID: appID)))
        let length = try Framing.payloadLength(try readExactly(descriptor, count: 4))
        return try Wire.decodeResponse(try readExactly(descriptor, count: length))
    }

    private func openConnection() throws -> Int32 {
        let descriptor = socket(AF_INET, SOCK_STREAM, 0)
        guard descriptor >= 0 else { throw ClientError.system(Self.errnoMessage()) }
        var window = timeval(tv_sec: Int(timeout), tv_usec: 0)
        let optionSize = socklen_t(MemoryLayout<timeval>.size)
        setsockopt(descriptor, SOL_SOCKET, SO_RCVTIMEO, &window, optionSize)
        setsockopt(descriptor, SOL_SOCKET, SO_SNDTIMEO, &window, optionSize)

        var address = sockaddr_in()
        address.sin_family = sa_family_t(AF_INET)
        address.sin_port = port.bigEndian
        address.sin_addr.s_addr = inet_addr("127.0.0.1")
        let result = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                connect(descriptor, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard result == 0 else {
            let failure = errno
            close(descriptor)
            throw failure == ECONNREFUSED
                ? ClientError.connectionRefused
                : ClientError.system(Self.errnoMessage(failure))
        }
        return descriptor
    }

    private func writeAll(_ descriptor: Int32, _ data: Data) throws {
        try data.withUnsafeBytes { raw in
            guard let base = raw.bindMemory(to: UInt8.self).baseAddress else { return }
            var offset = 0
            while offset < data.count {
                let written = write(descriptor, base + offset, data.count - offset)
                if written <= 0 {
                    if errno == EAGAIN || errno == EWOULDBLOCK { throw ClientError.timedOut }
                    throw ClientError.system(Self.errnoMessage())
                }
                offset += written
            }
        }
    }

    private func readExactly(_ descriptor: Int32, count: Int) throws -> Data {
        var out = Data()
        out.reserveCapacity(count)
        var buffer = [UInt8](repeating: 0, count: min(max(count, 1), 4096))
        while out.count < count {
            let want = min(count - out.count, buffer.count)
            let got = buffer.withUnsafeMutableBytes { read(descriptor, $0.baseAddress, want) }
            if got == 0 { throw ClientError.closedEarly }
            if got < 0 {
                if errno == EAGAIN || errno == EWOULDBLOCK { throw ClientError.timedOut }
                throw ClientError.system(Self.errnoMessage())
            }
            out.append(contentsOf: buffer[0 ..< got])
        }
        return out
    }

    static func errnoMessage(_ code: Int32 = errno) -> String {
        String(cString: strerror(code))
    }
}
