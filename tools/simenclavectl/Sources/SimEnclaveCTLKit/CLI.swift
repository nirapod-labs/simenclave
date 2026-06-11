// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

import Foundation
import SimEnclaveProtocol

/// The command dispatcher. Each command prints one JSON object to stdout and
/// returns a process exit code: 0 on success, 1 when the operation failed (for
/// example the helper is unreachable), 2 on a usage error. Diagnostics go to
/// stderr, so stdout stays a clean JSON stream a person or an agent can pipe.
public enum CLI {
    /// Run the CLI with a full argv (including the program name).
    public static func run(_ arguments: [String]) -> Int32 {
        let arguments = Array(arguments.dropFirst())
        guard let command = arguments.first else {
            printUsage()
            return 2
        }
        let rest = Array(arguments.dropFirst())
        switch command {
        case "doctor": return doctor(rest)
        case "status": return status(rest)
        case "token": return token(rest)
        case "help", "-h", "--help": printUsage(); return 0
        default:
            printError("unknown command: \(command)")
            printUsage()
            return 2
        }
    }

    /// `doctor` — always emits the full picture, then exits 0 only when the helper
    /// is reachable and answers a HELLO. The one command to run when something is
    /// wired wrong: it reports each step (directory, port, token, reach, hello).
    static func doctor(_ arguments: [String]) -> Int32 {
        let flags = Flags(arguments)
        let directory = flags.directory ?? Discovery.defaultDirectory
        let port = Discovery.port(override: flags.port, directory: directory)
        let token = Discovery.token(directory: directory)

        var reachable = false
        var helloOK = false
        var version: Int?
        if let port, let token {
            switch hello(port: port, token: token) {
            case let .success(negotiated):
                reachable = true
                helloOK = true
                version = negotiated
            case .refused:
                reachable = false
            case .failed:
                reachable = true
            }
        }
        let healthy = reachable && helloOK
        emit(.object([
            ("directory", .string(directory)),
            ("port", port.map { .int(Int($0)) } ?? .null),
            ("token_found", .bool(token != nil)),
            ("reachable", .bool(reachable)),
            ("hello_ok", .bool(helloOK)),
            ("version", version.map { .int($0) } ?? .null),
            ("healthy", .bool(healthy)),
        ]))
        return healthy ? 0 : 1
    }

    /// `status` — negotiate a HELLO and report the protocol version the helper speaks.
    static func status(_ arguments: [String]) -> Int32 {
        let flags = Flags(arguments)
        let directory = flags.directory ?? Discovery.defaultDirectory
        guard let port = Discovery.port(override: flags.port, directory: directory),
              let token = Discovery.token(directory: directory) else {
            printError("no running helper found (no port/token in \(directory))")
            emit(.object([("connected", .bool(false)), ("port", .null), ("version", .null)]))
            return 1
        }
        switch hello(port: port, token: token) {
        case let .success(version):
            emit(.object([
                ("connected", .bool(true)),
                ("port", .int(Int(port))),
                ("version", .int(version)),
            ]))
            return 0
        case .refused:
            printError("nothing is listening on port \(port); is the helper running?")
        case let .failed(message):
            printError("could not negotiate a HELLO on port \(port): \(message)")
        }
        emit(.object([("connected", .bool(false)), ("port", .int(Int(port))), ("version", .null)]))
        return 1
    }

    /// `token` — print the helper's port and capability token, the values an
    /// injected debug scheme needs (`SIMENCLAVE_PORT`, `SIMENCLAVE_TOKEN`).
    static func token(_ arguments: [String]) -> Int32 {
        let flags = Flags(arguments)
        let directory = flags.directory ?? Discovery.defaultDirectory
        guard let port = Discovery.port(override: flags.port, directory: directory),
              let token = Discovery.token(directory: directory) else {
            printError("no helper token/port in \(directory); is the helper running?")
            return 1
        }
        emit(.object([("port", .int(Int(port))), ("token", .string(Discovery.encodeHex(token)))]))
        return 0
    }

    // MARK: - HELLO

    private enum HelloResult {
        case success(Int)
        case refused
        case failed(String)
    }

    private static func hello(port: UInt16, token: Data) -> HelloResult {
        do {
            let response = try LoopbackClient(port: port, token: token).send(.hello(version: Wire.version1))
            guard case let .hello(version) = response else {
                return .failed("unexpected response to HELLO")
            }
            return .success(Int(version))
        } catch LoopbackClient.ClientError.connectionRefused {
            return .refused
        } catch {
            return .failed("\(error)")
        }
    }

    // MARK: - Flags

    /// The two overrides every command accepts: `--port <n>` and `--dir <path>`.
    private struct Flags {
        var port: UInt16?
        var directory: String?

        init(_ arguments: [String]) {
            var index = 0
            while index < arguments.count {
                switch arguments[index] {
                case "--port" where index + 1 < arguments.count:
                    port = UInt16(arguments[index + 1])
                    index += 1
                case "--dir" where index + 1 < arguments.count:
                    directory = arguments[index + 1]
                    index += 1
                default:
                    break
                }
                index += 1
            }
        }
    }

    // MARK: - Output

    static func emit(_ value: JSONValue) {
        print(value.encoded())
    }

    static func printError(_ message: String) {
        FileHandle.standardError.write(Data((message + "\n").utf8))
    }

    static func printUsage() {
        printError("""
        simenclavectl — drive a running SimEnclave helper

        usage: simenclavectl <command> [--port <n>] [--dir <path>]

          doctor    check the helper is reachable and answers a HELLO (JSON)
          status    report the protocol version the helper speaks (JSON)
          token     print the helper's port and capability token (JSON)
          help      show this message

        The port and token are discovered from SIMENCLAVE_PORT / SIMENCLAVE_TOKEN,
        then from the helper's support directory; --port and --dir override them.
        """)
    }
}
