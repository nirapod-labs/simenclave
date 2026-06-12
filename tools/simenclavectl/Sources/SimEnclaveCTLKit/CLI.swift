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
        case "init": return initialize(rest)
        case "keys": return keys(rest)
        case "sign": return sign(rest)
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
            case let .success(negotiated): reachable = true; helloOK = true; version = negotiated
            case .refused: reachable = false
            case .failed: reachable = true
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
        guard let endpoint = resolveEndpoint(flags) else {
            emit(.object([("connected", .bool(false)), ("port", .null), ("version", .null)]))
            return 1
        }
        switch hello(port: endpoint.port, token: endpoint.token) {
        case let .success(version):
            emit(.object([
                ("connected", .bool(true)),
                ("port", .int(Int(endpoint.port))),
                ("version", .int(version)),
            ]))
            return 0
        case .refused:
            printError("nothing is listening on port \(endpoint.port); is the helper running?")
        case let .failed(message):
            printError("could not negotiate a HELLO on port \(endpoint.port): \(message)")
        }
        emit(.object([
            ("connected", .bool(false)), ("port", .int(Int(endpoint.port))), ("version", .null),
        ]))
        return 1
    }

    /// `token` — print the helper's port and capability token.
    static func token(_ arguments: [String]) -> Int32 {
        guard let endpoint = resolveEndpoint(Flags(arguments)) else { return 1 }
        emit(.object([
            ("port", .int(Int(endpoint.port))),
            ("token", .string(Discovery.encodeHex(endpoint.token))),
        ]))
        return 0
    }

    /// `init` — emit the environment an injected debug scheme needs. With `--dylib`
    /// it includes DYLD_INSERT_LIBRARIES; the values map straight into the scheme's
    /// EnvironmentVariables. It only prints, so it never wires injection itself.
    static func initialize(_ arguments: [String]) -> Int32 {
        let flags = Flags(arguments)
        guard let endpoint = resolveEndpoint(flags) else { return 1 }
        var pairs: [(String, JSONValue)] = []
        if let dylib = flags["dylib"] {
            pairs.append(("DYLD_INSERT_LIBRARIES", .string(dylib)))
        }
        pairs.append(("SIMENCLAVE_PORT", .string(String(endpoint.port))))
        pairs.append(("SIMENCLAVE_TOKEN", .string(Discovery.encodeHex(endpoint.token))))
        emit(.object(pairs))
        return 0
    }

    /// `keys` — list the keys the helper holds for a simulator, scoped to an app
    /// with `--app`, the way an injected app's own enumerate is scoped.
    static func keys(_ arguments: [String]) -> Int32 {
        let flags = Flags(arguments)
        guard let endpoint = resolveEndpoint(flags) else { return 1 }
        guard let udid = flags["udid"] else {
            printError("keys needs --udid <simulator udid> (and optionally --app <bundle id>)")
            return 2
        }
        do {
            let response = try client(endpoint).send(.listKeys(udid: udid), appID: flags["app"])
            guard case let .listed(entries) = response else {
                printError("unexpected response to LIST_KEYS")
                return 1
            }
            let items = entries.map {
                JSONValue.object([
                    ("handle", .string(Discovery.encodeHex($0.handle))),
                    ("public_key", .string(Discovery.encodeHex($0.publicKey))),
                    ("tag", .string(Discovery.encodeHex($0.appTag))),
                ])
            }
            emit(.object([("count", .int(items.count)), ("keys", .array(items))]))
            return 0
        } catch {
            printError("could not list keys: \(error)")
            return 1
        }
    }

    /// `sign` — sign a digest with a key handle, the SIGN op an injected app drives.
    static func sign(_ arguments: [String]) -> Int32 {
        let flags = Flags(arguments)
        guard let endpoint = resolveEndpoint(flags) else { return 1 }
        guard let handle = flags["handle"].flatMap(Discovery.decodeHex),
              let digest = flags["digest"].flatMap(Discovery.decodeHex) else {
            printError("sign needs --handle <hex> and --digest <hex> (and optionally --algorithm)")
            return 2
        }
        // Default to digest-mode ECDSA over SHA-256, the SecKeyAlgorithm a stored
        // signing key usually uses; --algorithm overrides with any SecKeyAlgorithm.
        let algorithm = flags["algorithm"] ?? "algid:sign:ECDSA:digest-256"
        do {
            let response = try client(endpoint)
                .send(.sign(handle: handle, algorithm: algorithm, input: digest))
            switch response {
            case let .signed(signature):
                emit(.object([("signature", .string(Discovery.encodeHex(signature)))]))
                return 0
            case let .failure(code, message, _):
                printError("sign failed: \(message) (\(code))")
                return 1
            default:
                printError("unexpected response to SIGN")
                return 1
            }
        } catch {
            printError("could not sign: \(error)")
            return 1
        }
    }

    // MARK: - Endpoint

    private struct Endpoint {
        let port: UInt16
        let token: Data
    }

    /// Discover the helper's port and token, or print why it could not be reached.
    private static func resolveEndpoint(_ flags: Flags) -> Endpoint? {
        let directory = flags.directory ?? Discovery.defaultDirectory
        guard let port = Discovery.port(override: flags.port, directory: directory),
              let token = Discovery.token(directory: directory) else {
            printError("no running helper found (no port/token in \(directory)); is SimEnclave running?")
            return nil
        }
        return Endpoint(port: port, token: token)
    }

    private static func client(_ endpoint: Endpoint) -> LoopbackClient {
        LoopbackClient(port: endpoint.port, token: endpoint.token)
    }

    // MARK: - HELLO

    private enum HelloResult {
        case success(Int)
        case refused
        case failed(String)
    }

    private static func hello(port: UInt16, token: Data) -> HelloResult {
        do {
            let response = try LoopbackClient(port: port, token: token)
                .send(.hello(version: Wire.version1))
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

    /// Parses `--key value` pairs into a lookup. Commands read what they need;
    /// `port` and `dir` are common to all and exposed as typed accessors.
    private struct Flags {
        private var values: [String: String] = [:]

        init(_ arguments: [String]) {
            var index = 0
            while index < arguments.count {
                let argument = arguments[index]
                if argument.hasPrefix("--"), index + 1 < arguments.count {
                    values[String(argument.dropFirst(2))] = arguments[index + 1]
                    index += 2
                } else {
                    index += 1
                }
            }
        }

        subscript(_ key: String) -> String? { values[key] }
        var port: UInt16? { values["port"].flatMap(UInt16.init) }
        var directory: String? { values["dir"] }
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
          init      print the scheme environment to inject; --dylib <path> adds the loader var
          keys      list keys for a simulator; --udid <udid> [--app <bundle id>] (JSON)
          sign      sign a digest; --handle <hex> --digest <hex> [--algorithm <id>] (JSON)
          help      show this message

        The port and token are discovered from SIMENCLAVE_PORT / SIMENCLAVE_TOKEN,
        then from the helper's support directory; --port and --dir override them.
        """)
    }
}
