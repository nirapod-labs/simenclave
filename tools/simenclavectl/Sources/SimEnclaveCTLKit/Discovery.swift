// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

import Foundation

/// Locates a running helper's loopback endpoint: its port and capability token.
///
/// The helper writes both to its per-user support directory on launch (`port` and
/// a 0600 `token` of 64 hex characters). An injected debug scheme also exports
/// `SIMENCLAVE_PORT` and `SIMENCLAVE_TOKEN`, which take precedence so the CLI sees
/// the same endpoint an injected app does. All inputs are injectable, so discovery
/// is unit-testable without a running helper.
public enum Discovery {
    /// The helper's per-user support directory, where it writes `token` and `port`.
    public static var defaultDirectory: String {
        NSHomeDirectory() + "/Library/Application Support/SimEnclave"
    }

    /// The helper's loopback port: an explicit override, then `SIMENCLAVE_PORT`,
    /// then the `port` file the helper writes on launch. Nil when none is found.
    public static func port(override: UInt16? = nil,
                            directory: String = defaultDirectory,
                            environment: [String: String] = ProcessInfo.processInfo.environment)
        -> UInt16? {
        if let override { return override }
        if let env = environment["SIMENCLAVE_PORT"], let parsed = UInt16(env) { return parsed }
        if let text = try? String(contentsOfFile: directory + "/port", encoding: .utf8),
           let parsed = UInt16(text.trimmingCharacters(in: .whitespacesAndNewlines)) {
            return parsed
        }
        return nil
    }

    /// The 32-byte capability token: `SIMENCLAVE_TOKEN` (64 hex), then the `token`
    /// file the helper writes 0600. Nil when absent or not 32 valid hex bytes.
    public static func token(directory: String = defaultDirectory,
                             environment: [String: String] = ProcessInfo.processInfo.environment)
        -> Data? {
        if let env = environment["SIMENCLAVE_TOKEN"], let bytes = decodeHex(env), bytes.count == 32 {
            return bytes
        }
        if let hex = try? String(contentsOfFile: directory + "/token", encoding: .utf8),
           let bytes = decodeHex(hex.trimmingCharacters(in: .whitespacesAndNewlines)),
           bytes.count == 32 {
            return bytes
        }
        return nil
    }

    /// Decode an even-length hex string to bytes, or nil if it is not valid hex.
    static func decodeHex(_ hex: String) -> Data? {
        let characters = Array(hex)
        guard characters.count % 2 == 0 else { return nil }
        var out = Data(capacity: characters.count / 2)
        var index = 0
        while index < characters.count {
            guard let high = characters[index].hexDigitValue,
                  let low = characters[index + 1].hexDigitValue else { return nil }
            out.append(UInt8(high << 4 | low))
            index += 2
        }
        return out
    }

    /// Render bytes as lowercase hex, the form the helper stores the token in.
    static func encodeHex(_ data: Data) -> String {
        data.map { String(format: "%02x", $0) }.joined()
    }
}
