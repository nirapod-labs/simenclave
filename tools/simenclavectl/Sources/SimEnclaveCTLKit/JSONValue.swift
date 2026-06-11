// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

import Foundation

/// A minimal ordered JSON value, so each command emits stable, greppable output
/// without depending on dictionary iteration order. The CLI prints exactly one of
/// these per run; an agent or a `jq` pipeline reads the same key order every time.
public enum JSONValue: Equatable {
    case string(String)
    case int(Int)
    case bool(Bool)
    case null
    case object([(String, JSONValue)])

    /// The compact JSON encoding, keys in the order they were given.
    public func encoded() -> String {
        switch self {
        case let .string(value): return Self.quote(value)
        case let .int(value): return String(value)
        case let .bool(value): return value ? "true" : "false"
        case .null: return "null"
        case let .object(pairs):
            let body = pairs.map { "\(Self.quote($0.0)): \($0.1.encoded())" }.joined(separator: ", ")
            return "{\(body)}"
        }
    }

    public static func == (lhs: JSONValue, rhs: JSONValue) -> Bool {
        lhs.encoded() == rhs.encoded()
    }

    private static func quote(_ string: String) -> String {
        var out = "\""
        for scalar in string.unicodeScalars {
            switch scalar {
            case "\"": out += "\\\""
            case "\\": out += "\\\\"
            case "\n": out += "\\n"
            case "\r": out += "\\r"
            case "\t": out += "\\t"
            default:
                if scalar.value < 0x20 {
                    out += String(format: "\\u%04x", scalar.value)
                } else {
                    out.unicodeScalars.append(scalar)
                }
            }
        }
        out += "\""
        return out
    }
}
