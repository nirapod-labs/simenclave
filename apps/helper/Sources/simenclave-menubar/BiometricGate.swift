// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

import AppKit
import Foundation
import Security
import SimEnclaveHostCore

/// The real biometric gate for the menubar app. It brings the helper foreground on the main
/// thread so the Mac Touch ID sheet is attributed and visible, then signs on the calling
/// connection thread, where SecKeyCreateSignature triggers the SEP's biometric prompt and
/// blocks for the human while the main run loop presents it. Signing on the main thread
/// would deadlock the run loop the sheet needs, so it stays on the connection thread.
final class AppKitBiometricGate: BiometricGate {
    func promptedSign(key: SecKey, algorithm: String, input: Data, reason _: String) throws -> Data {
        DispatchQueue.main.sync { NSApp.activate(ignoringOtherApps: true) }
        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(
            key, SecKeyAlgorithm(rawValue: algorithm as CFString), input as CFData, &error
        ) as Data? else {
            throw Self.classify(error?.takeRetainedValue())
        }
        return signature
    }

    /// Classify the macOS sign error into the failure category the helper maps to the device
    /// error. The common OSStatus cases are covered; the LAError-specific categories are a
    /// device-verified refinement captured before M4's parity gate.
    private static func classify(_ error: CFError?) -> BiometricFailure {
        guard let error else { return .unknown }
        switch CFErrorGetCode(error) {
        case Int(errSecUserCanceled): return .userCanceled
        case Int(errSecAuthFailed): return .authenticationFailed
        default: return .unknown
        }
    }
}
