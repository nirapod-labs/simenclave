import Foundation
import Security

/// Why a biometric prompt did not produce a signature. The real gate classifies the
/// macOS error into one of these; the helper maps the category to the `(domain, code)` a
/// real iOS device returns, so an app's `do/catch` reads the device's error in the
/// simulator. The category set is knowable; the exact device codes are device-confirm
/// until a device capture (the M4 parity gate).
public enum BiometricFailure: Error, Equatable {
    case userCanceled
    case authenticationFailed
    case biometryLockout
    case biometryNotEnrolled
    case biometryNotAvailable
    case unknown
}

/// Drives the biometric prompt for a key that requires user presence. The real gate
/// (the menubar app) brings the helper foreground and runs the Mac Touch ID prompt on
/// the main thread; a test gate returns a canned outcome, so the routing is exercised
/// without a real sheet. The CLI helper installs no gate, so a prompted sign there is a
/// clear error rather than a silent or unprompted signature.
///
/// A biometric sign is delegated whole, not merely authorized, so the prompt and the
/// signature stay one operation: the SEP key's access control is satisfied by the same
/// `LAContext` the prompt ran on. The exact binding (an `LAContext` at create versus an
/// `evaluateAccessControl` pre-auth) is the spike the menubar gate resolves on real
/// hardware; this seam is what the headless suite exercises through a mock.
public protocol BiometricGate {
    /// Foreground, prompt, and sign the 32-byte `digest` with the prompted `key`,
    /// naming the caller in `reason`. Throws on a cancel or a failed prompt, which the
    /// helper maps to the device's error (slice 5).
    func promptedSign(key: SecKey, digest: Data, reason: String) throws -> Data
}
