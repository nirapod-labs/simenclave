// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

import Foundation
import SimEnclaveHostCore
import SimEnclaveProtocol

/// The error envelope a real iOS device returns for each biometric failure category: an
/// OSStatus or LAError code and the domain it lives in. The helper sends these so the
/// interposer rebuilds the exact CFError a device would, and an app's `do/catch` behaves
/// the same in the simulator as on a device.
///
/// The values are seeded from Apple's documented OSStatus and LAError constants and are
/// flagged device-confirm: a device capture pins them before M4's parity gate, where
/// parity is the release criterion. The mechanism (classify, map, carry, rebuild) is what
/// M3 proves; the numbers clear with the capture.
enum DeviceError {
    static func envelope(for failure: BiometricFailure) -> (code: Int64, domain: UInt64) {
        switch failure {
        // device-confirm: the codes below are the documented values, pending a device run.
        case .userCanceled: return (-128, Wire.domainOSStatus) // errSecUserCanceled
        case .authenticationFailed: return (-25293, Wire.domainOSStatus) // errSecAuthFailed
        case .biometryLockout: return (-8, Wire.domainLAError) // LAError.biometryLockout
        case .biometryNotEnrolled: return (-7, Wire.domainLAError) // LAError.biometryNotEnrolled
        case .biometryNotAvailable: return (-6, Wire.domainLAError) // LAError.biometryNotAvailable
        case .unknown: return (-25293, Wire.domainOSStatus) // errSecAuthFailed, the generic case
        }
    }
}
