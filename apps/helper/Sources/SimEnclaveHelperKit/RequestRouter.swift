// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

import Foundation
import SimEnclaveHostCore
import SimEnclaveProtocol

/// The OSStatus codes the helper returns for non-biometric failures. The biometric
/// device-to-error table is `DeviceError` (slice 5).
enum OSStatusCode {
    static let authFailed: Int64 = -25293 // errSecAuthFailed
    static let itemNotFound: Int64 = -25300 // errSecItemNotFound
    static let internalError: Int64 = -2070 // errSecInternalComponent
    static let userCanceled: Int64 = -128 // errSecUserCanceled, for an approval denial
}

/// Turns a request into a response by driving the Mac Secure Enclave, behind the
/// capability-token gate. One `SecureEnclaveService` is shared across every
/// connection, so a key from a `GENERATE` on one connection is signable by a
/// `SIGN` on the next.
public struct RequestRouter: Sendable {
    private let service: SecureEnclaveService
    private let gate: AuthGate
    private let approval: ApprovalGate?
    private let observer: ServeObserver?

    /// Build the router over the shared service, the token gate, the optional
    /// approval gate (the CLI passes none and proceeds), and an optional observer
    /// that sees each served request (the menubar uses it for live activity).
    public init(
        service: SecureEnclaveService, gate: AuthGate, approval: ApprovalGate? = nil,
        observer: ServeObserver? = nil
    ) {
        self.service = service
        self.gate = gate
        self.approval = approval
        self.observer = observer
    }

    /// Validate the token, then dispatch. The gate runs before the operation is
    /// interpreted, so a caller without the token learns nothing about the op
    /// surface beyond the auth failure.
    public func respond(toPayload payload: Data) -> Response {
        guard let presented = (try? Wire.token(in: payload)).flatMap(CapabilityToken.init(bytes:)),
              gate.accepts(presented)
        else {
            return .failure(code: OSStatusCode.authFailed, message: "invalid capability token")
        }
        // The approval prompt: a request carrying an app id (a generate from the
        // interposer) is checked against the in-session approval set, naming the app. A
        // convenience over the token, not a boundary; absent an approver it proceeds.
        if let approval, let appID = Wire.appID(in: payload), !approval.proceed(appID: appID) {
            return .failure(code: OSStatusCode.userCanceled, message: "app not approved: \(appID)")
        }
        do {
            let request = try Wire.decodeRequest(payload)
            // A per-request line on stderr, so a developer can watch the helper serve the
            // Secure Enclave traffic an injected app drives. Naming only the op, never the
            // token or key bytes. The observer gets the same, for a live UI.
            let appID = Wire.appID(in: payload)
            let label = Self.label(request)
            FileHandle.standardError.write(
                Data("[helper] served \(label)\(appID.map { " app=\($0)" } ?? "")\n".utf8))
            observer?.served(op: label, appID: appID)
            return handle(request)
        } catch {
            return .failure(code: OSStatusCode.internalError, message: String(describing: error))
        }
    }

    private static func label(_ request: Request) -> String {
        switch request {
        case .hello: return "HELLO"
        case .generate: return "GENERATE"
        case .getPublicKey: return "GET_PUBKEY"
        case .sign: return "SIGN"
        case .delete: return "DELETE"
        case .findByTag: return "FIND_BY_TAG"
        case .listKeys: return "LIST_KEYS"
        case .isAlgorithmSupported: return "IS_ALGO_SUPPORTED"
        case .copyAttributes: return "COPY_ATTRIBUTES"
        case .decrypt: return "DECRYPT"
        case .keyExchange: return "KEY_EXCHANGE"
        case .updateTag: return "UPDATE"
        }
    }

    func handle(_ request: Request) -> Response {
        do {
            switch request {
            case let .hello(version):
                return version == Wire.version1
                    ? .hello(version: Wire.version1)
                    : .failure(code: OSStatusCode.internalError,
                               message: "unsupported protocol version \(version)")
            case let .generate(keyClass, accessControl, persistent, keyType, keySizeInBits):
                let (handle, publicKey) = try service.generate(
                    requiresBiometry: keyClass == .biometry,
                    accessFlags: accessControl.map { UInt($0.flags) },
                    protection: accessControl?.protection,
                    persistentTag: persistent?.appTag,
                    udid: persistent?.udid,
                    keyType: keyType,
                    keySizeInBits: keySizeInBits.map { UInt($0) })
                return .generated(handle: handle, publicKey: publicKey)
            case let .getPublicKey(handle):
                return .publicKey(try service.publicKey(for: handle))
            case let .sign(handle, algorithm, input):
                return .signed(
                    signature: try service.sign(handle: handle, algorithm: algorithm, input: input))
            case let .delete(handle):
                try service.delete(handle: handle)
                return .deleted
            case let .findByTag(appTag, udid):
                // A permanent key the helper still holds (helper-lifetime store): a
                // relaunched app reloads it by tag. A miss is the device's item-not-found,
                // which is also what a real device returns after the key is gone. Durable
                // across helper restarts and Mac reboot is M5 (it needs the signed helper).
                let (handle, publicKey) = try service.findByTag(appTag: appTag, udid: udid)
                return .found(handle: handle, publicKey: publicKey)
            case let .listKeys(udid):
                // The native enumeration behind an app's kSecMatchLimitAll: every key the
                // helper holds for this simulator. An empty list is a valid result.
                let entries = service.listKeys(udid: udid).map {
                    KeyEntry(handle: $0.handle, publicKey: $0.publicKey, appTag: $0.appTag)
                }
                return .listed(keys: entries)
            case let .isAlgorithmSupported(handle, operation, algorithm):
                // The real key's own answer, so the shadow's SecKeyIsAlgorithmSupported matches
                // a device's private SE key instead of the public carrier.
                let flag = try service.isAlgorithmSupported(
                    handle: handle, operation: UInt(operation), algorithm: algorithm)
                return .supported(flag)
            case let .copyAttributes(handle):
                // The real key's attribute dictionary, so the shadow reports the SEP key's own
                // attributes (application label, capability flags, sizes) instead of a stub.
                return .attributes(try service.copyAttributes(handle: handle))
            case let .decrypt(handle, algorithm, ciphertext):
                // The real SEP key's ECIES decrypt, relayed; an unhooked shadow could not do it.
                return .decrypted(try service.decrypt(
                    handle: handle, algorithm: algorithm, ciphertext: ciphertext))
            case let .keyExchange(handle, algorithm, peerPublicKey, parameters):
                // The real SEP key's ECDH agreement, relayed with the caller's parameters.
                return .derived(try service.keyExchange(
                    handle: handle, algorithm: algorithm, peerPublicKey: peerPublicKey,
                    parameters: parameters))
            case let .updateTag(handle, appTag, udid):
                try service.updateTag(handle: handle, appTag: appTag, udid: udid)
                return .updated
            }
        } catch SecureEnclaveService.Failure.unknownHandle {
            return .failure(code: OSStatusCode.itemNotFound, message: "unknown handle")
        } catch let failure as BiometricFailure {
            // Map the category to the device's error envelope, so the interposer rebuilds
            // the CFError a device returns and an app's do/catch reads the same code.
            let envelope = DeviceError.envelope(for: failure)
            return .failure(code: envelope.code, message: "biometric prompt: \(failure)",
                            domain: envelope.domain)
        } catch {
            return .failure(code: OSStatusCode.internalError, message: String(describing: error))
        }
    }
}
