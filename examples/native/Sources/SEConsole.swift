// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Nirapod Labs

import CryptoKit
import Foundation
import Observation
import Security
import SwiftUI

/// The access-control gate a key is created with. Each is a real
/// `SecAccessControlCreateFlags` set; biometry and presence keys prompt at sign time.
enum KeyGate: String, CaseIterable, Identifiable {
    case silent = "Silent"
    case biometry = "Biometry"
    case presence = "Presence"
    case passcode = "Passcode"

    var id: String { rawValue }
    var symbol: String {
        switch self {
        case .silent: return "lock"
        case .biometry: return "faceid"
        case .presence: return "hand.raised"
        case .passcode: return "number"
        }
    }
    var color: Color {
        switch self {
        case .silent: return .secondary
        case .biometry: return .blue
        case .presence: return .indigo
        case .passcode: return .teal
        }
    }
    var flags: SecAccessControlCreateFlags {
        switch self {
        case .silent: return [.privateKeyUsage]
        case .biometry: return [.privateKeyUsage, .biometryCurrentSet]
        case .presence: return [.privateKeyUsage, .userPresence]
        case .passcode: return [.privateKeyUsage, .devicePasscode]
        }
    }
    var prompts: Bool { self != .silent }
}

/// The keychain protection class a key is bound to.
enum Protection: String, CaseIterable, Identifiable {
    case whenUnlockedThisDevice = "When unlocked, this device"
    case whenUnlocked = "When unlocked"
    case afterFirstUnlockThisDevice = "After first unlock, this device"
    case afterFirstUnlock = "After first unlock"

    var id: String { rawValue }
    var short: String {
        switch self {
        case .whenUnlockedThisDevice, .whenUnlocked: return "WhenUnlocked"
        case .afterFirstUnlockThisDevice, .afterFirstUnlock: return "AfterFirstUnlock"
        }
    }
    var cfString: CFString {
        switch self {
        case .whenUnlockedThisDevice: return kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        case .whenUnlocked: return kSecAttrAccessibleWhenUnlocked
        case .afterFirstUnlockThisDevice: return kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        case .afterFirstUnlock: return kSecAttrAccessibleAfterFirstUnlock
        }
    }
}

/// Digest mode signs a SHA-256 you computed; message mode signs the message and lets the
/// SEP hash it. Both are real device algorithms.
enum SignMode: String, CaseIterable, Identifiable {
    case digest = "Digest"
    case message = "Message"
    var id: String { rawValue }
    var algorithm: SecKeyAlgorithm {
        self == .digest ? .ecdsaSignatureDigestX962SHA256 : .ecdsaSignatureMessageX962SHA256
    }
}

/// One key the console has minted or loaded, with its facts. The `SecKey` itself lives in the
/// console's off-observation store keyed by `id`, so this stays a clean value for the list.
struct KeyInfo: Identifiable, Equatable {
    let id: UUID
    let seq: Int
    let gate: KeyGate
    let protection: Protection
    let hardwareBacked: Bool
    let tokenID: String
    let publicKeyHex: String
    let publicKeyBytes: Int
    let createdAt: Date
    /// The application tag a permanent key is stored under, nil for an ephemeral key.
    let tag: String?

    var label: String { "Key \(seq)" }
    var persistent: Bool { tag != nil }
}

/// The last signature produced, and whether it has been verified.
struct SignatureInfo: Equatable {
    let derHex: String
    let bytes: Int
    let mode: SignMode
    var verified: Bool?
}

/// A transient toast.
struct Toast: Identifiable, Equatable {
    let id = UUID()
    enum Kind { case success, error, info }
    let kind: Kind
    let text: String
}

/// One history line.
struct LogLine: Identifiable, Equatable {
    let id: Int
    let ok: Bool?
    let text: String
    let time: Date
}

/// Drives the Secure Enclave `SecKey` API on demand from the UI. Holds every key minted this
/// session (newest first), the selected key, the last signature, a history trail, and a
/// transient toast. Every call is the real native one, so the same actions run unchanged on a
/// device and, in the Simulator with SimEnclave injected, against the host Mac's SEP.
@MainActor
@Observable
final class SEConsole {
    private(set) var keys: [KeyInfo] = []
    var selectedID: UUID?
    private(set) var signature: SignatureInfo?
    private(set) var history: [LogLine] = []
    var toast: Toast?

    /// Create permanent (keychain-stored) keys, on by default, the way a real app stores a
    /// signing key. A permanent key is findable by tag and reloads on the next launch. Off
    /// makes an ephemeral key that is gone when the app closes.
    var persist = true

    /// Bumped on every success or failure, so a view can attach `.sensoryFeedback`.
    private(set) var successTick = 0
    private(set) var errorTick = 0

    /// The live `SecKey` pair for a minted key, off the observation graph.
    private struct Pair { let priv: SecKey; let pub: SecKey? }
    @ObservationIgnored private var pairs: [UUID: Pair] = [:]
    @ObservationIgnored private var lastSigData: Data?
    @ObservationIgnored private var lastSignedMessage: String?
    @ObservationIgnored private var lastMode: SignMode = .digest
    @ObservationIgnored private var seq = 0
    @ObservationIgnored private var counter = 0

    var selectedKey: KeyInfo? { keys.first { $0.id == selectedID } }
    var hasKey: Bool { selectedKey != nil }

    @ObservationIgnored private var didLoad = false

    /// Load the keys from the keychain, once. A native enumeration: `SecItemCopyMatching` with
    /// `kSecMatchLimitAll` returns every Secure Enclave key the simulator holds, exactly as on a
    /// device, so the list is the keychain's truth and not the app's own side store. The key's
    /// class and protection ride in its tag, so a relaunch rebuilds each row from the keychain
    /// alone. Driven from a `.task`, so the round-trip happens once on the retained instance.
    func loadKeys() {
        guard !didLoad else { return }
        didLoad = true
        var result: CFTypeRef?
        let status = SecItemCopyMatching([
            kSecClass as String: kSecClassKey,
            kSecMatchLimit as String: kSecMatchLimitAll,
            kSecReturnRef as String: true,
            kSecReturnAttributes as String: true,
        ] as CFDictionary, &result)
        guard status == errSecSuccess, let items = result as? [[String: Any]] else { return }
        var maxSeq = 0
        for item in items {
            guard let ref = item[kSecValueRef as String],
                  CFGetTypeID(ref as CFTypeRef) == SecKeyGetTypeID(),
                  let tagData = item[kSecAttrApplicationTag as String] as? Data,
                  let tag = String(data: tagData, encoding: .utf8),
                  let meta = Self.parseTag(tag) else { continue }
            // swiftlint:disable:next force_cast
            let key = ref as! SecKey
            let id = UUID()
            maxSeq = max(maxSeq, meta.seq)
            let info = keyInfo(id: id, seq: meta.seq, gate: meta.gate, protection: meta.protection,
                               from: key, tag: tag, createdAt: Date())
            pairs[id] = Pair(priv: key, pub: SecKeyCopyPublicKey(key))
            keys.append(info)
        }
        seq = maxSeq
        keys.sort { $0.seq > $1.seq }
        if selectedID == nil { selectedID = keys.first?.id }
        if !keys.isEmpty {
            note(nil, "Loaded \(keys.count) key\(keys.count == 1 ? "" : "s") from the keychain")
        }
    }

    // MARK: key creation

    func generate(gate: KeyGate, protection: Protection) {
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            nil, protection.cfString, gate.flags, &error) else {
            return fail("Access control failed", describe(error))
        }
        // The class, protection, and a sequence ride in the tag, so an enumeration on the next
        // launch rebuilds the row from the keychain with no app-side store.
        let nextSeq = seq + 1
        let tag = persist ? Self.makeTag(gate: gate, protection: protection, seq: nextSeq) : nil
        guard let priv = SecKeyCreateRandomKey(attributes(access, tag: tag) as CFDictionary, &error)
        else {
            return fail("Generate failed", describe(error))
        }
        let pub = SecKeyCopyPublicKey(priv)
        let exportable = SecKeyCopyExternalRepresentation(priv, nil) != nil
        let attrs = SecKeyCopyAttributes(priv) as? [String: Any]
        let token = attrs?[kSecAttrTokenID as String].map { "\($0)" } ?? "none"
        let pubData = pub.flatMap { SecKeyCopyExternalRepresentation($0, nil) as Data? } ?? Data()

        seq = nextSeq
        let id = UUID()
        let info = KeyInfo(
            id: id, seq: seq, gate: gate, protection: protection, hardwareBacked: !exportable,
            tokenID: token, publicKeyHex: hex(pubData), publicKeyBytes: pubData.count,
            createdAt: Date(), tag: tag)
        pairs[id] = Pair(priv: priv, pub: pub)
        keys.insert(info, at: 0)
        select(id)

        if exportable {
            note(false, "Generated a software key (exportable, not hardware)")
            toast(.error, "Software key, not hardware")
        } else {
            let kind = tag == nil ? "ephemeral" : "permanent"
            note(true, "Generated \(info.label), a \(kind) \(gate.rawValue.lowercased()) key")
            toast(.success, "\(info.label) created")
        }
    }

    private func keyInfo(id: UUID, seq: Int, gate: KeyGate, protection: Protection, from key: SecKey,
                         tag: String?, createdAt: Date) -> KeyInfo {
        let exportable = SecKeyCopyExternalRepresentation(key, nil) != nil
        let pubData = SecKeyCopyPublicKey(key)
            .flatMap { SecKeyCopyExternalRepresentation($0, nil) as Data? } ?? Data()
        let token = (SecKeyCopyAttributes(key) as? [String: Any])?[kSecAttrTokenID as String]
            .map { "\($0)" } ?? "none"
        return KeyInfo(id: id, seq: seq, gate: gate, protection: protection,
                       hardwareBacked: !exportable, tokenID: token, publicKeyHex: hex(pubData),
                       publicKeyBytes: pubData.count, createdAt: createdAt, tag: tag)
    }

    func select(_ id: UUID) {
        selectedID = id
        signature = nil
        lastSigData = nil
    }

    func deleteKey(_ id: UUID) {
        let key = keys.first { $0.id == id }
        let label = key?.label ?? "key"
        // A permanent key is deleted from the keychain too, so it does not reload next launch
        // and the helper drops it; this is the device's SecItemDelete.
        if let tag = key?.tag {
            SecItemDelete([
                kSecClass as String: kSecClassKey,
                kSecAttrApplicationTag as String: Data(tag.utf8),
            ] as CFDictionary)
        }
        pairs[id] = nil
        keys.removeAll { $0.id == id }
        if selectedID == id { selectedID = keys.first?.id; signature = nil; lastSigData = nil }
        note(nil, "Deleted \(label)")
        toast(.info, "\(label) deleted")
    }

    // MARK: key operations

    func tryExportPrivate() {
        guard let priv = selectedPair?.priv else { return }
        if let leaked = SecKeyCopyExternalRepresentation(priv, nil) as Data? {
            fail("Private key exported", "\(leaked.count) B, this is a software key")
        } else {
            note(true, "Private key export refused, as a device SE key")
            toast(.success, "Export refused, hardware-backed")
        }
    }

    // MARK: signing

    func sign(message: String, mode: SignMode) {
        guard let priv = selectedPair?.priv else { return }
        let input = signingInput(message, mode)
        var error: Unmanaged<CFError>?
        guard let sig = SecKeyCreateSignature(priv, mode.algorithm, input as CFData, &error)
            as Data? else {
            return fail("Sign failed", describe(error))
        }
        lastSigData = sig
        lastSignedMessage = message
        lastMode = mode
        signature = SignatureInfo(derHex: hex(sig), bytes: sig.count, mode: mode, verified: nil)
        note(true, "Signed \(sig.count) B in \(mode.rawValue.lowercased()) mode")
        toast(.success, "Signed")
    }

    func verify(tamper: Bool) {
        guard let pub = selectedPair?.pub, let sig = lastSigData, let message = lastSignedMessage
        else { return }
        var input = signingInput(message, lastMode)
        if tamper, !input.isEmpty { input[input.startIndex] ^= 0xFF }
        let ok = SecKeyVerifySignature(pub, lastMode.algorithm, input as CFData, sig as CFData, nil)
        if tamper {
            note(!ok, ok ? "Tampered input wrongly verified" : "Tampered input correctly rejected")
            ok ? toast(.error, "Tamper not caught") : toast(.success, "Tamper rejected")
        } else {
            signature?.verified = ok
            note(ok, ok ? "Signature verifies" : "Signature did not verify")
            ok ? toast(.success, "Verified") : toast(.error, "Did not verify")
        }
    }

    // MARK: keychain (SecItem)

    func keychainAdd(tag: String) {
        guard let priv = selectedPair?.priv, let tagData = data(tag) else { return }
        SecItemDelete(query(tagData) as CFDictionary)
        let status = SecItemAdd([
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tagData,
            kSecValueRef as String: priv,
        ] as CFDictionary, nil)
        record(status == errSecSuccess, "Add \"\(tag)\"", status)
    }

    func keychainFind(tag: String) {
        guard let tagData = data(tag) else { return }
        var found: CFTypeRef?
        var q = query(tagData)
        q[kSecReturnRef as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        let status = SecItemCopyMatching(q as CFDictionary, &found)
        if status == errSecSuccess, let ref = found {
            // swiftlint:disable:next force_cast
            adopt(ref as! SecKey, tag: tag)
        } else {
            record(false, "Find \"\(tag)\"", status)
        }
    }

    func keychainDelete(tag: String) {
        guard let tagData = data(tag) else { return }
        let status = SecItemDelete(query(tagData) as CFDictionary)
        record(status == errSecSuccess, "Delete \"\(tag)\"", status)
    }

    func clearHistory() { history.removeAll() }

    /// Screenshot-only seed, gated behind SE_DEMO_SEED at launch. Mints two keys and signs
    /// with the silent one (no prompt), so the populated screens can be captured headlessly.
    func seedDemo() {
        generate(gate: .biometry, protection: .whenUnlocked)
        generate(gate: .silent, protection: .whenUnlockedThisDevice)
        sign(message: "hello secure enclave", mode: .digest)
        verify(tamper: false)
    }

    // MARK: internals

    private var selectedPair: Pair? { selectedID.flatMap { pairs[$0] } }

    private func adopt(_ found: SecKey, tag: String) {
        // The same key found twice is one key: a find that matches a key already in the list
        // selects it rather than adding a duplicate row. Public-key bytes identify the key.
        let pubHex = SecKeyCopyPublicKey(found)
            .flatMap { SecKeyCopyExternalRepresentation($0, nil) as Data? }.map(hex) ?? ""
        if let existing = keys.first(where: { $0.publicKeyHex == pubHex }) {
            select(existing.id)
            note(true, "Found \"\(tag)\", already loaded as \(existing.label)")
            toast(.info, "Selected \(existing.label)")
            return
        }
        let gate = selectedKey?.gate ?? .silent
        let protection = selectedKey?.protection ?? .whenUnlockedThisDevice
        seq += 1
        let id = UUID()
        let info = keyInfo(id: id, seq: seq, gate: gate, protection: protection, from: found,
                           tag: tag, createdAt: Date())
        pairs[id] = Pair(priv: found, pub: SecKeyCopyPublicKey(found))
        keys.insert(info, at: 0)
        select(id)
        note(true, "Found \"\(tag)\", loaded it as \(info.label)")
        toast(.success, "Loaded \(info.label)")
    }

    private func attributes(_ access: SecAccessControl, tag: String?) -> [String: Any] {
        // A permanent key sets kSecAttrIsPermanent and carries its tag, so the SEP key is
        // stored and findable later; an ephemeral key sets neither and is gone on app close.
        var priv: [String: Any] = [
            kSecAttrIsPermanent as String: tag != nil,
            kSecAttrAccessControl as String: access,
        ]
        if let tag { priv[kSecAttrApplicationTag as String] = Data(tag.utf8) }
        return [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: priv,
        ]
    }

    // MARK: tag codec

    private static let tagPrefix = "dev.simenclave.example"

    /// Encode the key's class and protection (and a stable sequence for the label) into the
    /// application tag, so an enumeration rebuilds the row from the keychain alone, with no
    /// side store. Apps commonly carry their own metadata in the tag this way.
    private static func makeTag(gate: KeyGate, protection: Protection, seq: Int) -> String {
        let protectionIndex = Protection.allCases.firstIndex(of: protection) ?? 0
        return "\(tagPrefix)|v1|\(gate.rawValue)|\(protectionIndex)|\(seq)|\(UUID().uuidString)"
    }

    /// Inverse of `makeTag`: recover (gate, protection, seq) from a tag this app wrote, or nil
    /// for a tag in any other shape.
    private static func parseTag(_ tag: String) -> (gate: KeyGate, protection: Protection, seq: Int)? {
        let parts = tag.split(separator: "|", omittingEmptySubsequences: false).map(String.init)
        guard parts.count == 6, parts[0] == tagPrefix, parts[1] == "v1",
              let gate = KeyGate(rawValue: parts[2]),
              let protectionIndex = Int(parts[3]), Protection.allCases.indices.contains(protectionIndex),
              let seq = Int(parts[4]) else { return nil }
        return (gate, Protection.allCases[protectionIndex], seq)
    }

    private func signingInput(_ message: String, _ mode: SignMode) -> Data {
        let bytes = Data(message.utf8)
        return mode == .digest ? Data(SHA256.hash(data: bytes)) : bytes
    }

    private func query(_ tag: Data) -> [String: Any] {
        [kSecClass as String: kSecClassKey, kSecAttrApplicationTag as String: tag]
    }

    private func data(_ tag: String) -> Data? { tag.isEmpty ? nil : Data(tag.utf8) }

    private func record(_ ok: Bool, _ what: String, _ status: OSStatus) {
        note(ok, "\(what): OSStatus \(status)")
        ok ? toast(.success, what) : toast(.error, "\(what) failed (\(status))")
    }

    private func fail(_ what: String, _ detail: String) {
        note(false, "\(what): \(detail)")
        toast(.error, what)
    }

    private func note(_ ok: Bool?, _ text: String) {
        counter += 1
        history.insert(LogLine(id: counter, ok: ok, text: text, time: Date()), at: 0)
        if ok == true { successTick += 1 } else if ok == false { errorTick += 1 }
        print("[SE] \(ok == true ? "ok" : ok == false ? "FAIL" : "--") \(text)")
    }

    private func toast(_ kind: Toast.Kind, _ text: String) {
        toast = Toast(kind: kind, text: text)
    }

    private func describe(_ error: Unmanaged<CFError>?) -> String {
        guard let error = error?.takeRetainedValue() else { return "unknown error" }
        return CFErrorCopyDescription(error) as String? ?? "\(error)"
    }

    private func hex(_ data: Data) -> String {
        data.map { String(format: "%02x", $0) }.joined()
    }
}
