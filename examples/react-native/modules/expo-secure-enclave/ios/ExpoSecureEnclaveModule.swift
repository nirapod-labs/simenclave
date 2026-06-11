// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 SimEnclave Contributors

import CryptoKit
import ExpoModulesCore
import Security

// A thin first-party Expo native module that issues the raw Security-framework calls a device app
// makes for the Secure Enclave: SecKeyCreateRandomKey with kSecAttrTokenIDSecureEnclave, the
// access-control flags, SecKeyCreateSignature, SecKeyVerifySignature, and SecItemAdd/CopyMatching/
// Delete. It adds nothing of its own. In the Simulator with SimEnclave injected, these exact C
// calls are hooked and routed to the host Mac's SEP, which is the whole point of pairing this with
// a published biometrics library: the tool intercepts the native calls regardless of the JS lib.
public class ExpoSecureEnclaveModule: Module {
  /// Live private keys by handle, off the JS bridge. A permanent key is also in the keychain and
  /// re-adopted on enumerate; an ephemeral key lives only here, for the app's lifetime.
  private var privateKeys: [String: SecKey] = [:]
  private var publicKeys: [String: SecKey] = [:]

  public func definition() -> ModuleDefinition {
    Name("ExpoSecureEnclave")

    Function("isAvailable") { () -> Bool in
      // A real Secure Enclave answers a probe key-gen; the Simulator (unhooked) does not.
      var error: Unmanaged<CFError>?
      guard let ac = SecAccessControlCreateWithFlags(
        nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, [.privateKeyUsage], &error) else {
        return false
      }
      let attrs: [String: Any] = [
        kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrKeySizeInBits as String: 256,
        kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
        kSecPrivateKeyAttrs as String: [
          kSecAttrIsPermanent as String: false,
          kSecAttrAccessControl as String: ac,
        ],
      ]
      return SecKeyCreateRandomKey(attrs as CFDictionary, nil) != nil
    }

    AsyncFunction("generate") { (gate: String, protection: String, persist: Bool, tag: String?)
      -> [String: Any] in
      try self.generate(gate: gate, protection: protection, persist: persist, tag: tag)
    }

    AsyncFunction("sign") { (handle: String, messageHex: String, mode: String) -> String in
      try self.sign(handle: handle, messageHex: messageHex, mode: mode)
    }

    AsyncFunction("verify") {
      (handle: String, messageHex: String, mode: String, signatureHex: String, tamper: Bool) -> Bool in
      try self.verify(handle: handle, messageHex: messageHex, mode: mode,
                      signatureHex: signatureHex, tamper: tamper)
    }

    AsyncFunction("deleteKey") { (handle: String, tag: String?) -> Void in
      if let tag {
        SecItemDelete([
          kSecClass as String: kSecClassKey,
          kSecAttrApplicationTag as String: Data(tag.utf8),
        ] as CFDictionary)
      }
      self.privateKeys[handle] = nil
      self.publicKeys[handle] = nil
    }

    AsyncFunction("loadKeys") { () -> [[String: Any]] in self.loadKeys() }

    AsyncFunction("keychainAdd") { (handle: String, tag: String) -> Void in
      guard let priv = self.privateKeys[handle] else { throw Err.unknownHandle }
      let tagData = Data(tag.utf8)
      SecItemDelete(self.tagQuery(tagData) as CFDictionary)
      let status = SecItemAdd([
        kSecClass as String: kSecClassKey,
        kSecAttrApplicationTag as String: tagData,
        kSecValueRef as String: priv,
      ] as CFDictionary, nil)
      if status != errSecSuccess { throw Err.osStatus(status) }
    }

    AsyncFunction("keychainFind") { (tag: String) -> [String: Any]? in
      var q = self.tagQuery(Data(tag.utf8))
      q[kSecReturnRef as String] = true
      q[kSecMatchLimit as String] = kSecMatchLimitOne
      var found: CFTypeRef?
      guard SecItemCopyMatching(q as CFDictionary, &found) == errSecSuccess, let ref = found,
            CFGetTypeID(ref) == SecKeyGetTypeID() else { return nil }
      // swiftlint:disable:next force_cast
      let key = ref as! SecKey
      let handle = UUID().uuidString
      self.privateKeys[handle] = key
      self.publicKeys[handle] = SecKeyCopyPublicKey(key)
      return self.facts(handle: handle, key: key, tag: tag)
    }

    AsyncFunction("keychainDelete") { (tag: String) -> Void in
      let status = SecItemDelete(self.tagQuery(Data(tag.utf8)) as CFDictionary)
      if status != errSecSuccess && status != errSecItemNotFound { throw Err.osStatus(status) }
    }
  }

  // MARK: operations

  private func generate(gate: String, protection: String, persist: Bool, tag: String?) throws
    -> [String: Any] {
    var error: Unmanaged<CFError>?
    guard let access = SecAccessControlCreateWithFlags(
      nil, Self.protectionClass(protection), Self.flags(gate), &error) else {
      throw Err.message(Self.describe(error))
    }
    var priv: [String: Any] = [
      kSecAttrIsPermanent as String: persist && tag != nil,
      kSecAttrAccessControl as String: access,
    ]
    if persist, let tag { priv[kSecAttrApplicationTag as String] = Data(tag.utf8) }
    let attrs: [String: Any] = [
      kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
      kSecAttrKeySizeInBits as String: 256,
      kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
      kSecPrivateKeyAttrs as String: priv,
    ]
    guard let key = SecKeyCreateRandomKey(attrs as CFDictionary, &error) else {
      throw Err.message(Self.describe(error))
    }
    let handle = UUID().uuidString
    privateKeys[handle] = key
    publicKeys[handle] = SecKeyCopyPublicKey(key)
    return facts(handle: handle, key: key, tag: persist ? tag : nil)
  }

  private func sign(handle: String, messageHex: String, mode: String) throws -> String {
    guard let priv = privateKeys[handle] else { throw Err.unknownHandle }
    let input = Self.signingInput(messageHex, mode)
    var error: Unmanaged<CFError>?
    guard let sig = SecKeyCreateSignature(priv, Self.algorithm(mode), input as CFData, &error)
      as Data? else {
      throw Err.message(Self.describe(error))
    }
    return Self.hex(sig)
  }

  private func verify(handle: String, messageHex: String, mode: String, signatureHex: String,
                      tamper: Bool) throws -> Bool {
    guard let pub = publicKeys[handle] else { throw Err.unknownHandle }
    var input = Self.signingInput(messageHex, mode)
    if tamper, !input.isEmpty { input[input.startIndex] ^= 0xFF }
    guard let sig = Self.bytes(signatureHex) else { throw Err.message("bad signature hex") }
    return SecKeyVerifySignature(pub, Self.algorithm(mode), input as CFData, sig as CFData, nil)
  }

  private func loadKeys() -> [[String: Any]] {
    var result: CFTypeRef?
    let status = SecItemCopyMatching([
      kSecClass as String: kSecClassKey,
      kSecMatchLimit as String: kSecMatchLimitAll,
      kSecReturnRef as String: true,
      kSecReturnAttributes as String: true,
    ] as CFDictionary, &result)
    guard status == errSecSuccess, let items = result as? [[String: Any]] else { return [] }
    var out: [[String: Any]] = []
    for item in items {
      guard let ref = item[kSecValueRef as String], CFGetTypeID(ref as CFTypeRef) == SecKeyGetTypeID(),
            let tagData = item[kSecAttrApplicationTag as String] as? Data,
            let tag = String(data: tagData, encoding: .utf8) else { continue }
      // swiftlint:disable:next force_cast
      let key = ref as! SecKey
      let handle = UUID().uuidString
      privateKeys[handle] = key
      publicKeys[handle] = SecKeyCopyPublicKey(key)
      out.append(facts(handle: handle, key: key, tag: tag))
    }
    return out
  }

  // MARK: facts

  /// The facts the JS side shows. `hardwareBacked` is the device test: a Secure Enclave private
  /// key refuses export, a software key does not.
  private func facts(handle: String, key: SecKey, tag: String?) -> [String: Any] {
    let exportable = SecKeyCopyExternalRepresentation(key, nil) != nil
    let pubData = SecKeyCopyPublicKey(key)
      .flatMap { SecKeyCopyExternalRepresentation($0, nil) as Data? } ?? Data()
    let token = (SecKeyCopyAttributes(key) as? [String: Any])?[kSecAttrTokenID as String]
      .map { "\($0)" } ?? "none"
    return [
      "handle": handle,
      "hardwareBacked": !exportable,
      "tokenID": token,
      "publicKeyHex": Self.hex(pubData),
      "publicKeyBytes": pubData.count,
      "tag": tag as Any,
    ]
  }

  private func tagQuery(_ tag: Data) -> [String: Any] {
    [kSecClass as String: kSecClassKey, kSecAttrApplicationTag as String: tag]
  }

  // MARK: mappings (mirrors the native console)

  private static func flags(_ gate: String) -> SecAccessControlCreateFlags {
    switch gate {
    case "biometry": return [.privateKeyUsage, .biometryCurrentSet]
    case "presence": return [.privateKeyUsage, .userPresence]
    case "passcode": return [.privateKeyUsage, .devicePasscode]
    default: return [.privateKeyUsage]
    }
  }

  private static func protectionClass(_ protection: String) -> CFString {
    switch protection {
    case "whenUnlocked": return kSecAttrAccessibleWhenUnlocked
    case "afterFirstUnlockThisDevice": return kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
    case "afterFirstUnlock": return kSecAttrAccessibleAfterFirstUnlock
    default: return kSecAttrAccessibleWhenUnlockedThisDeviceOnly
    }
  }

  private static func algorithm(_ mode: String) -> SecKeyAlgorithm {
    mode == "message" ? .ecdsaSignatureMessageX962SHA256 : .ecdsaSignatureDigestX962SHA256
  }

  /// Digest mode hashes the message to SHA-256; message mode hands the raw bytes to the SEP.
  private static func signingInput(_ messageHex: String, _ mode: String) -> Data {
    let bytes = self.bytes(messageHex) ?? Data()
    return mode == "message" ? bytes : Data(SHA256.hash(data: bytes))
  }

  // MARK: hex + errors

  private static func hex(_ data: Data) -> String {
    data.map { String(format: "%02x", $0) }.joined()
  }

  private static func bytes(_ hex: String) -> Data? {
    guard hex.count % 2 == 0 else { return nil }
    var out = Data(capacity: hex.count / 2)
    var i = hex.startIndex
    while i < hex.endIndex {
      let j = hex.index(i, offsetBy: 2)
      guard let b = UInt8(hex[i ..< j], radix: 16) else { return nil }
      out.append(b)
      i = j
    }
    return out
  }

  private static func describe(_ error: Unmanaged<CFError>?) -> String {
    guard let error = error?.takeRetainedValue() else { return "unknown error" }
    return CFErrorCopyDescription(error) as String? ?? "\(error)"
  }

  private enum Err: Error, LocalizedError {
    case unknownHandle
    case osStatus(OSStatus)
    case message(String)

    var errorDescription: String? {
      switch self {
      case .unknownHandle: return "unknown key handle"
      case let .osStatus(status): return "OSStatus \(status)"
      case let .message(text): return text
      }
    }
  }
}
