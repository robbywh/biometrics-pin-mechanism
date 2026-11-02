import ExpoModulesCore
import LocalAuthentication
import Security
import CryptoKit

// SEC-017 / SEC-019 / SEC-023 / SEC-067.
// P-256 key in the Secure Enclave: access control [.privateKeyUsage, .biometryCurrentSet], accessible
// WhenPasscodeSetThisDeviceOnly, non-exportable, permanent. `sign` returns an ASN.1 DER ECDSA signature over SHA-256(message).
// There is no function in this module that returns "biometric ok" as a boolean.

private let p256SpkiHeader: [UInt8] = [
  0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
  0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
]

private final class BKError: Exception, @unchecked Sendable {
  init(_ code: String, _ reason: String) {
    super.init(name: "BiometricKeyError", description: reason, code: code)
  }
}

private func b64urlDecode(_ s: String) -> Data? {
  var t = s.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
  while t.count % 4 != 0 { t += "=" }
  return Data(base64Encoded: t)
}
private func b64urlEncode(_ d: Data) -> String {
  d.base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
}

public final class BiometricKeyModule: Module {
  private func tag(_ alias: String) -> Data { Data(("com.cryptoapp.biometric-key." + alias).utf8) }

  private func keyQuery(_ alias: String, context: LAContext? = nil) -> [String: Any] {
    var q: [String: Any] = [
      kSecClass as String: kSecClassKey,
      kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
      kSecAttrApplicationTag as String: tag(alias),
      kSecReturnRef as String: true,
    ]
    if let context = context { q[kSecUseAuthenticationContext as String] = context }
    return q
  }

  private func map(_ error: Error?) -> BKError {
    guard let nsError = error as NSError? else { return BKError("UNKNOWN", "unknown") }
    if nsError.domain == LAError.errorDomain {
      switch LAError.Code(rawValue: nsError.code) {
      case .userCancel, .appCancel, .systemCancel, .userFallback: return BKError("USER_CANCELED", "canceled")
      case .biometryLockout: return BKError("LOCKOUT", "lockout")
      case .biometryNotEnrolled: return BKError("NOT_ENROLLED", "not enrolled")
      case .biometryNotAvailable, .passcodeNotSet: return BKError("HARDWARE_UNAVAILABLE", "unavailable")
      case .authenticationFailed: return BKError("USER_CANCELED", "not recognised")
      default: return BKError("UNKNOWN", "la error")
      }
    }
    switch OSStatus(nsError.code) {
    case errSecUserCanceled: return BKError("USER_CANCELED", "canceled")
    // Enrollment change invalidates a .biometryCurrentSet key: the item is gone or no longer usable.
    case errSecItemNotFound, errSecAuthFailed: return BKError("KEY_INVALIDATED", "key invalidated")
    case errSecInteractionNotAllowed: return BKError("HARDWARE_UNAVAILABLE", "interaction not allowed")
    default: return BKError("UNKNOWN", "keychain error")
    }
  }

  public func definition() -> ModuleDefinition {
    Name("BiometricKey")

    // Does the device have a passcode (SEC-034 fail-closed check)?
    AsyncFunction("isDeviceSecure") { () -> Bool in
      var err: NSError?
      return LAContext().canEvaluatePolicy(.deviceOwnerAuthentication, error: &err)
    }

    AsyncFunction("isSupported") { () -> [String: Any] in
      let ctx = LAContext()
      var err: NSError?
      let ok = ctx.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &err)
      var enrolled = ok
      var reason = "ok"
      if !ok, let code = err.flatMap({ LAError.Code(rawValue: $0.code) }) {
        enrolled = false
        reason = code == .biometryNotEnrolled ? "NOT_ENROLLED" : (code == .biometryLockout ? "LOCKOUT" : "HARDWARE_UNAVAILABLE")
      }
      #if targetEnvironment(simulator)
      let hasSE = false
      #else
      let hasSE = SecureEnclave.isAvailable
      #endif
      return ["secureHardware": hasSE, "biometricEnrolled": enrolled, "reason": reason]
    }

    AsyncFunction("hasKey") { (alias: String) -> Bool in
      let ctx = LAContext()
      ctx.interactionNotAllowed = true // never prompt for an existence check
      var q = self.keyQuery(alias, context: ctx)
      q[kSecReturnRef as String] = false
      q[kSecReturnAttributes as String] = true
      let s = SecItemCopyMatching(q as CFDictionary, nil)
      // errSecInteractionNotAllowed means the item exists but needs auth.
      return s == errSecSuccess || s == errSecInteractionNotAllowed
    }

    // allowSoftware: only honoured on the simulator / DEBUG builds (SEC-017 / SEC-022); reported as securityLevel "software".
    AsyncFunction("generateKey") { (alias: String, allowSoftware: Bool) -> [String: Any] in
      _ = SecItemDelete(self.keyQuery(alias) as CFDictionary)
      var acErr: Unmanaged<CFError>?
      var flags: SecAccessControlCreateFlags = [.biometryCurrentSet]
      var useSE = true
      #if targetEnvironment(simulator)
      useSE = false
      #else
      useSE = SecureEnclave.isAvailable
      #endif
      if useSE { flags.insert(.privateKeyUsage) }
      guard let ac = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly, flags, &acErr) else {
        throw BKError("HARDWARE_UNAVAILABLE", "access control")
      }
      var allowSoft = false
      #if DEBUG
      allowSoft = allowSoftware
      #endif
      #if targetEnvironment(simulator)
      allowSoft = allowSoftware
      #endif
      if !useSE && !allowSoft { throw BKError("HARDWARE_UNAVAILABLE", "secure enclave unavailable") }

      let priv: [String: Any] = [
        kSecAttrIsPermanent as String: true,
        kSecAttrApplicationTag as String: self.tag(alias),
        kSecAttrAccessControl as String: ac,
      ]
      var attrs: [String: Any] = [
        kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrKeySizeInBits as String: 256,
        kSecPrivateKeyAttrs as String: priv,
      ]
      if useSE { attrs[kSecAttrTokenID as String] = kSecAttrTokenIDSecureEnclave }
      var cfErr: Unmanaged<CFError>?
      guard let key = SecKeyCreateRandomKey(attrs as CFDictionary, &cfErr), let pub = SecKeyCopyPublicKey(key),
            let raw = SecKeyCopyExternalRepresentation(pub, &cfErr) as Data? else {
        throw self.map(cfErr?.takeRetainedValue())
      }
      // X9.63 uncompressed point (0x04||X||Y, 65 bytes) -> SPKI DER (91 bytes) by prepending the fixed header.
      guard raw.count == 65, raw.first == 0x04 else { throw BKError("UNKNOWN", "unexpected public key format") }
      let spki = Data(p256SpkiHeader) + raw
      return ["publicKeySpki": b64urlEncode(spki), "securityLevel": useSE ? "secure_enclave" : "software"]
    }

    // Prompts for biometrics (Face ID / Touch ID); the OS releases the SE key only on a match. Returns DER signature.
    AsyncFunction("sign") { (alias: String, messageB64Url: String, promptTitle: String) -> [String: Any] in
      guard let message = b64urlDecode(messageB64Url) else { throw BKError("UNKNOWN", "bad message") }
      let ctx = LAContext()
      ctx.localizedReason = promptTitle
      ctx.localizedFallbackTitle = "" // hide the passcode fallback: our fallback is the in-app PIN
      var item: CFTypeRef?
      let s = SecItemCopyMatching(self.keyQuery(alias, context: ctx) as CFDictionary, &item)
      guard s == errSecSuccess, let item = item else { throw self.map(NSError(domain: NSOSStatusErrorDomain, code: Int(s))) }
      let key = item as! SecKey
      var cfErr: Unmanaged<CFError>?
      guard let sig = SecKeyCreateSignature(key, .ecdsaSignatureMessageX962SHA256, message as CFData, &cfErr) as Data? else {
        throw self.map(cfErr?.takeRetainedValue())
      }
      return ["signature": b64urlEncode(sig)]
    }

    AsyncFunction("deleteKey") { (alias: String) -> Void in
      let s = SecItemDelete(self.keyQuery(alias) as CFDictionary)
      if s != errSecSuccess && s != errSecItemNotFound { throw BKError("UNKNOWN", "delete failed") }
    }
  }
}
