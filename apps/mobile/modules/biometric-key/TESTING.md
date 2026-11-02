# biometric-key manual test checklist (T4/T5, security-spec s7 tests 16, 17)

Status: code written; NOT yet executed on hardware. Record device, OS version, date and tester per row.

## iOS (physical device with Face ID/Touch ID, dev build)
- [ ] generateKey returns securityLevel `secure_enclave`; SPKI decodes to 91 bytes starting `3059301306072a86...`.
- [ ] Key attributes (debug assertion): token = Secure Enclave, access control includes biometryCurrentSet, accessible WhenPasscodeSetThisDeviceOnly.
- [ ] sign shows Face ID / Touch ID prompt with the given reason; passcode fallback is hidden.
- [ ] Signature verifies independently (P-256 / SHA-256 / DER) against the SPKI: export one signature + message + SPKI and run `scripts/verify-sig.mjs`.
- [ ] Cancel prompt -> `USER_CANCELED`. Too many wrong faces -> `LOCKOUT` (verify the exact NSError the OS returns and fix `map()` if needed).
- [ ] Add a fingerprint/face in Settings -> next sign fails with `KEY_INVALIDATED`; app falls back to PIN; server key revoked after PIN unlock.
- [ ] Remove all biometrics -> `NOT_ENROLLED` / `isSupported().reason`.
- [ ] Device without passcode -> `isDeviceSecure()` false -> blocking screen.
- [ ] Simulator: generateKey fails unless `allowSoftware` (dev only); then securityLevel `software`.

## Android (physical device, API 30+; ideally one with StrongBox and one TEE-only)
- [ ] generateKey: securityLevel `strongbox` where FEATURE_STRONGBOX_KEYSTORE else `tee`; KeyInfo.isInsideSecureHardware true.
- [ ] sign shows BiometricPrompt, only BIOMETRIC_STRONG; negative button "Use PIN"; no device credential option.
- [ ] A Class 2 (weak) face unlock cannot satisfy the prompt/key.
- [ ] Enroll a new fingerprint -> sign throws `KEY_INVALIDATED`.
- [ ] Cancel / negative button -> `USER_CANCELED`; lockout -> `LOCKOUT`; no biometrics enrolled -> `NOT_ENROLLED`; no hardware -> `HARDWARE_UNAVAILABLE`.
- [ ] deleteKey removes alias (`hasKey` false).
- [ ] Signature verifies independently against SPKI.
- [ ] Unverified assumption to check: `BiometricPrompt` needs a `FragmentActivity` (ReactActivity is one).
