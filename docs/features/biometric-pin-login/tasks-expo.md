# Tasks: expo - biometric + PIN login
Contract: ./openapi.yaml   Security: ./security-spec.md   Notes/vectors: ./contract-notes.md, ./vectors/vectors.json   ADRs: ./decisions.md

Owner: expo-engineer. 22 tasks, each <= ~half a day. Order T1..T22. Dependencies only within this file or on the contract. This side NEVER imports backend code and NEVER needs the backend, Postgres or Docker to be running: it develops against a contract-derived mock (T3).

## Monorepo ground rules (apply to every task)
- App lives in `apps/mobile` (Expo SDK current stable, TypeScript strict, Expo Router, **development build / prebuild, NOT Expo Go**). Backend is `apps/api` (not yours).
- Files you OWN: everything under `apps/mobile/`, root `package.json`, `pnpm-workspace.yaml`, `.npmrc`, `.nvmrc`, `.github/workflows/mobile.yml`. Files you must NOT touch: root `Makefile`, `docker-compose.yml`, root `.env.example`, root `.gitignore`, `apps/api/**`, `.github/workflows/api.yml`. Need a root `.gitignore` entry? Use `apps/mobile/.gitignore` instead. All your commands are pnpm scripts in `apps/mobile/package.json` (the root `Makefile` merely forwards to `pnpm --filter mobile <script>`; keep these script names stable: `typecheck lint test gen:api mock android ios contract-test`).
- Contract is the only coupling: types are generated from `../../docs/features/biometric-pin-login/openapi.yaml` (path from `apps/mobile`) with `openapi-typescript`; never copy the YAML, never hand-write API types, never edit the contract.
- Workspace: pnpm workspaces (`apps/*`). Generated code goes to `apps/mobile/src/api/generated` (git-ignored or committed, pick one; `pnpm gen:api` must be idempotent).
- Security non-negotiables: PIN only in a ref buffer; no `console.*` in auth code; never put tokens/PIN in navigation params, state libs, AsyncStorage, logs; biometrics = native signature, never a boolean (SEC-019).

## Contract v1.1 amendments (security review) - these OVERRIDE any older task statement below
- `POST /auth/biometric/challenge` and `POST /auth/biometric/verify` now require `Authorization: Bearer <refresh token>` (same device credential as pin/verify). T14 must send it on both calls. Any 401 there is a normal biometric failure (go to PIN screen) and must NOT wipe the refresh token, deviceId or key (L-12). After 5 bad signatures the server suspends biometrics until the next PIN unlock (key is not revoked): the client simply falls back to PIN. (D-18, D-19)
- Sign out (T18): user-facing Sign out calls `DELETE /devices/{current}` first, then wipes SecureStore credentials and the local key; `POST /auth/logout` is end-session only and is not a substitute. (D-22)
- `X-StepUp-Token` is optional in the schema; handle 403 `STEPUP_REQUIRED` and 403 `STEPUP_INVALID` on `POST /transactions` and enroll challenge as before. Every operation has a `default` error response; regenerate types (`pnpm gen:api`) and make the typed error mapper accept the shared body. Mock (T3) must serve these. (D-21)
- T19: display-only impact of SEC-069 (`COOLING_OFF` 403 or `required=pin` may appear after several small transactions).
- `vectors.json` `tx-preimage-1` totalBytes is 138 (segments were always correct).

## T1 Scaffold workspace and Expo app
- **Status (expo-engineer): DONE. Workspace + Expo SDK 58 app, eas.json, ESLint (no-console, restricted imports), Jest (node + jest-expo), README, mobile.yml. `expo prebuild` verified for development and production variants; `scripts/check-manifest.mjs` passes (allowBackup=false, cleartext only in debug manifest, ATS local exception only in development variant). Not verified: that Expo Go refuses to open the app (documented only).**
- Depends on: (none)
- Implements: monorepo scaffolding; SEC-068 (dev build), SEC-067 (groundwork)
- Details: root `package.json` (private, `packageManager` pinned pnpm, scripts delegate `pnpm --filter mobile ...`), `pnpm-workspace.yaml` (`apps/*`), `.nvmrc`, `.npmrc` (strict peer deps off only if needed, documented). `apps/mobile`: Expo app with Expo Router, `app.config.ts`, `eas.json` (profiles `development` dev-client, `preview`, `production`), `expo-dev-client`, TypeScript strict, ESLint (with `no-console` error in `src/**`), Jest (`jest-expo`) + `@testing-library/react-native`. Android: `allowBackup=false`, `dataExtractionRules` excluding secure prefs, `usesCleartextTraffic` only in the debug variant (config plugin); iOS ATS exception only for localhost in debug. `expo-updates` OFF. `.github/workflows/mobile.yml`: install, typecheck, lint, test, `expo prebuild --no-install --platform all` smoke; path-filtered to `apps/mobile/**` and the contract.
- Acceptance criteria: `pnpm install && pnpm --filter mobile typecheck lint test` green; `pnpm --filter mobile exec expo prebuild` generates `android/` `ios/` (git-ignored) without errors; manifest check shows `allowBackup=false` and cleartext only in debug; app does not open in Expo Go (documented: requires dev build).
- Tests required: smoke render test; manifest assertion script (SEC-067 acceptance: `scripts/check-manifest.mjs`).
- Done when: README in `apps/mobile` explains `pnpm mock`, `pnpm android|ios` (dev build).

## T2 Typed API client generated from the contract
- **Status (expo-engineer): DONE. openapi-typescript types committed (`pnpm gen:api` idempotent), openapi-fetch client, exhaustive error mapping, base-URL guard, Idempotency-Key. Tests in `src/api/api.node.test.ts`. Note: dev http also allowed for private LAN IPs (physical device reaching `pnpm mock`).**
- Depends on: T1
- Implements: contract coupling; SEC-006 (client side), SEC-059 (error mapping)
- Details: `pnpm gen:api` runs `openapi-typescript` on the canonical spec (3.1 label is fine for this tool) into `src/api/generated/schema.d.ts`. `src/api/client.ts` uses `openapi-fetch` with base URL from `EXPO_PUBLIC_API_URL` (reject non-HTTPS in release builds at startup; `http://` only for localhost/10.0.2.2 in dev). A thin typed `ApiError` mapper turns `{error:{code,...}}` into a discriminated union on `code` (all codes from `ErrorCode`, exhaustive switch checked by TypeScript). Request wrapper: JSON only, no logging, timeouts (10 s), no automatic retry for non-idempotent calls, auto-attaches `Authorization` / `X-StepUp-Token` / `Idempotency-Key` (UUIDv4 via `expo-crypto`) only where the caller asks. Tokens never appear in URLs.
- Acceptance criteria: regenerating after a spec change breaks typecheck where a field is removed; an unknown error code in a response yields a typed `UNKNOWN_ERROR` and never throws raw body text into UI; building in release config with an `http://` base URL fails fast.
- Tests required: unit tests for error mapping (every code), idempotency-key attach, base-URL guard.
- Done when: all endpoints callable through typed functions in `src/api/endpoints.ts`.

## T3 Contract-derived mock server (MSW)
- **Status (expo-engineer): DONE. Mock core + MSW handlers (Jest via msw `getResponse`) + `node:http` host server instead of @mswjs/http-middleware (recorded in README). 14 scenarios, ajv request/response validation against the spec, conformance tests per scenario.**
- Depends on: T2
- Implements: development against the contract without backend; supports spec s7 tests 15-22 on the mock
- Details: `apps/mobile/mocks`: MSW handlers for every operation, request bodies validated against the spec schemas (ajv with schemas extracted from the OpenAPI, or `openapi-backend`/`@scalar` validators; pick one, strict `additionalProperties`), happy-path responses taken from the spec `examples` where present, otherwise generated from schemas. `pnpm mock` starts a host HTTP server (`msw` + `@mswjs/http-middleware` on port 8080, or Prism if MSW middleware proves unsuitable; record the choice in the README) so the dev build on a device/emulator can use `EXPO_PUBLIC_API_URL`. Jest uses the same handlers via `msw/node`. Scenario switch via a dev-only header-less control endpoint on the mock server (`POST /__mock/scenario {name}`) with scenarios: `happy`, `pin-invalid-n`, `pin-locked-soft`, `pin-hard-locked`, `unlock-required`, `refresh-reuse`, `bio-auth-failed`, `stepup-needs-pin`, `stepup-invalid`, `cooling-off`, `rate-limited`, `device-limit`, `service-unavailable`, `idempotent-replay`. The mock does NOT implement real crypto (any non-empty base64url signature accepted) and never contains real secrets. Conformance test: every mock response validates against the spec's response schema for that status.
- Acceptance criteria: `pnpm mock` serves all paths; unknown route -> 404; a body with an unknown field gets 400 VALIDATION_ERROR; scenario list matches contract-notes s7; conformance test green for every operation and scenario.
- Tests required: handler conformance test (response vs schema), request-validation test.
- Done when: all later UI tasks can be run end-to-end on the mock.

## T4 Native module: iOS Secure Enclave signing key
- **Status (expo-engineer): CODE DONE / DEVICE VERIFICATION PENDING. Swift module written (`modules/biometric-key/ios`); it COMPILES for iOS Simulator (Xcode build of the BiometricKey pod target succeeded) but has never been run: no Secure Enclave / Face ID exercised, no device. Checklist in TESTING.md. No independent signature-verification script was written yet.**
- Depends on: T1
- Implements: SEC-017, SEC-019, SEC-023 (iOS part), SEC-067 (ThisDeviceOnly), SEC-068 (own vetted module, pinned deps)
- Details: local Expo module `apps/mobile/modules/biometric-key` (Swift). API (shared with Android, T5): `isSupported()`, `generateKey(alias) -> {publicKeySpki: base64url, securityLevel, attestation?}`, `sign(alias, messageBase64Url, promptTitle) -> {signature: base64url DER}`, `deleteKey(alias)`, `hasKey(alias)`. iOS: `SecKeyCreateRandomKey` with `kSecAttrTokenIDSecureEnclave`, EC 256, access control `[.privateKeyUsage, .biometryCurrentSet]`, protection `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly`, non-exportable, `kSecAttrIsPermanent`. `sign` uses `SecKeyCreateSignature` with `.ecdsaSignatureMessageX962SHA256` (DER over SHA-256 of the message); prompt via `LAContext`/key access with `localizedReason`. Build SPKI from X9.63 public key by prepending the fixed header in contract-notes s0. Error enum: `USER_CANCELED`, `LOCKOUT`, `NOT_ENROLLED`, `KEY_INVALIDATED` (key missing or `errSecItemNotFound`/`errSecAuthFailed` after enrollment change), `HARDWARE_UNAVAILABLE`, `UNKNOWN`. Fail enrollment if Secure Enclave unavailable (simulator allowed only with a `__DEV__` flag, reported as `securityLevel: software`, SEC-022). Pin native dependencies; no third-party signing library.
- Acceptance criteria: on a physical device, key attributes assertion in a debug build shows SE token + `biometryCurrentSet`; adding a fingerprint/face makes `sign` fail with `KEY_INVALIDATED`; produced signature verifies with an independent P-256 check against the returned SPKI (unit test with CryptoKit or Node script using exported fixture); SPKI is 91 bytes.
- Tests required: spec s7 test 16 (iOS manual/instrumented), SEC-017 acceptance; JS-level mocks cover error mapping.
- Done when: module builds in a dev client; manual test checklist recorded in `modules/biometric-key/TESTING.md`.

## T5 Native module: Android Keystore signing key
- **Status (expo-engineer): CODE DONE / DEVICE VERIFICATION PENDING. Kotlin module written; `./gradlew :biometric-key:compileReleaseKotlin` succeeds, but it has never been run (no device, no BiometricPrompt/Keystore exercised). androidx.biometric pinned to 1.1.0. Checklist in TESTING.md.**
- Depends on: T1
- Implements: SEC-018, SEC-019, SEC-023 (Android part), SEC-067, SEC-068
- Details: same JS API as T4 (Kotlin). `KeyGenParameterSpec` EC `secp256r1`, `PURPOSE_SIGN`, digest SHA-256, `setUserAuthenticationRequired(true)`, per-use auth (`setUserAuthenticationParameters(0, AUTH_BIOMETRIC_STRONG)`), `setInvalidatedByBiometricEnrollment(true)`, `setIsStrongBoxBacked(true)` when `FEATURE_STRONGBOX_KEYSTORE` (retry without on `StrongBoxUnavailableException`; report `strongbox|tee`), `KeyInfo.isInsideSecureHardware` must be true else fail. `sign`: `BiometricPrompt` with `CryptoObject(Signature("SHA256withECDSA"))`, authenticators limited to `BIOMETRIC_STRONG`, NO device-credential fallback, negative button "Use PIN". Map `KeyPermanentlyInvalidatedException` -> `KEY_INVALIDATED`, lockout -> `LOCKOUT`, cancel -> `USER_CANCELED`, none enrolled -> `NOT_ENROLLED`. Public key from `getEncoded()` (already SPKI).
- Acceptance criteria: on a device, `isInsideSecureHardware` true; Class 2 (weak) face unlock cannot unlock the key; enrolling a new fingerprint yields `KEY_INVALIDATED`; signature verifies independently; deleteKey removes alias.
- Tests required: spec s7 test 16 (Android), test 17 (cancel/lockout/absent hardware map to errors, not success); instrumented checklist in `TESTING.md`.
- Done when: both platforms expose identical TypeScript types in `modules/biometric-key/src/index.ts`.

## T6 Signing message builder and shared vectors
- **Status (expo-engineer): DONE. `src/crypto/messages.ts`; both golden vectors reproduce byte for byte. Finding: `vectors.json` says tx-preimage-1 totalBytes=140 but its segments sum to 138 (contract-notes also says 140); test asserts the segments.**
- Depends on: T1
- Implements: SEC-027, SEC-043 (client), SEC-039 (client display only), SEC-019 (design)
- Details: `src/crypto/messages.ts` (pure TS, no native): `buildChallengeMessage(challenge)` exactly per contract-notes s1 from the server challenge fields (uint16 BE length prefixes, UUID strings as UTF-8, nonce decoded from base64url, expiresAt as 8-byte BE, empty boundHash as `0x0000`); base64url helpers (no padding, strict). Client does NOT compute `txHash` as authority; for display it uses the server `summary`. Optional local sanity function recomputing `txHash` from the entered fields only to detect server/client divergence and warn (never to bypass the server). Use `@noble/hashes` for SHA-256 in that check.
- Acceptance criteria: `login-preimage-1` and `tx-preimage-1` from `../../docs/features/biometric-pin-login/vectors/vectors.json` reproduce byte-for-byte (test reads the file via a relative path from `apps/mobile`, concatenates `segmentsHex`); `equivalentInputs` identical; mutation of any field changes bytes; base64url rejects padding/invalid chars.
- Tests required: spec s7 test 22 (golden vectors, message half), property tests on length-prefix encoding.
- Done when: module has zero imports from React or native modules.

## T7 Secure storage, passcode check, hint store
- **Status (expo-engineer): DONE. SecureStore (WHEN_PASSCODE_SET_THIS_DEVICE_ONLY) for refresh token + deviceId; access/step-up/bootstrap in memory; hint in AsyncStorage; `isDeviceSecure` via the native module; blocking passcode screen. Not done: standalone backup-inspection script (only manifest assertions + unit tests).**
- Depends on: T1, T4, T5 (uses `isDeviceSecure()` from the native module)
- Implements: SEC-034, SEC-054 (hint store), SEC-067, SEC-013 (nothing persisted about lock)
- Details: `src/storage/secureTokens.ts`: refresh token and deviceId in `expo-secure-store` with `keychainAccessible: WHEN_PASSCODE_SET_THIS_DEVICE_ONLY` (no `requireAuthentication`, see SEC-034 rationale); access token and step-up tokens in a module-level in-memory holder only (never persisted, cleared by `lock()`). `src/storage/hint.ts`: `biometricEnabled` hint in AsyncStorage (non-authoritative). Startup check: if the device has no passcode/biometric-capable secure lock (`SecureStore.canUseBiometricAuthentication` is not enough; use `expo-local-authentication` `getEnrolledLevelAsync` / `isDeviceSecure` equivalent via the native module `isDeviceSecure()` added to `biometric-key`) show a blocking "Set a device passcode" screen and refuse to proceed (fail closed). No lock state, PIN, attemptsRemaining or retryAfter is ever persisted.
- Acceptance criteria: unit tests prove tokens are never written to AsyncStorage; clearing AsyncStorage changes nothing about access; passcode-less simulation shows the blocking screen; backup inspection script confirms no token files in app data.
- Tests required: spec s7 tests 18 (clear storage), 21 (backup / no passcode).
- Done when: storage API is the only place importing SecureStore/AsyncStorage (lint rule `no-restricted-imports`).

## T8 Auth client: refresh, session holder, error policies
- **Status (expo-engineer): DONE. Single-flight refresh, write-then-use, UNLOCK_REQUIRED keeps token, AUTH_FAILED is the only wipe path, one 401 retry.**
- Depends on: T2, T7
- Implements: SEC-033 (client behaviour), SEC-013, SEC-006, SEC-032 (client side of rotation), SEC-055 (no logging)
- Details: `src/auth/session.ts`: holds access token in memory with expiry; `ensureAccess()` refreshes via `/auth/refresh` (refresh token in `Authorization` header) when the access token is within 30 s of expiry, serialising concurrent refreshes with a single in-flight promise; persists the rotated refresh token to SecureStore BEFORE using the new access token (write-then-use) and treats a failed write as fatal lock. On `UNLOCK_REQUIRED` -> go to Locked state (do not retry, token stays valid for pin/verify). On `AUTH_FAILED` from refresh -> credential gone: clear tokens, require re-bootstrap (demo-login flow). 401 on any API call -> try one refresh; never loop. Never logs; never stores lock state.
- Acceptance criteria: concurrent API calls cause exactly one refresh; refresh rotation persisted before use; UNLOCK_REQUIRED does not delete the refresh token; AUTH_FAILED clears it and routes to onboarding.
- Tests required: spec s7 test 19 (refresh without unlock => 401 handled), unit tests with T3 scenarios `unlock-required`, `refresh-reuse`.
- Done when: all API calls in the app go through `session.authedFetch`.

## T9 Lock manager and auth state machine
- **Status (expo-engineer): DONE. Zustand vanilla state machine without secrets; `__unlockFromServerSession` used only by session.ts (test-enforced); AutoLock 30 s / 5 min with injected clock.**
- Depends on: T8
- Implements: SEC-050, SEC-019, SEC-013, SEC-054 (state wiring)
- Details: single state machine (e.g. `zustand` store holding NO secrets, or XState): `Booting -> NeedsPasscode | Onboarding | Locked -> Unlocked`. Cold start always `Locked` (or `Onboarding` when no refresh token). `AppState` listener: on background start a timer (default 30 s, settings options immediate/30 s/1 min, max 1 min) and a 5 min foreground inactivity timer (reset on touch via a root `PanResponder`/`onTouchStart`); expiry or return after timer -> `lock()`: drop access token and step-up tokens from memory, clear sensitive component state (navigate to the lock route with `router.replace`, unmount protected tree), keep refresh token in SecureStore. Unlocking happens only via a successful `pin/verify` or `biometric/verify` response (T13, T14); nothing sets `Unlocked` from a local boolean. Protected route group is guarded by `Unlocked` AND an access token present.
- Acceptance criteria: background > 30 s -> lock screen; <= 30 s -> stays; cold start -> lock; no code path sets Unlocked without a server session response (test asserts via spying on the setter); after lock the in-memory token is null.
- Tests required: spec s7 tests 15 (hooked `authenticate()` returns true -> still locked), 19.
- Done when: `lock()` is invoked by logout, timers, `AUTH_FAILED` handling.

## T10 PIN keypad component
- **Status (expo-engineer): DONE. Custom keypad, ref'd PinBuffer, ownership handed to the caller, client policy mirror. Not done: the optional feature-flagged TextInput mode (not needed; SEC-052 allows the custom keypad).**
- Depends on: T1
- Implements: SEC-002, SEC-052, SEC-053
- Details: custom in-app numeric keypad (no system keyboard, hence no autofill/clipboard/third-party keyboards). Digits kept in a `useRef<number[]>` (never state, context, navigation params, error objects); display shows dots from a count-only state; on submit the buffer is passed to the callback then overwritten (`fill(0)`) and cleared immediately, also on failure/unmount/background. Props for an alternative `TextInput` mode (feature flag, off): `secureTextEntry`, `keyboardType="number-pad"`, `autoComplete="off"`, `textContentType="none"`, `autoCorrect={false}`, `importantForAutofill="noExcludeDescendants"`, `contextMenuHidden`, `maxLength=6`, paste disabled. Client policy mirror (`src/pin/policy.ts`): regex + all-same, runs, repeating blocks, small top-N list; message "choose a less predictable PIN" (server remains authority). Confirm-entry match for setup/change/reset. Accessibility labels without digit values leaking to logs.
- Acceptance criteria: after submit the ref buffer is zeroed and display count is 0; component never calls `console`; weak PIN set blocks locally AND still 422s on the mock (`PIN_WEAK`) with the same UI message; unmount mid-entry clears buffer.
- Tests required: spec s7 test 20 (PIN field flags/props, no PIN in React state snapshot), SEC-002 acceptance (tampered client check -> server 422 handled).
- Done when: PIN state is not reachable from any store (lint/test using React DevTools-like tree snapshot).

## T11 Screen capture protection and privacy overlay
- **Status (expo-engineer): CODE DONE / DEVICE VERIFICATION PENDING. usePreventScreenCapture app-wide + PrivacyOverlay (unit-tested). Screenshot/app-switcher results unverified; see docs/security-checklist.md.**
- Depends on: T1
- Implements: SEC-051
- Details: `expo-screen-capture` `usePreventScreenCapture()` at the app root (app-wide, simplest) on Android (FLAG_SECURE) and iOS capture blocking; opaque `PrivacyOverlay` rendered when `AppState` is `inactive` or `background` so the app-switcher snapshot is blank (render it synchronously on `inactive`, not after a timer). Do not render balances behind the overlay.
- Acceptance criteria: manual: screenshot on Android is black; app switcher shows overlay on both OS; unit test that the overlay is mounted on `inactive` and `background` events.
- Tests required: spec s7 test 20 (screenshot/app-switcher).
- Done when: checklist in `apps/mobile/docs/security-checklist.md` ticked on device.

## T12 Onboarding: demo-login, device registration, PIN setup
- **Status (expo-engineer): DONE on the mock. Deviation: on IDEMPOTENT_REPLAY/PIN_ALREADY_SET the flow returns to sign-in (bootstrap tokens are single use) instead of going directly to PIN unlock. Release-bundle secret scan in `scripts/check-release-bundle.mjs`.**
- Depends on: T3, T7, T9, T10
- Implements: screens `/onboarding/*`; SEC-015 (client path), SEC-016 (no secret in source), SEC-048, SEC-002, SEC-006, SEC-060 (client idempotency)
- Details: Flow per contract-notes s5.1: username + demo secret entry screen (secret typed by the user or read from `EXPO_PUBLIC_*` ONLY in a dev profile; never committed, never in the release bundle: assert in CI by grepping the bundle for the dev secret marker) -> `POST /auth/demo-login {intent: login}` -> if scope `pin-setup`: `POST /devices` (new `Idempotency-Key`, reuse the same key on retry of the same attempt) -> PIN entry + confirm -> `POST /pin` (new key) -> store refresh token + deviceId -> Unlocked -> offer "Enable biometrics?" (T15). If scope `pin-verify` (account already has a PIN, new install): `POST /devices` -> go to PIN unlock using the bootstrap token as credential (T13 variant). Handle `PIN_ALREADY_SET`, `PIN_WEAK`, `DEVICE_LIMIT`, `RATE_LIMITED` (countdown from `Retry-After`), `IDEMPOTENT_REPLAY` on `POST /pin` (means it already succeeded: send user to PIN unlock). Bootstrap token kept in memory only.
- Acceptance criteria: happy path on mock reaches Home; each error code above shows a distinct non-leaky message; killing the app between steps resumes safely (bootstrap tokens are not persisted, restart demo-login); no PIN or token in any navigation param (test inspects router state).
- Tests required: component/integration tests on T3 scenarios; SEC-002 UI test; spec s7 test 20 (no PIN in state).
- Done when: first-run flow demoed on mock.

## T13 PIN unlock screen with lockout UX
- **Status (expo-engineer): DONE. All lock/limit states tested on mock scenarios; countdown is UI-only. Not visually reviewed on a device.**
- Depends on: T3, T8, T9, T10
- Implements: SEC-013, SEC-012 (notice display), SEC-014 (client sends credential), SEC-054, SEC-050
- Details: screen shows PIN keypad (and a "Use biometrics" button only if the hint says enabled AND a local key exists). Submit: `POST /auth/pin/verify` with `Authorization: Bearer <refresh token from SecureStore>` (or bootstrap token on a fresh install) and body `{deviceId, pin}`. Responses: 200 -> store rotated refresh token, set session, Unlocked, update hint from `biometricEnabled` (reconciliation SEC-054), show a one-time notice if `recentFailures > 0` (SEC-012); `PIN_INVALID` -> shake + `attemptsRemaining`; `PIN_LOCKED` soft -> countdown from `retryAfter` (UI-only disable; every attempt still hits the server after the countdown; the countdown is not persisted), hard -> "Reset PIN" CTA (T17); `AUTH_FAILED` (credential missing/revoked) -> onboarding; `RATE_LIMITED` -> countdown from `Retry-After`; offline -> remain locked with retry (no offline unlock). Biometric button remains usable during soft lock.
- Acceptance criteria: clearing app storage does not reset the server lock (the mock keeps it); attemptsRemaining and countdown rendered only from server data; correct PIN during lock still shows locked (mock scenario); input cleared after every attempt.
- Tests required: spec s7 tests 18, 20, SEC-013 acceptance; scenario tests `pin-invalid-n`, `pin-locked-soft`, `pin-hard-locked`, `rate-limited`.
- Done when: all lock/limit states visually reviewed.

## T14 Biometric unlock
- **Status (expo-engineer): CODE DONE (JS verified with a fake native module; real signing/prompt/invalidation unverified on device). Bytes passed to the signer asserted against an independent re-implementation of contract-notes s1.**
- Depends on: T4, T5, T6, T3, T9
- Implements: SEC-019, SEC-023 (client fallback), SEC-029 (client treats all failures alike), SEC-054
- Details: on Locked with hint enabled and `hasKey(alias)`: `POST /auth/biometric/challenge {deviceId}` -> `buildChallengeMessage` from the response fields -> native `sign` (OS prompt unlocks the key) -> `POST /auth/biometric/verify {challengeId, deviceId, signature}`. 200 -> same session handling as T13 (`amr=bio`). Any failure (401 AUTH_FAILED, `USER_CANCELED`, `LOCKOUT`, `NOT_ENROLLED`, `HARDWARE_UNAVAILABLE`, network error) -> PIN screen with a neutral message; never "open". `KEY_INVALIDATED` -> `deleteKey`, clear hint, show PIN, after PIN unlock call `DELETE /devices/{id}/biometric` (T16 handles message). Do NOT import `expo-local-authentication` anywhere in the unlock path (lint `no-restricted-imports`), and no function returns a boolean "biometric ok".
- Acceptance criteria: with `LocalAuthentication.authenticate` mocked to true by a test harness the unlock still fails when the signature is absent/invalid (mock `bio-auth-failed`); cancel/lockout/absent hardware land on PIN; successful path calls verify with a signature over exactly the preimage built from the challenge (assert bytes passed to native signer equal vectors-based expectation).
- Tests required: spec s7 tests 15, 17, 22 (message passed to signer); 16 (invalidated flow, mocked native error).
- Done when: no screen reads a bare boolean for auth (grep/lint check in CI).

## T15 Enable biometrics flow
- **Status (expo-engineer): CODE DONE (JS verified with a fake native module). Lifecycle doc: docs/biometric-key-lifecycle.md.**
- Depends on: T14, T10, T3
- Implements: SEC-020, SEC-017/018 (via module), SEC-022 (attestation fields), SEC-038, SEC-054
- Details: Settings -> Enable biometrics: check `isSupported()` and enrolled biometrics; PIN keypad "Confirm your PIN" -> `POST /stepup/challenge {action: enable_biometric, targetDeviceId: deviceId}` -> `POST /stepup/verify {challengeId, pin}` -> `POST /devices/{id}/biometric/enroll/challenge` with `X-StepUp-Token` (step-up token held in memory, discarded right after) -> `generateKey(alias)` -> sign the enroll challenge with the NEW key (biometric prompt) -> `POST /devices/{id}/biometric/enroll {challengeId, publicKey, attestation{type:none, keySecurityLevel from module}, signature}` with `Idempotency-Key`. On any failure after key creation delete the key. On success set hint true, show cooling-off notice from `coolingOffUntil`. Step-up and enroll must complete within the 60 s TTLs: surface `STEPUP_INVALID` as "try again" and restart.
- Acceptance criteria: happy path against mock; `INVALID_PUBLIC_KEY` and `PIN_INVALID`/`PIN_LOCKED` handled; key deleted on failure; no key exists locally if server enrollment fails; hint only set after 201.
- Tests required: spec s7 tests 16 (enroll), 18, 22; negative scenarios on mock.
- Done when: key lifecycle diagram in `apps/mobile/docs/biometric-key-lifecycle.md`.

## T16 Disable biometrics and key invalidation handling
- **Status (expo-engineer): DONE (JS). Six-row reconciliation table tested; real key deletion on device unverified.**
- Depends on: T15
- Implements: SEC-023, SEC-024 (client deletes local key), SEC-054 (reconciliation matrix)
- Details: Settings -> Disable: if session `authTime` older than 5 min prompt PIN unlock first, then `DELETE /devices/{id}/biometric`, then `deleteKey`, hint false. Invalidation path from T14: after the PIN unlock call DELETE and show "Biometrics were disabled because your device biometrics changed. Re-enable in Settings". Reconciliation on every unlock response `biometricEnabled` vs hint vs `hasKey`: hint true + no key or server false -> clear hint; hint false + server true + key present -> set hint; hint true + invalidated -> invalidation path. `STEPUP_REQUIRED` from DELETE -> re-unlock then retry once.
- Acceptance criteria: matrix of 6 states covered by tests; flipping the AsyncStorage hint by hand never grants access (still needs signature/PIN); local key removed on revoke.
- Tests required: spec s7 tests 16, 18.
- Done when: matrix table in tests mirrors SEC-054 text.

## T17 PIN reset and hard-lock recovery
- **Status (expo-engineer): DONE on the mock (pin-hard-locked -> reset -> unlocked; old device/key/hint dropped).**
- Depends on: T12, T13
- Implements: SEC-046 (client), SEC-011 (client path), SEC-047 (cooling-off notice), SEC-024 (delete local key)
- Details: from hard lock (`lockType=hard`) or "Forgot PIN": `demo-login {intent: reset}` -> `POST /devices` (NEW device id; old one is revoked by the server) -> new PIN + confirm -> `POST /pin/reset` with `Idempotency-Key` -> replace stored deviceId and refresh token, delete the local biometric key and clear the hint (server revoked all keys), show cooling-off banner and "re-enable biometrics". `IDEMPOTENT_REPLAY` -> go to PIN unlock with the new PIN.
- Acceptance criteria: after reset the old deviceId/key are gone locally; user must re-enroll biometrics; reset path available from the hard-lock screen; mock scenario `pin-hard-locked` -> reset -> unlocked.
- Tests required: flow test; spec s7 test 18.
- Done when: recovery documented in README.

## T18 Settings: change PIN and device management
- **Status (expo-engineer): DONE on the mock.**
- Depends on: T13, T15
- Implements: SEC-045 (client), SEC-049, SEC-038, SEC-047 (display)
- Details: Change PIN: old PIN + new PIN + confirm -> `PUT /pin` (`Idempotency-Key`); on 200 swap in the re-issued tokens (write refresh token first); `PIN_INVALID`/`PIN_LOCKED` same UX as T13; `PIN_UNCHANGED`, `PIN_WEAK`. Devices screen: `GET /devices` (current badge, biometric status); revoke current device -> `DELETE /devices/{id}` then wipe local credentials and key; revoke OTHER device -> step-up with PIN (`action: revoke_device`) then DELETE with `X-StepUp-Token`. 404 treated as already gone.
- Acceptance criteria: after change PIN, tokens replaced and hint unchanged; revoke-other requires PIN prompt; revoke-current wipes SecureStore and key and routes to onboarding.
- Tests required: flow tests with mock; spec s7 test 18.
- Done when: both screens reachable from Settings.

## T19 Dashboard and send transaction with step-up
- **Status (expo-engineer): DONE on the mock for bio, PIN and server-forced-PIN proof paths.**
- Depends on: T14, T6, T3, T13
- Implements: SEC-039, SEC-041 (client follows server `required`), SEC-043, SEC-040 (client single use), SEC-044, SEC-060, SEC-047 (COOLING_OFF UX)
- Details: `GET /dashboard` rendering with decimal strings (no float math; use a decimal lib or string ops). Send form validates format locally (UX only). Flow: `POST /stepup/challenge {action: transaction, tx}` -> show the server `summary` (title/lines) as the confirmation text, NOT locally formatted fields; optionally warn if the local sanity hash differs from `txHash` (T6) -> proof per `required`: `bio` or `either` -> biometric sign (message purpose `stepup`, boundHash from challenge) unless user picks PIN; `pin` -> PIN keypad -> `POST /stepup/verify` -> `POST /transactions` with `X-StepUp-Token`, `Idempotency-Key` (same key reused only for retry of the same tx) and the SAME fields. Never mutate fields between challenge and submit. Handle `STEPUP_REQUIRED(required=pin)` by switching to PIN proof, `STEPUP_INVALID` (restart the flow), `COOLING_OFF` (message with retryAfter), `INSUFFICIENT_FUNDS`, `PIN_INVALID`/`PIN_LOCKED`. Step-up token held in memory, dropped on use or lock.
- Acceptance criteria: changing amount after the challenge forces a new challenge (form locks fields once the challenge is issued); biometric attempt when server demands PIN falls back to PIN screen; double-tap on Send submits once (idempotency + disabled button).
- Tests required: spec s7 tests 22 (stepup message bytes), 15, 20; mock scenarios `stepup-needs-pin`, `stepup-invalid`, `cooling-off`.
- Done when: flow works against the mock for all three proof paths.

## T20 Risk signals and notices
- **Status (expo-engineer): DONE. Advisory only; lint restricts imports.**
- Depends on: T13
- Implements: SEC-056, SEC-012 (client display), SEC-064 (client side)
- Details: `src/risk/signals.ts` uses `expo-device` `isRootedExperimentalAsync` (and emulator/debugger flags when available) and attaches `risk` to `POST /devices`, `pin/verify`, `biometric/verify` bodies (optional field). Never used by the client as a gate. Notices: one-time banner for `recentFailures > 0` ("N failed attempts since your last login") and cooling-off info.
- Acceptance criteria: with the root signal forced true, the app still works and the signal is sent; no UI logic branches on the signal.
- Tests required: unit tests; lint rule against importing `signals` outside the API layer.
- Done when: documented as advisory in README.

## T21 Release hardening
- **Status (expo-engineer): MOSTLY DONE. production babel console stripping, release export + bundle scan verified (no dev secret in the Hermes bundle), manifest check, CI wiring. Not verified: Hermes debugger/dev-menu disabled in a release build on device; native dependency pinning is limited to androidx.biometric.**
- Depends on: T1
- Implements: SEC-055, SEC-067, SEC-068, SEC-006, SEC-034 (verification)
- Details: babel `transform-remove-console` in production profile; disable Hermes debugger/dev menu in release; verify `expo-updates` disabled (or code-signing configured); scrub any error reporter/analytics (none by default; if added: `beforeSend` that drops bodies/headers/breadcrumbs); pin native dependency versions (lockfile + exact versions for `modules/biometric-key` deps); CI scripts: `scripts/check-release-bundle.mjs` greps the release bundle for `console.` in auth modules, for the dev demo secret marker, and for `http://` base URLs; `scripts/check-manifest.mjs` (cleartext off in release, `allowBackup=false`, iOS ATS).
- Acceptance criteria: scripts pass on a release export (`expo export` / EAS local build) and fail on a deliberate violation (verified once).
- Tests required: spec s7 tests 20 (no logs in release bundle), 21.
- Done when: scripts wired into `mobile.yml`.

## T22 Integration and contract tests (final)
- **Status (expo-engineer): PARTIAL. `contract-test` and `docs/sec7-matrix.md` exist and the automated part is green. The manual device checklist (rows 16, 17, 19-21 parts) has NOT been executed on any iOS/Android device.**
- Depends on: T21, T19, T18, T17, T16, T12
- Implements: contract conformance on the client side; spec s7 tests 15-22 matrix
- Details: `pnpm --filter mobile contract-test`: (a) static check that every operationId in the spec has a typed endpoint function and a mock handler; (b) run the full app flows (onboarding, PIN unlock, biometric unlock with mocked native module, enable/disable biometrics, change PIN, reset, revoke, send tx with each proof path) against the MSW handlers from T3 in Jest; (c) every mock scenario error code is rendered by some UI test; (d) golden-vector test (T6) wired in; (e) matrix file `apps/mobile/docs/sec7-matrix.md` mapping tests 15-22 to automated tests or to the manual device checklist (tests needing hardware: 16, parts of 17 and 20/21 are manual; list them with owner and date).
- Acceptance criteria: contract-test green in CI; removing an endpoint from the spec (simulated by regenerated types) fails typecheck; matrix has no empty row.
- Tests required: spec s7 tests 15-22.
- Done when: manual device checklist executed once on one iOS and one Android device and recorded.

## Definition of Done (expo)
- [ ] `pnpm --filter mobile typecheck lint test contract-test` pass in CI; app runs in a dev build (not Expo Go) against `pnpm mock`.
- [ ] No `console.*` in `src/`; no PIN/token/key in logs, navigation params, state stores or AsyncStorage; release bundle scan clean.
- [ ] No gating on a bare biometric boolean; `expo-local-authentication` not used in the unlock path.
- [ ] Spec s7 Expo tests 15-22 mapped in `apps/mobile/docs/sec7-matrix.md` (manual items executed on devices).
- [ ] Generated types come from the canonical spec; contract file unmodified.
- [ ] SEC coverage table below is complete.

## SEC coverage (Expo side; full table in decisions.md)
| SEC | Tasks | SEC | Tasks | SEC | Tasks |
|---|---|---|---|---|---|
| 002 | T10,T12 | 034 | T7,T21 | 054 | T7,T9,T13,T14,T15,T16 |
| 006 | T2,T21 | 038 | T15,T18 | 055 | T8,T21 |
| 011 | T13,T17 | 039 | T6,T19 | 056 | T20 |
| 012 | T13,T20 | 040 | T19 | 060 | T12,T19 |
| 013 | T7,T8,T13 | 041 | T19 | 064 | T20 |
| 015 | T12 | 043 | T6,T19 | 067 | T1,T4,T7,T21 |
| 016 | T12 | 044 | T19 | 068 | T1,T4,T21 |
| 017 | T4,T15 | 045 | T18 | 019 | T4,T5,T9,T14 |
| 018 | T5,T15 | 046 | T17 | 020 | T15 |
| 022 | T15 | 047 | T17,T18,T19 | 023 | T4,T5,T14,T16 |
| 024 | T16,T17 | 049 | T18 | 027 | T6 |
| 033 | T8,T9 | 050 | T9,T13 | 051 | T11 |
| 052 | T10 | 053 | T10 | 048 | T12 |
| 014 | T13 | 029 | T14 | 032 | T8 |
