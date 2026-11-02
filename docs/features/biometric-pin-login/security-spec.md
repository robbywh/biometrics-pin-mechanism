# Security Spec: Biometric + PIN login (slug: biometric-pin-login)

Status: Phase 2. Input: `draft.md`. Standards mapping: OWASP MASVS (STORAGE, CRYPTO, AUTH, NETWORK, PLATFORM, RESILIENCE), ASVS L2 (L3 where noted), NIST SP 800-63B (memorised secrets, throttling).
Legend per requirement: `[owner]` = BE (Go) / FE (Expo) / BOTH. `Sev` = severity if violated. `Demo` = **KEEP** (must not be relaxed for the demo) or **SIMPLIFY** (relaxation allowed as described). Short rationale after "Why".

## 1. Scope & assumptions

- Demo crypto app, no real funds. We still build it to wallet-grade rules because it is the reference for the real app. Anything labelled SIMPLIFY must be a conscious, documented config switch, not a missing code path.
- The PIN is verified **only on the server**. There is no offline unlock; if offline, the app stays locked. Consequently there is no local PIN verifier to steal (this removes the local-offline-attack class entirely, at a cost of requiring connectivity).
- A 6-digit PIN has 10^6 possibilities. It is **not** a strong secret. Its only real protection is online throttling plus the requirement that the attacker also hold a device-bound credential. Hashing (Argon2id + pepper) only matters after a DB leak, and even then buys limited time unless the pepper stays out of the DB. This is stated plainly so nobody oversells it.
- Biometrics is a local unlock factor: success releases a hardware-backed P-256 key that signs a server challenge. Never a boolean.
- Client: Expo **development build / prebuild with a native module** (Expo Go cannot do key-signing, `biometryCurrentSet` or StrongBox). `expo-secure-store` and `expo-local-authentication` alone are not sufficient for SEC-017..019.
- Out of scope per draft: real keys/funds, KYC, web, push. Device attestation enforcement is out for the demo (Q12) but the data model keeps the slots.

### Findings against the draft that change the design (read first)

1. **F1 (Critical): `POST /auth/pin/verify (deviceId, pin)` as drafted is unauthenticated.** Anyone who knows or guesses a deviceId could brute-force the PIN remotely, and trigger lockout DoS. Fixed by SEC-014 (device credential required).
2. **F2 (Critical): `demo-login` is a stub with no credential and doubles as "PIN reset" and "hard-lock recovery".** Anyone could call it, then `POST /pin` and overwrite the victim's PIN, bypassing all lockout. Fixed by SEC-015, SEC-016, SEC-046.
3. **F3 (High): `/auth/refresh` as drafted lets a refresh token alone mint an access token, so the PIN/biometric gate would be client-side UI only** (malware or a stolen phone skips the lock screen and calls refresh). Fixed by SEC-033 (server-enforced unlock window).
4. **F4 (High): step-up draft sends only `txHash` from the client.** The server must receive the transaction fields and recompute. Fixed by SEC-039.
5. **F5 (Medium): distinct codes CHALLENGE_EXPIRED / CHALLENGE_REPLAYED / unknown device give an oracle.** Fixed by SEC-029, SEC-059.

## 2. Assets / actors / trust boundaries

Assets: (A1) PIN (knowledge factor); (A2) biometric private key (non-exportable, in SE/StrongBox/TEE); (A3) refresh token = long-lived device credential; (A4) access token; (A5) step-up tokens; (A6) server PIN hash + pepper; (A7) mock balances/tx authority (stand-in for funds); (A8) audit log integrity; (A9) device registry/public keys.

Actors: legitimate user; thief with the unlocked or locked phone; thief who knows/shoulder-surfed the PIN; malware / Frida on a rooted device; remote attacker with a stolen refresh token or DB dump; MITM on hostile Wi-Fi; insider with log/DB access; credential-stuffing bot hitting demo-login; social engineer targeting reset.

Trust boundaries: (TB1) JS runtime <-> native secure hardware (JS is hookable; only the hardware key is trusted); (TB2) device <-> network (TLS); (TB3) API <-> data store; (TB4) API <-> secrets/KMS (pepper); (TB5) logs/crash reports (untrusted sink).

## 3. Threats & abuse cases (STRIDE)

| # | Threat | STRIDE | Impact | Mitigation |
|---|---|---|---|---|
| T1 | Online PIN brute force (remote, by deviceId/user) | S/E | Account takeover (10^6 space) | SEC-008..012, 014, 058 |
| T2 | Parallel guessing to race the counter | T | Bypass lockout | SEC-008 (atomic), SEC-005b |
| T3 | DB dump, offline PIN crack | I | PIN recovered in minutes if no pepper | SEC-003, 004 (and residual risk R1) |
| T4 | Lockout DoS by attacker | D | User locked out | SEC-014 (needs device credential), SEC-005b, SEC-011, SEC-057; residual R2 |
| T5 | Replay of biometric signature | S/R | Session theft | SEC-025..028 |
| T6 | Hooked `authenticate()` returns true (Frida) | S/E | Bypass biometric | SEC-019: no valuable action depends on a boolean; server demands signature |
| T7 | Attacker adds own fingerprint to stolen phone | E | Biometric unlock by attacker | SEC-017, 018, 023 (invalidate on enrollment change), SEC-041 |
| T8 | Downgrade biometric -> PIN (cancel prompt, flip local hint, MITM says "disabled") | T | Forces weaker/throttled path | SEC-056, 011; PIN is throttled and device-credential-gated; high-value steps need PIN anyway (SEC-041) |
| T9 | Refresh/access token theft | I/S | Persistent access | SEC-031..037 |
| T10 | Forged biometric enrollment (attacker with session registers own key) | E | Persistent backdoor | SEC-020, 021, 047 |
| T11 | Tx parameters tampered between UI and signing | T | Funds to wrong address | SEC-039, 040, 043 |
| T12 | Step-up token reuse / use for another tx | S | Unauthorised tx | SEC-040 |
| T13 | PIN reset via stub login / social engineering | S/E | PIN bypass | SEC-015, 016, 046, 047 |
| T14 | Device theft, thief waits for unlocked state | E | Data/tx access | SEC-033, 052, 053 |
| T15 | Screenshots, app-switcher snapshot, keyboard cache, clipboard | I | PIN/balances leaked | SEC-053..055 |
| T16 | PIN/tokens/keys in logs, crash reports, analytics | I | Insider leak | SEC-061, 062, 057 |
| T17 | User enumeration / oracle through error codes or timing | I | Targeting | SEC-029, 059 |
| T18 | Idempotency/replay of state-changing calls | T | Double tx, double enroll | SEC-060 |
| T19 | MITM on PIN submit | I | PIN theft | SEC-006 (TLS, release cleartext off; pinning in prod) |
| T20 | Rooted device with malware reading JS memory | I | PIN captured as typed | SEC-054/055 best effort; SEC-065 risk signal; residual R3 |
| T21 | Refresh token reuse after theft | S | Detect compromise | SEC-032 |
| T22 | Backup extraction of secure storage | I | Token leak | SEC-034, 067 |
| T23 | Audit log tampering / missing events | R | Cannot investigate | SEC-061 |

## 4. Requirements

### 4.1 PIN policy and server-side storage

**SEC-001 [BE] MUST** accept a PIN only if it matches `^[0-9]{6}$`, then apply a blocklist: all-same digits, ascending/descending runs (123456, 654321, 234567...), repeating pairs/triples (121212, 123123), `000000`-style, and a top-N (>=200) common 6-digit list (embedded file). Reject with 422 `PIN_WEAK` (generic text, no list leak). Applies to set, change, reset. Sev: High. Demo: KEEP. Why: first-line defence against the most-guessed PINs, which an attacker tries first. Acceptance: table-driven test of 20 weak PINs rejected, 20 good PINs accepted.

**SEC-002 [FE] MUST** mirror SEC-001 in the UI for UX only (inline "choose a less predictable PIN"), never as the authority. Also require the confirm-entry to match. Sev: Low. Demo: KEEP. Why: usability; server remains authority. Acceptance: UI test; tampering the client check still yields server 422.

**SEC-003 [BE] MUST** store the PIN as Argon2id of `HMAC-SHA256(pepper_vN, pin)` with a random 16-byte per-user salt, PHC-string format with the pepper version stored beside it. Params: production m=64 MiB, t=3, p=1; demo floor m=19 MiB, t=2, p=1 (OWASP minimum). Sev: High. Demo: SIMPLIFY (params only, algorithm KEEP). Why: slows offline cracking; pepper makes a DB-only leak insufficient. Acceptance: DB fixture contains no raw PIN, no pepper; verify with a wrong pepper fails; unit test for pepper-version upgrade-on-login.

**SEC-004 [BE] MUST** load the pepper from a secret manager/KMS (demo: env var or secrets file, mounted outside the repo and DB), never in the DB, source, logs, or config dumps; the process MUST refuse to start if it is absent or shorter than 32 bytes. Sev: High. Demo: SIMPLIFY (env var instead of KMS). Why: with a 10^6 keyspace the pepper is the only thing making a DB leak non-trivial. Acceptance: startup test with missing pepper exits non-zero; grep of repo/logs finds no pepper.

**SEC-005 [BE] MUST** verify with constant-time comparison (the Argon2 library's verify or `subtle.ConstantTimeCompare` on the derived bytes). The PIN, hash, salt, counters beyond `attemptsRemaining`, and pepper version MUST NOT appear in any response. Sev: High. Demo: KEEP. Acceptance: contract/schema tests assert no `pin`, `hash`, `salt` fields in any response.

**SEC-005b [BE] MUST** bound concurrent Argon2 evaluations (semaphore / worker pool) and apply per-IP limits before hashing, so unauthenticated floods cannot exhaust memory. Sev: Medium. Demo: KEEP (small pool). Acceptance: load test with 200 concurrent verifies does not OOM; excess returns 429.

**SEC-006 [BOTH] MUST** send the PIN only in a JSON POST/PUT body over TLS >= 1.2. Never in URL, query string, headers, or analytics. Release builds disable cleartext traffic (Android `usesCleartextTraffic=false`, iOS ATS on); dev may use localhost only. Production: SPKI pinning with a backup pin (SIMPLIFY for demo: not required). Raw PIN over TLS is accepted for the demo; OPAQUE/PAKE is not required (see Q1 and residual R4). Sev: High. Demo: KEEP TLS, SIMPLIFY pinning. Acceptance: release manifest scan shows cleartext off; access-log lines contain no body; packet capture against a proxy without the trusted CA fails when pinning is on.

### 4.2 Lockout and brute-force protection

**SEC-008 [BE] MUST** keep a per-**user** consecutive-failure counter on the server, stored durably (demo: in-memory acceptable, see SEC-066 caveat). The increment MUST be atomic and happen **before** the hash result is returned (lock row / atomic compare-and-set, `UPDATE ... RETURNING`), so N parallel requests cannot all see "attempt 4". Schedule of consecutive failures since last success:

| Failures | Effect |
|---|---|
| 1-4 | none (attemptsRemaining shown) |
| 5 | locked 30 s |
| 6 | 1 min |
| 7 | 5 min |
| 8 | 15 min |
| 9 | 1 h |
| 10 | HARD LOCK (SEC-011) |

Counter resets only on a successful PIN verify (not on biometric success, not on timeout). Sev: Critical. Demo: KEEP (schedule values may be shortened via config for demo, e.g. 5 s/10 s, but the escalation and hard lock path must exist and be tested). Why: this is the primary PIN protection. Acceptance: test with 50 parallel wrong guesses against a fresh counter yields exactly <=5 evaluated before lock, then 423; test the schedule.

**SEC-009 [BE] MUST** additionally keep a per-**device** failure counter (10 failures in 15 min => device blocked from pin/verify for 1 h, and audit event) and per-IP request limits (SEC-057). The per-user counter is the one that ultimately locks; device/IP counters never *reset* it. Sev: High. Demo: KEEP simple version. Why: user-only counting enables DoS; device/IP-only counting is bypassable by rotation. Acceptance: a rotating-IP attack still hits the user counter.

**SEC-010 [BE] MUST** check the lock state **before** evaluating the PIN. While locked a correct PIN gets the same 423 as a wrong one and does not reset or advance the counter. `retryAfter` is returned only to a caller that passed SEC-014. Sev: High. Demo: KEEP. Acceptance: correct PIN during lock => 423, still locked after expiry only when time elapses.

**SEC-011 [BE] MUST** implement hard lock: after failure 10 no PIN verification is accepted. Recovery path: re-authentication through demo-login (SEC-016) **plus** PIN reset (SEC-046) which applies the cooling-off (SEC-047). Biometric unlock is also refused in hard lock (see Q5). Sev: High. Demo: KEEP. Acceptance: hard-locked user cannot unlock with PIN or biometric; recovery works and cooling-off is active.

**SEC-012 [BE] MUST** emit an audit event on first lock, hard lock and unlock-after-lock, and surface a "N failed attempts since your last login" notice on the next successful unlock (demo substitute for push/email/SMS; production MUST notify all channels). Sev: Medium. Demo: SIMPLIFY (in-app notice). Acceptance: after lock, next login response contains `recentFailures` count and the event exists.

**SEC-013 [FE] MUST NOT** enforce or store lock state locally as authoritative. Show a countdown from `retryAfter` and disable input only as UX; every attempt still goes to the server. No local PIN verifier and no offline unlock exist. Sev: Medium. Demo: KEEP. Acceptance: code review plus test that clearing app storage does not reset the lock.

### 4.3 Authentication of unlock endpoints (fixes F1, F2)

**SEC-014 [BE] MUST** require, for `POST /auth/pin/verify`, a valid **device credential** presented in the `Authorization: Bearer` header (the device's current refresh token, or a still-valid bootstrap token from demo-login for that device), in addition to the PIN. `deviceId` alone MUST NOT select a user or permit a guess. Missing/invalid/revoked credential => 401 `AUTH_FAILED` and the user's counter is **not** touched. Sev: Critical. Demo: KEEP. Why: possession + knowledge; stops remote guessing and lockout DoS by third parties. Acceptance: request with valid deviceId + PIN but no credential => 401, counter unchanged.

**SEC-015 [BE] MUST** make `POST /pin` (initial set) succeed only when the user has **no PIN set** and the caller holds a bootstrap token with scope `pin-setup`; otherwise 409 `PIN_ALREADY_SET`. It must never overwrite an existing PIN. Sev: Critical. Demo: KEEP. Acceptance: demo-login on an account with a PIN then `POST /pin` => 409, hash unchanged.

**SEC-016 [BE] MUST** protect `demo-login` as a real credential check: require a demo password/secret from config (not hard-coded in the app source), rate limit it (SEC-057), return only a limited-scope bootstrap token (scopes `pin-setup` or `pin-verify`/`pin-reset`, TTL <= 10 min, **no dashboard/tx access**), and be hard-gated by a `DEMO_MODE=true` flag; the server MUST refuse to start with `DEMO_MODE` in a production environment. A bootstrap token for an account that already has a PIN can only be exchanged for a session through PIN verify (SEC-014) or reset (SEC-046). Sev: Critical. Demo: SIMPLIFY (shared demo secret instead of password+OTP; documented as known weak, see R5). Acceptance: no-secret demo-login => 401; bootstrap token on `/dashboard` => 403.

### 4.4 Biometric key, enrollment, and challenge-response

**SEC-017 [FE] MUST (iOS)** generate an EC P-256 key inside the Secure Enclave (`kSecAttrTokenIDSecureEnclave`) with access control `.biometryCurrentSet` + `.privateKeyUsage`, accessibility `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly`, non-exportable. Fail enrollment (do not fall back to a software key) if the Secure Enclave is unavailable, except explicitly flagged dev builds/simulators (SEC-022). Sev: Critical. Demo: KEEP. Acceptance: key attributes inspected in a debug assertion; enrolling a new fingerprint makes signing fail with a key-invalidated error.

**SEC-018 [FE] MUST (Android)** generate the key in Android Keystore, EC `secp256r1`, `setUserAuthenticationRequired(true)`, per-use authentication (timeout 0 / `BiometricPrompt` with `CryptoObject`), `setInvalidatedByBiometricEnrollment(true)`, `setIsStrongBoxBacked(true)` when available (fallback to TEE, record level), and the prompt authenticator limited to `BIOMETRIC_STRONG` (Class 3), **no device-credential fallback** for this key (PIN is our own fallback). Sev: Critical. Demo: KEEP (StrongBox optional). Acceptance: `KeyInfo.isInsideSecureHardware` true on device; Class 2 face unlock cannot unlock the key; new fingerprint invalidates it.

**SEC-019 [FE] MUST NOT** treat the `expo-local-authentication` result (or any JS boolean) as proof. Biometric unlock = native module call that signs the server nonce with the key from SEC-017/018; the server decides. No screen or API call may skip the server check on the basis of a client flag. Sev: Critical. Demo: KEEP. Why: Frida hooks the boolean in one line. Acceptance: with `authenticate()` hooked to return true (test harness), biometric unlock still fails because no valid signature exists; lint rule/review: no gating on a bare boolean.

**SEC-020 [BOTH] MUST** require enrollment to be authorised by: (a) a fresh PIN step-up token, purpose `enable_biometric`, TTL <= 60 s, single use, bound to session and deviceId (SEC-038); (b) **proof of possession**: the server issues an enrollment challenge, the client signs it with the new key after a biometric prompt, and the server verifies the signature against the submitted public key before marking the key active. Sev: High. Demo: KEEP. Why: stops a stolen session silently adding a backdoor key, and proves the key is usable and biometric-gated at enrol time. Acceptance: enroll without step-up token => 403; with wrong-key PoP => 401; replayed step-up token => 401.

**SEC-021 [BE] MUST** validate the submitted public key: SPKI DER, P-256 only, point on curve (Go `ecdsa`/`x509.ParsePKIXPublicKey`), size cap 200 bytes, reject other curves/RSA. One **active** key per device; re-enrollment revokes the previous key atomically. Sev: Medium. Demo: KEEP. Acceptance: invalid/oversized/wrong-curve keys => 422.

**SEC-022 [BOTH] MUST** carry an `attestation` object in the enroll request and store `attestation_type` (`none|android_key|app_attest|play_integrity`) and self-reported `key_security_level` in `DeviceKey`. Demo: SIMPLIFY: attestation not verified, type `none`, level stored as **untrusted**. Production: MUST verify Android Key Attestation (challenge = enrollment nonce, root pinned, `securityLevel`>= TEE, `userAuthType`=biometric, `invalidatedByBiometricEnrollment`) and iOS App Attest. Policy: keys with attestation `none` MUST NOT get the biometric-only step-up allowance above a small demo threshold in a production environment. Sev: High (prod) / Low (demo). Acceptance: schema has the fields; production-mode flag rejects `none`.

**SEC-023 [BOTH] MUST** handle key invalidation: when signing fails with key-permanently-invalidated (Android `KeyPermanentlyInvalidatedException`, iOS missing/invalid key after enrollment change), the client deletes the key, falls back to PIN, and after a successful PIN verify calls `DELETE /devices/{id}/biometric`; the server revokes the public key. Re-enabling requires the full SEC-020 flow. Biometric lockout/cancel falls back to PIN, never to "no auth". Sev: High. Demo: KEEP. Acceptance: instrumented test: add fingerprint => next launch shows PIN, server key revoked.

**SEC-024 [BE] MUST** on `DELETE /devices/{id}/biometric`, `DELETE /devices/{id}`, PIN reset, and hard lock recovery revoke the corresponding `DeviceKey` rows and invalidate outstanding challenges for them. **[FE]** deletes the local key on disable/revoke. Sev: High. Demo: KEEP. Acceptance: a signature from a revoked key => 401 `AUTH_FAILED`.

**SEC-025 [BE] MUST** generate challenge nonces with `crypto/rand`, 32 bytes, TTL 60 s (demo: may be 30 s), tied server-side to `deviceId`, `userId`, `purpose` (`login` | `enroll` | `stepup`), optional `bound_hash`. At most one live challenge per (device, purpose); a new request supersedes the old. The client cannot choose any challenge field. Sev: High. Demo: KEEP. Acceptance: statistical/uniqueness test; two live challenges not possible.

**SEC-026 [BE] MUST** consume the challenge **atomically on the first verification attempt**, success or failure (`UPDATE ... SET consumed_at WHERE consumed_at IS NULL AND expires_at > now() RETURNING`). Expiry uses the **server clock only**; client time is ignored. Sev: Critical. Demo: KEEP. Why: no signature-guessing retries and no replay. Acceptance: two concurrent verifies of one nonce => exactly one proceeds; expired nonce rejected; replay rejected.

**SEC-027 [BOTH] MUST** use this signed message (server rebuilds it from its own stored challenge, never from client-sent fields). All fields length-prefixed (uint16 BE) in order:
`"CRYPTOAPP/BIO/v1" || purpose || userId || deviceId || nonce(32) || expiresAt(unix s, 8B BE) || boundHash(32 or empty)`
Signature: ECDSA P-256 over SHA-256 of that message, ASN.1 DER, parsed strictly (reject trailing bytes, r/s out of range). Domain tag differs per purpose so login signatures cannot be reused for step-up or enroll. Sev: High. Demo: KEEP. Acceptance: signature made for purpose `login` fails for `stepup`; flipping any field fails; golden test vector shared by FE and BE.

**SEC-028 [BE] MUST** verify: device exists and not revoked, user not hard-locked, active key exists, challenge live and unconsumed, signature valid. Then issue the session (SEC-037). Sev: High. Demo: KEEP. Acceptance: unit tests for each failing branch, all returning the same external response (SEC-029).

**SEC-029 [BE] MUST** make the biometric endpoints non-oracular: `POST /auth/biometric/challenge` for an unknown, revoked or non-enrolled deviceId returns a normal-looking 200 with a random decoy nonce and plausible `expiresAt` (not stored as live); `verify` returns a single `401 AUTH_FAILED` for bad signature, expired, replayed, unknown device, revoked key, no challenge. Response time equalised within reason (always run signature-shaped work or a fixed minimum delay). Sev: Medium. Demo: SIMPLIFY (timing equalisation best-effort). Acceptance: response bodies/headers for the five failure modes are byte-identical aside from timestamps.

**SEC-030 [BE] MUST** count `AUTH_FAILED` from biometric verify per device: 5 consecutive invalid signatures => that device's biometric key is revoked (user falls back to PIN) and an audit event is raised; these failures do **not** advance the PIN counter. Rate limits in SEC-057 also apply. OS-level biometric failures never reach the server and need no counting. Sev: Medium. Demo: KEEP. Acceptance: 5 bad signatures => key revoked.

### 4.5 Tokens and session (fixes F3)

**SEC-031 [BE] MUST** issue access tokens with TTL <= 10 min (default 5 min for demo is fine), audience-bound, signed (EdDSA/ES256, key from secret store) or opaque with server lookup. Claims: `sub`, `sid` (session), `did` (device), `amr` (`pin` | `bio`), `auth_time`, `scope`. Never contain PIN, hash, or PII beyond ids. Sev: High. Demo: KEEP. Acceptance: decode test; expired token => 401.

**SEC-032 [BE] MUST** issue refresh tokens as 256-bit random values, stored only as SHA-256 hash, **single use, rotated on each use**, with a `family_id`. Presenting an already-used (or revoked) token => revoke the entire family, audit event `REFRESH_REUSE`, 401. Absolute lifetime 30 days, idle 7 days. Sev: High. Demo: KEEP. Acceptance: reuse test revokes both old and newest tokens.

**SEC-033 [BE] MUST** enforce unlock server-side: the session records `last_unlock_at` (set only by successful PIN verify or biometric verify or a step-up). `POST /auth/refresh` returns a new access token only while `now - last_unlock_at` <= 15 min absolute **and** idle <= 5 min; beyond that => 401 `UNLOCK_REQUIRED` and the client must go through PIN or biometric. The refresh token alone therefore cannot open the app after auto-lock. Sev: High. Demo: KEEP (windows may be tuned). Why: otherwise the lock screen is cosmetic and defeated by a stolen device or hooked JS. Acceptance: refresh 16 min after unlock => 401; calling refresh after the client "locks" for >5 min idle => 401.

**SEC-034 [FE] MUST** store the refresh token only in `expo-secure-store` with `keychainAccessible: WHEN_PASSCODE_SET_THIS_DEVICE_ONLY` (iOS) and Keystore-backed storage on Android, `allowBackup=false` / data-extraction rules excluding it, never AsyncStorage/MMKV plaintext. Access token in memory only, never persisted. (`requireAuthentication` is not used on the refresh token because the PIN path must work without biometrics; its protection is server-side per SEC-014/033.) If the device has no passcode set, refuse to enable the app (fail closed). Sev: High. Demo: KEEP. Acceptance: inspection of app data dir / backup shows no token; passcode-less simulator shows blocking message.

**SEC-035 [BE] MUST** put the session assurance (`amr`, `auth_time`) in the token and have step-up policy (SEC-041) read it. Sev: Medium. Demo: KEEP. Acceptance: tokens from PIN unlock carry `amr=pin`; from biometrics `amr=bio`.

**SEC-036 [BE] MUST** implement `/auth/logout` to revoke the session and refresh family, and revoke all sessions of a device on device revoke, and all other sessions on PIN change (SEC-045). Sev: Medium. Demo: KEEP. Acceptance: token use after logout => 401.

**SEC-037 [BE] MUST** keep one active session family per device; a successful PIN or biometric unlock creates a fresh family (revoking the prior one) and returns a new refresh token. Bearer tokens are accepted for the demo; DPoP / device-key-bound tokens are not required (SIMPLIFY, residual R6; production SHOULD add a non-biometric hardware request-signing key so a stolen refresh token plus PIN is useless off-device). Sev: Medium. Demo: SIMPLIFY. Acceptance: two unlocks leave exactly one live family.

### 4.6 Step-up and transactions (fixes F4)

**SEC-038 [BE] MUST** require step-up (fresh proof, `auth_time` or proof <= 60 s, single use, purpose-bound) for the operations in this table:

| Operation | Required proof |
|---|---|
| Send transaction (any) | biometric signature OR PIN, per SEC-041, bound to tx hash |
| Enable biometrics | PIN (fresh); never biometric alone |
| Disable biometrics | PIN or biometric proof, `auth_time` <= 5 min |
| Change PIN | old PIN in the request (counts toward lockout) |
| Revoke **other** device | PIN |
| Revoke **current** device / logout | valid session only |
| View device list / dashboard | valid access token |

Sev: High. Demo: KEEP. Acceptance: each operation without the proof => 403 `STEPUP_REQUIRED`.

**SEC-039 [BOTH] MUST** have the client send the **transaction fields** (asset, network, amount as decimal string, destination, fee, tx nonce, expiry) to `/stepup/challenge`; the server canonicalises them (fixed field order, length-prefixed UTF-8, amount normalised) and computes `txHash = SHA-256(canonical)`, stores it in the challenge, and returns the hash and a human-readable summary for display. `POST /transactions` recomputes the hash from **its own** body and compares with the token's `bound_hash`; mismatch => 403, token consumed. Sev: Critical. Demo: KEEP. Why: client-computed hashes can be forged by hooked JS; recompute defeats in-app tampering. Acceptance: change one digit of amount between challenge and submit => 403; shared golden vectors for canonicalisation.

**SEC-040 [BE] MUST** make the step-up token single use (consumed atomically in the same DB transaction as the tx creation), TTL <= 60 s, bound to `session_id`, `device_id`, purpose and `txHash`. Reuse/other session/other tx => 403. Sev: Critical. Demo: KEEP. Acceptance: concurrent double-submit creates one tx.

**SEC-041 [BE] MUST** decide proof strength server-side: biometric signature suffices for tx amount <= `BIO_ONLY_MAX` (config; demo e.g. 1,000 USD-equivalent of mock value), above it PIN is required (and for `attestation=none` keys in production, PIN always). If the account/device is in cooling-off (SEC-047) amounts above `COOLING_OFF_MAX` are rejected regardless. The client never decides. Sev: High. Demo: KEEP the mechanism, thresholds are config. Why: biometrics can be coerced/forced and the sleeping-owner case; PIN adds knowledge. Acceptance: tx above threshold with biometric proof only => 403 `STEPUP_REQUIRED` with `required=pin`.

**SEC-042 [BE] MUST** count failed PIN proofs in `/stepup/verify` against the **same** user counter and lock as pin/verify (SEC-008). Sev: High. Demo: KEEP. Acceptance: 5 wrong step-up PINs => user locked.

**SEC-043 [BOTH] MUST** sign the step-up message per SEC-027 with `purpose=stepup` and `boundHash=txHash`; PIN-based step-up is bound by the server challenge id (the PIN is not signed). Sev: High. Demo: KEEP. Acceptance: golden vector test.

**SEC-044 [BE] MUST** keep limits, whitelists, velocity and the mock balance check on the server; `POST /transactions` requires `Idempotency-Key` (SEC-060) and has no client-supplied "approved" flag. Sev: High. Demo: SIMPLIFY (only balance + threshold rules). Acceptance: schema has no such field.

### 4.7 PIN change, reset, cooling-off

**SEC-045 [BE] MUST** `PUT /pin`: requires the **old PIN** (verified, counted toward lockout) and a new PIN passing SEC-001 and different from the current PIN. On success revoke all **other** sessions and **biometric keys on other devices**; the current device's session is re-issued and its biometric key stays. Notify (audit + in-app notice). Sev: High. Demo: KEEP. Acceptance: after change, another device's refresh => 401, its biometric verify => 401.

**SEC-046 [BE] MUST** `POST /pin/reset` (forgot PIN): requires a bootstrap token from demo-login (SEC-016; production: password + 2FA + ID/liveness for high-value accounts), then sets the new PIN, **revokes all sessions and all biometric keys on all devices including the current one**, clears the lock counters, starts cooling-off (SEC-047), emits an audit event and notice. Biometrics must be re-enrolled with a fresh PIN. Sev: Critical. Demo: SIMPLIFY (demo-login secret stands in for primary auth). Acceptance: after reset every old device must re-enroll; reset without bootstrap token => 401.

**SEC-047 [BE] MUST** apply a cooling-off period after PIN reset, new-device registration and new biometric enrollment: tx above `COOLING_OFF_MAX` rejected, and biometric-only tx approval disabled for a newly enrolled key during the period. Default 24 h; demo MAY configure minutes, but the code path and its tests MUST exist. Sev: High. Demo: SIMPLIFY (duration). Acceptance: tx above limit within window => 403 `COOLING_OFF`; after clock advance => allowed.

### 4.8 Devices

**SEC-048 [BE] MUST** `POST /devices` returns a **server-generated** 128-bit random `deviceId` (client hardware identifiers are not used as identity), max 5 active devices per user, tied to the authenticated bootstrap/session. First session on a new device requires PIN verify (never biometric only) and triggers cooling-off + audit/notice. Sev: High. Demo: KEEP. Acceptance: 6th device => 409; biometric enrollment before PIN unlock on a new device => 403.

**SEC-049 [BE] MUST** `GET /devices` returns only the caller's devices (id, name, platform, created, last_seen, `current`, `biometricEnabled`); IDOR check on every `{id}` path (resource must belong to the token's `sub`, else 404). Revoke per SEC-024/038. Sev: High. Demo: KEEP. Acceptance: user B cannot read/revoke user A's device (404).

### 4.9 Client hardening

**SEC-050 [FE] MUST** lock the app: on background start a timer, default **30 s** (options: immediate, 30 s, 1 min; max 1 min), plus 5 min foreground inactivity; on lock discard the access token from memory, clear sensitive component state, require PIN/biometric (server enforces via SEC-033). Cold start always starts locked. Sev: High. Demo: KEEP. Acceptance: device test; token absent from memory heap after lock (best effort).

**SEC-051 [FE] MUST** prevent capture: `expo-screen-capture` `preventScreenCapture` (Android `FLAG_SECURE`, iOS capture-blocking) on PIN, enrol, step-up, balance and tx screens (simplest: app-wide), and show an opaque overlay when `AppState` is `inactive`/`background` so the app-switcher snapshot is blank. Sev: Medium. Demo: KEEP. Acceptance: screenshot attempt yields black on Android; switcher shows overlay.

**SEC-052 [FE] MUST** harden the PIN field: custom in-app numeric keypad preferred (resists third-party keyboards/loggers); if a `TextInput` is used: `secureTextEntry`, `keyboardType="number-pad"`, `autoComplete="off"`, `textContentType="none"`, `autoCorrect={false}`, `importantForAutofill="noExcludeDescendants"`, `contextMenuHidden`, paste disabled, `maxLength=6`. Sev: Medium. Demo: KEEP (stock `TextInput` with the flags acceptable; custom keypad SIMPLIFY). Acceptance: manual + unit test on props; clipboard never contains the PIN.

**SEC-053 [FE] MUST** keep the PIN out of long-lived state: hold digits in a ref/array, never in Redux/context/persisted store, navigation params, or error objects; overwrite the buffer and clear the input immediately after the request is dispatched or on failure. (JS strings are immutable; zeroing is best effort and must be documented.) Sev: Medium. Demo: KEEP. Acceptance: code review; heap snapshot check after submit.

**SEC-054 [FE] MUST** treat `biometricEnabled` in plain storage (AsyncStorage) as a **non-authoritative UI hint** only. The hint can only select which screen to show first; it cannot grant anything. Reconciliation: hint=true but no local key or server says disabled => clear hint, show PIN; hint=false but server says enabled for this device (learned from authenticated pin/verify response `biometricEnabled`) => set hint true; hint=true, key invalidated => SEC-023. Sev: Low. Demo: KEEP. Acceptance: flipping the hint by hand never yields access; mismatch cases covered by tests.

**SEC-055 [FE] MUST** strip `console.*` in release (babel `transform-remove-console` or equivalent), disable verbose network/devtools logging, and scrub crash-reporting/analytics (no request bodies, headers, state). Sev: High. Demo: KEEP. Acceptance: grep of release bundle for logging calls on auth modules; redaction test of error reporter.

**SEC-056 [FE] SHOULD** read root/jailbreak/hook signals (e.g. `expo-device` `isRootedExperimentalAsync`) and send them as an advisory header/field the server stores as a risk signal; the client MUST NOT use it as the sole gate and the server MUST NOT trust it for authorisation. Sev: Low. Demo: SIMPLIFY (optional, log-only).

### 4.10 Backend cross-cutting

**SEC-057 [BE] MUST** apply per-endpoint rate limits (key = user AND device AND IP, whichever applies), return `429` with `Retry-After`:

| Endpoint | Limit |
|---|---|
| `/auth/demo-login` | 5/min/IP, 20/h/IP, global circuit breaker |
| `/auth/pin/verify` | 10/min/device, 30/min/IP, plus lockout (SEC-008) |
| `/auth/biometric/challenge` | 10/min/device, 30/min/IP |
| `/auth/biometric/verify` | 10/min/device, 30/min/IP |
| `/auth/refresh` | 6/min/device |
| `/stepup/challenge`, `/stepup/verify` | 10/min/user |
| `/devices/{id}/biometric/enroll` | 5/h/user |
| `/pin` (PUT/reset) | 5/h/user |
| `/transactions` | 20/min/user |

Sev: High. Demo: SIMPLIFY (in-memory token bucket). Acceptance: limit tests per endpoint.

**SEC-059 [BE] MUST** use a uniform error model `{ "error": {"code","message"} }` with generic messages. External codes for auth: `AUTH_FAILED` (401), `PIN_INVALID` (401, only to a caller with a valid device credential; includes `attemptsRemaining`), `PIN_LOCKED` (423 + `retryAfter`, same condition), `UNLOCK_REQUIRED`, `STEPUP_REQUIRED`, `COOLING_OFF`, `RATE_LIMITED`, `VALIDATION_ERROR`. `CHALLENGE_EXPIRED` / `CHALLENGE_REPLAYED` / `BIOMETRIC_SIGNATURE_INVALID` from the draft are **collapsed into `AUTH_FAILED`** externally; detail is logged internally only. No stack traces, SQL errors, or internal ids. Sev: Medium. Demo: KEEP. Acceptance: contract test enumerates codes; fuzzed requests never return internal text.

**SEC-060 [BE] MUST** require `Idempotency-Key` (UUIDv4, header) on `POST /devices`, enroll, `PUT /pin`, `POST /pin/reset`, `POST /transactions`; store (user, endpoint, key) -> request hash + status for 24 h; same key + same body => same status without re-executing; same key + different body => 422. **Never** store or replay token-bearing responses (a replay of a response containing tokens returns 409 `IDEMPOTENT_REPLAY` with no body tokens). Not used on pin/verify, challenge or biometric verify (those rely on single-use nonces). Sev: Medium. Demo: KEEP for transactions/enroll; SIMPLIFY others. Acceptance: double-submit tests.

**SEC-061 [BE] MUST** write append-only audit events: `PIN_SET`, `PIN_CHANGED`, `PIN_RESET`, `PIN_VERIFY_FAIL`, `PIN_LOCKED`, `PIN_HARD_LOCKED`, `BIO_ENROLLED`, `BIO_DISABLED`, `BIO_KEY_INVALIDATED`, `BIO_VERIFY_FAIL`, `LOGIN_OK(method)`, `REFRESH_REUSE`, `DEVICE_ADDED/REVOKED`, `STEPUP_OK/FAIL`, `TX_CREATED`, `COOLING_OFF_STARTED`, `RATE_LIMITED`. Fields: id, ts, user_id, device_id, ip, user-agent, request id, event type, result, non-secret metadata (e.g. key fingerprint = truncated SHA-256 of SPKI). Never: PIN, tokens, nonces, signatures, public key bytes, hashes. Tamper evidence: hash-chain each record (`prev_hash`) (SIMPLIFY for demo: optional). Retention: 12 months production, 30 days demo. Sev: Medium. Demo: SIMPLIFY (stdout JSON). Acceptance: test that sensitive fixtures never occur in captured log output.

**SEC-062 [BE] MUST** never log request/response bodies or `Authorization`/`Idempotency-Key` headers; use an allowlist logger; tokens only in the `Authorization` header (never URL/query); redact panics; `Cache-Control: no-store` on auth/session responses. Sev: High. Demo: KEEP. Acceptance: integration test with canary PIN `987654` and canary token asserts absence from all log output.

**SEC-063 [BE] MUST** validate all input strictly (typed structs, `DisallowUnknownFields`, max body 16 KiB, UUID formats, enum purposes, decimal-string amount regex and range), use parameterised queries only, run with a least-privilege DB role, and set security headers (`X-Content-Type-Options`, no CORS for non-browser clients, HSTS). Sev: High. Demo: KEEP. Acceptance: fuzz/negative tests; SQL injection payload tests.

**SEC-064 [BE] SHOULD** accept an optional `risk` object from clients (SEC-056) and store it; policy hooks exist to force PIN or deny, but nothing relies on it for the demo. Sev: Low. Demo: SIMPLIFY.

**SEC-065 [BE] MUST** fail closed on configuration: missing pepper/JWT key/demo secret, `DEMO_MODE` in a production env, or unreachable store => refuse to start / return 503, never default to open. Sev: High. Demo: KEEP.

**SEC-066 [BE] MUST** persist the lock counters, consumed-challenge state and refresh-token families in a store that survives a **process restart** **unless** restart is not attacker-triggerable; the demo may use an in-memory store only if documented, because a crash/restart resets the lockout and refresh reuse state (residual R7). Sev: High (production) / Medium (demo). Demo: SIMPLIFY. Acceptance: restart test documents behaviour; production profile uses a durable store.

**SEC-067 [BOTH] MUST** keep secrets out of backups: Android `allowBackup=false` and `dataExtractionRules` excluding secure prefs; iOS items `ThisDeviceOnly` (no iCloud Keychain sync); exclude any files from iCloud backup. Sev: Medium. Demo: KEEP. Acceptance: manifest check.

**SEC-068 [FE] MUST** use a development/production build (not Expo Go) for any biometric key work, pin dependency versions of the native key-signing module, review its source/licence, and disable Hermes debugger/dev menu in release. OTA updates (expo-updates) MUST be code-signed if enabled, since an OTA JS update changes the security-critical client. Sev: Medium. Demo: SIMPLIFY (OTA off).

## 5. Data handling table

| Data | Where stored | Protection | Lifetime | Logged? |
|---|---|---|---|---|
| PIN (plaintext) | Memory only, server request body | TLS; ref buffer cleared after submit; never persisted | Seconds | Never |
| PIN hash | Server DB `User.pin_hash` | Argon2id(HMAC(pepper, pin)), salt per user | Until change/reset | Never |
| Pepper | Secret manager / env (demo) | Not in DB/repo, versioned | Rotated per policy | Never |
| Lock counters | Server DB | Atomic updates | Until success/reset | Counts only in audit |
| Biometric private key | Secure Enclave / StrongBox-TEE | Non-exportable, auth-per-use, invalidated on enrollment change, ThisDeviceOnly | Until disable/revoke/invalidation | Never |
| Biometric public key | Server `DeviceKey` | Integrity (DB role), SPKI | Until revoke | Fingerprint only |
| Challenge nonce | Server DB | CSPRNG 32 B, single-use, TTL 60 s | <= 60 s, purge after 24 h | Never (id only) |
| Refresh token | Client SecureStore (WHEN_PASSCODE_SET_THIS_DEVICE_ONLY), server SHA-256 hash | Rotation, reuse detection | <= 30 d abs / 7 d idle | Never |
| Access token | Client memory only | TTL <= 10 min | Minutes | Never |
| Step-up token | Client memory; server hash | Single use, bound, 60 s | <= 60 s | Never |
| `biometricEnabled` hint | AsyncStorage plain | Non-authoritative | Until changed | Ok (non-secret) |
| Audit events | Server log/DB | Append-only, hash-chain (prod) | 12 mo (demo 30 d) | n/a, no secrets |
| Mock balances | Server fixtures | Auth required | n/a | Ok |
| Idempotency records | Server | Request hash only, no tokens | 24 h | Key not logged |

## 6. API security constraints for the tech lead

- **Auth model:** `demo-login` (secret + rate limit, bootstrap token only) -> `pin` / `pin/verify` / `pin/reset` -> session. Dashboard, devices, transactions, step-up require an access token. `pin/verify` requires the device credential in `Authorization` (SEC-014). `biometric/challenge` and `biometric/verify` are unauthenticated (signature is the credential) and are non-oracular (SEC-029).
- **Biometric enroll** is a two-step: `POST /devices/{id}/biometric/enroll/challenge` (new, step-up token required) then `POST /devices/{id}/biometric/enroll` (publicKey, attestation, signature over challenge). Contract needs the extra call (SEC-020).
- **Step-up:** `POST /stepup/challenge` body = purpose + full transaction fields (asset, network, destination, amount string, fee, txNonce, expiry); response = challengeId, nonce, expiresAt, `txHash`, human-readable summary, `required` (`bio|pin|either`). `POST /stepup/verify` body = challengeId + (signature | pin). `POST /transactions` takes the same fields + stepUpToken; server recomputes.
- **Nonce/TTL:** nonce 32 B base64url; challenge TTL 60 s; step-up token TTL 60 s; access <= 10 min; bootstrap <= 10 min.
- **Status codes:** 200/201 ok; 400/422 validation; 401 `AUTH_FAILED`, `PIN_INVALID`, `UNLOCK_REQUIRED`; 403 `STEPUP_REQUIRED`, `COOLING_OFF`; 404 for foreign resources; 409 `PIN_ALREADY_SET`, `IDEMPOTENT_REPLAY`; 423 `PIN_LOCKED`; 429 with `Retry-After`; 503 fail-closed config.
- **Headers:** `Authorization: Bearer`, `Idempotency-Key`, `X-Request-Id`; responses `Cache-Control: no-store` on auth routes, `Retry-After`, `RateLimit-*`.
- **Fields that MUST NOT exist:** `pin`, `pinHash`, `salt`, `pepper` in any response; PIN or tokens in any URL/query; `biometricVerified: true` or any client-asserted auth boolean in requests; client-supplied `userId`; client-supplied `txHash` as authority; client-supplied `approved`/`limitOk`; `deviceId` as sole credential; reasons that distinguish expired/replayed/unknown on auth failure; stack traces.
- **`attemptsRemaining` / `retryAfter`** only returned after the device credential is validated.
- **`biometricEnabled`** per device is returned in authenticated responses (pin/verify, GET /devices); server is authoritative.

## 7. Security test cases (engineers must implement)

Backend:
1. 50 parallel wrong PINs: exactly <=5 evaluated, then 423; counter durable across a simulated restart (production profile).
2. Correct PIN during lock => 423 and lock unaffected; after expiry correct PIN works and counter resets.
3. `pin/verify` without device credential => 401, user counter unchanged (F1).
4. demo-login on account with PIN, then `POST /pin` => 409 (F2); demo-login without secret => 401; bootstrap token on `/dashboard` => 403.
5. Hard lock blocks PIN and biometric; recovery via reset revokes all sessions and keys and sets cooling-off.
6. Replay of a captured biometric `verify` body => 401 `AUTH_FAILED`; concurrent double verify => one success; expired nonce => 401; signature for purpose `login` presented as `stepup` => 401; unknown device and revoked key responses byte-identical to bad signature.
7. Enroll without PIN step-up => 403; wrong PoP signature => 401; non-P-256 key => 422; second enroll replaces first.
8. Refresh reuse revokes family; refresh after unlock window => `UNLOCK_REQUIRED`; logout invalidates tokens.
9. Tx: tamper amount/destination/asset/network/fee after challenge => 403; token reuse => 403; token from another session => 403; above-threshold with biometric only => `STEPUP_REQUIRED`; within cooling-off above limit => 403; double-submit with same Idempotency-Key => one tx.
10. IDOR: user B accessing user A device/key/session => 404.
11. Canary secrets (PIN `987654`, token) never appear in logs or audit output; no response contains `pin|hash|salt` keys; error fuzzing returns no internals.
12. PIN policy table (SEC-001) and Argon2 hash check with wrong pepper.
13. Rate limit tests per endpoint; concurrent 200 verifies does not exhaust memory.
14. Startup fails with missing pepper / `DEMO_MODE` in production env.

Expo:
15. With `authenticate()` hooked to return true, biometric unlock still fails (no signature) and no screen is reachable (SEC-019).
16. Enroll a new fingerprint in the OS => key invalidated => PIN prompt => server key revoked => message shown.
17. Biometric cancel / lockout / hardware absent => PIN screen, never open.
18. Clearing AsyncStorage or editing `biometricEnabled` never grants access; mismatch matrix per SEC-054.
19. Background >30 s => locked, access token dropped, refresh without unlock => 401; cold start locked.
20. Screenshot blocked, app-switcher overlay, PIN field flags, no PIN in React state snapshot, no logs in release bundle.
21. Backup/extraction inspection shows no tokens; device without passcode blocked.
22. Golden-vector tests for SEC-027 message and SEC-039 canonical hash shared with backend.

## 8. Open questions / residual risk

Questions that change scope or posture (need tech-lead or product decision):
- **OQ1:** Accept the contract changes in "Findings" (device credential on pin/verify, bootstrap scopes, two-step enroll, server-side tx field canonicalisation, unlock window)? These are not optional; they fix F1-F4.
- **OQ2:** Product's requirement "PIN fallback always available" is retained; "biometric only, no PIN" is rejected (a lost/invalidated key would lock users out and give no recovery). Confirm.
- **OQ3:** Is a pure in-memory store acceptable for the demo, given restart resets lockout (R7)? Recommendation: SQLite/Postgres for counters, challenges, tokens if the demo is ever exposed beyond localhost.
- **OQ4:** Demo-login credential: who holds the demo secret, and is the demo ever internet-facing? If yes, the reset/hard-lock path is only as strong as this secret (R5).
- **OQ5:** Dev-build requirement (no Expo Go) and choice of native signing module (own Expo module vs vetted library); this affects the Expo task estimate.
- **OQ6:** Are 30 s auto-lock and a 5 min foreground inactivity acceptable UX defaults?

Residual risk:
- **R1:** 10^6 keyspace: a DB dump plus pepper compromise exposes all PINs within seconds-hours. Pepper separation and Argon2id mitigate, not eliminate. Longer PIN or password-based step-up is the real fix.
- **R2:** Anyone holding a stolen device credential (refresh token) can deliberately lock the user's PIN path (soft locks). Biometrics still works in soft lock (Q5), hard lock needs reset.
- **R3:** Malware on a rooted device can read the PIN as typed or hook the app; hardware keys survive but the attacker can ask the user to sign. Transaction summaries come from the server-computed hash (SEC-039) to reduce, not remove, this.
- **R4:** No OPAQUE/PAKE and no pinning in demo: a TLS-breaking MITM sees the PIN. Production adds pinning (backup pins) and device request-signing key (R6).
- **R5:** Stub demo-login is a weak recovery root of trust.
- **R6:** Bearer tokens not device-bound in demo; refresh theft + PIN from elsewhere works.
- **R7:** In-memory demo store resets state on restart.
- **R8:** Without attestation, server cannot prove the key is hardware-backed or biometric-gated; trust is on client honesty in the demo.

## 9. Decisions on the 16 questions

| Q | Decision (requirements) |
|---|---|
| 1 | 6 digits exactly, blocklist as SEC-001. Argon2id+HMAC pepper acceptable **only as defense-in-depth**; online throttling and device credential are the real controls (SEC-003/004/008/014). Raw PIN in TLS body acceptable for the demo; OPAQUE not required (SEC-006, R4). A hardware-key signature on PIN requests is **not required in the demo** (the biometric key cannot sign silently by design); production adds a non-biometric hardware request-signing key / DPoP (SEC-037, R6). The device credential (SEC-014) is the demo's binding. |
| 2 | Per-user counter + per-device + per-IP limits; schedule 5 fails -> 30 s, 6 -> 1 min, 7 -> 5 min, 8 -> 15 min, 9 -> 1 h, 10 -> hard lock; resets only on PIN success; hard lock recovery = reauth (demo-login secret) + PIN reset + cooling-off (SEC-008..012, 046, 047). |
| 3 | ES256/P-256; iOS SE `biometryCurrentSet`+ThisDeviceOnly; Android StrongBox-if-available/TEE, Class 3 only, auth-per-use, invalidate on enrollment; attestation fields mandatory in the model, verification required in production, skipped in demo (SEC-017, 018, 021, 022). |
| 4 | 32 B CSPRNG nonce, TTL 60 s, single-use consumed on first attempt, server clock only; message `CRYPTOAPP/BIO/v1 \|\| purpose \|\| userId \|\| deviceId \|\| nonce \|\| expiresAt \|\| boundHash`, length-prefixed, server-rebuilt (SEC-025..028). |
| 5 | Biometric **allowed** during a soft PIN lock (biometrics is not guessable online; blocking it hands attackers a DoS), **blocked** during hard lock. Bio failures counted separately per device: 5 bad signatures => key revoked, PIN counter untouched (SEC-011, 030). |
| 6 | Access <= 10 min, in memory; refresh 256-bit, rotating, reuse => family revoked, 30 d abs/7 d idle, SecureStore `WHEN_PASSCODE_SET_THIS_DEVICE_ONLY`; server-enforced unlock window so refresh alone cannot unlock; `amr`/`auth_time` claims included; bearer for demo, DPoP/device-bound for production (SEC-031..037). |
| 7 | Step-up on every send; server recomputes canonical tx hash from fields; token single-use, 60 s, bound to session/device/hash; biometric suffices up to `BIO_ONLY_MAX`, PIN above (and always for unattested keys in production) (SEC-038..044). |
| 8 | Enable biometrics: fresh PIN. Disable: PIN or biometric proof within 5 min. Change PIN: old PIN. Revoke other device: PIN; revoke current: session (SEC-038). |
| 9 | Change: revoke all other sessions + biometric keys on other devices, keep current. Reset (forgot): reauth via demo-login (production password+2FA+ID), revoke everything including current device, re-enroll biometrics, cooling-off, notices (SEC-045..047). |
| 10 | Auto-lock after 30 s background (max 1 min), 5 min inactivity, cold start locked; FLAG_SECURE/capture prevention app-wide, app-switcher overlay; no autofill/paste, number-pad, prefer custom keypad (SEC-050..053). |
| 11 | Limits table SEC-057; `429`+`Retry-After`; uniform errors, collapsed challenge/signature codes, decoy challenge for unknown devices; `attemptsRemaining` only after the device credential is validated (SEC-029, 057, 059). |
| 12 | Enforcement **out** for the demo; keep attestation and risk-signal slots; root/jailbreak = advisory server signal, never a lone gate; production requires Play Integrity / App Attest and key attestation (SEC-022, 056, 064). |
| 13 | Idempotency-Key on devices, enroll, PIN change/reset, transactions; 24 h; token-bearing responses never replayed; nonce single-use is the replay control for auth (SEC-060, 026). |
| 14 | Audit event list and field allowlist as SEC-061; no bodies/headers logged, no secrets in URLs, `no-store`, canary tests; retention 30 d demo / 12 mo production (SEC-061, 062). |
| 15 | Plain AsyncStorage hint is acceptable because it can only choose the first screen; server authoritative; reconciliation matrix in SEC-054. |
| 16 | See table below. |

### Demo simplifications (Q16)

May be simplified: in-memory or SQLite store (note R7); stub demo-login (but with a secret, rate limit, `DEMO_MODE` gate); mock balances/fixtures; pepper from env instead of KMS; Argon2id params at OWASP floor; no attestation verification (fields kept); no cert pinning; no OPAQUE/DPoP; push/email notifications replaced by in-app notice and audit event; audit as stdout JSON without hash chain; cooling-off and lockout durations shortened by config; StrongBox not mandatory; OTA off; optional root detection log-only.

MUST NOT be relaxed in the demo: server-side PIN verification only; atomic per-user lockout with hard lock; device credential on `pin/verify`; `POST /pin` cannot overwrite; hardware-backed biometric key with signature challenge (never a boolean), including invalidation on enrollment change and PIN fallback; single-use server-clock challenges and domain-separated signatures; server-side canonical tx hash recomputation and single-use step-up; refresh rotation with reuse detection and server-enforced unlock window; PIN required to enable biometrics, PoP at enrollment; reset revokes all sessions/keys and starts cooling-off (mechanism); tokens in SecureStore/memory only; no PIN/token/key logging with canary tests; uniform non-oracular errors; screen-capture/app-switcher protection and PIN field hardening; HTTPS in release builds; fail-closed config; input validation and parameterised queries.
