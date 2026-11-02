# Security Review: biometric-pin-login

Reviewer: security-specialist. Mode: review against `security-spec.md` (67 SEC ids, section 7 tests, section 9 decisions), `openapi.yaml`, `contract-notes.md`, `decisions.md`, `vectors/vectors.json`.

Method and limits (read first):
- Static review of the code in `apps/api` and `apps/mobile`. I read the handlers, SQL, migrations, config, crypto, logging, native Swift/Kotlin, storage, flows, build config and scripts. I had no shell: **I did not run the Go or Jest suites, the build, or any device.** "Verified in code" means I read the code path and it does what the spec says. The engineers' matrices (`apps/api/docs/sec7-matrix.md`, `apps/mobile/docs/sec7-matrix.md`) were treated as claims, and I only credit them where I also read the code.
- Everything labelled "needs device" cannot be signed off from source (Secure Enclave, StrongBox, enrollment-change invalidation, FLAG_SECURE, app-switcher snapshot, backup extraction).
- Application code was not modified.

## 1. Summary

| Severity | Count | Owner split |
|---|---|---|
| Critical | 0 | - |
| High | 1 | backend |
| Medium | 5 | 2 expo, 2 backend, 1 expo+backend |
| Low | 12 | 8 backend, 3 expo, 1 tech lead |
| Info | 9 | mixed |

No Critical findings. The core controls the spec calls non-negotiable hold in code: server-only PIN verification with a device credential (F1), atomic reserve-before-hash lockout, `POST /pin` never overwriting (F2), server-enforced unlock window (F3), server-side tx recomputation with single-use bound step-up token (F4), single-use challenges consumed on first attempt, domain-separated signed messages that match the golden login vector, hardware-key flags on both platforms, no `expo-local-authentication`, canary-tested logging.

**High (clearly marked): H-01, owner backend.** The cooling-off and bio-only limits are per transaction, so they are defeated by splitting the withdrawal into many small transactions.

Top findings in order of importance: H-01 (cumulative limits), M-04 (one IP can disable demo-login, which is also the recovery path, for everyone), M-01 and M-02 (client signs and approves whatever challenge/summary the server returns), M-03 (sign-out leaks device records and pushes users towards forced PIN resets), M-05 (cleartext LAN transport carries the one secret that gates PIN reset).

## 2. Findings

### High

#### H-01 [BACKEND] Cooling-off and bio-only limits are per transaction only (no cumulative limit)
- SEC: 047, 041, 044 (also weakens T13, T9 mitigation story).
- Evidence: `apps/api/internal/handlers/tx.go:75-79` and `handlers/stepup.go:98-103` compare a single transaction's USD value to `CoolingOffMax`; `stepup/stepup.go:65-70` and `stepup.go:104-106` compare a single amount to `BioOnlyMax`. There is no SUM over `transactions` anywhere (`store/queries/tx_audit.sql` has only `InsertTransaction`). The only other brake is 20 tx/min/user (`config.go:57`).
- Impact: PIN reset (SEC-046) by anyone holding the demo secret starts cooling-off precisely to cap damage. An attacker then sends repeated transactions at or below `COOLING_OFF_MAX` (default 500 mock USD), each with a PIN step-up they just set themselves; the seeded balance (about 12.8k) drains in roughly 26 requests, well inside one minute. The same split defeats `BIO_ONLY_MAX` for a coerced or hooked biometric. The mechanism exists and tests pass, but it does not deliver its purpose.
- Fix: (1) add `usd_value numeric` to `transactions` (computed at insert from the same price table). (2) In `CreateTransaction` and `StepupChallenge`, inside the existing user-row lock (`LockUserRow` is already taken in the tx), compute `SUM(usd_value)` over the rolling window: during cooling-off use the window `[cooling start, cooling end]` and require `sum + new <= COOLING_OFF_MAX`; outside cooling-off apply a 24 h cap for bio-proof transactions (`BIO_ONLY_DAILY_MAX`) and force PIN when `sum + new > BIO_ONLY_MAX`. (3) Add a per-window transaction count cap during cooling-off. (4) Tests: 10 x 400 USD within cooling-off => the 2nd is `COOLING_OFF`; 3 x 400 USD by biometric => 3rd requires PIN. Spec amendment: SEC-041/047 should say "aggregate over the window", I will carry that into `security-spec.md` at the next revision.
- Severity note: Medium for the mock-funds demo, High as soon as any real value is attached. Kept at High because SEC-047 is on the MUST-NOT-relax list and is the only compensating control for the static recovery secret (R5).

### Medium

#### M-01 [EXPO] Client signs server-supplied challenge fields without validating them
- SEC: 019, 027, 039, 043, 020.
- Evidence: `src/auth/unlock.ts:71-79` builds and signs the message from `ch.data` with no check that `purpose === 'login'`, `deviceId` equals the stored device id, or `boundHash` is empty. `src/flows/send.ts:53-54` signs `c.purpose`/`c.boundHash` without checking `purpose === 'stepup'`, `deviceId === session.deviceId`, or `boundHash === computeTxHash(this.tx)`. `src/flows/biometrics.ts:62-64` signs the enroll challenge without checking `purpose === 'enroll'` or the device id. `buildChallengeMessage` (`src/crypto/messages.ts:63-78`) only checks shape.
- Impact: confused-deputy. Anything that can alter a challenge response (a LAN MITM against the dev cleartext transport, a compromised API, or a hooked JS layer) can make the user's "Unlock" biometric tap sign a step-up challenge for an attacker transaction (the attacker needs a session token to have created that challenge, which a cleartext sniffer gets). It also nullifies the value of the local hash check in M-02.
- Fix: validate before prompting, fail closed with `SERVER_REJECTED`: unlock `purpose==='login' && deviceId===own && !boundHash`; step-up transaction `purpose==='stepup' && deviceId===own && boundHash===computeTxHash(frozen tx)`; step-up action `boundHash===computeActionHash(action,target)`; enroll `purpose==='enroll' && deviceId===own && !boundHash`. Pin `userId` from the first session response and compare on later challenges. Add negative tests that feed a tampered challenge to the fake backend.

#### M-02 [EXPO] Hash divergence is advisory; Approve stays enabled
- SEC: 039, 043.
- Evidence: `src/flows/send.ts:41` sets `divergence`; `src/app/(app)/send.tsx:111` only shows a banner, and `:118` renders the Approve button regardless. The text the user confirms is the server's `summary` (`send.tsx:113-117`), not the fields the user typed.
- Impact: the one client-side check that detects a server/MITM-altered transaction does not stop it.
- Fix: when `divergence` is true, disable Approve and the PIN/biometric proof, drop the flow, and show the locally entered destination/amount/fee next to the server summary (two-source display). `proveWithBiometric` and `proveWithPin` must throw if `divergence`.

#### M-03 [EXPO primary, BACKEND secondary] Sign-out does not revoke the device record or biometric key; device records accumulate
- SEC: 036, 024, 048; ruling (e) below.
- Evidence: `src/flows/account.ts:58-63` `signOut()` calls `/auth/logout` (family revoke, `auth/sessions.go:138-148`) and deletes the local key, but never `DELETE /devices/{id}`. Every sign-in registers a brand-new device (`handlers/devices.go:91`, `flows/onboarding.ts:48`), and the cap is 5 active devices (`devices.go:75`). A lost refresh-rotation response (ADR-007) also strands the install and forces a re-bootstrap.
- Impact: (1) the server keeps an active biometric public key and device row whose private key may no longer exist (if the best-effort local delete fails at `account.ts:61`, the key is orphaned and, until the 7 d idle limit, the unauthenticated biometric endpoints for that device id still mint sessions with no PIN or demo secret). (2) After five sign-outs or recoveries the user gets `DEVICE_LIMIT` (409) and the only way out is `pin-reset` (exempt from the cap, `devices.go:75`), which revokes every key and starts cooling-off. That trains users into the most dangerous recovery path.
- Fix: expo: `signOut()` must call `revokeCurrentDevice()` semantics (`DELETE /devices/{current}`; it revokes sessions, key and challenges atomically via `revokeDeviceTx`, `devices.go:168-180`), then wipe locally; if offline, queue the revoke and refuse to keep the key. Backend: when the cap is hit, after a successful PIN verify auto-revoke the stalest device (`last_seen_at` older than 30 d) or return the list so the user can pick one; do not make reset the only escape. Keep `/auth/logout` as "end this session" for the lock use case.

#### M-04 [BACKEND] One IP can trip the global demo-login breaker and deny sign-in/recovery for everyone
- SEC: 016, 057, 011 (recovery path), T4.
- Evidence: `internal/server/server.go:252-257`: `b.lim.Breaker(l.DemoLoginGlobal, ...)` runs **before** the per-IP checks and counts every request, including those the per-IP rule would reject. `ip-global` allows 600/min (`config.go:58`), so a single source can send over 100 demo-login requests per minute and open the breaker for `DemoBreakerOpenFor` (60 s), repeatedly.
- Impact: demo-login is the only way to onboard, to recover from a hard lock, and to reset the PIN. A one-IP flood denies the legitimate owner recovery indefinitely (availability attack on the recovery path; the lockout design in SEC-011 deliberately relies on that path staying available).
- Fix: apply `demo-ip-min` and `demo-ip-hour` first; feed the breaker only with requests that passed the per-IP rules, and preferably only with credential failures (breaker on failure ratio). Add a test: 200 requests from one IP must not block a second IP.

#### M-05 [BACKEND, docs EXPO] Secret-bearing traffic over cleartext HTTP on the LAN; no TLS or prod guard on the server
- SEC: 006, 016, 065; R4/R5.
- Evidence: `.env.example:15` `LISTEN_ADDR=0.0.0.0:8080`; `cmd/api/main.go:70-73` serves plain `ListenAndServe` and there is no TLS option; `config.go` does not require TLS or a trusted proxy when `ENV=prod` (HSTS is only set when `r.TLS != nil` or a trusted `X-Forwarded-Proto`, `httpx/middleware.go:124-126`). On the client, cleartext is deliberately allowed for dev: `src/api/baseUrl.ts:31-33` (loopback, emulator hosts, RFC1918, `.local`), iOS `NSAllowsLocalNetworking: isDev` (`app.config.ts:24`), Android debug manifest `usesCleartextTraffic=true` (`plugins/withAndroidHardening.js:36-39,62-75`). I checked that release builds are clean: main manifest cleartext false, `baseUrl.ts` throws for http in non-dev, and `getApi()` runs at startup (`src/app/_layout.tsx:16`).
- Impact: on a shared Wi-Fi the PIN, refresh/access tokens and, most importantly, the demo secret are readable. The demo secret is the root of trust for PIN reset (R5), so a sniffed secret equals account takeover. The dev allowance itself is acceptable (it is scoped, see ruling in section 4), but the default LAN-listening example makes the exposure the normal setup.
- Fix: backend: default and example `LISTEN_ADDR=127.0.0.1:8080` with `adb reverse tcp:8080 tcp:8080` for Android and the simulator for iOS; document that LAN mode is for a trusted network only; offer optional TLS (`TLS_CERT_FILE`/`TLS_KEY_FILE`, mkcert) and in `ENV=prod` refuse to start unless TLS is configured or `TRUSTED_PROXY=true` and the proxy reports https (reject requests whose `X-Forwarded-Proto` is not https). expo: keep the allowlist as is; additionally log nothing but show a persistent "insecure dev transport" banner when `http:` is in use.

### Low

#### L-01 [BACKEND] Unauthenticated biometric challenge/verify lets a holder of a deviceId revoke the key and starve login (ruling c)
- SEC: 029, 030, 057.
- Evidence: `handlers/biometric.go:57-101` (challenge needs only `deviceId` and also supersedes any live login challenge for the device, `:90`), `:124-187` (verify), `:104-121` (5th bad signature revokes the key). Rate buckets are keyed on the attacker-chosen id (`bio-challenge-dev`, `bio-verify-dev`, 10/min).
- Impact: someone who knows a deviceId (128-bit random; visible in audit/request logs and in `/devices/{id}/...` URLs, so not secret against an insider) can force the key revocation (user must re-enrol with a PIN and sits in 24 h key cooling-off) or keep the login challenge permanently superseded. Needs the id, so Low.
- Fix: preferred, require the device credential (the refresh token already in SecureStore, same as SEC-014) as `Authorization` on `biometric/challenge` and `biometric/verify`; anonymous callers then get nothing. The client always has it when it offers biometrics (`boot.ts:13`). Minimum alternative: keep unauthenticated, but on 5 failures **suspend** biometrics for that device until the next successful PIN unlock instead of revoking the key, and do not supersede a live challenge from a caller that presents no credential. Contract change (tech lead).

#### L-02 [BACKEND] Decoy challenge is distinguishable from a real one
- SEC: 029.
- Evidence: `handlers/biometric.go:64` the decoy `userId` is `uuid.New()` per call; a real challenge returns the device's stable `userId` (`:94`, `:48`). Decoys also skip two DB writes (timing).
- Impact: a caller who knows a deviceId can tell enrolled from non-enrolled/revoked/hard-locked by calling twice. Also a real challenge discloses the user's id to an unauthenticated caller. Needs a known deviceId, so Low.
- Fix: derive the decoy `userId` as `HMAC(serverKey, deviceId)` formatted as a UUID so it is stable per device; ideally resolved by the L-01 credential fix.

#### L-03 [BACKEND] Per-device PIN block (SEC-009) is unreachable with the default schedule (ruling b)
- SEC: 009.
- Evidence: `handlers/session.go:95-98` counts only `Invalid` outcomes; defaults `DeviceFailMax=10`, `DeviceFailWindow=15 min` (`config.go:60`). With the lock schedule 30 s / 60 s / 5 min / 15 min the 9th failure comes at least 21 min after the 1st, so the window resets; the maximum counted in 15 min is 8.
- Impact: the control exists and is tested with shortened schedules but never fires in the default deployment. Not a vulnerability because the durable per-user counter and the device credential (SEC-014) already bound guessing.
- Fix: see ruling (b): do not count lock-refused attempts. Retune to `DeviceFailMax=8` over a 60 min window, or declare it alerting-only and amend SEC-009.

#### L-04 [BACKEND] `PUT /pin` and `POST /pin/reset` share one per-user rate bucket that is charged before validation
- SEC: 057, 011, 046.
- Evidence: `handlers/pin.go:133` and `:226` both use class `pinchange-user`, 5/h/user, charged before `pin.Validate` and before any credential check. A holder of any live access token can burn the bucket with weak-PIN `PUT /pin` calls (no lockout counter touched).
- Impact: the legitimate owner's PIN reset (after a hard lock) returns 429 for up to an hour. Needs a live session, so Low.
- Fix: separate buckets for change and reset; key reset by user and IP; charge the change bucket only after the old PIN was evaluated, or only on failures.

#### L-05 [BACKEND] Hard lock does not end live sessions or gate biometric step-up
- SEC: 011, 042.
- Evidence: `handlers/stepup.go:231-249` signature proof path has no hard-lock or lock check; `ReserveAttempt` sets `hard_locked` without revoking sessions (`queries/users.sql:30-40`).
- Impact: a session that already exists keeps transacting up to `BIO_ONLY_MAX` by biometric while the account is hard locked (attacker caused or genuine). The spec only forbids biometric *unlock* in hard lock, so this is an extension of intent. Low.
- Fix: in the bio step-up branch require `NOT hard_locked`; on the transition to hard lock call `RevokeUserSessions`.

#### L-06 [BACKEND] `DELETE /devices/{id}/biometric` can target any of the user's devices with only a recent unlock
- SEC: 038.
- Evidence: `handlers/biometric.go:357,365` uses `GetDeviceForUser` (any own device) and a 5 min `last_unlock_at` check.
- Impact: a thief in a 5 min unlocked window can silently strip biometrics from the owner's other devices. Revoking another device requires a PIN step-up (SEC-038) but disabling its key does not. Low (availability, not takeover).
- Fix: restrict to the current device, or require the `revoke_device`-style PIN step-up for other devices.

#### L-07 [EXPO] Build variant defaults to `development`
- SEC: 006, 068.
- Evidence: `app.config.ts:4` `process.env.APP_VARIANT ?? 'development'`; the cleartext exception (`:24`) follows it. `scripts/check-manifest.mjs:10` defaults to production, so the two defaults disagree.
- Impact: a release/preview build made without the env var ships `NSAllowsLocalNetworking` on iOS (local networks only, so limited) and generates the debug manifest. Fail-open default.
- Fix: default to `production`; require explicit `APP_VARIANT=development` (set it in `eas.json` development profile, already done) and in the local `expo run:*` scripts. CI should run prebuild with no variable and assert the production result.

#### L-08 [BACKEND] Audit lifecycle gaps
- SEC: 061, 062.
- Evidence: retention not implemented: `PurgeAudit` exists (`queries/tx_audit.sql:21-22`) but is never called (`server/maintenance.go:12-23`), and the API role has no `DELETE` on `audit_events` (`migrations/000002_grants.up.sql:9`), correctly. Hash chain is off by default (`.env.example` `AUDIT_HASH_CHAIN=false`) and `VerifyChain` (`audit/audit.go:232`) is not scheduled or exposed. Audit write failures are swallowed by design (`audit.go:142-144`). Nothing verifies at startup that the connecting DB role is the restricted one (if `DATABASE_URL` pointed at the owner, audit immutability is silently gone).
- Impact: SEC-061 retention and tamper evidence are not delivered; immutability depends on operator configuration.
- Fix: startup self-check `has_table_privilege(current_user,'audit_events','UPDATE'|'DELETE'|'TRUNCATE')` must be false, else refuse to start; retention via an owner-role job; run `VerifyChain` on a schedule when the chain is enabled; for security-critical events (`PIN_RESET`, `PIN_CHANGED`, `BIO_ENROLLED`) fail the request if the audit insert fails (production profile).

#### L-09 [BACKEND] In-memory rate-limit map grows with attacker-chosen keys
- SEC: 057, 005b.
- Evidence: `ratelimit/ratelimit.go:53-57,46-52` creates a window per `class:key`; unauthenticated classes are keyed by request-supplied `deviceId`. Sweep runs every 2048 ops and drops entries older than 2 h.
- Impact: slow memory growth from random UUIDs (bounded by the 600/min/IP global limit). Low.
- Fix: cap the map size and evict oldest, or key unauthenticated limits by IP only.

#### L-10 [TECH LEAD, backend harness] Contract and test-harness gaps (ruling f)
- SEC: 059, 063.
- Evidence: `X-StepUp-Token` is `required: true` (`openapi.yaml:707-715`) so the server injects a constant placeholder (`server/server.go:184-192`, `handlers/common.go:37`) to turn a missing header into 403 instead of 400. Undeclared responses (400, 500, 503, some 403/404) are exempted in the validating transport (`internal/e2e/harness_test.go:232-235`), so the claim "every HTTP response is validated against openapi.yaml" does not hold for those statuses.
- Impact: contract drift is not detectable for the exempted statuses; the placeholder is a hack that must not grow.
- Fix: make the header optional and document 403 `STEPUP_REQUIRED`; add a shared `default` ErrorResponse (400/403/404/500/503) to every operation; remove the allowlist in the harness.

#### L-11 [EXPO] Biometric prompt carries no transaction context
- SEC: 039, R3.
- Evidence: prompt text is a JS-supplied title only (`unlock.ts:57`, `send.ts:54` "Confirm transaction"); native `sign` accepts any message (`BiometricKeyModule.swift:151-165`, `.kt:117-167`).
- Impact: malware that controls JS can obtain a biometric signature over an attacker transaction behind a generic prompt, bounded by `BIO_ONLY_MAX` (and H-01 makes the bound weak). Cannot be fully fixed in software.
- Fix: pass the server `summary` title and first line as the prompt subtitle/reason; production should add Android Protected Confirmation or a hardware-backed display path; keep the cumulative cap from H-01.

#### L-12 [EXPO] A single 401 on `pin/verify` wipes the refresh token, deviceId and biometric key
- SEC: 023, 034.
- Evidence: `src/auth/unlock.ts:34` `AUTH_FAILED && !useBoot => wipeCredentials()`; `src/auth/session.ts:82` same on refresh.
- Impact: an injected 401 (cleartext dev transport, misbehaving proxy) or a lost rotation response destroys the local identity and pushes the user to demo-login and a new device (feeds M-03). Not a confidentiality problem.
- Fix: wipe only after a second consecutive `AUTH_FAILED` on a fresh request, or after confirming via the unauthenticated `/healthz` plus a retry; never wipe on the first.

### Info

- **I-01 [TECH LEAD]** `vectors.json` `tx-preimage-1` declares `totalBytes: 140` and `contract-notes.md:66` says 140 bytes; the segments add up to **138** (2+15, 2+3, 2+8, 2+42, 2+3, 2+5, 2+36, 2+10). Both implementations reproduce the segments, so no security impact. Fix the number in both files (login vector 147 is correct).
- **I-02** SEC-007 and SEC-058 do not exist (ruling d). No requirement is missing.
- **I-03** Pepper comes from env/file and only the length is checked (`config.go:177-190`); entropy and placeholder prefix are not verified beyond `CHANGE_ME`. SIMPLIFY accepted for the demo; production must load from KMS.
- **I-04** iOS Keychain items (SecureStore tokens and the Secure Enclave key) survive app uninstall. After a reinstall the old identity is still present and still valid server-side. Acceptable (PIN still required) but document; `boot.ts` handles it by starting Locked.
- **I-05** Dev builds prefill `EXPO_PUBLIC_DEMO_SECRET` (`src/config/devDefaults.ts`): in a dev-client build the secret is in the JS bundle and the field is pre-populated, so anyone holding that phone can run PIN reset. Dev-client builds must never hold real accounts or be distributed. The release gate (`scripts/check-release-bundle.mjs`) and my grep of `dist/` found no secret or http URL.
- **I-06** Attestation is `none` and `securityLevel` is self-reported (`handlers/biometric.go:320`, Android `isSupported.secureHardware` is constant true, real check at `generateKey` via `KeyInfo`). Demo scope per SEC-022; production policy forcing PIN for `none` keys is implemented (`stepup.RequiredForTx`, `Prod && AttestationNone`).
- **I-07** `deploy/postgres-init/01-api-role.sh` interpolates `$API_DB_PASSWORD` into an unquoted heredoc; a password containing `'`, `$` or a backtick breaks or injects. Compose image is pinned by tag, not digest.
- **I-08** Failed demo-login is audited as event type `LOGIN_OK` with `result=fail` (`handlers/session.go:49`). Rename to `LOGIN_FAIL` so alerting on type does not misfire.
- **I-09** Idempotency request hashes for PIN bodies are a fast HMAC under a pepper-derived key held 24 h (`handlers/common.go:62-67,170-181`). A DB leak alone is safe; DB leak plus pepper gives the PINs without Argon2 cost, but that attacker already holds the pepper (R1).

## 3. Verification detail on the requested focus areas

| Area | Verdict | Where |
|---|---|---|
| PIN verify path, device credential first | Verified. Credential resolved in the auth middleware before the handler; mismatch with body `deviceId`, revoked device, used or revoked refresh token all give uniform 401 and do not touch the counter. | `server/server.go:296-301`, `auth/sessions.go:254-285` |
| Atomic lockout, reserve-before-hash | Verified. One conditional `UPDATE ... RETURNING` reserves the attempt before any Argon2 work; locked/hard-locked users hit zero rows and no hashing. The hashing slot is acquired before the reservation, so a saturated pool returns 429 without charging an attempt. A correct PIN clears the counter, including a hard lock set by its own reservation. Correct PIN during an existing lock is refused. | `queries/users.sql:30-49`, `lockout/lockout.go:58-106` |
| Pepper and Argon2 | Verified. `Argon2id(HMAC-SHA256(pepper_vN, pin))`, 16-byte random salt, PHC string with `pv=`, constant-time compare, upgrade-on-login with compare-and-set, dummy work for the no-PIN path. Floors: dev m=19456 KiB t=2, prod m=65536 t=3 (startup fails below). Startup fails on missing or short pepper. | `pin/hash.go`, `config.go:177-243` |
| Challenge and nonce handling | Verified. 32-byte CSPRNG nonce, server TTL, one live challenge per (device, purpose) enforced by a partial unique index, consumed atomically on first attempt scoped to device and purpose (session, user for step-up/enroll), message rebuilt from the stored row, domain tag and purpose in the message, strict DER parse (re-marshal equality, r/s range). Login vector: my byte count is 147 and matches the code's field order and `lp` encoding. Tx vector: 138, not 140 (I-01). | `queries/challenges.sql`, `cryptomsg/cryptomsg.go:44-62,187-209`, `handlers/biometric.go:124-187` |
| Refresh rotation, reuse, unlock window | Verified. Used or revoked token => whole family revoked + `REFRESH_REUSE`; lost race handled; `UNLOCK_REQUIRED` leaves state untouched; 15 min absolute from `last_unlock_at`, 5 min idle, 30 d / 7 d lifetimes; refresh never sets `last_unlock_at`; successful PIN/bio unlock creates a new family and revokes the device's earlier ones. Step-up verify also sets `last_unlock_at` (consistent with `contract-notes.md` section 4). | `auth/sessions.go:47-135` |
| Step-up binding and tx recomputation | Verified. Server recomputes the hash from the `POST /transactions` body, token bound to user, session, device, action and hash, consumed in the same DB transaction as debit and insert, mismatch burns the token and forgets the idempotency record, unique `(user_id, tx_nonce)` stops nonce replay, no client approval flag. Proof strength is decided at challenge time and enforced at verify. Gap: aggregate limits (H-01). | `handlers/tx.go:86-139`, `stepup/stepup.go`, `handlers/stepup.go:196-217` |
| `POST /pin` never overwrites | Verified. `SetInitialPin ... WHERE pin_hash IS NULL` plus scope check plus `UseBootstrap` in one transaction; 409 otherwise. | `handlers/pin.go:54-90`, `queries/users.sql:19-22` |
| Demo-login gating | Verified with one defect. `DEMO_MODE` 404 when off, startup refuses `DEMO_MODE` with `ENV=prod`, secret >= 12 chars, hash-then-constant-time compare, unknown user and bad secret indistinguishable, scope chosen server-side, 600 s TTL, device-bound, single use for set/reset, bootstrap token rejected on session routes with 403. Defect: breaker (M-04). | `handlers/session.go:29-70`, `config.go:157-159,215-230`, `auth/sessions.go:172-250` |
| Reset and recovery | Verified. Needs a device-bound `pin-reset` bootstrap, revokes every session, key and other device record, clears locks, starts cooling-off, exempt from the 5-device cap. Effectiveness of cooling-off is H-01. | `handlers/pin.go:202-294`, `handlers/devices.go:75` |
| Error uniformity and timing | Verified for biometric verify (all failures one 401, `burnVerify()` equalises ECDSA work), demo-login, pin/verify. Decoy distinguishable only by `userId` stability (L-02). Timing equalisation is best effort as the spec allows. | `handlers/biometric.go:43-45,124-187` |
| Logging redaction | Verified. Key allowlist plus secret-key regex, request log has ids and route template only, no bodies or headers, `slog.LogValuer` on config, audit metadata allowlist and value shape check, canary test covers PIN, bearer, idempotency key, pepper, DB secrets. | `platform/log/log.go`, `audit/audit.go:64-108`, `e2e/leak_test.go:52-104` |
| DB roles and audit immutability | Verified for the role design: runtime role has no DDL and `SELECT, INSERT` only on `audit_events`; owner role is read only by `cmd/migrate`; port bound to 127.0.0.1. Not enforced at startup (L-08). | `migrations/000002_grants.up.sql`, `deploy/postgres-init/01-api-role.sh`, `docker-compose.yml:14` |
| Client storage | Verified. Refresh token and deviceId only in SecureStore with `WHEN_PASSCODE_SET_THIS_DEVICE_ONLY`; access and step-up tokens module memory only; `lock()` clears them; AsyncStorage holds only the hint and the auto-lock delay; no `requireAuthentication` on tokens as the spec intends; storage imports confined to `src/storage` (test-enforced). | `src/storage/*.ts`, `src/auth/session.ts` |
| Native key flags | Verified in source, **needs device**. iOS: P-256 in Secure Enclave, `[.biometryCurrentSet, .privateKeyUsage]`, `WhenPasscodeSetThisDeviceOnly`, no software fallback outside simulator/DEBUG, SPKI header prepended, `ecdsaSignatureMessageX962SHA256`, passcode fallback hidden. Android: `secp256r1`, `setUserAuthenticationRequired(true)`, `setUserAuthenticationParameters(0, AUTH_BIOMETRIC_STRONG)`, `setInvalidatedByBiometricEnrollment(true)`, StrongBox with TEE fallback, `isInsideSecureHardware` enforced, `BiometricPrompt` with `CryptoObject`, no device-credential authenticator, `KeyPermanentlyInvalidatedException` mapped to `KEY_INVALIDATED`; minSdk 30 set in `app.config.ts:36` (required for `setUserAuthenticationParameters`). No `expo-local-authentication` in `package.json` or `src` (grep clean; contract test also asserts it). | `BiometricKeyModule.swift:105-165`, `BiometricKeyModule.kt:47-56,81-167` |
| Screen capture and auto-lock | Code verified, **needs device**. App-wide `usePreventScreenCapture()`, privacy overlay on `inactive`/`background`, auto-lock 30 s default with 0/30/60 options, 5 min inactivity, wall-clock check on resume, cold start Locked, no-passcode blocks. Risk: the overlay is rendered after a React state update, so the first iOS app-switcher snapshot may race the overlay (verify on device). | `src/app/_layout.tsx`, `src/auth/autoLock.ts`, `src/auth/boot.ts`, `src/ui/PrivacyOverlay.tsx` |
| Bundle and manifest hardening | Verified in config, **needs build**. `allowBackup=false`, extraction rules exclude all domains, main manifest cleartext false, debug-only cleartext, `SYSTEM_ALERT_WINDOW` removed from release, ATS on, `expo-updates` absent, `transform-remove-console` for production, no `console.*` in `src`. `dist/` contains no demo secret or dev URL. Variant default is fail-open (L-07). | `app.config.ts`, `plugins/withAndroidHardening.js`, `babel.config.js`, `scripts/*` |
| Dev-only cleartext allowance | Acceptable as scoped: gated by `isDev` in `baseUrl.ts`, restricted to loopback, emulator hosts and private ranges, absent from release manifests, enforced by `check-manifest.mjs`. Residual: M-05, L-07, I-05. | `src/api/baseUrl.ts`, `app.config.ts:24` |

## 4. Rulings on the engineer-raised items

**(a) D-14, SEC-020 vs SEC-040: 403 `STEPUP_INVALID` vs 401. Confirmed: 403 `STEPUP_INVALID`.** Rationale: a bad or reused step-up token means the *session* is valid but the *action proof* is not. 401 makes the client's `authedCall` retry/refresh loop (it treats `AUTH_FAILED` as "refresh then retry once", `session.ts:112-119`) and risks wiping credentials; 403 does not. Keep `AUTH_FAILED` 401 for a bad proof-of-possession signature (no valid session semantics are involved). Keep all misuse variants (unknown, expired, reused, other session/device/action, hash mismatch) on the same code and body, which the code does (`stepUpInvalid()` for both `Invalid` and `Mismatch`). Spec change: SEC-020 acceptance line "replayed step-up token => 401" becomes "=> 403 `STEPUP_INVALID`". D-06 (5th failure returns 423 with `retryAfter`) and D-08 (step-up PIN consumes the challenge) are also confirmed.

**(b) SEC-009 unreachable with the default schedule; should lock-refused attempts count?** The unreachability is real (L-03). **Do not count lock-refused attempts toward the user counter**: that would let anyone holding the device credential spam during a soft lock to reach failure 10 within seconds and hard-lock the victim, turning the escalation schedule into a lockout-DoS lever and contradicting SEC-010. Do not count them toward a *blocking* device counter either, for the same DoS reason. Resolution: amend SEC-009 so that (1) lock-refused attempts are neither counted nor blocking, but are audited/alerted; (2) the device-level control is the existing 10/min rate limit plus a device block at 8 counted failures within 60 min (or alert-only). The user counter plus the device credential remain the real controls.

**(c) Unauthenticated biometric challenge/verify DoS (SEC-030).** Real but Low (needs a known deviceId; see L-01). Should failures without a valid session count? They cannot be told apart from a hooked client, so yes they must count, but the *consequence* must change. Recommended: require the device credential (refresh token) on both biometric endpoints, which removes the anonymous case, the userId disclosure and the challenge-supersede problem in one change and matches SEC-014; if the contract must stay unauthenticated, make the 5-failure consequence "suspend biometrics until next PIN unlock" rather than key revocation, and keep the audit event.

**(d) SEC-007 / SEC-058 numbering gaps.** Confirmed: no requirement is missing. SEC-058's intent (rate limiting) is SEC-057; T1 in the spec cites 058 by mistake and should cite 057. Do not renumber (traceability in `decisions.md` section 5 depends on current ids); add "SEC-007, SEC-058: intentionally unused" to the spec and fix T1. The count of 67 ids stands.

**(e) Logout does not revoke the device record or biometric key.** Distinguish *lock/logout* from *sign out of this device*. `/auth/logout` correctly ends the session and refresh family and should stay that way. The user-facing **Sign out** on a shared device must revoke the device (`DELETE /devices/{current}`), which atomically revokes sessions, the biometric key and outstanding challenges. Today `signOut()` does not, which leaves an active biometric public key on the server and burns one of five device slots per sign-in (M-03). Fix on the expo side, plus the cap-relief change on the backend. No contract change needed.

**(f) Contract issues.**
1. `X-StepUp-Token required: true` vs 403 `STEPUP_REQUIRED`: make the parameter optional and document the 403 (L-10); remove `stepUpPlaceholder` once done. Owner: tech lead (contract), backend (remove middleware).
2. Undeclared 403/400/500/503/404: add a shared default error response to every operation and delete the exemption list in `e2e/harness_test.go:232-235`; until then the "all responses validated" claim is weaker than the matrix states. Owner: tech lead, then backend.
3. `tx-preimage-1` 140 vs 138: **138 is correct**; fix `vectors.json` `totalBytes` and `contract-notes.md:66` (I-01). Owner: tech lead.

Also noted from the spec side: the dev cleartext allowance stays, restricted as it is today (M-05, L-07).

## 5. SEC coverage table

Legend: **V** verified in code (read by me); **V+D** verified in code, needs device; **P** partial (see note); **C** claimed only, not inspected by me; **N** not implemented; **-** id does not exist.

| SEC | Status | Note |
|---|---|---|
| 001 | V | `pin/policy.go`; embedded list has 243 entries (>= 200) |
| 002 | C | `src/pin/policy.ts` not read line by line; server is authority regardless |
| 003 | V | Argon2id over HMAC(pepper), per-user salt, params floors, `pv=` version |
| 004 | V | env/file, >= 32 bytes, fail-closed; KMS is SIMPLIFY (I-03) |
| 005 | V | constant-time compare; no pin/hash/salt in responses (test claimed, schema checked by reading) |
| 005b | V | bounded pool, 429 without charging an attempt, per-IP limits before hashing |
| 006 | P | FE verified (HTTPS-only release, dev scope); BE has no TLS/prod guard (M-05); pinning not required |
| 007 | - | does not exist (ruling d) |
| 008 | V | atomic reserve-before-hash, durable, schedule matches |
| 009 | P | counter exists but unreachable by default (L-03) |
| 010 | V | lock checked first, correct PIN during lock refused, `retryAfter` only after credential |
| 011 | V | hard lock blocks PIN and biometric; reset recovers; live sessions not ended (L-05) |
| 012 | V | `recentFailures`, `PIN_LOCKED`, `PIN_HARD_LOCKED`, `PIN_UNLOCKED_AFTER_LOCK` audited |
| 013 | V | no local lock state; countdown only |
| 014 | V | auth middleware resolves credential before handler |
| 015 | V | conditional update + scope + 409 |
| 016 | P | all gates present; breaker defect M-04; secret is a shared demo secret (R5) |
| 017 | V+D | flags correct in Swift; device test needed |
| 018 | V+D | flags correct in Kotlin; device test needed |
| 019 | V | no `expo-local-authentication`; unlock only via server session; hint/boolean cannot unlock |
| 020 | V | two-step enrol, PIN step-up, PoP; 403 vs 401 per ruling (a) |
| 021 | V | SPKI P-256 on-curve canonical, 200-byte cap, one active key by unique index |
| 022 | P | fields stored, attestation not verified (demo), prod policy forces PIN for `none` keys |
| 023 | V+D | client deletes key and tells server after PIN; real invalidation needs device |
| 024 | V | key/session/challenge revoke on delete, reset, device revoke, PIN change |
| 025 | V | CSPRNG 32 B, TTL, one live per (device,purpose), server-chosen fields |
| 026 | V | atomic consume on first attempt, server clock |
| 027 | V | login vector 147 B matches; tx vector is 138 B (I-01) |
| 028 | V | all failure branches return one 401 |
| 029 | P | uniform 401; decoy distinguishable by userId (L-02); timing best effort |
| 030 | P | 5 bad signatures revoke key, PIN counter untouched; DoS concern (L-01) |
| 031 | V | EdDSA, aud/iss/exp enforced, TTL <= 600 s, claims sid/did/amr/auth_time/scope |
| 032 | V | hashed, single use, family reuse revoke, 30 d / 7 d |
| 033 | V | 15 min absolute, 5 min idle, `UNLOCK_REQUIRED` stateless |
| 034 | V+D | SecureStore options correct; backup/no-passcode need device |
| 035 | P | `amr`/`auth_time` issued; step-up policy does not read `amr` |
| 036 | V | logout revokes family; device revoke and PIN change revoke sessions; sign-out gap M-03 |
| 037 | V | new family per unlock |
| 038 | V | proof table implemented (disable biometrics is 5 min unlock, L-06) |
| 039 | V | server recompute; client divergence not enforced (M-02) |
| 040 | V | single use, same DB transaction, bound |
| 041 | P | server-side proof strength; per-tx only (H-01) |
| 042 | V | PIN step-up shares the lockout |
| 043 | V | `purpose=stepup`, `boundHash`; client validation gap (M-01) |
| 044 | P | no approval flag, balance check; no velocity (H-01) |
| 045 | V | old PIN through lockout, other sessions and other devices' keys revoked |
| 046 | V | bootstrap-gated, revokes all, cooling-off started |
| 047 | P | mechanism exists, bypassable by splitting (H-01) |
| 048 | V | server-generated id, cap 5, new device cooling-off; cap relief M-03 |
| 049 | V | ownership checks return 404 |
| 050 | V+D | logic verified; real AppState needs device |
| 051 | V+D | needs device (screenshot, switcher race) |
| 052 | V | custom keypad, no `TextInput` for the PIN; secret field has autofill flags |
| 053 | V | ref buffer, `take()` zeroes, count-only state |
| 054 | V | hint is non-authoritative; reconciliation implemented |
| 055 | V+D | `transform-remove-console`, no `console.*`; confirm in a real release bundle |
| 056 | V | advisory risk only |
| 057 | P | table implemented; breaker defect M-04, shared bucket L-04 |
| 058 | - | does not exist (ruling d) |
| 059 | V | uniform envelope, generic messages; extra codes per D-13 |
| 060 | V | key per (user, endpoint), 24 h, token-bearing responses never replayed |
| 061 | P | events and field allowlist present; retention N, chain off by default (L-08) |
| 062 | V | allowlist logger, `no-store`, canary test |
| 063 | V | `additionalProperties:false` validation, 16 KiB, parameterised sqlc queries |
| 064 | V | risk stored, no reliance |
| 065 | V | fail closed on config and store |
| 066 | V | Postgres-backed counters, challenges, families; rate buckets in memory by design (D-12) |
| 067 | V+D | manifest and options correct; extraction test needs device |
| 068 | V | dev build, own module, no OTA; Hermes debugger/dev menu in release not independently confirmed |

Section 7 negative tests: I confirmed by code reading that tests 1-14 (backend) and 15-22 (expo) have matching implementation paths. Tests 16, parts of 17, 20 and 21 remain manual device checks, none of which has been run (the Expo matrix itself states "nothing has been run on a device yet"). The existing suites were not executed by me.

## 6. Residual risks

- **R1 (unchanged)** 10^6 PIN space: a DB dump plus the pepper exposes PINs quickly; the pepper lives in env, not KMS.
- **R5 (raised in weight by M-05 and H-01)** The shared demo secret is both login and recovery root of trust. Over cleartext LAN it is sniffable, and a reset is only partly contained by cooling-off until H-01 is fixed.
- **R3** Malware controlling JS can ask the OS to sign attacker-chosen bytes behind a generic prompt (L-11) and read the PIN as typed.
- **R7 (changed)** Counters and families are durable now, but the rate-limit buckets and the demo-login breaker reset on restart (accepted in D-12).
- **New R9** Refresh rotation can strand an install if the response is lost (ADR-007), which funnels users into re-bootstrap and the device cap (M-03, L-12).
- **New R10** Attestation absent: the server cannot prove a key is hardware- and biometric-bound; trust rests on client honesty (I-06, SEC-022).
- Needs-device items listed above remain unproven until executed and signed in `apps/mobile/docs/sec7-matrix.md`.

## 7. Fix ownership and order

1. **Backend:** H-01, M-04, M-05, then L-01 (with tech lead on the contract), L-03/L-04/L-05/L-06/L-08/L-09.
2. **Expo:** M-01, M-02, M-03 (client part), L-07, L-11, L-12.
3. **Tech lead:** L-10, I-01, ruling (a) and (d) spec edits, L-01 contract change, SEC-009 amendment (ruling b), SEC-041/047 aggregate wording (H-01).
4. **Both:** execute the device checklist before any claim of SEC-017/018/023/034/050/051/067 sign-off.

---

# Re-review (HEAD ab96c92, contract v1.1.0)

Method and limits: static read only, as in the first review. I read the changed handlers, SQL, migration 000003, auth middleware, config, rate limiter, e2e `review_test.go`, and the Expo flows/session/config. I did not run `make api-test` or the Jest suites; the stated passes (Go suite, 213 unit and 198 contract tests) are taken as given and are not evidence about device behaviour. Nothing was verified on a physical device. Application code was not modified.

## R1. Verdict

**No open Critical. No open High. No open Medium.** All five original Medium findings and the High are closed or reduced to Low residuals. Seven Low and eleven Info items remain open (listed below); none blocks the demo. Sign-off scope is code level only: SEC-017/018/023/034/050/051/055/067 stay "needs device".

## R2. Status of every prior finding

| ID | Status | Evidence read |
|---|---|---|
| H-01 | **Closed** | `handlers/tx.go:86-138`: `LockUserRow` is the first statement in the DB tx (`:89`), then idempotency, then `coolingAggregate` (`:106-113`, rolling window `COOLING_OFF_WINDOW`, USD cap plus `COOLING_OFF_MAX_TX` count) and only then `stepup.Consume`. After consume, a `bio` proof is re-checked with `bioOverAggregate` (`:128-137`) and returns 403 `STEPUP_REQUIRED required=pin`. Any aggregate error returns an error from `InTx`, so the token consume rolls back (not burned). The sum (`tx_audit.sql SumTxByAsset`) joins `step_up_tokens` for the proof; the FK `transactions.step_up_token_hash -> step_up_tokens` and the absence of any token purge in `maintenance.go` mean the inner join cannot silently drop rows. Under READ COMMITTED the sum is a statement issued after the lock is held, so it sees every earlier committed insert. Index `transactions(user_id, created_at)` in migration 000003. Also checked at `/stepup/challenge` (`stepup.go:98-115`, advisory; re-enforced at submit). Test `review_test.go` covers split sends, count cap, 6 concurrent pre-minted tokens (exactly 2 succeed), and bio aggregate. Sums are exact `big.Rat`. |
| M-01 | **Closed** (one small gap, N-01) | `crypto/challengeCheck.ts`; used before any biometric prompt in `unlock.ts:74`, `send.ts:45` (purpose, device id, bound hash equals the locally computed tx hash), `biometrics.ts:55`. Fails closed with no prompt. |
| M-02 | **Closed** | `send.ts:45-46`: on divergence the challenge is dropped and `begin()` fails with `CHALLENGE_MISMATCH`; `proveWithBiometric`/`proveWithPin` refuse when `divergence`; `send.tsx:118-122` shows the user's own fields next to the server summary and disables Approve. |
| M-03 | **Partially closed (accepted)** | Expo half closed: `account.ts:62-73` `signOut()` calls `DELETE /devices/{current}`, falls back to `/auth/logout`, always deletes the key and wipes credentials. Backend cap relief not implemented: `devices.go:75` still returns `DEVICE_LIMIT` with reset as the only escape. Low residual (N-04 for the offline case). |
| M-04 | **Closed** | `server.go:252-259`: per-IP rules run first, the breaker is fed only by requests that passed them. Test `TestM04_OneIPCannotOpenGlobalBreaker`. |
| M-05 | **Closed for demo scope** | Default and example `LISTEN_ADDR=127.0.0.1:8080` (`config.go:165`, `.env.example:17`); non-loopback bind logs a warning (`main.go:62-64`); `ENV=prod` refuses to start without `TRUSTED_PROXY=true` or a loopback bind (`config.go:306`); `requireHTTPSInProd` (`server.go:149-158`) rejects plain HTTP in prod. No TLS listener (ruling below). Caveat N-03. |
| L-01 | **Closed** | `server.go:302-313` requires the device credential on both biometric endpoints; `DeviceCredential` (`auth/sessions.go:254-285`) has no side effects (no mark-used, no rotation), rejects used/revoked/idle/expired refresh tokens, a body deviceId different from the token's device, and revoked devices, all with the uniform 401. Five bad signatures now SUSPEND (`biometric.go:104-123`, `SuspendKey`), not revoke; challenge returns a decoy while suspended (`:77`), verify returns the uniform 401 (`:154`, `:160`), step-up bio is refused (`stepup.go:243`). `UnsuspendKey` runs only inside the successful `pin/verify` transaction after the PIN was accepted (`session.go:119`), not on step-up PIN, so a session holder cannot clear it. Revoke-and-re-enrol resets the state because a new key row has `bio_suspended_at` null. |
| L-02 | **Closed** | `biometric.go:126-135`: decoy `userId` is `HMAC(macKey, "decoy-user-id-v1" || deviceId)` formatted as a v4-style UUID; `macKey` derives from the pepper (`common.go:58-62`), so it is stable per device and not guessable. Timing difference (two fewer DB writes) remains best effort per SEC-029. |
| L-03 | **Closed** | `config.go:61` `DeviceFailMax=8`, window 1 h, block 1 h; lock-refused attempts are not counted (`session.go:96-98`). Test `TestRuling_b_DeviceBlockReachableWithDefaultSchedule` also proves 40 spam attempts during a lock do not extend it. |
| L-04 | **Closed** | Separate classes `pinchange-user` and `pinreset-user` (`pin.go:133`, `:226`); test `TestL04_ChangeAndResetBucketsSeparate`. The change bucket is still charged before validation, which only affects the session holder's own change attempts. |
| L-05 | **Partially closed (accepted)** | Bio step-up is refused while hard locked (`stepup.go:250-253`); PIN step-up is refused by the lockout. Sessions are still not revoked on transition to hard lock (known gap, ruling below). |
| L-06 | **Closed** | `biometric.go:378-382`: another device's biometrics cannot be disabled without the PIN step-up path. Note the current-device case still returns `STEPUP_REQUIRED` with no valid way to satisfy it except re-unlock (client maps it to `REAUTH_REQUIRED`); acceptable. |
| L-07 | **Closed** | `app.config.ts:4` defaults to `production`; `package.json` scripts and `eas.json` development profile set `development` explicitly; `check-manifest.mjs` default agrees. |
| L-08 | **Partially closed** | Closed: startup self-check `CanModifyAudit` refuses to start if the runtime role can UPDATE/DELETE/TRUNCATE (`main.go:57-61`). Open: `PurgeAudit` still never called, `VerifyChain` only runs in tests (`leak_test.go:308`), chain still default off, audit write failures still swallowed for security-critical events. Low, acceptable for the demo. |
| L-09 | **Closed** (new side effect N-02) | `ratelimit.go:13,55-64` caps at 100000 keys. |
| L-10 | **Closed** | `X-StepUp-Token` is `required: false` with documented 403 `STEPUP_REQUIRED`/`STEPUP_INVALID` (`openapi.yaml:744-753`); placeholder hack gone from `server`/`common.go`; the harness validates every response with no status allowlist (`harness_test.go:217-235`); openapi has 17 shared error responses. I did not check each operation's declared error set one by one. |
| L-11 | **Closed** (residual R3 stays) | `send.ts:61` passes `Confirm: <server summary title>` as the prompt text. Protected Confirmation is out of scope. |
| L-12 | **Closed (risk reduced)** | A first 401 never wipes (`session.ts:14-19,91-94`, `unlock.ts:36`); biometric-path 401 never wipes (`unlock.ts:67`). Two consecutive injected 401s still wipe; acceptable because injection needs the cleartext dev transport. |
| I-01 | **Closed** | `vectors.json:40` is 138; D-24. |
| I-08 | **Closed** | `session.go:49` emits `LoginFail`. |
| I-02..I-07, I-09 | Unchanged, accepted as before | - |

Rulings b, c, e and the contract items (a, d, f) are implemented as ruled: (b) D-20 verified above; (c) D-18/D-19 verified above; (e) D-22 verified in `account.ts`; (a) `STEPUP_INVALID` is 403 throughout (`stepUpInvalid()`); (d) SEC-007/058 unused, 68 ids now; (f) items 1-3 closed (see L-10, I-01).

## R3. New findings introduced by the fixes (and ones found while verifying)

No new Critical, High or Medium.

**Low**

- **N-01 [EXPO] Challenge validation is incomplete for two PIN-only flows.** `flows/account.ts:46-48` (`revokeOtherDevice`) takes the server's `revoke_device` challenge without checking `deviceId` or that `boundHash === computeActionHash('revoke_device', target)`, and `flows/biometrics.ts:44` checks `deviceId` and `boundHash` for `enable_biometric` but not `purpose === 'stepup'`. The token is bound to whatever the server received, so a transport attacker who rewrites the request could point the PIN step-up at a different device. Needs the dev cleartext transport. Fix: add `isValidStepUpChallenge(ch.data, ownDeviceId, computeActionHash(action, target))` to both before `stepupVerifyPin`.
- **N-02 [BACKEND] Limiter saturation resets every limiter.** `ratelimit/ratelimit.go:61-63`: when 100000 fresh keys exist, the whole map is replaced, which also clears the per-device and per-IP PIN-verify counters and the global ones. With device-id keys now behind the device credential, the practical trigger is 100000 distinct IPs (or forged `X-Forwarded-For` if N-03 applies). The durable user lockout is unaffected. Fix: evict the oldest N entries (or the shortest-window classes) instead of clearing, and never evict the `ip-global`/`pinverify-*` classes.
- **N-03 [BACKEND] `TRUSTED_PROXY=true` is a trust switch, not a check.** `server.go:152` and `httpx/middleware.go:69-72,124` accept client-supplied `X-Forwarded-Proto` and the last `X-Forwarded-For` entry; `config.go:306` is satisfied by the flag alone even on a non-loopback bind. If the listener is reachable without the proxy, the HTTPS-in-prod guard and per-IP limits are spoofable. Fix: document that the listener must only be reachable from the proxy (private network or loopback), and in prod require a loopback or proxy-network bind when the flag is set. Prod is not a demo target, so Low.
- **N-04 [EXPO] Sign-out failure is silent.** `settings.tsx:67` ignores the `{ deviceRevoked }` result of `signOut()`. If the device DELETE fails (offline, locked session), the server keeps the device row and the public key active, the local key and credentials are wiped, and the user is not told; repeated cases refill the 5-device cap (M-03 residual). The orphaned key cannot sign (private key deleted) and the refresh token is gone, so this is hygiene. Fix: show a notice when `deviceRevoked` is false and tell the user to remove the device from another device; backend: the auto-revoke of the stalest device (>30 d idle) after a successful PIN verify when the cap is hit.

**Info**

- **N-05 [BACKEND]** SEC-069 sums use the amount only, not the fee (`tx.go` `txFields` / `sumSince`); the fee is debited but not counted toward the USD caps. Also `COOLING_OFF_WINDOW` is not validated to be at least `COOLING_OFF_DURATION` (`config.go:283-285`); an operator can weaken the aggregate. Add the floor check.
- **N-06** The device block (D-20) refuses a correct PIN for 1 h after 8 evaluated failures (`session.go:81-84`). Only a holder of the device credential can trigger it, and biometric login is unaffected. Intended; make sure the UI shows `retryAfter`.
- **N-07** `DeviceCredential` accepts a device-bound `pin-verify` bootstrap token on the biometric endpoints (`auth/sessions.go:278`). Harmless (the signature is still required) but could be tightened to refresh tokens only.
- **N-08** `authFailedStreak` (`session.ts:14`) is process-wide with no time decay; two unrelated 401s without a successful session between them wipe the identity. Matches the stated L-12 rule; consider decaying after a few minutes.
- **N-09** Bio failure counter (`bio_fail_count`) is reset on login success and PIN unlock only, not on a successful step-up signature; slow accumulation of rare real failures could suspend biometrics. Reset it on step-up success too.
- **N-10** The client does not pin `userId` from the first session response across challenges (my M-01 suggestion). The server rebuilds the signed message from its own row, so a wrong `userId` cannot produce an accepted signature. No action needed.

## R4. Rulings on the engineers' known gaps

| Gap | Ruling |
|---|---|
| SEC-069 limit is per user, not per device | **Acceptable.** Per-user is the stricter bound (an attacker cannot multiply the allowance by registering devices), and a new device already starts cooling-off. A per-device limit would be weaker. |
| Sessions not revoked on hard lock | **Acceptable for the demo.** Both step-up proofs are refused while hard locked (PIN via the lockout, biometric via `stepup.go:250`), so a live session cannot move funds, change the PIN (old PIN needed) or enrol a key (PIN step-up needed). It can still read the dashboard and disable its own biometrics. Add `RevokeUserSessions` on the hard-lock transition before any real-value use. |
| No TLS listener | **Acceptable for the demo** with loopback default, the LAN warning, the prod bind/proxy guard and the HTTPS-in-prod refusal. Do not treat the LAN mode as secure (R5). See N-03 for the proxy-trust caveat. |
| Nothing verified on a physical device | **Acceptable for a code-level sign-off, not for a hardware claim.** SEC-017, 018, 023, 034, 050, 051, 055, 067 remain unproven (Secure Enclave/StrongBox flags, enrollment-change invalidation, `FLAG_SECURE`, app-switcher snapshot race, backup exclusion, release bundle contents). Run the device checklist and sign `apps/mobile/docs/sec7-matrix.md` before presenting the app as a working hardware-backed demo. |

## R5. Updated SEC coverage

Total ids: **68** (001-006, 005b, 008-057, 059-069; 007 and 058 intentionally unused; SEC-069 added). Legend as in section 5.

| Status | Count | Ids |
|---|---|---|
| V (verified in code) | 56 | all others, now including 006 (demo scope, no TLS listener), 009, 011, 016, 020, 029, 030, 036, 039, 041, 043, 044, 047, 057, 069 |
| V+D (code verified, needs device) | 8 | 017, 018, 023, 034, 050, 051, 055, 067 |
| P (partial) | 3 | 022 (attestation not verified, demo), 035 (`amr` not read by step-up policy), 061 (audit retention/chain verification not delivered, L-08) |
| C (claimed, not inspected) | 1 | 002 (`src/pin/policy.ts` not re-read; the server is the authority) |
| N (not implemented) | 0 | - |

Compared with the first review: P went from 12 to 3 (006, 009, 016, 029, 030, 041, 044, 047, 057 moved to V). Section 7 negative tests: 1-14 and 15-22 still map to implementation paths; tests 16 and the device-dependent parts of 17, 20, 21 are still manual and unexecuted.

## R6. Open findings after re-review

| Severity | Open | Items |
|---|---|---|
| Critical | 0 | - |
| High | 0 | - |
| Medium | 0 | - |
| Low | 7 | M-03 residual (backend cap relief), L-05 residual (sessions on hard lock), L-08 residual (audit retention, chain, fail-closed events), N-01 (expo), N-02 (backend), N-03 (backend), N-04 (expo) |
| Info | 11 | I-02, I-03, I-04, I-05, I-06, I-07, I-09, N-05, N-06 to N-10 as listed (I-01 and I-08 closed; N-xx new) |

Closed since first review: 1 High, 4 Medium, 2 Medium-to-Low residual conversions (M-03, and M-05 for the demo), 10 Low, 2 Info.

## R7. Residual risks

- **R1** (unchanged) 10^6 PIN space; DB dump plus pepper exposes PINs; pepper in env, not KMS.
- **R3** (unchanged) JS-level malware can ask the OS to sign attacker-chosen bytes behind a prompt that now carries the server summary title; bounded by the SEC-069 aggregate.
- **R5** (reduced) The shared demo secret remains the recovery root of trust and is sniffable on a cleartext LAN; cooling-off is now effective (aggregate USD and count caps), so a reset gives at most the cooling-off allowance per window.
- **R7** Rate-limit buckets and the demo breaker are in memory and reset on restart or saturation (N-02).
- **R9** Lost refresh-rotation response strands the install (ADR-007); the Expo side no longer wipes on the first 401.
- **R10** No attestation; `securityLevel` is self-reported; production policy forces PIN for `none` keys.
- **R11 (new)** Aggregate caps are mock-USD from a static price table and per user. Real value needs a live price feed, fee inclusion (N-05) and per-asset/destination velocity rules.
- Device-only controls (list in R4) are unproven until the checklist is run.
