# Decisions (ADR-style): biometric-pin-login

Artifacts: [draft](./draft.md), [security-spec](./security-spec.md), [openapi.yaml](./openapi.yaml), [contract-notes](./contract-notes.md), [vectors](./vectors/vectors.json), [erd](./erd.md) (database schema, migrations must match), [sequence-diagrams](./sequence-diagrams.md) (9 flows, derived from the final contract), [tasks-backend](./tasks-backend.md), [tasks-expo](./tasks-expo.md).

## 1. Monorepo layout and ownership (ADR-001)

```
/                                   repo root
  package.json                      [Expo owner]   pnpm workspace root, scripts only delegate
  pnpm-workspace.yaml  .npmrc  .nvmrc               [Expo owner]
  Makefile                          [Backend owner] delegating targets only (make api-*, db-up, db-down, migrate, mobile-*)
  docker-compose.yml                [Backend owner] Postgres only (healthcheck, named volume pgdata)
  .env.example                      [Backend owner] placeholders only; real .env git-ignored
  .gitignore  .golangci.yml         [Backend owner]
  .github/workflows/api.yml         [Backend owner]
  .github/workflows/mobile.yml      [Expo owner]
  apps/mobile/                      [Expo owner]   Expo Router, dev build + local native module modules/biometric-key
  apps/api/                         [Backend owner] single Go module github.com/cryptoapp/api (no go.work), migrations/, sqlc, oapi-codegen config
  docs/features/biometric-pin-login [Tech lead]    openapi.yaml (the ONLY contract), contract-notes.md, vectors/, erd.md, tasks, decisions
```

- The contract stays at `docs/features/biometric-pin-login/openapi.yaml`. Codegen configs live inside each app and point at it by relative path (`apps/api/oapi-codegen.yaml`, `apps/mobile` `gen:api` script). No second copy exists. Only the tech lead edits the contract, vectors and ERD.
- Disjoint file sets: the two engineers never edit the same file. Root `Makefile` is backend-owned and only forwards (`make -C apps/api`, `pnpm --filter mobile`); Expo tasks never need it (they use pnpm scripts with stable names `typecheck lint test gen:api mock android ios contract-test`). Root `.gitignore` is backend-owned; Expo uses `apps/mobile/.gitignore`.
- Docker is infrastructure only (Postgres). The Go API and the Expo app run on the host.
- CI: two workflows, path-filtered, one per owner.

## 2. Architecture decision records

**ADR-002 Go stack.** Chi on stdlib `net/http`; `oapi-codegen` v2 strict-server generated from `openapi.yaml`; `kin-openapi` request/response validation; `log/slog` JSON with `ReplaceAttr` redaction and an allowlist logger; `golang.org/x/crypto/argon2`; JWT EdDSA for access tokens; `testify`. Why: smallest dependency surface, idiomatic, the contract drives the compile (a contract change breaks the build). Alternatives rejected: Gin/Echo (custom context, no benefit here), Fiber (fasthttp, not `net/http` compatible), grpc-gateway (REST is the contract).

**ADR-003 Database: PostgreSQL (supersedes the earlier SQLite proposal).** User requirement: durable store so lockout counters and refresh-token reuse state survive restarts. Postgres 16 in Docker Compose (healthcheck, named volume `pgdata`, bound to 127.0.0.1), driver `pgx/v5` (`pgxpool`), migrations `golang-migrate`, typed queries `sqlc` (pgx target). Atomicity by single-statement compare-and-set (`UPDATE ... RETURNING`) or `SELECT ... FOR UPDATE` row locks at READ COMMITTED; time comparisons use an injected app clock parameter, not `now()`. Roles: migration owner role vs least-privilege API role (no DDL, INSERT-only on `audit_events`). Credentials only in `.env.example` placeholders; real values in a git-ignored `.env`. Schema: [erd.md](./erd.md). Resolves security-spec OQ3 and residual R7 (restart no longer resets lockout). Rate-limit token buckets stay in process memory (D-12) and reset on restart; acceptable because the user lockout counter (the real control) is durable.

**ADR-004 OpenAPI 3.1 label, 3.0 subset.** As far as I know oapi-codegen v2 and kin-openapi target OpenAPI 3.0.x and support for 3.1 is partial or experimental; this could not be verified offline here. The file declares `openapi: 3.1.0` but uses only the 3.0-compatible subset: no `const`, no `type` arrays, no `nullable` (optional fields are omitted instead), `additionalProperties: false` everywhere (matches `DisallowUnknownFields`), `oneOf` with single-value `enum` discriminators. Fallback if the Go tools reject `3.1.0`: `make gen` rewrites the version line into a temp copy and generates from that (backend T2); the canonical file is never modified. `openapi-typescript` on the Expo side handles both.

**ADR-005 Mobile stack.** pnpm workspaces; Expo SDK stable + Expo Router; development build/prebuild (not Expo Go); types via `openapi-typescript` + `openapi-fetch`; contract mock via MSW (host HTTP server `pnpm mock`, Prism acceptable fallback); Jest + Testing Library. Native signing: own local Expo module `apps/mobile/modules/biometric-key` (Swift Secure Enclave, Kotlin Keystore/StrongBox), no third-party signing library (proposed answer to OQ5; flagged for user).

**ADR-006 Bootstrap token and device binding.** Order: `POST /auth/demo-login {username, secret, intent}` -> bootstrap token (opaque, scope chosen by server) -> `POST /devices` with the bootstrap token (server generates deviceId and binds the token to it server-side, so no token is returned from an idempotent endpoint) -> `POST /pin` | `/auth/pin/verify` | `/pin/reset` (device-bound bootstrap). `pin/verify` additionally accepts the refresh token as the device credential. `username` is added to demo-login (not in the draft) so multiple seeded users exist for IDOR tests.

**ADR-007 Refresh token is the device credential.** The refresh token authorises `pin/verify` (SEC-014). A wrong PIN does not consume or rotate it. `401 UNLOCK_REQUIRED` from `/auth/refresh` does not consume, rotate or trigger reuse detection, otherwise auto-lock would strand the user and force demo-login. Successful unlock creates a new family. Known gap: a lost refresh response (network) strands a rotated token; the user re-bootstraps via demo-login. Production could add a short grace window (not in demo).

**ADR-008 Tokens only in headers.** Refresh token on `/auth/refresh` goes in `Authorization` (no body). Step-up token travels in `X-StepUp-Token` (DELETE endpoints have no body). Nothing sensitive in URLs/queries (SEC-062).

**ADR-009 Integration test infrastructure.** Backend integration and e2e tests use `testcontainers-go` (postgres module) with per-test schema isolation; if `TEST_DATABASE_URL` is set (compose DB via `make db-up`) the helper uses it instead. CI uses testcontainers. Expo tests never need Docker.

## 3. Contract decisions

- **D-01 Mandatory spec changes accepted (OQ1).** F1 device credential on pin/verify, F2 bootstrap scopes and `POST /pin` never overwrites, F3 server-enforced unlock window, F4 server-side tx canonicalisation, F5 collapsed auth errors, and the two-step biometric enrollment. No user confirmation needed.
- **D-02 Step-up shape.** `POST /stepup/challenge` takes a discriminated body on `action`: `transaction` (full fields), `enable_biometric`, `revoke_device` (`targetDeviceId`). `disable_biometric` has no step-up: `DELETE /devices/{id}/biometric` is allowed when the session's `last_unlock_at` is within 5 min (SEC-038 "PIN or biometric proof, auth_time <= 5 min"), else 403 `STEPUP_REQUIRED`. The draft's "pin/verify returns step-up token (purpose=enable_biometric)" is dropped; pin/verify never mints step-up tokens.
- **D-03 Challenges return every signed field** (purpose, userId, deviceId, nonce, expiresAt, boundHash). The client never sends userId but must sign it; decoys therefore include a random userId and challengeId.
- **D-04 Encodings.** uint16 BE length prefix on every field including fixed-size; UUIDs as lowercase 36-char UTF-8 strings; `expiresAt` 8-byte BE integer seconds; DER signatures; base64url no padding; SPKI public keys. Details and worked pre-images: contract-notes.md, vectors/vectors.json.
- **D-05 Biometric during lock.** Allowed during a soft PIN lock, refused (uniform 401) during hard lock (security-spec Q5).
- **D-06 Lock response shape.** Failures 1-4: 401 `PIN_INVALID` with `attemptsRemaining = 5 - failures`. Failure 5 and later: 423 `PIN_LOCKED` (the 5th wrong attempt itself returns 423) with `retryAfter` and `attemptsUntilHardLock`; failure 10: `lockType=hard`, no `retryAfter`. Wrong credential (SEC-014 failure) gives `AUTH_FAILED` with none of these fields.
- **D-07 Reset semantics.** `POST /pin/reset` revokes all sessions, all biometric keys and all other device records; the device registered in the same recovery flow survives. Clients discard the old deviceId and re-enroll biometrics. This restores the 5-device budget. Registration with a `pin-reset` bootstrap token is exempt from the 5-device cap (otherwise a hard-locked user with 5 devices could never recover).
- **D-17 Lockout reserves the attempt before hashing.** One conditional `UPDATE ... WHERE NOT hard_locked AND (locked_until IS NULL OR locked_until <= now) RETURNING` increments the counter and sets the lock for the new count before any Argon2 work, so 50 parallel wrong guesses start at most 5 hash evaluations (SEC-008 test). A correct PIN clears the counter. Shared by pin/verify, PUT /pin and step-up PIN (backend T13). Rejected alternative: row lock held across the hash.
- **D-08 Step-up challenge consumption.** Consumed on the first verify attempt even for PIN proofs (follows SEC-026 literally); a wrong PIN requires a fresh `/stepup/challenge`. Counts toward the user PIN lock (SEC-042).
- **D-09 Idempotency scope.** Required on `POST /devices`, `POST /pin`, `PUT /pin`, `POST /pin/reset`, biometric enroll, `POST /transactions`. Token-bearing responses are never replayed (409 `IDEMPOTENT_REPLAY`). Enroll challenge and verify endpoints rely on single-use nonces.
- **D-10 Enrollment consumes the step-up token at `enroll/challenge`** and binds the enroll challenge to session+device. `enroll` carries publicKey (SPKI base64url), attestation, and a signature with purpose `enroll`.
- **D-11 Cooling-off defaults.** Config `COOLING_OFF_DURATION` 24 h (demo may set minutes), `COOLING_OFF_MAX` and `BIO_ONLY_MAX` mock-USD thresholds from config. Started by reset, new device (not the first), new biometric enrollment.
- **D-12 Rate limits (SEC-057), in-memory buckets.** demo-login 5/min/IP + 20/h/IP + global breaker; pin/verify 10/min/device + 30/min/IP; biometric challenge and verify 10/min/device + 30/min/IP; refresh 6/min/device; stepup challenge+verify 10/min/user; enroll 5/h/user; PUT /pin and /pin/reset 5/h/user; transactions 20/min/user. 429 with `Retry-After`; `RateLimit-*` headers.
- **D-13 Extra error codes beyond SEC-059** (stable, in the `ErrorCode` enum): `STEPUP_INVALID` 403, `SCOPE_INSUFFICIENT` 403 (bootstrap token on dashboard), `DEVICE_LIMIT` 409, `NOT_FOUND` 404, `PIN_WEAK` 422, `PIN_UNCHANGED` 422, `IDEMPOTENCY_KEY_REUSED` 422, `INVALID_PUBLIC_KEY` 422, `INSUFFICIENT_FUNDS` 422, `SERVICE_UNAVAILABLE` 503, `INTERNAL` 500, `PIN_ALREADY_SET`, `IDEMPOTENT_REPLAY`, `COOLING_OFF`.
- **D-14 ESCALATION: spec inconsistency SEC-020 vs SEC-040.** SEC-020 says a replayed step-up token at enrollment yields 401; SEC-040 says reuse yields 403. Chosen: 403 `STEPUP_INVALID` for every step-up token misuse (reuse, expired, other session/device/action, hash mismatch) and 403 `STEPUP_REQUIRED` when missing; 401 `AUTH_FAILED` stays for a bad proof-of-possession signature. Security-specialist to confirm or overrule; this changes only status codes in openapi.yaml and two tests.
- **D-15 Spec housekeeping.** There are 67 SEC identifiers: 001-006, 005b, 008-057, 059-068. SEC-007 and SEC-058 do not exist in the spec (SEC-058 is cited in threat T1 but never defined; the intent is presumably rate limiting, which SEC-057 covers). The brief's "66 requirements" is off by one (67 ids are present, counting 005b); the table below lists all 67. Security-specialist to confirm no requirement is missing under 007/058.
- **D-16 Hard-locked biometric challenge.** The challenge endpoint returns a decoy for a hard-locked user (not-oracular); verify then fails uniformly.

## 4. Answers to the security-specialist open questions

| Q | Proposed answer | User must confirm? |
|---|---|---|
| OQ1 contract changes F1-F4 | Accepted as mandatory (D-01). | No |
| OQ2 PIN fallback always available, no biometric-only | Keep: PIN fallback always; biometric-only rejected (lost/invalidated key would lock users out). | **Yes** |
| OQ3 in-memory store acceptable? | No. Postgres via Docker Compose (ADR-003) per user requirement; lockout, challenges and token families are durable. | Already decided by user |
| OQ4 who holds demo secret; internet-facing? | Proposed: the user (project owner) holds per-user secrets in a git-ignored `.env`; the demo is localhost/LAN only, never internet-facing; `DEMO_MODE` refuses to start in prod. The reset/hard-lock path is only as strong as this secret (R5). | **Yes (most important)** |
| OQ5 dev build and native module | Dev build required (no Expo Go); write our own small Expo module (Swift/Kotlin) for key-signing, no third-party signing lib; budget about 2 task-days (Expo T4, T5). Requires a Mac with Xcode and Android SDK, physical devices for biometric tests. | **Yes** (effort and device availability) |
| OQ6 auto-lock 30 s background / 5 min inactivity | Accept the defaults; user-selectable immediate/30 s/1 min. | **Yes** |

Additional items for the user: (a) StrongBox optional vs required (proposed optional, TEE accepted); (b) confirm pnpm (vs npm) and Postgres 16 in Docker; (c) confirm D-07 (reset revokes all device records) and D-08 (PIN step-up consumes the challenge on the first try, new challenge after a wrong PIN); (d) demo thresholds (`BIO_ONLY_MAX`, `COOLING_OFF_MAX`, cooling-off minutes) for a usable demo.

## 5. Traceability: SEC-id to contract element and tasks

BE = tasks-backend.md, FE = tasks-expo.md. Contract column = element in openapi.yaml or contract-notes/erd that carries the requirement.

| SEC | Contract / schema element | BE tasks | FE tasks |
|---|---|---|---|
| SEC-001 | `PIN_WEAK` 422, `Pin` pattern | T6, T16 | (see 002) |
| SEC-002 | UI mirror only | - | T10, T12 |
| SEC-003 | erd users.pin_hash | T3, T6 | - |
| SEC-004 | startup fail-closed | T3 | - |
| SEC-005 | no pin/hash/salt in responses (writeOnly Pin) | T6, T13, T21 | - |
| SEC-005b | 429 on hash saturation | T6, T8 | - |
| SEC-006 | JSON body only, TLS, no query secrets | T4, T13 | T2, T21 |
| SEC-007 | does not exist in spec (D-15) | - | - |
| SEC-008 | `PIN_INVALID`/`PIN_LOCKED`, erd users counters | T5, T13 | - |
| SEC-009 | erd device_pin_failures | T8, T13 | - |
| SEC-010 | PinLocked response | T13 | - |
| SEC-011 | `lockType=hard`, `/pin/reset` | T13, T14, T16 | T13, T17 |
| SEC-012 | `recentFailures` in SessionResponse | T13, T19 | T13, T20 |
| SEC-013 | server authoritative lock | - | T7, T8, T13 |
| SEC-014 | `deviceCredential` scheme on pin/verify | T10, T13 | T13 |
| SEC-015 | `POST /pin` 409 `PIN_ALREADY_SET` | T11, T13 | T12 |
| SEC-016 | demo-login, bootstrap scopes | T3, T11 | T12 |
| SEC-017 | attestation/keySecurityLevel fields | - | T4, T15 |
| SEC-018 | attestation/keySecurityLevel fields | - | T5, T15 |
| SEC-019 | biometric/verify (signature only) | T14 | T4, T5, T9, T14 |
| SEC-020 | enroll/challenge + enroll | T15 | T15 |
| SEC-021 | `INVALID_PUBLIC_KEY` 422 | T7, T15 | - |
| SEC-022 | `Attestation` schema, erd device_keys | T15 | T15 |
| SEC-023 | `DELETE .../biometric` | T15 | T4, T5, T14, T16 |
| SEC-024 | revoke endpoints | T12, T14, T15, T16 | T16, T17 |
| SEC-025 | `Challenge` schema | T7, T14 | - |
| SEC-026 | consume-on-first-attempt | T5, T14, T17 | - |
| SEC-027 | contract-notes s1, vectors | T7, T14 | T6 |
| SEC-028 | biometric/verify | T14 | - |
| SEC-029 | decoy challenge, uniform 401 | T14 | T14 |
| SEC-030 | key revoked after 5 failures | T14 | - |
| SEC-031 | access token claims | T10 | - |
| SEC-032 | refresh rotation, erd sessions | T5, T10 | T8 |
| SEC-033 | `UNLOCK_REQUIRED` on refresh | T10 | T8, T9 |
| SEC-034 | client storage | - | T7, T21 |
| SEC-035 | `amr`, `authTime` | T10 | - |
| SEC-036 | logout, revoke on change | T10, T16 | - |
| SEC-037 | one live family per device | T10, T13, T14 | - |
| SEC-038 | `X-StepUp-Token`, `STEPUP_REQUIRED` | T12, T15, T17 | T15, T18 |
| SEC-039 | `/stepup/challenge` tx fields, `txHash`, contract-notes s2 | T7, T18 | T6, T19 |
| SEC-040 | single-use step-up token | T17, T18 | T19 |
| SEC-041 | `required` field | T17 | T19 |
| SEC-042 | stepup/verify PIN uses same counter | T17 | - |
| SEC-043 | purpose stepup + boundHash | T7, T17 | T6, T19 |
| SEC-044 | no approval flag in schema | T9, T18 | T19 |
| SEC-045 | `PUT /pin` | T16 | T18 |
| SEC-046 | `POST /pin/reset` | T11, T16 | T17 |
| SEC-047 | `coolingOffUntil`, `COOLING_OFF` | T12, T15, T16, T17, T18 | T17, T18, T19 |
| SEC-048 | `POST /devices`, `DEVICE_LIMIT` | T12 | T12 |
| SEC-049 | `GET /devices`, NOT_FOUND | T12 | T18 |
| SEC-050 | client auto-lock | - | T9, T13 |
| SEC-051 | client capture protection | - | T11 |
| SEC-052 | PIN field hardening | - | T10 |
| SEC-053 | PIN buffer handling | - | T10 |
| SEC-054 | hint reconciliation, `biometricEnabled` in responses | - | T7, T9, T13, T14, T15, T16 |
| SEC-055 | no console/logs | - | T8, T21 |
| SEC-056 | `RiskSignals` | T19 | T20 |
| SEC-057 | rate-limit headers, 429 | T8, T11 | - |
| SEC-058 | does not exist in spec (D-15) | - | - |
| SEC-059 | `ErrorResponse`, `ErrorCode` | T4, T21 | T2 |
| SEC-060 | `Idempotency-Key`, `IDEMPOTENT_REPLAY`, erd idempotency_keys | T9 | T12, T19 |
| SEC-061 | erd audit_events | T4, T19 | - |
| SEC-062 | no-store, redaction | T4 | - |
| SEC-063 | additionalProperties false, 16 KiB | T2, T4, T5 | - |
| SEC-064 | `RiskSignals` stored | T12, T19 | T20 |
| SEC-065 | fail-closed config, 503 | T3 | - |
| SEC-066 | Postgres durability (ADR-003) | T5, T20 | - |
| SEC-067 | client backups (server: nothing to store) | - | T1, T4, T7, T21 |
| SEC-068 | dev build, OTA off | - | T1, T4, T21 |

Check performed: ids 001-006, 005b, 008-057, 059-068 (67 ids) all appear above; 007 and 058 flagged as nonexistent. Every BOTH-owned requirement (002, 006, 020, 022, 023, 024, 027, 039, 043, 060, 064, 067) has tasks on both sides where a client half exists.

## 6. Security test mapping (security-spec s7)

Backend tests 1-14: implemented across T5-T19 and consolidated in T20 (`apps/api/docs/sec7-matrix.md`), contract verification in T21. Expo tests 15-22: T3-T22, consolidated in T22 (`apps/mobile/docs/sec7-matrix.md`); hardware-dependent items (16, parts of 17, 20, 21) are manual device checks recorded there.

## 7. Residual open questions

1. Security-specialist: confirm D-14 (403 vs 401 for replayed step-up token), D-15 (nothing missing under SEC-007/058), D-06 (5th failure returns 423), D-08.
2. Tech/user: production refresh-grace window for lost rotation responses (ADR-007), out of scope for the demo.
3. Verify on first use of the pinned tools whether oapi-codegen and kin-openapi accept `openapi: 3.1.0` (ADR-004 fallback prepared).
