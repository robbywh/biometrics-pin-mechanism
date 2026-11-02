# Tasks: backend - biometric + PIN login
Contract: ./openapi.yaml   Security: ./security-spec.md   Schema: ./diagrams/erd/README.md   Notes/vectors: ./contract-notes.md, ./vectors/vectors.json   ADRs: ./decisions.md

Owner: backend-engineer. 21 tasks, each <= ~half a day. Order is T1..T21; dependencies only within this file or on the contract.

## Monorepo ground rules (apply to every task)
- Layout: Go service in `apps/api` (single module `github.com/cryptoapp/api`, NO go.work). Mobile app is `apps/mobile` (not yours). Canonical contract: `docs/features/biometric-pin-login/openapi.yaml`; never copy it into `apps/api`, never edit it (raise changes with the tech lead).
- Files you OWN: everything under `apps/api/`, root `Makefile`, root `docker-compose.yml`, root `.env.example`, root `.gitignore`, `.github/workflows/api.yml`, `.golangci.yml`. Files you must NOT touch: root `package.json`, `pnpm-workspace.yaml`, `apps/mobile/**`, `.github/workflows/mobile.yml`.
- The root `Makefile` only delegates (`make -C apps/api ...`, and `pnpm --filter mobile ...` for mobile targets); the mobile side never needs it. Real logic lives in `apps/api/Makefile`.
- Stack (ADR-002/003/004): Chi on stdlib `net/http`; `oapi-codegen` v2 (chi-server + models, strict-server) with `kin-openapi` request validation; `log/slog` JSON handler with a `ReplaceAttr` redactor; PostgreSQL 16 run via Docker Compose (infra only; the Go API and Expo app run on the host), `jackc/pgx/v5` (`pgxpool`), `golang-migrate` (pgx5 driver), `sqlc` for typed queries (ADR-003, ADR-009), `testcontainers-go` (postgres module) for integration tests; `golang.org/x/crypto/argon2`; `testify`; `golang-jwt/jwt/v5` (EdDSA) or equivalent.
- Handlers implement the generated `StrictServerInterface`; a contract change breaks the build. Strict `json.Decoder` with `DisallowUnknownFields`, 16 KiB `http.MaxBytesReader`.
- Never log bodies, `Authorization`, `X-StepUp-Token`, `Idempotency-Key`, PINs, nonces, signatures, public keys, hashes.

## Contract v1.1 amendments (security review) - these OVERRIDE any older task statement below
- Biometric challenge and verify require the device credential (refresh token in `Authorization`, deviceId must match, no side effects on the token); the T14 statements "unauthenticated" and "5 failures revoke the key" are void: 5 consecutive bad signatures suspend biometric login until the next PIN unlock (`device_keys.bio_suspended_at`, audit `BIO_SUSPENDED`), key stays active. Decoy `userId` is HMAC(serverKey, deviceId) formatted as UUID. (decisions D-18, D-19)
- SEC-009 (T8/T13): count only evaluated wrong PINs, 8 within 60 min blocks the device for 1 h (or alert-only, documented); lock-refused attempts are not counted. (D-20)
- `X-StepUp-Token` is optional in the schema: remove the server placeholder-header hack; missing => 403 `STEPUP_REQUIRED`, anything else => 403 `STEPUP_INVALID`. Every operation declares `default: DefaultError`, so T21 and the e2e harness must NOT exempt undeclared statuses. Declare/return 403 `SCOPE_INSUFFICIENT` on logout and changePin, 404 on demo-login when `DEMO_MODE` is off. (D-21)
- SEC-069 (T17/T18): rolling-window cumulative limits (`COOLING_OFF_WINDOW`, `BIO_ONLY_WINDOW`) summed inside the same DB transaction as token consumption, applied at `/stepup/challenge` and `POST /transactions`; index `transactions (user_id, created_at)`. Tests: split-withdrawal and parallel-transaction cases. (D-23)
- `vectors.json` `tx-preimage-1` totalBytes is 138. Migrations must also match `bio_suspended_at` in diagrams/erd/01-identity-devices.md.

## T1 Scaffold apps/api, root Makefile, CI
- Depends on: (none)
- Implements: monorepo scaffolding; SEC-065 (groundwork), SEC-063 (lint gates)
- Details: `apps/api/go.mod` (Go >= 1.23), dirs `cmd/api`, `internal/{config,platform,apigen,handlers,auth,pin,lockout,challenge,biometric,device,stepup,tx,audit,store,idem}`, `migrations/`. `apps/api/Makefile` targets: `gen` (oapi-codegen + sqlc), `build`, `run`, `test`, `lint`, `contract-test`, `vulncheck`, `migrate`, `migrate-down`. Root `docker-compose.yml`: service `postgres` (image `postgres:16-alpine`, pinned minor), credentials from `${POSTGRES_USER}`, `${POSTGRES_PASSWORD}`, `${POSTGRES_DB}` (no defaults for the password), port bound to `127.0.0.1:${POSTGRES_PORT:-5432}` only, named volume `pgdata`, `healthcheck: pg_isready -U $POSTGRES_USER -d $POSTGRES_DB` (interval 5 s, retries 10), `restart: unless-stopped`; no API or Expo service in compose. Root `.env.example` with PLACEHOLDER values only (`POSTGRES_*`, `DATABASE_URL=postgres://app:CHANGE_ME@127.0.0.1:5432/cryptoapp?sslmode=disable`, plus the T3 variables); real `.env` is git-ignored. Root `Makefile` delegating targets `api-gen api-test api-lint api-run`, `db-up` (`docker compose up -d --wait postgres`), `db-down` (`docker compose down`, keeps volume), `db-reset` (`docker compose down -v`, local only), `migrate` (-> `make -C apps/api migrate`), plus `mobile-*` that call `pnpm --filter mobile <script>`; just forward, no logic. Root `.gitignore` (Go, node, Expo, ios/android, `.env`, `.env.*` except `.env.example`, secrets). `.golangci.yml` (govet, staticcheck, gosec, errcheck, forbidigo banning `fmt.Print*`, `log.Print*`, `slog` default logger outside `internal/platform/log`). `.github/workflows/api.yml`: `go vet`, lint, `go test -race ./...`, `govulncheck`, runs only on changes under `apps/api/**` or the contract path.
- Acceptance criteria: `make -C apps/api build test lint` passes on an empty skeleton; root `make api-test` works; `make db-up` returns only when the container is healthy, `make db-down` then `make db-up` keeps data (named volume); `git ls-files` contains no real credential (only `.env.example` placeholders); compose binds Postgres to loopback only; CI file validates (`actionlint`) and path-filters correctly; no file outside the owned list is created.
- Tests required: smoke test `TestMain` compiles; forbidigo rule demonstrably fails on a deliberate `fmt.Println` (verified once, then removed).
- Done when: skeleton merged and documented in `apps/api/README.md` (how to run, env vars list stub).

## T2 Codegen pipeline, request validation middleware, 3.1 compatibility
- Depends on: T1
- Implements: contract coupling; SEC-063 (strict input validation), SEC-059 (uniform validation error)
- Details: `apps/api/oapi-codegen.yaml` with spec path `../../docs/features/biometric-pin-login/openapi.yaml`, generate chi strict-server + models into `internal/apigen` (committed or generated in CI, pick one and make `make gen` idempotent). Pin the tool via `go.mod` `tool` directive. The spec is labelled 3.1.0 but restricted to the 3.0 subset (ADR-004): if the pinned oapi-codegen or kin-openapi rejects `3.1.0`, `make gen` must rewrite the version line into a temp copy (`sed`) and generate from that; NEVER modify the canonical file. Record the result (works natively or via temp copy) in `apps/api/README.md`. Mount `kin-openapi` `openapi3filter` request validation middleware (ValidateRequest, with auth handled by our own middleware: `AuthenticationFunc` no-op) that maps all failures to 400 `VALIDATION_ERROR` with the generic body. Verify oneOf bodies (`StepUpChallengeRequest`, `StepUpVerifyRequest`) are decoded correctly and ambiguous bodies (both `pin` and `signature`) are rejected.
- Acceptance criteria: FIRST STEP: the canonical spec loads with the kin-openapi loader and `doc.Validate()` passes (the YAML was authored without a machine validator; fix findings by reporting them to the tech lead, not by editing the contract); `make gen` produces identical output twice (no diff); the kin-openapi router matches requests on an `httptest` server with a random host/port (servers url is relative `/v1`); spec edit that removes a response code breaks compile or a test; unknown field, wrong type, bad UUID/PIN pattern, missing `Idempotency-Key`, body > 16 KiB each give the contract-defined error with no internal text.
- Tests required: table-driven validation tests (>= 15 cases incl. SQL-injection strings in string fields, `pin` as number, both proofs present); fuzz target for the decoder (SEC-063; part of spec s7 test 11).
- Done when: `go build ./...` uses generated types; stub handlers return 501.

## T3 Config and fail-closed startup
- Depends on: T1
- Implements: SEC-004, SEC-016 (DEMO_MODE gate, secret from config), SEC-065, SEC-003 (param config), SEC-047/SEC-041/SEC-008 (tunables)
- Details: `internal/config` loads env/secret files only: `ENV` (dev|prod), `DEMO_MODE`, `PEPPER_FILE|PEPPER` (>= 32 bytes, version `PEPPER_VERSION`), `ACCESS_SIGNING_KEY` (Ed25519 seed), `DEMO_SECRETS` (username -> secret; two seeded users alice and bob for IDOR tests), Argon2 params (demo floor m=19 MiB t=2 p=1; prod m=64 MiB t=3 p=1), lock schedule (default 30s,1m,5m,15m,1h; demo override allowed), unlock windows (900 s / 300 s), `BIO_ONLY_MAX`, `COOLING_OFF_DURATION`, `COOLING_OFF_MAX`, limits, `ARGON2_CONCURRENCY`. Refuse to start (exit non-zero, no secret in the message) when: pepper missing/short, signing key missing, demo secrets missing while `DEMO_MODE=true`, `ENV=prod` and `DEMO_MODE=true`, DB unreachable (`DATABASE_URL` required, no default; `sslmode=disable` rejected when `ENV=prod`; `DATABASE_MIGRATE_URL` only read by the migrate command, never by the server). `/healthz` returns 503 `SERVICE_UNAVAILABLE` if the store ping fails. `Config` implements `slog.LogValuer` returning `[redacted]` for secrets.
- Acceptance criteria: each fail-closed condition has a test that asserts non-zero exit / returned error; printing `%+v` of Config reveals no secret; no default values for secrets exist in code.
- Tests required: spec s7 test 14 (missing pepper; DEMO_MODE in prod); config dump redaction test.
- Done when: root `.env.example` (owned by T1, extended here) lists every variable with placeholder values only; no real secret in git history.

## T4 Logging, redaction, error model, HTTP security headers
- Depends on: T1
- Implements: SEC-059, SEC-061 (stdout JSON sink), SEC-062, SEC-063 (headers), SEC-006 (server side: no secrets in URLs)
- Details: `internal/platform/log` slog JSON handler with allowlisted attributes plus `ReplaceAttr` that redacts keys matching `pin|token|authorization|secret|signature|nonce|key|hash|salt|pepper|idempotency`. Request logger logs only method, route template (not raw path with ids if they are secrets), status, latency, request id, user id, device id, ip; never headers/bodies. Panic recovery logs a redacted marker, returns 500 `INTERNAL` generic body. Central `WriteError(code, status, ...)` so every error follows the contract (`{error:{code,message,...}}`, generic messages, no stack/SQL). Middleware: `X-Request-Id` (generate; accept client value only if `^[A-Za-z0-9-]{1,64}$`), `Cache-Control: no-store` on all auth/session routes, `X-Content-Type-Options: nosniff`, `Strict-Transport-Security` when behind TLS, no CORS headers. Audit writer interface (`audit.Emit(ctx, Event)`) with the SEC-061 field allowlist (event type enum; metadata map validated against allowlist) writing JSON to the audit sink (stdout).
- Acceptance criteria: canary PIN `987654`, canary bearer and canary Idempotency-Key sent in a request never appear in captured log output (test hooks into the slog handler); panic in a handler returns the contract body; every error response validates against `ErrorResponse`.
- Tests required: spec s7 test 11 (canary + no `pin|hash|salt` response keys + error fuzz); header tests.
- Done when: `forbidigo` rule from T1 shows no stray loggers.

## T5 Postgres store, migrations, atomic primitives
- Depends on: T1
- Implements: SEC-066, SEC-008 (atomic counter storage), SEC-026 (atomic consume), SEC-032 (family storage), SEC-063 (parameterised queries, least privilege)
- Details: The schema is defined by [./diagrams/erd/](./diagrams/erd/README.md) (tables, columns, types, keys, constraints, notes); migrations MUST match it exactly, and a test compares `information_schema` against the expected table/column list derived from diagrams/erd/. Table names there are authoritative (`idempotency_keys`, `device_pin_failures`, `bootstrap_tokens`, `step_up_tokens`, ...); the informal column list that follows is only a summary. `golang-migrate` SQL migrations in `apps/api/migrations` creating: users(id, username, pin_hash, pepper_version, pin_set_at, fail_count, locked_until, hard_locked, failures_since_unlock, cooling_off_until), devices(id, user_id, platform, name, created_at, last_seen_at, revoked_at, risk_json), device_keys(id, device_id, spki, fingerprint, attestation_type, key_level, created_at, revoked_at, cooling_off_until, bio_fail_count), challenges(id, device_id, user_id, purpose, nonce, bound_hash, expires_at, consumed_at, session_id, step_up_action), sessions(id, user_id, device_id, family_id, refresh_hash, parent_id, created_at, last_unlock_at, last_seen_at, expires_at, revoked_at, used_at, amr), bootstrap_tokens(hash, user_id, scope, device_id, expires_at, used_at), step_up_tokens(hash, session_id, device_id, action, bound_hash, expires_at, consumed_at), idempotency(user_id, endpoint, key_hash, request_hash, status, created_at), audit_events(append-only, optional `prev_hash`), transactions, mock balances. Types: `uuid` ids, `timestamptz` (all comparisons use the injected app clock passed as a parameter, never `now()` in security-relevant predicates, so tests can advance time), `bytea` for hashes/keys/nonces, `smallint`/`int` counters, CHECK constraints for enums (purpose, scope, amr). Required unique/partial indexes: `sessions(refresh_hash)` unique; `device_keys(device_id) WHERE revoked_at IS NULL` unique (one active key per device); `challenges(device_id, purpose) WHERE consumed_at IS NULL` unique-live (one live challenge per device+purpose, new one supersedes by marking the old consumed in the same tx); `idempotency(user_id, endpoint, key_hash)` primary key; `bootstrap_tokens(hash)`, `step_up_tokens(hash)` unique. Access via `pgxpool` (max conns configurable), queries written in `internal/store/queries/*.sql` and generated with `sqlc` (pgx/v5 target); no string-built SQL. All multi-step state changes run in ONE transaction at `READ COMMITTED` using single-statement compare-and-set or `SELECT ... FOR UPDATE` row locks (never read-then-write across statements without a lock). Repository layer exposes: `ReserveAttempt(userID, now) -> (counters, ok)` as ONE conditional statement (decision: reserve-before-hash, see T13): `UPDATE users SET fail_count = fail_count + 1, locked_until = <schedule via CASE on fail_count+1>, hard_locked = (fail_count + 1 >= 10) WHERE id = $1 AND NOT hard_locked AND (locked_until IS NULL OR locked_until <= $2) RETURNING fail_count, locked_until, hard_locked` (zero rows => locked), plus `ClearFailures(userID)` on PIN success; `ConsumeChallenge(id, now) -> (row, ok)` as `UPDATE challenges SET consumed_at=$2 WHERE id=$1 AND consumed_at IS NULL AND expires_at > $2 RETURNING ...`; refresh rotation compare-and-set `UPDATE sessions SET used_at=$now WHERE refresh_hash=$1 AND used_at IS NULL AND revoked_at IS NULL RETURNING ...` (zero rows on an existing hash => reuse detected => revoke the family in the same tx and emit `REFRESH_REUSE`); idempotency insert via `INSERT ... ON CONFLICT DO NOTHING RETURNING`. Least privilege: migrations run as the owner role (`DATABASE_MIGRATE_URL`); the API connects with a role that has only SELECT/INSERT/UPDATE/DELETE on app tables, no DDL, and INSERT-only on `audit_events` (append-only, REVOKE UPDATE/DELETE). State is NEVER kept in process memory (rate-limit buckets excepted, see T8), so a restart cannot reset lockout, consumed challenges or refresh reuse state (SEC-066, resolves OQ3).
- Acceptance criteria: `make migrate` / `migrate-down` apply cleanly against the compose Postgres; restart test (close pool, stop and restart the API process or container, reopen) retains fail_count, locked_until, hard lock, consumed challenges, used refresh tokens; concurrent `ConsumeChallenge` (50 goroutines) yields exactly one ok; 50 concurrent `ReserveAttempt` calls from a fresh counter succeed exactly 5 times (the rest return locked) and the counter ends at 5 with a 30 s lock; concurrent refresh with the same token yields exactly one rotation and the loser triggers family revocation consistently; the API DB role cannot `UPDATE audit_events` or run DDL (test); no string-built SQL (grep test, sqlc only).
- Tests required: spec s7 test 1 (durability part), test 6 (concurrent consume), test 10 groundwork (every repo getter takes user id); SQL injection payload test. Integration setup (ADR-009): `internal/testutil/pg` starts a throwaway Postgres with `testcontainers-go`, runs migrations, hands each test a fresh schema (or template database clone); CI uses the same code (Docker available on the runner). If `TEST_DATABASE_URL` is set (e.g. compose DB from `make db-up`) the helper uses it instead and creates an isolated schema per test.
- Done when: `make db-up migrate && make -C apps/api test` green with `-race`.

## T6 PIN policy, hashing, Argon2 bounded concurrency
- Depends on: T3
- Implements: SEC-001, SEC-003, SEC-005, SEC-005b
- Details: `internal/pin`: `Validate(pin)` (regex then blocklist: all-same, ascending/descending runs of any length-6 window, repeating pairs/triples, `000000`-style, embedded top-N >= 200 list file via `go:embed`). `Hash(pin, userSalt, pepperVN)`: `HMAC-SHA256(pepper, pin)` -> Argon2id (PHC string with salt and pepper version, e.g. `$argon2id$v=19$m=..,t=..,p=..$salt$hash$pv=1`). `Verify` uses constant-time compare; returns `needsRehash` for pepper/params upgrade-on-login. A weighted semaphore (`ARGON2_CONCURRENCY`, default 4) bounds concurrent hashing; callers waiting longer than 2 s receive 429 `RATE_LIMITED`. Unknown user paths run a dummy hash to equalise timing.
- Acceptance criteria: 20 weak PINs rejected / 20 good accepted (table test); hash fixture has no raw PIN or pepper; verify with wrong pepper fails; pepper-version upgrade-on-login test; 200 concurrent verifies complete without exceeding the semaphore (instrumented counter) and excess returns 429.
- Tests required: spec s7 tests 12 and 13 (concurrency part).
- Done when: benchmarks documented for both parameter sets.

## T7 Crypto message encoders and verifiers
- Depends on: T1
- Implements: SEC-027, SEC-039, SEC-043, SEC-021, SEC-025 (nonce generation helper)
- Details: `internal/cryptomsg`: `ChallengeMessage(purpose,userID,deviceID,nonce,expiresAt,boundHash)`, `TxCanonical(fields)` + `NormalizeDecimal`, `ActionHash(action,target)` exactly per contract-notes s1-s3. `ParseSPKI(b64url) -> *ecdsa.PublicKey` (x509.ParsePKIXPublicKey, P-256 only, on-curve, <= 200 bytes, reject RSA/other curves/trailing bytes). `VerifyDER(pub, msg, sig)` strict DER parse (asn1 with no trailing data, r,s in [1,n-1]). `NewNonce()` = 32 bytes `crypto/rand`.
- Acceptance criteria: both vectors in `../../docs/features/biometric-pin-login/vectors/vectors.json` reproduce byte-for-byte (test loads the file, concatenates `segmentsHex`); `equivalentInputs` yield identical bytes; flipping any single field changes the output; a login-purpose signature fails when verified as `stepup`/`enroll`; trailing-byte and non-minimal DER rejected; P-384, RSA, off-curve points, 201-byte keys rejected; destination case change changes the hash.
- Tests required: spec s7 test 6 (purpose confusion), test 7 (non-P-256 key), test 9 groundwork; local sign/verify round trip with a generated key (do not store signature vectors).
- Done when: package has no dependency on HTTP or DB packages.

## T8 Rate limiting
- Depends on: T4
- Implements: SEC-057, SEC-009 (per-IP and per-device request limits), SEC-061 (RATE_LIMITED audit)
- Details: in-memory token buckets keyed by (route class, user | device | ip) per the SEC-057 table (see decisions.md D-12). Middleware reads client IP from the socket (trust `X-Forwarded-For` only when `TRUSTED_PROXY=true`). Sets `RateLimit-*` headers and on rejection 429 `RATE_LIMITED` with `Retry-After` and `retryAfter`. Limits come from config. IP checks run BEFORE any hashing or DB write. Demo-login global circuit breaker (e.g. > 100 req/min total => 429 for 60 s). Per-device pin failure block (10 failures in 15 min => device blocked from pin/verify for 1 h) lives in T13 but uses this package's primitives.
- Acceptance criteria: every row of the table has a test that exceeds the limit and sees 429 with `Retry-After`; successful requests carry `RateLimit-*` headers; rotating IPs against one user still hits the user lock (T13).
- Tests required: spec s7 test 13.
- Done when: limits documented in `apps/api/README.md`.

## T9 Idempotency
- Depends on: T5, T4
- Implements: SEC-060, SEC-044 (no approval flag; idempotent tx)
- Details: middleware/helper keyed (user, endpoint, SHA-256(key)) storing request-body hash + status + stored response ONLY for non-token responses (`POST /devices`, enroll, `POST /transactions`). Token-bearing endpoints (`POST /pin`, `PUT /pin`, `POST /pin/reset`) store only request hash + status; a repeated key with same body returns 409 `IDEMPOTENT_REPLAY` with no tokens. Same key + different body => 422 `IDEMPOTENCY_KEY_REUSED`. Missing/non-UUIDv4 key => 400. Retention 24 h purge. Key never logged.
- Acceptance criteria: double-submit of transaction creates one tx and returns the same 202; replayed `POST /pin` never returns tokens; concurrent identical requests execute once.
- Tests required: spec s7 test 9 (double-submit), SEC-060 negative cases.
- Done when: helpers used by T12, T13, T15, T16, T18.

## T10 Tokens, sessions, refresh families, unlock window
- Depends on: T5, T3
- Implements: SEC-031, SEC-032, SEC-033, SEC-035, SEC-036, SEC-037, SEC-014 (credential resolution), SEC-016 (bootstrap token store)
- Details: `internal/auth`: access JWT (EdDSA, aud `cryptoapp-api`, claims per contract-notes s4, TTL 300 s default, max 600). Refresh token = 32 random bytes base64url, only SHA-256 stored, single use, rotated with `family_id`; reuse of a used/revoked token revokes the whole family and emits `REFRESH_REUSE`. One live family per device: creating a session (unlock) revokes the previous family of that device. `POST /auth/refresh` per contract: requires unlock window (`now - last_unlock_at <= 900 s` AND idle `<= 300 s` since `last_seen_at`) else 401 `UNLOCK_REQUIRED` WITHOUT consuming/rotating the token or triggering reuse logic; absolute 30 d, idle 7 d. Auth middlewares: `RequireAccess` (JWT valid, session not revoked, scope `session`; bootstrap token => 403 `SCOPE_INSUFFICIENT`), `RequireBootstrap(scope)`, `ResolveDeviceCredential` (refresh token or device-bound bootstrap pin-verify; returns userID+deviceID without side effects). `POST /auth/logout` revokes session + family. Sessions record `amr` and `last_unlock_at` (set by pin/verify, biometric verify, step-up verify; never by refresh).
- Acceptance criteria: decode test of claims; expired access => 401; reuse of rotated refresh revokes both old and newest; `UNLOCK_REQUIRED` leaves the token usable by pin/verify afterwards; 16 min after unlock refresh => 401 UNLOCK_REQUIRED; idle > 5 min => 401; two unlocks leave exactly one live family; logout invalidates access and refresh; `amr` pin vs bio carried.
- Tests required: spec s7 test 8 (all), SEC-035 claim tests; clock injected via interface (no `time.Sleep`).
- Done when: no handler parses tokens itself.

## T11 demo-login and bootstrap tokens
- Depends on: T10, T8, T3
- Implements: `POST /auth/demo-login`; SEC-016, SEC-015 (scope selection), SEC-046 (reset entry), SEC-057 (demo-login limits), SEC-029-style uniform failure
- Details: constant-time compare of secret per username from config; unknown user and wrong secret both 401 `AUTH_FAILED` with equalised work. Scope selection per openapi description (pin-setup / pin-verify / pin-reset). Bootstrap token: opaque, hashed at rest, TTL 600 s, single purpose, usable only on routes that declare its scope. Route only registered when `DEMO_MODE=true` (otherwise 404, and startup refuses `ENV=prod`+demo, see T3).
- Acceptance criteria: no/incorrect secret => 401; bootstrap token on `/dashboard`, `/transactions`, `/devices` GET => 403 `SCOPE_INSUFFICIENT`; token past TTL => 401; 6th request/min/IP => 429.
- Tests required: spec s7 test 4 (first and third bullets), test 14.
- Done when: audit event `LOGIN_OK(method=demo)` emitted without secret.

## T12 Devices
- Depends on: T10, T9
- Implements: `POST /devices`, `GET /devices`, `DELETE /devices/{deviceId}`; SEC-048, SEC-049, SEC-024 (device revoke), SEC-038 (revoke other device needs PIN step-up), SEC-047 (new-device cooling-off), SEC-064 (store risk), SEC-061
- Details: server-generated 128-bit random id formatted as lowercase UUIDv4; bind the presenting bootstrap token to the new device in the same transaction; max 5 active devices => 409 `DEVICE_LIMIT` (checked under a row lock on the user), EXCEPT when the presenting bootstrap token has scope `pin-reset`: that registration is exempt from the cap so a hard-locked user with 5 devices can recover (reset revokes the others in T16); first device of a user does not start cooling-off, later ones do (`coolingOffUntil` on response). `GET` returns only the caller's devices with `current` and `biometricEnabled`. Every `{id}` lookup is scoped by token `sub`; foreign/unknown => 404 `NOT_FOUND`. DELETE: current device (id equals token `did`) needs only the access token; other device requires a valid `X-StepUp-Token` (action `revoke_device`, target = path id; verified/consumed via the T17 service interface `stepup.Consume`). Revocation revokes sessions, refresh families, device keys, live challenges of the device.
- Acceptance criteria: 6th device => 409; user B gets 404 for user A's device on DELETE and for biometric endpoints; revoked device's refresh and biometric verify => 401 AUTH_FAILED; revoking another device without step-up => 403 STEPUP_REQUIRED.
- Tests required: spec s7 test 10, test 7 first half (new device cannot enroll before PIN unlock: no access token exists), SEC-048 acceptance.
- Done when: `stepup.Consume` is used through an interface with a fake in tests; the real one arrives with T17 (revoke-other-device real-token tests are completed in T20).

## T13 PIN set, PIN verify, lockout
- Depends on: T6, T10, T11, T12, T8, T9
- Implements: `POST /pin`, `POST /auth/pin/verify`; SEC-005, SEC-008, SEC-009, SEC-010, SEC-011, SEC-012, SEC-014, SEC-015, SEC-029 (n/a), SEC-037, SEC-006
- Details: `internal/lockout` service `Attempt(userID, pin) -> (ok|invalid{remaining}|locked{retryAfter,type})` shared with T16 (PUT /pin) and T17 (step-up PIN). Order (RESERVE BEFORE HASHING, otherwise parallel guesses all pass the lock check): validate device credential (T10) => 401 AUTH_FAILED with NO counter change; then ONE conditional statement reserves the attempt: `UPDATE users SET fail_count = fail_count + 1, locked_until = <schedule(fail_count+1)>, hard_locked = (fail_count + 1 >= 10) WHERE id = $1 AND NOT hard_locked AND (locked_until IS NULL OR locked_until <= $now) RETURNING fail_count, locked_until, hard_locked`. Zero rows => the user is locked: 423 (hard or soft, correct PIN included) with NO hashing and no counter change. Rows returned => acquire the Argon2 semaphore and hash-verify. Wrong PIN: the reservation stands (also `failures_since_unlock + 1` in a follow-up statement); respond from the reserved count f: f 1-4 => 401 PIN_INVALID `attemptsRemaining = 5 - f`; f >= 5 => 423 PIN_LOCKED with the lock the reservation already set (30 s,1 m,5 m,15 m,1 h for f=5..9) and `attemptsUntilHardLock = 10 - f`; f=10 => hard lock (no retryAfter, `lockType=hard`). The 5th failure itself returns 423. Correct PIN: set `fail_count=0, locked_until=NULL` (the reserved attempt is not a failure and is not added to `failures_since_unlock`). Consequence: at most 5 hash evaluations can start from a fresh counter before the lock row blocks the rest (the alternative, `SELECT ... FOR UPDATE` held across the Argon2 call, is rejected because it holds a DB row lock for the hash duration). `lockout.Attempt` is the single implementation used by T13, T16 (old PIN) and T17 (step-up PIN). Success: reset counters, rotate pepper/params if `needsRehash`, create session (amr=pin, new family), return `recentFailures` (failures since last successful unlock, incl. biometric successes? count resets only on PIN success, but `recentFailures` is reported then cleared) and `biometricEnabled` for the device. Per-device counter (10 failures/15 min => block 1 h; returns 429 not touching user counter) and per-IP limits. Audit: `PIN_VERIFY_FAIL`, `PIN_LOCKED` (first lock), `PIN_HARD_LOCKED`, unlock-after-lock. `POST /pin`: requires device-bound bootstrap scope `pin-setup`; if user has a PIN => 409 `PIN_ALREADY_SET` and hash unchanged; weak => 422 `PIN_WEAK`; token single-use; idempotency per T9; success 201 SessionResponse; audit `PIN_SET`. Biometric success never resets the counter.
- Acceptance criteria: 50 parallel wrong guesses on a fresh counter => at most 5 evaluated, rest 423, counter durable across simulated restart; correct PIN during lock => 423, lock unchanged, after (fake) clock expiry correct PIN works and resets; no credential => 401 with counter unchanged; valid credential for device A with body deviceId B => 401; hard lock after 10 and PIN no longer accepted; `PIN_ALREADY_SET` leaves hash byte-identical; responses never include pin/hash/salt; `attemptsRemaining`/`retryAfter` absent on 401 AUTH_FAILED.
- Tests required: spec s7 tests 1, 2, 3, 4 (second bullet), 5 (PIN part), 11, 12, 13.
- Done when: lock schedule configurable and covered by a table test.

## T14 Challenge service and biometric login
- Depends on: T5, T7, T10, T8
- Implements: `POST /auth/biometric/challenge`, `POST /auth/biometric/verify`; SEC-025, SEC-026, SEC-027, SEC-028, SEC-029, SEC-030, SEC-011 (hard lock blocks), SEC-024 (invalidate challenges), SEC-037
- Details: `internal/challenge`: issue (32-byte nonce, TTL 60 s config, server clock, one live challenge per (device,purpose), new supersedes old), consume atomically on first attempt. `challenge` endpoint: for unknown/revoked/not-enrolled/hard-locked device returns decoy (random challengeId/userId/nonce, expiresAt = now + TTL, nothing stored) with identical JSON shape and `Cache-Control` as real. `verify`: look up challenge by id + deviceId; consume; rebuild message with T7; verify signature with active key; check device, user not hard-locked (soft lock allowed per D-05). Every failure branch returns the single 401 AUTH_FAILED body, same headers, with minimum-delay equalisation (run a dummy ECDSA verify on missing-key paths). Per-device consecutive failure counter: 5 => revoke the key + audit `BIO_KEY_INVALIDATED`; success resets; does not touch the PIN counter. Success creates session (amr=bio, new family, `last_unlock_at=now`).
- Acceptance criteria: replay of a captured verify body => 401; two concurrent verifies of one nonce => exactly one 200; expired nonce 401; login signature presented to step-up/enroll verification => fails; unknown device, revoked key, bad signature, expired, replayed, no challenge: byte-identical bodies and header sets (ignoring `X-Request-Id`, `Date`); 5 bad signatures => biometrics suspended until next PIN unlock (key NOT revoked, amended SEC-030) so the next valid signature => 401 until a PIN unlock, then works again; challenge/verify without or with a mismatching device credential => 401 and no failure counting; hard-locked user => 401; soft-locked user => 200.
- Tests required: spec s7 tests 5 (biometric part), 6 (all), 13.
- Done when: golden DER fixtures for malformed signatures exist.

## T15 Biometric enrollment (two-step) and disable
- Depends on: T14, T12, T9, T17
- Implements: `POST /devices/{id}/biometric/enroll/challenge`, `POST /devices/{id}/biometric/enroll`, `DELETE /devices/{id}/biometric`; SEC-020, SEC-021, SEC-022, SEC-023, SEC-024, SEC-038, SEC-047, SEC-056/064 (store)
- Details: enroll/challenge: path id must equal token `did` and belong to `sub` (404 otherwise); requires `X-StepUp-Token` for action `enable_biometric`, target = path id, PIN proof (T17 `stepup.Consume`, which consumes it); 403 `STEPUP_REQUIRED` (absent) or `STEPUP_INVALID` (used/expired/other session/other target, including a replayed token: documented conflict with SEC-020's "401", see decisions.md D-14). Issues enroll challenge (purpose enroll, empty boundHash, bound to session). enroll: consume challenge, `ParseSPKI` (422 `INVALID_PUBLIC_KEY`), verify PoP signature over the enroll message with the SUBMITTED key (401 AUTH_FAILED on failure), store attestation type `none` and self-reported level as untrusted (production profile rejects `none` for biometric-only allowance via `required=pin`), revoke previous key atomically, start key cooling-off, audit `BIO_ENROLLED` with fingerprint only. Rate limit 5/h/user. DELETE biometric: allowed if `now - session.last_unlock_at <= 300 s` else 403 `STEPUP_REQUIRED`; revokes key + live challenges; audit `BIO_DISABLED`; idempotent 204.
- Acceptance criteria: enroll/challenge without step-up => 403; replayed step-up token => 403 STEPUP_INVALID; wrong-key PoP => 401; P-384/RSA/off-curve/201-byte keys => 422; second enroll replaces the first (old signatures then fail); biometric-only step-up refused while key in cooling-off; disable after 6 min without re-unlock => 403; after disable, biometric verify => 401.
- Tests required: spec s7 test 7 (all), SEC-023 server half (revoke after PIN unlock), SEC-024 acceptance.
- Done when: attestation fields round-trip in DB; policy hook documented.

## T16 PIN change and PIN reset
- Depends on: T13, T12, T9
- Implements: `PUT /pin`, `POST /pin/reset`; SEC-045, SEC-046, SEC-047, SEC-024, SEC-036, SEC-011 (recovery path), SEC-001
- Details: PUT: access token, old PIN through `lockout.Attempt` (counted toward the same lockout, same 401/423 shapes), new PIN passes SEC-001 and differs from old => 422 `PIN_UNCHANGED`; revoke ALL other sessions and biometric keys on other devices; re-issue current session (new family/tokens, amr pin); audit `PIN_CHANGED`; limit 5/h/user; token-bearing so replay => 409. Reset: device-bound bootstrap scope `pin-reset`; set PIN, clear failure/lock/hard-lock, revoke ALL sessions, ALL device keys and ALL other device records (the registering device stays), start cooling-off (user level + new device), audit `PIN_RESET` + `COOLING_OFF_STARTED`, issue session (amr=pin). Reset without bootstrap token => 401.
- Acceptance criteria: after change, another device's refresh => 401 and its biometric verify => 401 while the current device's key still works; after reset every old device must re-register and re-enroll; hard-locked user can recover via reset and unlocks with the new PIN; reset without bootstrap => 401; reset sets cooling-off.
- Tests required: spec s7 tests 5 (recovery), 8 (logout/sessions after change); SEC-045/046 acceptance.
- Done when: cooling-off start covered by a clock-advance test.

## T17 Step-up service
- Depends on: T13, T14, T7, T10
- Implements: `POST /stepup/challenge`, `POST /stepup/verify`; SEC-038, SEC-040 (token), SEC-041, SEC-042, SEC-043, SEC-047, SEC-026
- Details: challenge: validate body (oneOf), for `transaction` canonicalise via T7 and compute `txHash`; build server `summary`; compute `required`: `pin` when action is enable_biometric/revoke_device, when amount-in-USD (fixed mock price table) > `BIO_ONLY_MAX`, when key is in cooling-off, when no active key, or (prod profile) key attestation `none`; else `either` (`bio` if no PIN allowed is never used). Cooling-off + amount > `COOLING_OFF_MAX` => 403 `COOLING_OFF`. One live step-up challenge per session. verify: consume challenge first (atomic); proof kind must match `required` else 403 `STEPUP_REQUIRED` (+`required`); signature path: rebuild message (purpose `stepup`, boundHash) and verify with active key, same non-oracular 401; PIN path via `lockout.Attempt` (same counter/lock as pin/verify; PIN_INVALID/PIN_LOCKED shapes). On success mint step-up token (32 random bytes, hash stored, TTL 60 s, bound to session, device, action, boundHash) and set `last_unlock_at`. Expose `stepup.Consume(ctx, token, session, device, action, boundHash)` consumed atomically inside the caller's DB transaction. Limit 10/min/user.
- Acceptance criteria: 5 wrong step-up PINs => user locked (same lock as pin/verify); biometric proof above threshold => 403 STEPUP_REQUIRED required=pin; unknown/expired challenge => 401; token cannot be used by another session/device/action; enable_biometric with biometric proof => 403.
- Tests required: spec s7 tests 9 (threshold, cooling-off), 6 (stepup purpose confusion), 13.
- Done when: mock price table is config, not hard-coded in handlers.

## T18 Transactions, dashboard, logout wiring
- Depends on: T17, T9, T10
- Implements: `POST /transactions`, `GET /dashboard`, `POST /auth/logout`; SEC-039, SEC-040, SEC-044, SEC-047, SEC-063
- Details: `POST /transactions`: access token, `Idempotency-Key`, `X-StepUp-Token`, body = `TransactionFields`. Recompute `txHash` from THIS body; in ONE DB transaction: validate expiry window, balance (mock balances, 422 `INSUFFICIENT_FUNDS`), cooling-off cap (403 `COOLING_OFF`), `stepup.Consume(... boundHash = txHash)` then insert tx and debit balance. Any mismatch/reuse/other session => 403 `STEPUP_INVALID` (token consumed if it was valid and the hash mismatched). Missing header => 403 `STEPUP_REQUIRED`. No approval/limit flags in the schema. `GET /dashboard` returns per-user seeded fixtures, access token only (bootstrap => 403). Per-user `txNonce` uniqueness (replay of same txNonce => 409 `IDEMPOTENT_REPLAY`, no new tx).
- Acceptance criteria: change one digit of amount, or destination/asset/network/fee after challenge => 403; token reuse => 403; token from another session => 403; concurrent double-submit creates one tx; amount `1.50` vs `1.5` treated identically; balance debit exact decimal arithmetic (no float).
- Tests required: spec s7 test 9 (all), test 4 (third bullet), test 10.
- Done when: transaction + token consumption verified atomic by a fault-injection test (failure after consume rolls back consume).

## T19 Notices, audit completeness, risk signals
- Depends on: T13, T14, T15, T16, T17, T18
- Implements: SEC-012, SEC-061, SEC-064, SEC-056 (server side), SEC-062
- Details: Verify that every SEC-061 event type is emitted exactly where specified, with allowlisted fields and none of: PIN, tokens, nonces, signatures, public key bytes, hashes (fingerprint only). `recentFailures` surfaced on the next successful unlock (T13) and reset. Store optional `risk` objects (devices, pin/verify, biometric verify) in a column / audit metadata; no policy depends on it. Optional hash-chained `prev_hash` for audit rows behind a config flag. 30-day retention job (demo).
- Acceptance criteria: event-coverage table test (event type -> triggering test); canary secrets absent from all captured audit output; chain verification passes when enabled; after lock then success the next response has `recentFailures > 0` and an audit unlock-after-lock event.
- Tests required: spec s7 test 11; SEC-012 acceptance.
- Done when: coverage table checked into `apps/api/docs/audit-events.md`.

## T20 Security negative test suite sweep
- Depends on: T19
- Implements: verification of SEC-005, 008-016, 020, 024-030, 032-033, 038-042, 045-049, 057, 059-063, 065-066 (cross-cutting)
- Details: `apps/api/internal/e2e` black-box tests using `httptest` + real Postgres (testcontainers helper from T5) + injected clock. Create a matrix mapping each spec s7 backend test (1-14) to a named test function; fill any gap left by earlier tasks. Include the error-fuzz test (random malformed JSON/headers => only contract error bodies, no internal strings), a restart simulation (build a fresh server instance on the same Postgres and assert lockout, consumed challenges and refresh-reuse state persist), and `govulncheck`.
- Acceptance criteria: matrix file `apps/api/docs/sec7-matrix.md` lists tests 1-14 with passing test names; `go test -race ./...` green; no flaky tests across 20 runs (`-count=20` on e2e).
- Tests required: spec s7 tests 1-14 (all).
- Done when: matrix reviewed against security-spec s7.

## T21 Contract tests (final integration)
- Depends on: T20
- Implements: contract conformance; SEC-059, SEC-005, SEC-062
- Details: `make contract-test`: (a) start the server in-process; drive every operation in openapi.yaml through happy and failure paths and validate EVERY response (status, headers declared, body) with `kin-openapi` `openapi3filter.ValidateResponse` against the canonical spec; (b) assert every status code listed in the spec for each operation is reachable by at least one test OR is listed in an allowlist with a reason; (c) schema walk asserting no response schema contains properties named `pin`, `pinHash`, `hash`, `salt`, `pepper`, `privateKey` (excluding request-only `Pin` schema usage); (d) assert no operation takes tokens in path/query; (e) run vectors tests from T7 against `vectors/vectors.json`.
- Acceptance criteria: failing a response shape (e.g. renaming a field in a handler) makes `make contract-test` fail; all error codes in `ErrorCode` enum are exercised or allowlisted.
- Tests required: as above.
- Done when: CI job `contract-test` green.

## Definition of Done (backend)
- [ ] `make -C apps/api test lint contract-test` and `govulncheck` pass; `-race` clean.
- [ ] No secrets, PINs, tokens, nonces, signatures, keys or hashes in logs (canary tests pass); `forbidigo` clean.
- [ ] Fail-closed startup verified; `.env.example` has placeholders only; pepper never in repo/DB.
- [ ] Generated server matches `openapi.yaml` (no hand-edited generated files); canonical contract unmodified.
- [ ] Spec s7 backend tests 1-14 mapped in `apps/api/docs/sec7-matrix.md` and passing.
- [ ] SEC coverage table below is complete (no SEC id left without a task or recorded decision).

## SEC coverage (backend side; full table in decisions.md)
| SEC | Task | SEC | Task | SEC | Task |
|---|---|---|---|---|---|
| 001 | T6,T16 | 026 | T5,T14 | 048 | T12 |
| 003 | T3,T6 | 027 | T7,T14 | 049 | T12 |
| 004 | T3 | 028 | T14 | 057 | T8,T11 |
| 005 | T6,T13 | 029 | T14 | 059 | T4,T21 |
| 005b | T6,T8 | 030 | T14 | 060 | T9 |
| 006 | T4,T13 | 031 | T10 | 061 | T4,T19 |
| 008 | T5,T13 | 032 | T5,T10 | 062 | T4 |
| 009 | T8,T13 | 033 | T10 | 063 | T2,T4,T5 |
| 010 | T13 | 035 | T10 | 064 | T12,T19 |
| 011 | T13,T14,T16 | 036 | T10,T16 | 065 | T3 |
| 012 | T13,T19 | 037 | T10,T13,T14 | 066 | T5,T20 |
| 014 | T10,T13 | 038 | T12,T15,T17 | 020 | T15 |
| 015 | T11,T13 | 039 | T7,T18 | 021 | T7,T15 |
| 016 | T3,T11 | 040 | T17,T18 | 022 | T15 |
| 024 | T12,T14,T15,T16 | 041 | T17 | 023 | T15 |
| 025 | T7,T14 | 042 | T17 | 043 | T7,T17 |
| 044 | T9,T18 | 045 | T16 | 046 | T11,T16 |
| 047 | T12,T15,T16,T17,T18 | 056 | T19 (server store) | 067/068 | FE only |
