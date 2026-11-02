# apps/api - PIN and biometric login backend (Go)

Single Go module `github.com/cryptoapp/api`. Contract: `../../docs/features/biometric-pin-login/openapi.yaml` (the only coupling with the Expo app).
Security spec: `../../docs/features/biometric-pin-login/security-spec.md`. Schema: `../../docs/features/biometric-pin-login/erd.md`.

## Run (demo, localhost/LAN only: never expose this to the internet)

```sh
cp .env.example .env           # repo root; replace every CHANGE_ME (git-ignored)
make db-up                     # Postgres 16 in Docker, healthy before it returns
make migrate                   # owner role (DATABASE_MIGRATE_URL); creates the schema + grants for the runtime role
make api-run                   # sources .env, seeds the DEMO_SECRETS users (alice, bob), listens on LISTEN_ADDR
```

`make db-down` keeps the volume, `make db-reset` deletes it. The runtime role must be named `cryptoapp_api` (created by
`apps/api/deploy/postgres-init/01-api-role.sh` on first volume init, privileges granted by migration `000002_grants`).

Targets (`make -C apps/api ...`): `gen` (oapi-codegen + sqlc, idempotent), `build`, `run`, `test` (vet + `-race`), `lint` (golangci-lint v2.15, gosec,
forbidigo), `contract-test`, `vulncheck`, `migrate`, `migrate-down`. Docker is required for the integration tests (testcontainers starts a
throwaway `postgres:16-alpine`; every test gets a database cloned from a migrated template and connects as the least-privilege role). Set
`TEST_DATABASE_URL` (owner/superuser DSN, e.g. the compose DB) to reuse an existing server; tests then skip the container. Without Docker the
database-backed tests are SKIPPED (not failed) with the message "postgres unavailable".

## Environment variables (see `.env.example`; the server refuses to start when a secret is missing, short or a placeholder)

`ENV` (dev|prod), `DEMO_MODE` (refused when `ENV=prod`), `LISTEN_ADDR`, `DATABASE_URL` (runtime role; TLS required when prod),
`DATABASE_MIGRATE_URL` (only read by `cmd/migrate`), `DB_MAX_CONNS`, `PEPPER`|`PEPPER_FILE` (>= 32 bytes), `PEPPER_VERSION`, `PEPPER_OLD`,
`PEPPER_OLD_VERSION`, `ACCESS_SIGNING_KEY` (base64 Ed25519 seed), `DEMO_SECRETS` (`user=secret,...`), `ARGON2_*`, `LOCK_SCHEDULE`, `ACCESS_TTL`,
`UNLOCK_WINDOW`, `IDLE_WINDOW`, `CHALLENGE_TTL`, `STEPUP_TOKEN_TTL`, `BOOTSTRAP_TTL`, `BIO_ONLY_MAX`, `COOLING_OFF_DURATION`, `COOLING_OFF_MAX`,
`MOCK_PRICES`, `TRUSTED_PROXY`, `AUDIT_HASH_CHAIN`.

## Layout

`cmd/api` (server), `cmd/migrate` (up/down/purge-audit), `migrations/` (golang-migrate, embedded), `internal/`: `config` (fail-closed, redacted),
`platform/{log,httpx}` (allow-list redacting slog, error envelope, middleware), `apigen` (generated, committed), `store` (+ `queries/*.sql` -> sqlc),
`cryptomsg` (signed byte layouts, strict DER/SPKI), `pin` (policy, Argon2id + pepper, bounded pool), `lockout` (reserve-before-hash), `auth`
(JWT, sessions, refresh families), `ratelimit`, `idem`, `audit`, `stepup`, `handlers` (StrictServerInterface; challenge, biometric, device, tx
logic lives here), `server` (router, validation, auth middleware), `testutil/pg`, `e2e` (black box + contract tests).
`docs/audit-events.md`, `docs/sec7-matrix.md`.

## OpenAPI 3.1 label (ADR-004)

The contract says `openapi: 3.1.0` but uses the 3.0 subset. Verified with the pinned tools: oapi-codegen v2.8.2 generates from it natively and
kin-openapi v0.152.0 loads it and `doc.Validate()` passes, so no temp-copy workaround is needed and none is implemented. The canonical file is never
modified. Notes: kin-openapi ignores `format: uuid` unless registered (done in `internal/server`), the embedded spec is used for validation.

## Argon2id benchmarks (Apple M-series, no -race, `go test -bench . ./internal/pin`)

demo floor m=19 MiB t=2 p=1: ~21 ms per hash; production m=64 MiB t=3 p=1: ~118 ms. Concurrency is bounded by `ARGON2_CONCURRENCY` (default 4,
2 s wait budget, then 429). Tune upward on the target hardware until a hash takes >= ~100 ms.

## Rate limits (SEC-057, defaults in `config.DefaultLimits`, in-memory fixed windows, reset on restart by design)

demo-login 5/min and 20/h per IP plus a global breaker (100/min opens it for 60 s); pin/verify 10/min/device and 30/min/IP; biometric
challenge and verify 10/min/device and 30/min/IP; refresh 6/min/device; step-up challenge+verify 10/min/user; enroll 5/h/user (per step);
PUT /pin and /pin/reset 5/h/user; transactions 20/min/user; global 600/min/IP. Per-device PIN failures: 10 in 15 min blocks pin/verify for 1 h
(429, user counter untouched). `X-Forwarded-For` is honoured only with `TRUSTED_PROXY=true`. RateLimit-* headers are sent on pin/verify,
demo-login and the user-scoped limits, and on every 429; the biometric endpoints send them only on 429 so that failures stay byte-identical.

## Policy hooks

Attestation is stored, not verified (SEC-022 demo): the stored `attestation_type` is therefore always `none` and the self-reported level is kept as
untrusted; the claimed type is only written to the audit event. `stepup.RequiredForTx` already requires the PIN for `none` keys when `ENV=prod`.
`risk` objects are stored on the device (`devices.risk`) and never used for decisions (SEC-064).
