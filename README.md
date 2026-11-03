# Crypto app: PIN and biometric login

A demo crypto wallet that shows a secure PIN and biometric unlock flow. The Expo (React Native) client and the Go backend live in one monorepo and are coupled only by an OpenAPI contract.

**The flow:** a cold start is always locked.
- If biometrics are **not enabled**, the user unlocks with the **PIN**.
- If biometrics are **enabled**, the OS biometric prompt unlocks a hardware-backed key. That key signs a server challenge, and any failure falls back to the PIN.
- Either success opens the **home dashboard**, which shows mock crypto balances.

> This is a demo. It is meant for localhost or LAN only and must never be exposed to the internet. Balances and prices are mock data and the sign-in is a stub (`demo-login`).

## Security principles

- The PIN is verified **server-side** (Argon2id with a pepper). Lockout is atomic and escalating, and a hard lock needs a PIN reset.
- Biometrics unlock a **hardware-backed ES256 key** (Secure Enclave on iOS, StrongBox or TEE on Android). The key signs a single-use server nonce. The app never relies on a bare "biometric succeeded" boolean.
- Sending funds requires **step-up** auth. The server recomputes the hash of the transaction itself and binds the approval to it.
- Refresh tokens rotate, and reuse revokes the whole token family. Refresh only works inside a server-enforced unlock window.
- Auth errors are uniform, so they don't reveal why a login failed.
- PINs, tokens and keys are never logged.
- Biometric-only is rejected on purpose, so the PIN fallback is always available.

The full threat model and the 67 numbered requirements (SEC-ids) are in the [security spec](docs/features/biometric-pin-login/security-spec.md).

## Repo layout

| Path | What |
|---|---|
| `apps/mobile` | Expo client (Expo Router, development build, local native module `biometric-key` in Swift and Kotlin) |
| `apps/api` | Go backend (Chi on `net/http`, oapi-codegen, pgx, sqlc, golang-migrate, slog) |
| `docs/features/biometric-pin-login/` | The spec-first artifacts: contract, security spec, tasks, decisions and ERD |
| `docker-compose.yml` | Postgres 16 for local development |
| `Makefile` | Root targets that forward to `apps/api` and `apps/mobile` |
| `.claude/agents/` | The four project agents used by the `/secure-feature` workflow |

The contract at `docs/features/biometric-pin-login/openapi.yaml` is the only coupling between client and server. The client types are generated from it and the Go server is validated against it.

## Prerequisites

- Node 24 and pnpm (see `.nvmrc` and `packageManager`)
- Go (version in `apps/api/go.mod`)
- Docker, for Postgres
- For the mobile app: Xcode (iOS) and/or the Android SDK. Biometrics need a **development build on a physical device**. They do not work in Expo Go.

## Quick start

```bash
pnpm install
cp .env.example .env        # replace every CHANGE_ME, never commit real values

make db-up                  # Postgres in Docker
make migrate
make api-run                # Go API

pnpm --filter mobile ios    # or: pnpm --filter mobile android
```

To work on the client without the backend, run the contract mock instead of the API:

```bash
pnpm mock                   # mock API on :8080
```

Point the app at it with `EXPO_PUBLIC_API_URL` in `apps/mobile/.env`. See [apps/mobile/README.md](apps/mobile/README.md) for the per-platform URLs and mock scenarios.

## Docker

Docker runs **only Postgres 16**. The Go API and the Expo app run on your machine, not in containers.

```bash
make db-up        # start Postgres and wait until it is healthy
make migrate      # create the schema and the least-privilege runtime role (cryptoapp_api)
make db-down      # stop it, data is kept in the named volume
make db-reset     # stop it and delete the volume (wipes all data)
```

- The database is bound to loopback only, and its credentials come from `.env`.
- The API connects as the restricted runtime role. Migrations run as the owner role, which the server never reads.
- Docker is also needed to run the backend integration tests, which start Postgres through testcontainers. Without Docker those tests are skipped.
- `make api-run` loads `.env` and seeds the demo users (`alice` and `bob`) from `DEMO_SECRETS`.

## Common commands

| Command | What |
|---|---|
| `make db-up` / `make db-down` / `make db-reset` | Start, stop or wipe the local Postgres |
| `make migrate` / `make migrate-down` | Apply or roll back migrations |
| `make api-gen` / `api-build` / `api-test` / `api-lint` | Go codegen, build, tests and lint |
| `make api-contract-test` | Check the API against the OpenAPI contract |
| `pnpm typecheck` / `lint` / `test` | Mobile quality gates |
| `pnpm contract-test` | Mobile contract and policy tests |
| `pnpm gen:api` | Regenerate the client types from the contract |

## How this was built

The feature was produced with a spec-first workflow, run with `/secure-feature`:

1. **tech-lead** drafts the scope and candidate endpoints.
2. **security-specialist** threat-models it and writes the security spec.
3. **tech-lead** writes the OpenAPI contract and the task files.
4. **expo-engineer** and **backend-engineer** build their sides in parallel.
5. **security-specialist** reviews the code against the spec.

The artifacts for this feature are in `docs/features/biometric-pin-login/`:
`draft.md`, `security-spec.md`, `openapi.yaml`, `contract-notes.md`, `decisions.md`, `diagrams/erd/` (schema), `diagrams/sequences/` (9 flows), `api-contracts/` (readable API docs), `tasks-backend.md`, `tasks-expo.md` and `vectors/vectors.json`. The security review and re-review are in `security-review.md`.

## Status and known gaps

- Nothing here has been verified on a physical device: Secure Enclave or StrongBox signing, enrollment-change invalidation, and screen-capture blocking all still need a manual run.
- Device attestation is stored but not verified. Certificate pinning and device-bound tokens are not in the demo.
- The 6-digit PIN has only 10^6 combinations, so its strength rests on the server-side lockout.
