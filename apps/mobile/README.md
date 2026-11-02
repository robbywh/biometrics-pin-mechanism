# Crypto app mobile client (Expo, dev build)

Feature `biometric-pin-login`. Contract: `../../docs/features/biometric-pin-login/openapi.yaml` (the only coupling with `apps/api`).

## Requirements
- Node 24 (`.nvmrc`), pnpm 12 (`packageManager`). `.npmrc` sets `node-linker=hoisted` because Metro/autolinking break on pnpm's symlinked layout.
- **Development build, NOT Expo Go.** The local native module `modules/biometric-key` (Swift Secure Enclave / Kotlin Keystore) and `expo-secure-store` key options do not run in Expo Go. Xcode (iOS) / Android SDK (API 30+) are needed; biometric behaviour needs a physical device.

## Commands (stable names, forwarded by the root Makefile)
| Script | What |
|---|---|
| `pnpm --filter mobile gen:api` | regenerate `src/api/generated/schema.d.ts` from the canonical spec (idempotent, committed; CI runs `git diff --exit-code`) |
| `pnpm --filter mobile mock` | contract mock API on `:8080` (`MOCK_PORT` to change). Scenarios: `POST /__mock/scenario {"name":"pin-locked-soft"}`; list with `GET /__mock/scenario` |
| `pnpm --filter mobile typecheck / lint / test / contract-test` | quality gates (`test` = Jest `node` + `ui` projects) |
| `pnpm --filter mobile android / ios` | `expo run:*` dev build (runs prebuild) |
| `node scripts/check-manifest.mjs --variant production` | SEC-067/006 native config assertions after prebuild (`APP_VARIANT=production npx expo prebuild --no-install --clean` first) |
| `pnpm --filter mobile export:release` then `check:bundle` | release bundle scan (SEC-055/016/006) |

Contract v1.1: `biometric/challenge` and `biometric/verify` send the refresh token as `Authorization`; a 401 there never wipes credentials or the key; after 5 bad signatures the server suspends biometrics until the next PIN unlock and the app simply uses the PIN. The mock models this.

Mock server choice: a thin `node:http` adapter over the same contract mock core (`mocks/core.ts`) that Jest drives through MSW's `getResponse` (`mocks/msw.ts`). `@mswjs/http-middleware` and `msw/node` interceptors were not used (msw 3 interceptors are ESM + wasm and do not load under Jest CJS). The mock validates every request body and (in tests) every response against the spec with ajv.

## Build variant (`APP_VARIANT`)
`APP_VARIANT` defaults to **production** (fail closed: ATS local-network exception off, cleartext rejected). Only an explicit `APP_VARIANT=development` enables the iOS local-networking exception; the `start`, `android` and `ios` scripts set it for you, and `eas.json` sets it in the `development` profile. Run `node scripts/check-manifest.mjs --variant production` after a plain `expo prebuild` to confirm.

## Running against the mock
1. `cp .env.example .env` and set `EXPO_PUBLIC_API_URL` (`http://10.0.2.2:8080` Android emulator, `http://localhost:8080` iOS simulator, `http://<LAN-ip>:8080` device). `EXPO_PUBLIC_DEMO_SECRET` is optional, dev only, and is never bundled in release builds. `.env` is git-ignored.
2. `pnpm --filter mobile mock` in one terminal; `pnpm --filter mobile ios|android` in another. Any non-empty secret works on the mock except `wrong-secret`.
3. Release/preview builds accept only `https://` API URLs and fail at startup otherwise. Cleartext is enabled in the Android debug manifest only; the iOS local-network ATS exception ships only when `APP_VARIANT=development`.

## Flow
Cold start is always locked. No biometric enabled -> PIN keypad. Biometric enabled -> OS prompt unlocks a hardware key that signs the server challenge; any failure lands on the PIN keypad. Success of either (a server session response) opens the dashboard. The PIN fallback is always available.

## PIN reset / hard-lock recovery (T17)
From the lock screen ("Forgot PIN?" or the "Reset PIN" CTA after a hard lock): demo sign-in with intent `reset`, a NEW device is registered, a new PIN is set. The server revokes every old device and biometric key; the client deletes its old key and hint, adopts the new deviceId and shows a cooling-off banner. Re-enable biometrics from Settings.

## Risk signals (T20)
`expo-device` root/emulator/debugger signals are attached to `POST /devices`, `pin/verify` and `biometric/verify` as the optional advisory `risk` field. They are never used as a gate and no UI branches on them. Lint forbids importing `risk/signals` outside `src/api`.

## Layout
`src/api` generated types + typed endpoints + error mapping; `src/crypto` signing-message builders (pure TS, golden vectors); `src/storage` the only module touching SecureStore/AsyncStorage; `src/auth` session, unlock, auto-lock, state machine; `src/flows` onboarding/biometrics/account/send controllers; `src/ui` PinPad etc.; `src/app` Expo Router screens; `modules/biometric-key` native module; `mocks` contract mock.

See `docs/sec7-matrix.md`, `docs/biometric-key-lifecycle.md`, `docs/security-checklist.md`, `modules/biometric-key/TESTING.md`.
