# API contracts: biometric-pin-login (v1.1.0)

> **Authority.** [`../openapi.yaml`](../openapi.yaml) is the only contract and wins every conflict. These pages are a generated, readable view of it. Do not edit them to change behaviour: change `openapi.yaml` (tech lead only), then regenerate. Byte layouts for signing and hashing are in [`../contract-notes.md`](../contract-notes.md), and test vectors are in [`../vectors/vectors.json`](../vectors/vectors.json).

All example values are placeholders such as `"<refresh-token>"` or `"<6-digit-pin>"`. None of them are real credentials.

## Contents

- [Basics](#basics)
- [Credentials and tokens](#credentials-and-tokens)
- [Idempotency-Key](#idempotency-key)
- [Errors](#errors) and [error codes](#error-codes)
- [Uniform 401](#uniform-401)
- [Rate limits](#rate-limits)
- [Endpoint index](#endpoint-index)
- [Discrepancies](#discrepancies)

Detail pages: [bootstrap](./bootstrap.md) · [devices](./devices.md) · [pin](./pin.md) · [session](./session.md) · [biometric](./biometric.md) · [step-up](./step-up.md) · [transactions](./transactions.md) · [dashboard](./dashboard.md) · [ops](./ops.md) · [shared schemas](./schemas.md)

Diagrams: [sequences](../diagrams/sequences/README.md) · [ERD](../diagrams/erd/README.md) · Security: [security-spec.md](../security-spec.md)

## Basics

- **Base path:** `/v1` (relative server URL). The only exception is `GET /healthz`, which is served at the root.
- **Format:** JSON only. Request bodies are limited to 16 KiB, and unknown fields are rejected.
- **Transport:** dev builds may use cleartext. Release builds use HTTPS only (SEC-006).
- **Secrets never go in URLs or query strings.** Tokens are sent only in headers. The PIN is sent only in JSON bodies.
- **Binary values** (`nonce`, `signature`, `publicKey`, `txHash`, `boundHash`) are base64url without padding. Signatures are ASN.1 DER ECDSA P-256.
- **Timestamps** are integer unix seconds.
- **Response headers:**
  - Every response has `X-Request-Id`. A client may send its own value: max 64 characters from `[A-Za-z0-9-]`.
  - Auth and session responses have `Cache-Control: no-store`.

## Credentials and tokens

| Credential | Header | Scope | Lifetime |
|---|---|---|---|
| `bootstrapToken` | `Authorization: Bearer` | `pin-setup` / `pin-verify` / `pin-reset` | ≤ 600 s |
| `accessToken` | `Authorization: Bearer` | `session` | 300 s default, ≤ 600 s |
| `deviceCredential` (refresh token) | `Authorization: Bearer` | device | 30 d absolute, 7 d idle |
| step-up token | `X-StepUp-Token` | one action | 60 s, single use |

### Bootstrap token

- Format: opaque, 256-bit, base64url.
- Issued by `POST /auth/demo-login`. The server picks the scope.
- It is bound to one `deviceId` when it is presented to `POST /devices`.
- It is single use for `POST /pin`.
- It has no access to `/dashboard`, `/transactions` or any access-token endpoint. Those return 403 `SCOPE_INSUFFICIENT`.

### Access token

- Format: JWT (EdDSA) with the claims `sub, sid, did, amr, auth_time, scope=session, aud, exp`.
- The client keeps it in memory only.
- A bootstrap token sent where an access token is required returns 403 `SCOPE_INSUFFICIENT`.

### Device credential (refresh token)

- Format: opaque, 256-bit, base64url.
- It is the device's current refresh token. For `pin/verify` only, a device-bound bootstrap token with scope `pin-verify` is also accepted.
- It is used on `pin/verify`, `biometric/challenge`, `biometric/verify` and `refresh`.
- Only `/auth/refresh` consumes and rotates it. The other endpoints just look it up.
- The client stores it in SecureStore.

### Step-up token

- Format: opaque, 256-bit, base64url.
- Issued by `POST /stepup/verify`.
- It is bound to one session, device, action and `boundHash`.
- The schema marks it optional, so the server decides the status:
  - Missing header: 403 `STEPUP_REQUIRED`.
  - Unknown, used, expired, mismatched or malformed token: 403 `STEPUP_INVALID`. This is never a 400.

### Challenges

- The nonce is 32 random bytes, encoded as base64url.
- A challenge lives 60 s by the server clock and can be used once.
- It is consumed on the **first** verify attempt, whether that attempt succeeds or fails.
- The challenge response includes every field the client signs. The client never invents a signed field.

## Idempotency-Key

The `Idempotency-Key` header is a UUIDv4. It is required on:

- `POST /devices`
- `POST /pin`
- `PUT /pin`
- `POST /pin/reset`
- `POST /devices/{deviceId}/biometric/enroll`
- `POST /transactions`

The server keeps each key for 24 h per (user, endpoint) and never logs it.

| Case | Result |
|---|---|
| Same key, same body, response has no tokens | stored response replayed (see each endpoint) |
| Same key, same body, response has tokens | 409 `IDEMPOTENT_REPLAY`, no tokens in body |
| Same key, different body | 422 `IDEMPOTENCY_KEY_REUSED` |

## Errors

Every error uses one envelope. Branch on `code`. `message` is generic text and must not be used for branching. Optional fields: see [ErrorResponse](./schemas.md#errorresponse).

```json
{ "error": { "code": "AUTH_FAILED", "message": "Authentication failed." } }
```

Every operation declares a shared `default` response. Any endpoint may therefore also return:

- 400 `VALIDATION_ERROR`
- 403 `STEPUP_REQUIRED`, `STEPUP_INVALID`, `SCOPE_INSUFFICIENT` or `COOLING_OFF`
- 404 `NOT_FOUND`
- 500 `INTERNAL`
- 503 `SERVICE_UNAVAILABLE`

Every one of these uses the same envelope.

### Error codes

| Code | HTTP | Meaning |
|---|---|---|
| `VALIDATION_ERROR` | 400 / 422 | malformed (400) or semantically invalid (422) |
| `AUTH_FAILED` | 401 | any credential, signature or challenge failure |
| `PIN_INVALID` | 401 | wrong PIN, has `attemptsRemaining` |
| `UNLOCK_REQUIRED` | 401 | refresh outside the unlock window |
| `STEPUP_REQUIRED` | 403 | step-up missing or proof kind not allowed, has `required` |
| `STEPUP_INVALID` | 403 | step-up token bad, used, expired or mismatched |
| `COOLING_OFF` | 403 | action limited during cooling-off, has `retryAfter` |
| `SCOPE_INSUFFICIENT` | 403 | valid credential of the wrong kind or scope |
| `NOT_FOUND` | 404 | unknown resource, or one owned by another user |
| `PIN_ALREADY_SET` | 409 | `POST /pin` when a PIN exists |
| `DEVICE_LIMIT` | 409 | 5 active devices already |
| `IDEMPOTENT_REPLAY` | 409 | token-bearing request already processed |
| `PIN_WEAK` | 422 | PIN fails policy (blocklist not revealed) |
| `PIN_UNCHANGED` | 422 | new PIN equals old PIN |
| `IDEMPOTENCY_KEY_REUSED` | 422 | same key, different body |
| `INVALID_PUBLIC_KEY` | 422 | enroll key not a valid P-256 SPKI |
| `INSUFFICIENT_FUNDS` | 422 | mock balance too low |
| `PIN_LOCKED` | 423 | soft or hard PIN lock, has `lockType` |
| `RATE_LIMITED` | 429 | too many requests, has `Retry-After` |
| `INTERNAL` | 500 | unexpected error |
| `SERVICE_UNAVAILABLE` | 503 | fail-closed: misconfiguration or store down |

### PIN lockout (shared by `pin/verify`, `PUT /pin` and PIN step-up)

The server checks the lock state **before** it checks the PIN, so even a correct PIN gets 423 while the account is locked.

| Wrong PINs so far | Response |
|---|---|
| 1–4 | 401 `PIN_INVALID`, `attemptsRemaining` = 5 − failures |
| 5–9 | 423 `PIN_LOCKED`, `lockType: soft`, `retryAfter`, `attemptsUntilHardLock` |
| 10 | 423 `PIN_LOCKED`, `lockType: hard`, no `retryAfter` → recover via `/pin/reset` |

## Uniform 401

The API is non-oracular: a 401 does not reveal *why* authentication failed (SEC-029).

- Any problem with a credential returns the **same** `401 AUTH_FAILED` body with `Cache-Control: no-store`. This covers credentials that are missing, invalid, expired, revoked or replayed, and a credential that belongs to a different device than the body `deviceId`.
- Expired, replayed or unknown challenges, bad signatures, unknown devices and revoked keys are all `AUTH_FAILED` from the outside.
- `POST /auth/biometric/verify` returns the identical 401 for every failure.
- `POST /auth/biometric/challenge` always returns a well-formed 200 to a valid credential. When biometrics cannot be used, the challenge is a decoy.
- `POST /auth/demo-login` gives the same 401 for a wrong username and for a wrong secret.
- `PIN_INVALID` and its `attemptsRemaining` appear only after the device credential has been validated.

## Rate limits

- Any response may carry `RateLimit-Limit`, `RateLimit-Remaining` and `RateLimit-Reset` (seconds).
- A 429 `RATE_LIMITED` response also carries `Retry-After` and `error.retryAfter`.
- `openapi.yaml` points to [decisions.md D-12](../decisions.md) for the full table:

| Endpoint | Limit |
|---|---|
| `POST /auth/demo-login` | 5/min/IP, 20/h/IP, global breaker |
| `POST /auth/pin/verify` | 10/min/device, 30/min/IP |
| `POST /auth/biometric/challenge`, `/verify` | 10/min/device, 30/min/IP (D-12) |
| `POST /auth/refresh` | 6/min/device |
| `POST /stepup/challenge`, `/verify` | 10/min/user (verify: D-12) |
| `POST .../biometric/enroll/challenge` | 5/h/user |
| `PUT /pin`, `POST /pin/reset` | 5/h/user (reset: D-12) |
| `POST /transactions` | 20/min/user |

## Endpoint index

Auth key:

- **—**: none
- **BS**: `bootstrapToken`
- **DC**: `deviceCredential`
- **AT**: `accessToken`
- **+SU**: also needs `X-StepUp-Token`
- **(SU)**: `X-StepUp-Token` needed only when revoking a device other than the current one

In the **Idem.** column, **Key** means the `Idempotency-Key` header is required.

| Method | Path | Auth | Idem. | Docs | Seq. |
|---|---|---|---|---|---|
| GET | `/healthz` | — | — | [ops](./ops.md#get-healthz) | — |
| POST | `/auth/demo-login` | — | — | [bootstrap](./bootstrap.md#post-authdemo-login) | [1](../diagrams/sequences/01-first-launch-pin-setup.md), [7](../diagrams/sequences/07-change-reset-recover-pin.md) |
| POST | `/devices` | BS | Key | [devices](./devices.md#post-devices) | [1](../diagrams/sequences/01-first-launch-pin-setup.md), [7](../diagrams/sequences/07-change-reset-recover-pin.md) |
| GET | `/devices` | AT | — | [devices](./devices.md#get-devices) | — |
| DELETE | `/devices/{deviceId}` | AT (SU) | — | [devices](./devices.md#delete-devicesdeviceid) | [8](../diagrams/sequences/08-disable-biometrics-revoke-device.md) |
| POST | `/pin` | BS | Key | [pin](./pin.md#post-pin) | [1](../diagrams/sequences/01-first-launch-pin-setup.md) |
| PUT | `/pin` | AT | Key | [pin](./pin.md#put-pin) | [7](../diagrams/sequences/07-change-reset-recover-pin.md) |
| POST | `/pin/reset` | BS | Key | [pin](./pin.md#post-pinreset) | [7](../diagrams/sequences/07-change-reset-recover-pin.md) |
| POST | `/auth/pin/verify` | DC | — | [session](./session.md#post-authpinverify) | [2](../diagrams/sequences/02-pin-unlock-lockout.md) |
| POST | `/auth/refresh` | DC | — | [session](./session.md#post-authrefresh) | [5](../diagrams/sequences/05-refresh-rotation.md) |
| POST | `/auth/logout` | AT | — | [session](./session.md#post-authlogout) | — |
| POST | `/auth/biometric/challenge` | DC | — | [biometric](./biometric.md#post-authbiometricchallenge) | [4](../diagrams/sequences/04-biometric-unlock.md) |
| POST | `/auth/biometric/verify` | DC | — | [biometric](./biometric.md#post-authbiometricverify) | [4](../diagrams/sequences/04-biometric-unlock.md) |
| POST | `/devices/{deviceId}/biometric/enroll/challenge` | AT +SU | — | [biometric](./biometric.md#post-devicesdeviceidbiometricenrollchallenge) | [3](../diagrams/sequences/03-enable-biometrics.md) |
| POST | `/devices/{deviceId}/biometric/enroll` | AT | Key | [biometric](./biometric.md#post-devicesdeviceidbiometricenroll) | [3](../diagrams/sequences/03-enable-biometrics.md) |
| DELETE | `/devices/{deviceId}/biometric` | AT | — | [biometric](./biometric.md#delete-devicesdeviceidbiometric) | [4](../diagrams/sequences/04-biometric-unlock.md), [8](../diagrams/sequences/08-disable-biometrics-revoke-device.md) |
| POST | `/stepup/challenge` | AT | — | [step-up](./step-up.md#post-stepupchallenge) | [3](../diagrams/sequences/03-enable-biometrics.md), [6](../diagrams/sequences/06-step-up-transaction.md), [8](../diagrams/sequences/08-disable-biometrics-revoke-device.md) |
| POST | `/stepup/verify` | AT | — | [step-up](./step-up.md#post-stepupverify) | [3](../diagrams/sequences/03-enable-biometrics.md), [6](../diagrams/sequences/06-step-up-transaction.md), [8](../diagrams/sequences/08-disable-biometrics-revoke-device.md) |
| POST | `/transactions` | AT +SU | Key | [transactions](./transactions.md#post-transactions) | [6](../diagrams/sequences/06-step-up-transaction.md) |
| GET | `/dashboard` | AT | — | [dashboard](./dashboard.md#get-dashboard) | — |

App launch and auto-lock, which combine several of these calls, are shown in [sequence 9](../diagrams/sequences/09-app-launch-auto-lock.md).

## Discrepancies

These conflicts were found while generating these docs. In every case the docs follow `openapi.yaml`. Nothing was changed in the source files. The tech lead should resolve each one in the source.

1. **Decoy `userId`: random or stable?**
   - `openapi.yaml` (`/auth/biometric/challenge`) and contract-notes §8 say the decoy `userId` is *derived stably per device*.
   - contract-notes §1 ("Server decoys … use random userId") and decisions D-03 ("decoys therefore include a random userId") still say *random*.
2. **Access token claims.**
   - The `accessToken` scheme in the yaml lists `sub, sid, did, amr, auth_time, scope=session, aud, exp`.
   - contract-notes §4 also lists `iat`.
3. **Status of an idempotent replay.**
   - The yaml conventions say a same-key, same-body replay "returns the stored status".
   - `POST /devices` and biometric enroll document the replay as **200**, while the original returns 201.
   - `POST /transactions` replays the stored **202**, yet it also declares 409 `IDEMPOTENT_REPLAY` even though its response carries no tokens.
4. **Device count and `maxItems`.**
   - `POST /devices` with a `pin-reset` token is exempt from the 5-device cap.
   - `DeviceList.devices` has `maxItems: 5`.
   - If a user registers through reset but never calls `/pin/reset`, they could have 6 active devices, and `GET /devices` would then break its own schema.
5. **Per-device PIN block has no documented response.** decisions D-20 says 8 evaluated wrong PINs in 60 min block the device from `pin/verify` for 1 h (or alert only). The yaml does not say which status or code that block returns.
6. **Rate limits missing from operation descriptions.** The yaml defers to D-12 overall. However, the limits for biometric challenge/verify, `/stepup/verify` and `/pin/reset` appear only in D-12 and not in those operations' descriptions. The table above marks these with "(D-12)".
7. **Single-use bootstrap token.**
   - contract-notes §4 says the bootstrap token is "single use for set/reset".
   - The yaml states single use only for `POST /pin`. `/pin/reset` does not say.
