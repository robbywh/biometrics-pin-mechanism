# Shared schemas

[← API contracts index](./README.md)

These objects appear in more than one endpoint. Source: `components/schemas` in [openapi.yaml](../openapi.yaml). Every object has `additionalProperties: false`, so the server rejects unknown fields with 400 `VALIDATION_ERROR`. Optional fields are left out of the JSON. They are never sent as `null`.

## Primitive types

| Type | JSON | Constraints |
|---|---|---|
| `Uuid` | string | lowercase canonical, `^[0-9a-f]{8}-…-[0-9a-f]{12}$` |
| `Base64Url` | string | `^[A-Za-z0-9_-]+$`, max 512, no padding |
| `OpaqueToken` | string | `^[A-Za-z0-9_-]{43,512}$` |
| `Pin` | string | exactly 6 digits `^[0-9]{6}$`, write-only |
| `DecimalString` | string | `^(0\|[1-9][0-9]{0,17})(\.[0-9]{1,18})?$`, max 38 |
| `UnixSeconds` | integer | int64, ≥ 0 |

- `Pin` is used only in request bodies. It never appears in a response, URL or log.
- `DecimalString` is a non-negative decimal with no sign and no exponent. The server normalises it (see [contract-notes.md §2](../contract-notes.md)).

## ErrorResponse

Every error uses this body. Branch on `error.code`. Never branch on `message`.

| Field | Type | Req | Notes |
|---|---|---|---|
| `error.code` | `ErrorCode` | yes | see [error codes](./README.md#error-codes) |
| `error.message` | string | yes | max 200, generic text |
| `error.attemptsRemaining` | integer | no | 0–4, only on `PIN_INVALID` |
| `error.attemptsUntilHardLock` | integer | no | 0–10, only on soft `PIN_LOCKED` |
| `error.retryAfter` | integer | no | seconds; `PIN_LOCKED` soft, `RATE_LIMITED`, `COOLING_OFF` |
| `error.lockType` | string | no | `soft` \| `hard` |
| `error.required` | string | no | `bio` \| `pin` \| `either`, only on `STEPUP_REQUIRED` |

```json
{ "error": { "code": "PIN_INVALID", "message": "Authentication failed.", "attemptsRemaining": 3 } }
```

## SessionResponse

Returned by `POST /pin`, `PUT /pin`, `POST /pin/reset`, `POST /auth/pin/verify`, `POST /auth/biometric/verify` and `POST /auth/refresh`. It contains tokens, so never cache, log or replay it. Store `refreshToken` only in SecureStore. Keep `accessToken` in memory only.

| Field | Type | Req | Notes |
|---|---|---|---|
| `accessToken` | string | yes | max 2048, JWT |
| `expiresIn` | integer | yes | seconds (default 300, max 600) |
| `refreshToken` | `OpaqueToken` | yes | the new device credential |
| `amr` | string | yes | `pin` \| `bio` |
| `authTime` | `UnixSeconds` | yes | |
| `deviceId` | `Uuid` | yes | |
| `biometricEnabled` | boolean | yes | server-side state for this device |
| `recentFailures` | integer | no | ≥ 0; failed PINs since last unlock (unlock responses only) |
| `coolingOffUntil` | `UnixSeconds` | no | |

```json
{
  "accessToken": "<access-token>",
  "expiresIn": 300,
  "refreshToken": "<refresh-token>",
  "amr": "pin",
  "authTime": 1767225600,
  "deviceId": "<device-id>",
  "biometricEnabled": false,
  "recentFailures": 0
}
```

## Challenge (login / enroll)

Returned by `POST /auth/biometric/challenge` and `POST .../biometric/enroll/challenge`. Every field the client signs is in this object. The client builds the signed message ([contract-notes.md §1](../contract-notes.md)) from exactly these values. If `boundHash` is absent, the message uses an empty value for it. A decoy challenge has the same shape.

| Field | Type | Req | Notes |
|---|---|---|---|
| `challengeId` | `Uuid` | yes | |
| `purpose` | string | yes | `login` \| `enroll` |
| `userId` | `Uuid` | yes | signed, never sent by the client |
| `deviceId` | `Uuid` | yes | |
| `nonce` | `Base64Url` | yes | 32 random bytes |
| `expiresAt` | `UnixSeconds` | yes | server clock, TTL 60 s |
| `boundHash` | `Base64Url` | no | absent for login and enroll |

## StepUpChallenge

See [step-up.md](./step-up.md#post-stepupchallenge).

## TransactionFields

Used by `POST /stepup/challenge` (as `tx`) and `POST /transactions` (as the body).

| Field | Type | Req | Constraints |
|---|---|---|---|
| `asset` | string | yes | `BTC` \| `ETH` \| `USDC` |
| `network` | string | yes | `bitcoin` \| `ethereum` |
| `destination` | string | yes | `^[A-Za-z0-9]{26,90}$` |
| `amount` | `DecimalString` | yes | |
| `fee` | `DecimalString` | yes | |
| `txNonce` | `Uuid` | yes | |
| `expiry` | `UnixSeconds` | yes | |

- `destination` is ASCII only and is hashed as the exact bytes submitted. There is no case folding, and a `0x` prefix is allowed.
- An unsupported asset/network pair or an out-of-range expiry returns 422 `VALIDATION_ERROR`.

## RiskSignals

This object is optional on `POST /devices`, `POST /auth/pin/verify` and `POST /auth/biometric/verify`. It is advisory only (SEC-056, SEC-064): the server stores it but never uses it as the only gate.

| Field | Type | Req |
|---|---|---|
| `rooted` | boolean | no |
| `debugger` | boolean | no |
| `emulator` | boolean | no |
