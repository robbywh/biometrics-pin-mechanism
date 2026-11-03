# Session

[← API contracts index](./README.md) · Tag: `session`

## POST /auth/pin/verify

Unlocks with the PIN and returns a new session in a new refresh family.

- **Auth:** `Authorization: Bearer <refresh-token>` (`deviceCredential`, SEC-014). A device-bound bootstrap token with scope `pin-verify` is also accepted.
- **Rate limits:** 30/min/IP and 10/min/device.

**Rules**

- The body `deviceId` must equal the credential's device. If it does not, the call returns 401 `AUTH_FAILED` and the failure counter is not touched.
- The lock state is checked **before** the PIN, so a correct PIN during a lock still gets 423. See [PIN lockout](./README.md#pin-lockout-shared-by-pinverify-put-pin-and-pin-step-up).
- A wrong PIN does **not** consume or rotate the refresh token.

**On success**

- A new session family is created and the refresh token is rotated.
- The failure counter is reset.
- The session has `amr=pin`.

### Request body

| Field | Type | Req | Constraints |
|---|---|---|---|
| `deviceId` | `Uuid` | yes | must match the credential |
| `pin` | `Pin` | yes | `^[0-9]{6}$` |
| `risk` | [`RiskSignals`](./schemas.md#risksignals) | no | advisory |

```json
{ "deviceId": "<device-id>", "pin": "<6-digit-pin>" }
```

### Responses

**200** Unlocked. Header: `Cache-Control: no-store`. Body: [SessionResponse](./schemas.md#sessionresponse), including `recentFailures`.

| Status | Code | When |
|---|---|---|
| 400 | `VALIDATION_ERROR` | malformed body |
| 401 | `AUTH_FAILED` | credential missing, invalid or revoked, or device mismatch |
| 401 | `PIN_INVALID` | wrong PIN, failures 1–4; `attemptsRemaining` |
| 423 | `PIN_LOCKED` | failure ≥ 5 (soft) or 10 (hard) |
| 429 | `RATE_LIMITED` | |
| 503 | `SERVICE_UNAVAILABLE` | fail-closed |

Plus the shared [default errors](./README.md#errors).

```json
{ "error": { "code": "PIN_INVALID", "message": "Authentication failed.", "attemptsRemaining": 3 } }
```

```json
{ "error": { "code": "PIN_LOCKED", "message": "Try again later.", "retryAfter": 30, "lockType": "soft", "attemptsUntilHardLock": 5 } }
```

```json
{ "error": { "code": "PIN_LOCKED", "message": "Reset required.", "lockType": "hard" } }
```

**Sequences:**

- [2. PIN unlock with soft and hard lock](../diagrams/sequences/02-pin-unlock-lockout.md)
- [9. App launch and auto-lock](../diagrams/sequences/09-app-launch-auto-lock.md)

**SEC:** SEC-008, SEC-009, SEC-010, SEC-011, SEC-012, SEC-014, SEC-037, SEC-056.

## POST /auth/refresh

Rotates the refresh token and returns a new access token. There is no request body.

- **Auth:** `Authorization: Bearer <refresh-token>` (`deviceCredential`).
- **Rate limit:** 6/min/device.

**Unlock window (SEC-033).** Refresh works only while the server-side unlock window holds:

- `now − last_unlock_at` ≤ 15 min, **and**
- idle time ≤ 5 min.

Outside the window the call returns 401 `UNLOCK_REQUIRED`. The refresh token is then **not** consumed, **not** rotated and does **not** trigger reuse detection. The client unlocks with the PIN or biometrics instead.

**Reuse detection.** Presenting a refresh token that was already used or revoked revokes its whole family (audit `REFRESH_REUSE`) and returns 401 `AUTH_FAILED`.

**Lifetimes and claims**

- The refresh token has a 30 d absolute lifetime and a 7 d idle lifetime.
- The new access token inherits `amr` and `auth_time` from the session.

### Request

There is no body. The only input is the `Authorization` header.

### Responses

**200** New access token and rotated refresh token. Header: `Cache-Control: no-store`. Body: [SessionResponse](./schemas.md#sessionresponse).

| Status | Code | When |
|---|---|---|
| 401 | `AUTH_FAILED` | invalid, reused, revoked or expired token |
| 401 | `UNLOCK_REQUIRED` | valid token, unlock window elapsed |
| 429 | `RATE_LIMITED` | |

Plus the shared [default errors](./README.md#errors).

```json
{ "error": { "code": "UNLOCK_REQUIRED", "message": "Unlock required." } }
```

**Sequences:**

- [5. Refresh with rotation and reuse detection](../diagrams/sequences/05-refresh-rotation.md)
- [9. App launch and auto-lock](../diagrams/sequences/09-app-launch-auto-lock.md)

**SEC:** SEC-032, SEC-033, SEC-035, SEC-037.

## POST /auth/logout

Revokes the current session and its refresh family. It does **not** revoke the device or its biometric key. To sign out the user, use [`DELETE /devices/{current}`](./devices.md#delete-devicesdeviceid) (decisions D-22).

- **Auth:** `Authorization: Bearer <access-token>`.
- **Request body:** none.

### Responses

**204** Logged out. There is no body.

| Status | Code | When |
|---|---|---|
| 401 | `AUTH_FAILED` | bad access token |
| 403 | `SCOPE_INSUFFICIENT` | wrong token kind |

Plus the shared [default errors](./README.md#errors).

**Sequences:** none.

**SEC:** SEC-036.
