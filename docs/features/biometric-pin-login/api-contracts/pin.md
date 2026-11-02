# PIN

[← API contracts index](./README.md) · Tag: `pin`

The PIN is always exactly 6 digits and is sent only in JSON bodies. It never appears in a response, URL or log. PIN unlock (`POST /auth/pin/verify`) is in [session.md](./session.md#post-authpinverify).

## POST /pin

Sets the initial PIN. This works only when the user has no PIN yet. On success the device gets a session with `amr=pin`.

**Auth and headers**

| Header | Value |
|---|---|
| `Authorization` | `Bearer <bootstrap-token>` |
| `Idempotency-Key` | UUIDv4, required |

**Rules**

- The bootstrap token must be device-bound (registered via `POST /devices`) and have scope `pin-setup`.
- The bootstrap token can be used once.
- If a PIN already exists, the call returns 409 `PIN_ALREADY_SET` and nothing changes (SEC-015).
- The response carries tokens, so a replay returns 409 `IDEMPOTENT_REPLAY`.

### Request body

| Field | Type | Req | Constraints |
|---|---|---|---|
| `pin` | `Pin` | yes | `^[0-9]{6}$` |

```json
{ "pin": "<6-digit-pin>" }
```

### Responses

**201** PIN set and session issued (`amr=pin`). Header: `Cache-Control: no-store`. Body: [SessionResponse](./schemas.md#sessionresponse).

| Status | Code | When |
|---|---|---|
| 400 | `VALIDATION_ERROR` | malformed body or missing header |
| 401 | `AUTH_FAILED` | bad, expired or used bootstrap token |
| 403 | `SCOPE_INSUFFICIENT` | wrong scope or token kind |
| 409 | `PIN_ALREADY_SET` | a PIN exists (it is not changed) |
| 409 | `IDEMPOTENT_REPLAY` | same key already succeeded |
| 422 | `PIN_WEAK` | fails policy (generic message) |
| 422 | `IDEMPOTENCY_KEY_REUSED` | same key, different body |
| 429 | `RATE_LIMITED` | |

Plus the shared [default errors](./README.md#errors).

**Sequences:** [1. First launch and PIN setup](../diagrams/sequences/01-first-launch-pin-setup.md).

**SEC:** SEC-001, SEC-005, SEC-015, SEC-016, SEC-060.

## PUT /pin

Changes the PIN. The old PIN is required, and a wrong old PIN counts toward the lockout.

- **Auth:** `Authorization: Bearer <access-token>`, plus a required `Idempotency-Key` (UUIDv4).
- **Rate limit:** 5/h/user.

**Effects on success**

- All **other** sessions are revoked, and so are the biometric keys on **other** devices.
- The current device gets a new session (new tokens) and keeps its biometric key (SEC-045).

**Rules**

- A wrong old PIN uses the same counter and responses as `pin/verify` (see [PIN lockout](./README.md#pin-lockout-shared-by-pinverify-put-pin-and-pin-step-up)).
- The response carries tokens, so a replay returns 409 `IDEMPOTENT_REPLAY`.

### Request body

| Field | Type | Req | Constraints |
|---|---|---|---|
| `oldPin` | `Pin` | yes | 6 digits |
| `newPin` | `Pin` | yes | 6 digits, ≠ `oldPin` |

```json
{ "oldPin": "<6-digit-pin>", "newPin": "<6-digit-pin>" }
```

### Responses

**200** PIN changed and session re-issued. Header: `Cache-Control: no-store`. Body: [SessionResponse](./schemas.md#sessionresponse).

| Status | Code | When |
|---|---|---|
| 400 | `VALIDATION_ERROR` | malformed body or missing header |
| 401 | `AUTH_FAILED` | bad access token |
| 401 | `PIN_INVALID` | wrong old PIN; `attemptsRemaining` |
| 403 | `SCOPE_INSUFFICIENT` | wrong token kind |
| 409 | `IDEMPOTENT_REPLAY` | same key already succeeded |
| 422 | `PIN_WEAK` | new PIN fails policy |
| 422 | `PIN_UNCHANGED` | new PIN equals old |
| 422 | `IDEMPOTENCY_KEY_REUSED` | same key, different body |
| 423 | `PIN_LOCKED` | soft or hard lock; `Retry-After` when soft |
| 429 | `RATE_LIMITED` | |

Plus the shared [default errors](./README.md#errors).

**Sequences:** [7. Change, reset and recover PIN](../diagrams/sequences/07-change-reset-recover-pin.md).

**SEC:** SEC-001, SEC-008, SEC-036, SEC-045, SEC-060.

## POST /pin/reset

Handles forgot-PIN and hard-lock recovery.

**Auth and headers**

| Header | Value |
|---|---|
| `Authorization` | `Bearer <bootstrap-token>` |
| `Idempotency-Key` | UUIDv4, required |

- The bootstrap token must be device-bound and have scope `pin-reset`. To get one, call demo-login with `intent: reset`, then `POST /devices`.

**Effects on success (SEC-046)**

- The new PIN is set and the lock counters are cleared.
- **All** of the user's sessions, biometric keys and device records are revoked. Only the device just registered survives.
- Cooling-off starts, and an audit event is written.

**Client rules**

- Discard the old `deviceId`.
- Re-enroll biometrics through the full flow.
- The response carries tokens, so a replay returns 409 `IDEMPOTENT_REPLAY`.

### Request body

| Field | Type | Req | Constraints |
|---|---|---|---|
| `pin` | `Pin` | yes | `^[0-9]{6}$` |

```json
{ "pin": "<6-digit-pin>" }
```

### Responses

**200** PIN reset and session issued for the registering device. Header: `Cache-Control: no-store`. Body: [SessionResponse](./schemas.md#sessionresponse).

| Status | Code | When |
|---|---|---|
| 400 | `VALIDATION_ERROR` | malformed body or missing header |
| 401 | `AUTH_FAILED` | bad, expired or unbound bootstrap token |
| 403 | `SCOPE_INSUFFICIENT` | scope is not `pin-reset` |
| 409 | `IDEMPOTENT_REPLAY` | same key already succeeded |
| 422 | `PIN_WEAK` | fails policy |
| 422 | `IDEMPOTENCY_KEY_REUSED` | same key, different body |
| 429 | `RATE_LIMITED` | |

Plus the shared [default errors](./README.md#errors).

**Sequences:** [7. Change, reset and recover PIN](../diagrams/sequences/07-change-reset-recover-pin.md).

**SEC:** SEC-011, SEC-046, SEC-047, SEC-060.
