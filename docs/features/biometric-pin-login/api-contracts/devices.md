# Devices

[← API contracts index](./README.md) · Tag: `devices`

## POST /devices

Registers this installation as a device. The server generates the `deviceId` and binds the presented bootstrap token to it on the server side. Because no token is returned, the endpoint is safe to make idempotent. Client hardware identifiers are not accepted as identity.

**Auth and headers**

| Header | Value |
|---|---|
| `Authorization` | `Bearer <bootstrap-token>` |
| `Idempotency-Key` | UUIDv4, required |

- The bootstrap token can have scope `pin-setup`, `pin-verify` or `pin-reset`, and must not be bound to a device yet.

**Rules**

- A user can have at most 5 active devices (409 `DEVICE_LIMIT`).
- Registration with a `pin-reset` token is **exempt** from the cap, so a hard-locked user who already has 5 devices can still recover.
- Registering any device except the user's first starts cooling-off (SEC-047).

### Request body

| Field | Type | Req | Constraints |
|---|---|---|---|
| `name` | string | yes | 1–64 |
| `platform` | string | yes | `ios` \| `android` |
| `risk` | [`RiskSignals`](./schemas.md#risksignals) | no | advisory |

```json
{ "name": "<device-name>", "platform": "ios" }
```

### Responses

**201** Device created. **200** Idempotent replay (same key and same body), with the same shape.

| Field | Type | Req |
|---|---|---|
| `deviceId` | `Uuid` | yes |
| `createdAt` | `UnixSeconds` | yes |
| `coolingOffUntil` | `UnixSeconds` | no |

```json
{ "deviceId": "<device-id>", "createdAt": 1767225600, "coolingOffUntil": 1767312000 }
```

| Status | Code | When |
|---|---|---|
| 400 | `VALIDATION_ERROR` | malformed body or missing header |
| 401 | `AUTH_FAILED` | bad, expired or used bootstrap token |
| 403 | `SCOPE_INSUFFICIENT` | wrong credential kind or scope |
| 409 | `DEVICE_LIMIT` | 5 active devices (non-reset scope) |
| 422 | `IDEMPOTENCY_KEY_REUSED` | same key, different body |
| 429 | `RATE_LIMITED` | |

Plus the shared [default errors](./README.md#errors).

**Sequences:**

- [1. First launch](../diagrams/sequences/01-first-launch-pin-setup.md)
- [7. Reset and recover PIN](../diagrams/sequences/07-change-reset-recover-pin.md)

**SEC:** SEC-047, SEC-048, SEC-056, SEC-060, SEC-064.

## GET /devices

Lists the caller's own devices.

- **Auth:** `Authorization: Bearer <access-token>`.

### Response 200

| Field | Type | Req | Notes |
|---|---|---|---|
| `devices` | array of `Device` | yes | max 5 items |

`Device`:

| Field | Type | Req | Notes |
|---|---|---|---|
| `id` | `Uuid` | yes | |
| `name` | string | yes | |
| `platform` | string | yes | `ios` \| `android` |
| `createdAt` | `UnixSeconds` | yes | |
| `lastSeenAt` | `UnixSeconds` | yes | |
| `current` | boolean | yes | true for the calling device |
| `biometricEnabled` | boolean | yes | |

```json
{
  "devices": [
    { "id": "<device-id>", "name": "<device-name>", "platform": "ios",
      "createdAt": 1767225600, "lastSeenAt": 1767225600,
      "current": true, "biometricEnabled": false }
  ]
}
```

| Status | Code | When |
|---|---|---|
| 401 | `AUTH_FAILED` | missing, invalid or expired access token |
| 403 | `SCOPE_INSUFFICIENT` | bootstrap token presented |
| 429 | `RATE_LIMITED` | |

Plus the shared [default errors](./README.md#errors).

**Sequences:** none.

**SEC:** SEC-049.

## DELETE /devices/{deviceId}

Revokes a device: its sessions, refresh tokens and biometric keys. User-facing **Sign out** calls this on the *current* device (decisions D-22).

**Path parameter:** `deviceId` (`Uuid`).

**Auth and headers**

| Header | Value |
|---|---|
| `Authorization` | `Bearer <access-token>` |
| `X-StepUp-Token` | `<step-up-token>`; only to revoke **another** device |

**Rules**

- If `deviceId` is the token's own device (`did`), a valid access token is enough.
- To revoke another device, you also need a step-up token from `/stepup` with action `revoke_device` and `targetDeviceId` equal to the path id. The proof must be a PIN.
- An id that is unknown or belongs to another user returns 404 `NOT_FOUND`.

**Request body:** none.

### Responses

**204** Revoked. There is no body.

| Status | Code | When |
|---|---|---|
| 401 | `AUTH_FAILED` | bad access token |
| 403 | `STEPUP_REQUIRED` | other device, header missing |
| 403 | `STEPUP_INVALID` | step-up token bad, used, expired or mismatched |
| 404 | `NOT_FOUND` | unknown or foreign id |
| 429 | `RATE_LIMITED` | |

Plus the shared [default errors](./README.md#errors).

**Sequences:** [8. Disable biometrics and revoke device](../diagrams/sequences/08-disable-biometrics-revoke-device.md).

**SEC:** SEC-024, SEC-036, SEC-038, SEC-049.
