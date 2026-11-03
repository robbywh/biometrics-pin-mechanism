# Step-up

[← API contracts index](./README.md) · Tag: `stepup`

Sensitive actions need a fresh proof (biometric signature or PIN). The proof is exchanged for a single-use **step-up token**, which is sent in `X-StepUp-Token`. The flow is:

1. `POST /stepup/challenge`
2. `POST /stepup/verify`
3. The protected call: `POST /transactions`, `POST .../biometric/enroll/challenge` or `DELETE /devices/{other}`.

## POST /stepup/challenge

Starts a step-up for a sensitive action.

- **Auth:** `Authorization: Bearer <access-token>`.
- **Rate limit:** 10/min/user.

**Rules**

- `action` decides the body shape:
  - `transaction`: the request carries the full transaction fields. The server canonicalises them and computes `txHash` ([contract-notes.md §2](../contract-notes.md)). The client never supplies a hash.
  - `enable_biometric` / `revoke_device`: the request carries `targetDeviceId`. `boundHash` is the action hash ([contract-notes.md §3](../contract-notes.md)).
- A new challenge replaces the previous live step-up challenge of the same session.

**Which proof is required (`required`)**

| Situation | `required` |
|---|---|
| `enable_biometric`, `revoke_device` | always `pin` |
| `transaction`, amount above `BIO_ONLY_MAX` | `pin` |
| `transaction`, key in cooling-off | `pin` |
| `transaction`, unattested key in production | `pin` |
| `transaction`, otherwise | as decided by the server (`bio`, `pin` or `either`) |

During cooling-off, a transaction above `COOLING_OFF_MAX` already fails here with 403 `COOLING_OFF`.

### Request body: `action: transaction`

| Field | Type | Req | Constraints |
|---|---|---|---|
| `action` | string | yes | `transaction` |
| `tx` | [`TransactionFields`](./schemas.md#transactionfields) | yes | |

```json
{
  "action": "transaction",
  "tx": {
    "asset": "ETH", "network": "ethereum",
    "destination": "<destination-address>",
    "amount": "1.5", "fee": "0.001",
    "txNonce": "<tx-nonce-uuid>", "expiry": 1767225900
  }
}
```

### Request body: `action: enable_biometric | revoke_device`

| Field | Type | Req | Constraints |
|---|---|---|---|
| `action` | string | yes | `enable_biometric` \| `revoke_device` |
| `targetDeviceId` | `Uuid` | yes | |

```json
{ "action": "enable_biometric", "targetDeviceId": "<device-id>" }
```

### Responses

**200** Step-up challenge. Header: `Cache-Control: no-store`.

| Field | Type | Req | Notes |
|---|---|---|---|
| `challengeId` | `Uuid` | yes | |
| `purpose` | string | yes | always `stepup` |
| `action` | string | yes | echoes the request |
| `userId` | `Uuid` | yes | signed |
| `deviceId` | `Uuid` | yes | signed |
| `nonce` | `Base64Url` | yes | signed |
| `expiresAt` | `UnixSeconds` | yes | signed, TTL 60 s |
| `boundHash` | `Base64Url` | yes | signed |
| `txHash` | `Base64Url` | no | transaction only |
| `required` | string | yes | `bio` \| `pin` \| `either` |
| `summary` | object | yes | see below |

`summary` is display text built by the server. The UI **must** show it instead of formatting the transaction fields locally (SEC-039).

| Field | Type | Req | Constraints |
|---|---|---|---|
| `title` | string | yes | max 80 |
| `lines` | string[] | yes | max 10 items, each max 200 |

```json
{
  "challengeId": "<challenge-id>",
  "purpose": "stepup",
  "action": "transaction",
  "userId": "<user-id>",
  "deviceId": "<device-id>",
  "nonce": "<nonce-base64url>",
  "expiresAt": 1767225660,
  "boundHash": "<bound-hash-base64url>",
  "txHash": "<tx-hash-base64url>",
  "required": "either",
  "summary": { "title": "Send 1.5 ETH", "lines": ["To: <destination-address>", "Network: ethereum", "Fee: 0.001 ETH"] }
}
```

| Status | Code | When |
|---|---|---|
| 400 | `VALIDATION_ERROR` | malformed body |
| 401 | `AUTH_FAILED` | bad access token |
| 403 | `COOLING_OFF` | above `COOLING_OFF_MAX` in cooling-off; `retryAfter` |
| 403 | `SCOPE_INSUFFICIENT` | wrong token kind |
| 404 | `NOT_FOUND` | unknown or foreign resource |
| 422 | `VALIDATION_ERROR` | e.g. bad asset/network pair, expiry out of range |
| 429 | `RATE_LIMITED` | |

Plus the shared [default errors](./README.md#errors).

**Sequences:**

- [3. Enable biometrics](../diagrams/sequences/03-enable-biometrics.md)
- [6. Step-up transaction](../diagrams/sequences/06-step-up-transaction.md)
- [8. Revoke device](../diagrams/sequences/08-disable-biometrics-revoke-device.md)

**SEC:** SEC-038, SEC-039, SEC-041, SEC-043, SEC-047, SEC-069.

## POST /stepup/verify

Proves the step-up and returns a single-use step-up token.

- **Auth:** `Authorization: Bearer <access-token>`.
- **Rate limit:** 10/min/user (decisions D-12).

**Rules**

- Send exactly **one** proof:
  - `signature`: made with the biometric key. The message uses purpose `stepup` and the `boundHash` from the challenge.
  - `pin`: the user's PIN.
- The challenge is consumed on the first attempt. After a wrong PIN, start a new `/stepup/challenge`.
- A PIN proof counts toward the **same** user counter and lock as `pin/verify` (SEC-042). See [PIN lockout](./README.md#pin-lockout-shared-by-pinverify-put-pin-and-pin-step-up).
- If the proof kind is not allowed by the challenge's `required`, the call returns 403 `STEPUP_REQUIRED` with `required`.

### Request body (one of)

Biometric proof:

| Field | Type | Req |
|---|---|---|
| `challengeId` | `Uuid` | yes |
| `signature` | `Base64Url` | yes |

```json
{ "challengeId": "<challenge-id>", "signature": "<signature-base64url>" }
```

PIN proof:

| Field | Type | Req |
|---|---|---|
| `challengeId` | `Uuid` | yes |
| `pin` | `Pin` | yes |

```json
{ "challengeId": "<challenge-id>", "pin": "<6-digit-pin>" }
```

### Responses

**200** Step-up token. Header: `Cache-Control: no-store`. The token is bound to the session, device, action and `boundHash`.

| Field | Type | Req | Notes |
|---|---|---|---|
| `stepUpToken` | `OpaqueToken` | yes | send as `X-StepUp-Token` |
| `expiresIn` | integer | yes | seconds, max 60 |

```json
{ "stepUpToken": "<step-up-token>", "expiresIn": 60 }
```

| Status | Code | When |
|---|---|---|
| 400 | `VALIDATION_ERROR` | malformed or both/neither proof |
| 401 | `AUTH_FAILED` | bad signature, expired, replayed or unknown challenge |
| 401 | `PIN_INVALID` | wrong PIN; `attemptsRemaining` |
| 403 | `STEPUP_REQUIRED` | proof kind not allowed; `required` |
| 423 | `PIN_LOCKED` | user PIN lock |
| 429 | `RATE_LIMITED` | |

Plus the shared [default errors](./README.md#errors).

```json
{ "error": { "code": "STEPUP_REQUIRED", "message": "Additional verification is required.", "required": "pin" } }
```

**Sequences:**

- [3. Enable biometrics](../diagrams/sequences/03-enable-biometrics.md)
- [6. Step-up transaction](../diagrams/sequences/06-step-up-transaction.md)
- [8. Revoke device](../diagrams/sequences/08-disable-biometrics-revoke-device.md)

**SEC:** SEC-026, SEC-040, SEC-041, SEC-042, SEC-043.
