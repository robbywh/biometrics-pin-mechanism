# Transactions

[← API contracts index](./README.md) · Tag: `transactions`

## POST /transactions

A demo send (mock). It requires a step-up token. The server recomputes the transaction hash from **this** body and compares it with the hash bound to the step-up token.

**Auth and headers**

| Header | Value |
|---|---|
| `Authorization` | `Bearer <access-token>` |
| `X-StepUp-Token` | `<step-up-token>` (action `transaction`) |
| `Idempotency-Key` | UUIDv4, required |

**Rules**

- The body must have the same transaction fields as the step-up challenge.
- The step-up token is consumed atomically with transaction creation (SEC-040).
- There are no client-supplied approval flags.
- **Rate limit:** 20/min/user.
- The response contains no tokens, so an idempotent replay returns the stored 202.

### Request body

[`TransactionFields`](./schemas.md#transactionfields):

| Field | Type | Req | Constraints |
|---|---|---|---|
| `asset` | string | yes | `BTC` \| `ETH` \| `USDC` |
| `network` | string | yes | `bitcoin` \| `ethereum` |
| `destination` | string | yes | `^[A-Za-z0-9]{26,90}$` |
| `amount` | `DecimalString` | yes | |
| `fee` | `DecimalString` | yes | |
| `txNonce` | `Uuid` | yes | |
| `expiry` | `UnixSeconds` | yes | |

```json
{
  "asset": "ETH", "network": "ethereum",
  "destination": "<destination-address>",
  "amount": "1.5", "fee": "0.001",
  "txNonce": "<tx-nonce-uuid>", "expiry": 1767225900
}
```

### Responses

**202** Accepted (mock).

| Field | Type | Req | Notes |
|---|---|---|---|
| `transactionId` | `Uuid` | yes | |
| `status` | string | yes | `accepted_mock` |
| `txHash` | `Base64Url` | yes | server-computed |

```json
{ "transactionId": "<transaction-id>", "status": "accepted_mock", "txHash": "<tx-hash-base64url>" }
```

| Status | Code | When |
|---|---|---|
| 400 | `VALIDATION_ERROR` | malformed body or missing header |
| 401 | `AUTH_FAILED` | bad access token |
| 403 | `STEPUP_REQUIRED` | `X-StepUp-Token` missing |
| 403 | `STEPUP_INVALID` | see below |
| 403 | `COOLING_OFF` | in cooling-off and above `COOLING_OFF_MAX`; `retryAfter` |
| 409 | `IDEMPOTENT_REPLAY` | declared (see README discrepancy 3) |
| 422 | `INSUFFICIENT_FUNDS` | mock balance too low |
| 422 | `IDEMPOTENCY_KEY_REUSED` | same key, different body |
| 422 | `VALIDATION_ERROR` | semantically invalid fields |
| 429 | `RATE_LIMITED` | |

Plus the shared [default errors](./README.md#errors).

**When `STEPUP_INVALID` is returned**

- The hash does not match.
- The token was already used.
- The token belongs to another session or device.
- The token has expired.

If the token was otherwise valid, it is consumed.

```json
{ "error": { "code": "COOLING_OFF", "message": "This action is temporarily limited.", "retryAfter": 3600 } }
```

**Sequences:** [6. Step-up transaction](../diagrams/sequences/06-step-up-transaction.md).

**SEC:** SEC-039, SEC-040, SEC-044, SEC-047, SEC-060, SEC-069.
