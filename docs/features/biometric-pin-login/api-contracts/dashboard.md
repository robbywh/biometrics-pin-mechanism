# Dashboard

[← API contracts index](./README.md) · Tag: `dashboard`

## GET /dashboard

Returns mock balances.

- **Auth:** `Authorization: Bearer <access-token>`. A bootstrap token gets 403 `SCOPE_INSUFFICIENT`.

### Response 200

Header: `Cache-Control: no-store`.

| Field | Type | Req | Notes |
|---|---|---|---|
| `currency` | string | yes | `USD` |
| `totalValue` | `DecimalString` | yes | |
| `balances` | array of `Balance` | yes | max 20 items |

`Balance`:

| Field | Type | Req | Notes |
|---|---|---|---|
| `asset` | string | yes | `BTC` \| `ETH` \| `USDC` |
| `amount` | `DecimalString` | yes | |
| `value` | `DecimalString` | yes | in `currency` |

```json
{
  "currency": "USD",
  "totalValue": "12843.20",
  "balances": [
    { "asset": "BTC", "amount": "0.15", "value": "9750.00" },
    { "asset": "ETH", "amount": "1.2", "value": "3000.00" },
    { "asset": "USDC", "amount": "93.20", "value": "93.20" }
  ]
}
```

| Status | Code | When |
|---|---|---|
| 401 | `AUTH_FAILED` | bad access token |
| 403 | `SCOPE_INSUFFICIENT` | bootstrap token presented |
| 429 | `RATE_LIMITED` | |

Plus the shared [default errors](./README.md#errors).

**Sequences:** none.

**SEC:** SEC-016 (bootstrap tokens excluded), SEC-031.
