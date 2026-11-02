# Bootstrap

[← API contracts index](./README.md) · Tag: `bootstrap`

## POST /auth/demo-login

This is the demo's primary login, standing in for password + 2FA. It returns a limited-scope **bootstrap token** only. The token cannot reach `/dashboard`, `/transactions` or any access-token endpoint; those return 403 `SCOPE_INSUFFICIENT`.

- **Auth:** none.
- **Requires:** the server must run with `DEMO_MODE=true`. The request needs the per-account demo secret from the server config (SEC-016).
- **Rate limits:** 5/min/IP and 20/h/IP, plus a global circuit breaker.

### Request body

| Field | Type | Req | Constraints |
|---|---|---|---|
| `username` | string | yes | 1–64, `^[a-z0-9_.-]+$` |
| `secret` | string | yes | 1–256, write-only |
| `intent` | string | yes | `login` \| `reset` |

```json
{ "username": "alice", "secret": "<demo-secret>", "intent": "login" }
```

### How the scope is chosen

| `intent` | Server state | `scope` |
|---|---|---|
| `login` | no PIN set | `pin-setup` |
| `login` | PIN set | `pin-verify` |
| `reset` | PIN set or hard-locked | `pin-reset` |
| `reset` | no PIN set | `pin-setup` (same as `login`) |

### Responses

**200** Bootstrap token issued. Headers: `Cache-Control: no-store`, `RateLimit-Remaining`.

| Field | Type | Req | Notes |
|---|---|---|---|
| `bootstrapToken` | `OpaqueToken` | yes | |
| `expiresIn` | integer | yes | seconds, max 600 |
| `scope` | string | yes | `pin-setup` \| `pin-verify` \| `pin-reset` |

```json
{ "bootstrapToken": "<bootstrap-token>", "expiresIn": 600, "scope": "pin-setup" }
```

| Status | Code | When |
|---|---|---|
| 400 | `VALIDATION_ERROR` | malformed body |
| 401 | `AUTH_FAILED` | wrong username or wrong secret (same body for both) |
| 404 | `NOT_FOUND` | `DEMO_MODE=false`: the route does not exist |
| 429 | `RATE_LIMITED` | over limit; `Retry-After` |
| 503 | `SERVICE_UNAVAILABLE` | fail-closed |

Plus the shared [default errors](./README.md#errors).

**Sequences:**

- [1. First launch and PIN setup](../diagrams/sequences/01-first-launch-pin-setup.md)
- [7. Change, reset and recover PIN](../diagrams/sequences/07-change-reset-recover-pin.md)

**SEC:** SEC-016, SEC-057, SEC-065. See [security-spec.md](../security-spec.md).
