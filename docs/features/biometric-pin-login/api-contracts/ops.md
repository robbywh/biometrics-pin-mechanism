# Ops

[← API contracts index](./README.md) · Tag: `ops`

## GET /healthz

Reports liveness and fail-closed readiness.

- **Path:** served at the root (`/healthz`), **not** under `/v1`.
- **Auth:** none. The response contains no data.

### Responses

**200** Ready.

| Field | Type | Req | Values |
|---|---|---|---|
| `status` | string | yes | `ok` |

```json
{ "status": "ok" }
```

| Status | Code | When |
|---|---|---|
| 503 | `SERVICE_UNAVAILABLE` | misconfiguration or store unreachable (never fails open) |

Plus the shared [default errors](./README.md#errors).

**Sequences:** none.

**SEC:** SEC-004, SEC-065.
