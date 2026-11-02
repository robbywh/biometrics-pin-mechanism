# ERD: PostgreSQL schema (biometric-pin-login)

Authority for backend migrations (`apps/api/migrations`, task T5 in [tasks-backend.md](../../tasks-backend.md)): the migrations MUST match these diagrams; change them first (via the tech lead), then the migrations. Engine: PostgreSQL 16. Types: `uuid`, `text`, `bytea`, `int`, `smallint`, `bigint`, `boolean`, `timestamptz`, `jsonb`, `numeric(38,18)`.

The schema is split so each diagram stays readable. The overview shows only how tables relate. The detail diagrams hold every column.

| # | Diagram | Tables |
|---|---|---|
| 01 | [Identity and devices](./01-identity-devices.md) | `users`, `devices`, `device_pin_failures`, `device_keys` |
| 02 | [Sessions and tokens](./02-sessions-tokens.md) | `sessions`, `bootstrap_tokens`, `step_up_tokens` |
| 03 | [Challenges](./03-challenges.md) | `challenges` |
| 04 | [Transactions, idempotency and audit](./04-transactions-audit.md) | `transactions`, `balances`, `idempotency_keys`, `audit_events` |

## Overview (relationships only)

```mermaid
erDiagram
    users ||--o{ devices : owns
    users ||--o{ sessions : has
    users ||--o{ bootstrap_tokens : receives
    users ||--o{ step_up_tokens : holds
    users ||--o{ challenges : issued_to
    users ||--o{ idempotency_keys : scopes
    users ||--o{ transactions : creates
    users ||--o{ balances : owns
    users ||--o{ audit_events : subject_of
    devices ||--o{ device_keys : registers
    devices ||--o{ sessions : runs
    devices ||--o{ challenges : targets
    devices ||--o| device_pin_failures : tracks
    devices ||--o{ bootstrap_tokens : binds
    devices ||--o{ step_up_tokens : scopes
    devices ||--o{ audit_events : subject_of
    sessions ||--o{ sessions : rotates_to
    sessions ||--o{ step_up_tokens : authorises
    sessions ||--o{ challenges : binds
    sessions ||--o{ transactions : authorises
    step_up_tokens ||--o| transactions : consumed_by
```

## Constraints

Postgres partial and composite unique constraints that Mermaid cannot show:
- `device_keys (device_id) WHERE revoked_at IS NULL` unique (one active key per device).
- `challenges (device_id, purpose) WHERE consumed_at IS NULL` unique (one live challenge per device and purpose; for stepup also scope by session_id).
- `sessions (device_id) WHERE revoked_at IS NULL AND used_at IS NULL` is NOT unique (a family has one live row at a time but old rows stay); the invariant "one live family per device" is enforced in code in the unlock transaction (revoke previous family then insert).
- `transactions (user_id, created_at)` index (SEC-069 rolling-window sums).
- `transactions (user_id, tx_nonce)` unique; `transactions (step_up_token_hash)` unique.
- `devices` count of active rows per user is limited to 5 in the registration transaction (`SELECT ... FOR UPDATE` on the user row).
- `audit_events`: API role has INSERT only (no UPDATE or DELETE).

## Notes

Sensitive columns (only hashes or public material are ever stored):
- `users.pin_hash`: Argon2id PHC string over `HMAC-SHA256(pepper, pin)`; includes salt and params. The raw PIN and the pepper are never stored. The pepper lives in env or a secret store (SEC-004).
- `sessions.refresh_hash`, `bootstrap_tokens.token_hash`, `step_up_tokens.token_hash`: SHA-256 of 256-bit random tokens; the tokens themselves are never stored. Access tokens are not stored (JWT, checked against `sessions.revoked_at`).
- `device_keys.spki`: public key only; the private key never leaves the device hardware. `fingerprint` is the only form that may appear in audit or logs.
- `challenges.nonce`: random, single use, purge after 24 h; never logged. No signatures are stored anywhere.
- `idempotency_keys.key_hash`/`request_hash`: hashes only; `response_body` is NULL for endpoints that return tokens.
- `audit_events.metadata`: allowlisted keys only; never PIN, tokens, nonces, signatures, public key bytes or hashes.

Table to SEC mapping:

| Table | Supports |
|---|---|
| users (incl. lockout state: fail_count, locked_until, hard_locked, failures_since_unlock) | SEC-001, 003, 004, 005, 008, 009, 010, 011, 012, 015, 042, 045, 046, 047, 066 |
| devices | SEC-024, 047, 048, 049, 056, 064 |
| device_pin_failures | SEC-009, 057 |
| device_keys | SEC-017, 018, 020, 021, 022, 023, 024, 030, 041, 047 |
| challenges | SEC-020, 025, 026, 027, 028, 029, 043, 066 |
| sessions (refresh families) | SEC-014, 031, 032, 033, 035, 036, 037, 066 |
| bootstrap_tokens | SEC-014, 015, 016, 046 |
| step_up_tokens | SEC-020, 038, 039, 040, 041, 042, 043 |
| idempotency_keys | SEC-060, 044 |
| audit_events | SEC-012, 030, 032, 061, 062, 064 |
| transactions, balances | SEC-039, 040, 044, 047 |
| (not in DB) rate-limit buckets | SEC-005b, 057 (in-memory by design, see [decisions.md](../../decisions.md) D-12) |
