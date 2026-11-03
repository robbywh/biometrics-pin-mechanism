# ERD 04: Transactions, idempotency and audit

[ERD index](./README.md) (constraints, notes and SEC mapping live there)

Mock send transactions and balances, idempotency records and the append-only audit log.

Tables from other diagrams are shown with their key only: `users` ([01-identity-devices](./01-identity-devices.md)), `devices` ([01-identity-devices](./01-identity-devices.md)), `sessions` ([02-sessions-tokens](./02-sessions-tokens.md)), `step_up_tokens` ([02-sessions-tokens](./02-sessions-tokens.md)).

```mermaid
erDiagram
    users ||--o{ idempotency_keys : scopes
    users ||--o{ transactions : creates
    users ||--o{ balances : owns
    users ||--o{ audit_events : subject_of
    devices ||--o{ audit_events : subject_of
    sessions ||--o{ transactions : authorises
    step_up_tokens ||--o| transactions : consumed_by

    users {
        uuid id PK "see 01-identity-devices"
    }

    devices {
        uuid id PK "see 01-identity-devices"
    }

    sessions {
        uuid id PK "see 02-sessions-tokens"
    }

    step_up_tokens {
        bytea token_hash PK "see 02-sessions-tokens"
    }

    idempotency_keys {
        uuid user_id PK, FK
        text endpoint PK
        bytea key_hash PK "SHA-256 of the Idempotency-Key header"
        bytea request_hash "SHA-256 of canonical request body"
        smallint response_status
        jsonb response_body "NULL for token bearing endpoints - never store tokens"
        timestamptz created_at
        timestamptz expires_at "24 h"
    }

    audit_events {
        bigint id PK "identity - append only"
        timestamptz ts
        uuid user_id FK "nullable"
        uuid device_id FK "nullable"
        text event_type "SEC-061 enum"
        text result
        inet ip
        text user_agent
        text request_id
        jsonb metadata "allowlisted non secret fields only"
        bytea prev_hash "optional hash chain"
    }

    transactions {
        uuid id PK
        uuid user_id FK
        uuid session_id FK
        uuid device_id FK
        bytea step_up_token_hash FK "UK - one token one transaction"
        uuid tx_nonce "UK together with user_id"
        bytea tx_hash "SHA-256 canonical hash"
        text asset
        text network
        text destination
        numeric amount
        numeric fee
        text status "accepted_mock"
        timestamptz created_at
    }

    balances {
        uuid user_id PK, FK
        text asset PK
        numeric amount
    }
```
