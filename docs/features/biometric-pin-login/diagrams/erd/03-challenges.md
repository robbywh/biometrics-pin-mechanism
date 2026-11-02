# ERD 03: Challenges

[ERD index](./README.md) (constraints, notes and SEC mapping live there)

Server nonces signed by the device key for biometric login, biometric enrollment and step-up.

Tables from other diagrams are shown with their key only: `users` ([01-identity-devices](./01-identity-devices.md)), `devices` ([01-identity-devices](./01-identity-devices.md)), `sessions` ([02-sessions-tokens](./02-sessions-tokens.md)).

```mermaid
erDiagram
    users ||--o{ challenges : issued_to
    devices ||--o{ challenges : targets
    sessions ||--o{ challenges : binds

    users {
        uuid id PK "see 01-identity-devices"
    }

    devices {
        uuid id PK "see 01-identity-devices"
    }

    challenges {
        uuid id PK
        uuid user_id FK
        uuid device_id FK
        uuid session_id FK "set for enroll and stepup - NULL for login"
        text purpose "login or enroll or stepup"
        text action "transaction or enable_biometric or revoke_device - stepup only"
        bytea nonce "32 random bytes"
        bytea bound_hash "32 bytes or NULL"
        text required_proof "bio or pin or either - stepup only"
        timestamptz expires_at "server clock"
        timestamptz consumed_at "set atomically on first attempt"
        timestamptz created_at
    }

    sessions {
        uuid id PK "see 02-sessions-tokens"
    }
```
