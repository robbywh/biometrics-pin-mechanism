# ERD 02: Sessions and tokens

[ERD index](./README.md) (constraints, notes and SEC mapping live there)

Refresh-token families (rotation and reuse detection), single-use bootstrap tokens for PIN setup/verify/reset, and short-lived step-up tokens.

Tables from other diagrams are shown with their key only: `users` ([01-identity-devices](./01-identity-devices.md)), `devices` ([01-identity-devices](./01-identity-devices.md)).

```mermaid
erDiagram
    users ||--o{ sessions : has
    users ||--o{ bootstrap_tokens : receives
    users ||--o{ step_up_tokens : holds
    devices ||--o{ sessions : runs
    devices ||--o{ bootstrap_tokens : binds
    devices ||--o{ step_up_tokens : scopes
    sessions ||--o{ sessions : rotates_to
    sessions ||--o{ step_up_tokens : authorises

    users {
        uuid id PK "see 01-identity-devices"
    }

    devices {
        uuid id PK "see 01-identity-devices"
    }

    sessions {
        uuid id PK
        uuid user_id FK
        uuid device_id FK
        uuid family_id "refresh token family - one live family per device"
        uuid parent_id FK "previous refresh token row in the family - NULL for first"
        bytea refresh_hash UK "SHA-256 of refresh token"
        text amr "pin or bio"
        timestamptz created_at
        timestamptz last_unlock_at "set only by pin verify or biometric verify or step-up verify"
        timestamptz last_seen_at "idle window"
        timestamptz expires_at "absolute 30 d"
        timestamptz used_at "set on rotation - reuse of a used row revokes the family"
        timestamptz revoked_at
        text revoke_reason
    }

    bootstrap_tokens {
        bytea token_hash PK "SHA-256 of bootstrap token"
        uuid user_id FK
        uuid device_id FK "bound by POST devices - NULL before"
        text scope "pin-setup or pin-verify or pin-reset"
        timestamptz expires_at "max 10 min"
        timestamptz used_at "single use for set and reset"
        timestamptz created_at
    }

    step_up_tokens {
        bytea token_hash PK "SHA-256 of step-up token"
        uuid user_id FK
        uuid session_id FK
        uuid device_id FK
        text action
        bytea bound_hash "tx hash or action hash"
        text proof "bio or pin"
        timestamptz expires_at "60 s"
        timestamptz consumed_at "set in the same tx as the action"
    }
```
