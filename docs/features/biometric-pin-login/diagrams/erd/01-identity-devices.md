# ERD 01: Identity and devices

[ERD index](./README.md) (constraints, notes and SEC mapping live there)

Who the user is, which devices they registered, PIN lockout state and the hardware-backed biometric key per device.

```mermaid
erDiagram
    users ||--o{ devices : owns
    devices ||--o{ device_keys : registers
    devices ||--o| device_pin_failures : tracks

    users {
        uuid id PK
        text username UK "demo account name"
        text pin_hash "PHC string argon2id of HMAC(pepper,pin) - NULL until PIN set"
        smallint pepper_version "pepper generation used for pin_hash"
        timestamptz pin_set_at
        smallint fail_count "consecutive PIN failures since last PIN success"
        timestamptz locked_until "soft lock end - NULL when not locked"
        boolean hard_locked "true after failure 10"
        int failures_since_unlock "reported once as recentFailures then cleared"
        timestamptz last_failure_at
        timestamptz cooling_off_until "user level cooling off after reset"
        timestamptz created_at
    }

    devices {
        uuid id PK "server generated 128 bit random"
        uuid user_id FK
        text platform "ios or android"
        text name
        jsonb risk "advisory signals only"
        timestamptz created_at
        timestamptz last_seen_at
        timestamptz cooling_off_until "new device cooling off"
        timestamptz revoked_at
    }

    device_pin_failures {
        uuid device_id PK, FK
        timestamptz window_started_at
        smallint fail_count "10 in 15 min blocks the device for 1 h"
        timestamptz blocked_until
    }

    device_keys {
        uuid id PK
        uuid device_id FK "partial unique index: one active key per device"
        bytea spki "P-256 SubjectPublicKeyInfo DER - public only"
        bytea fingerprint "first 8 bytes of SHA-256 of spki"
        text attestation_type "none or android_key or app_attest or play_integrity"
        text key_security_level "self reported and untrusted in demo"
        smallint bio_fail_count "5 consecutive bad signatures suspends biometric login"
        timestamptz bio_suspended_at "set at 5 failures - cleared by next PIN unlock - key stays active"
        timestamptz cooling_off_until "biometric only approval disabled until then"
        timestamptz created_at
        timestamptz revoked_at
        text revoke_reason
    }
```
