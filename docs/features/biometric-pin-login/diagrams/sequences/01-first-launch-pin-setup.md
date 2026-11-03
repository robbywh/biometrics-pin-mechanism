# 1. First launch, demo-login, device registration, PIN setup

[Index](./README.md) · [2. PIN unlock with soft lock and hard lock](./02-pin-unlock-lockout.md) →

```mermaid
sequenceDiagram
    autonumber
    participant U as User
    participant A as App
    participant K as Secure key
    participant S as API
    participant D as DB
    A->>A: Cold start, no refresh token in SecureStore
    A->>A: Device passcode check, block if none
    U->>A: Enter username and demo secret
    A->>S: POST /auth/demo-login username secret intent login
    S->>D: Load user, constant time secret check
    alt wrong username or secret
        S-->>A: 401 AUTH_FAILED
    else too many requests
        S-->>A: 429 RATE_LIMITED with Retry-After
    else ok and no PIN yet
        S->>D: Store bootstrap token hash, scope pin-setup
        S-->>A: 200 bootstrapToken scope pin-setup
    end
    A->>S: POST /devices name platform with bootstrap token and Idempotency-Key
    S->>D: Lock user row, count active devices, insert device, bind bootstrap token
    alt more than 5 active devices
        S-->>A: 409 DEVICE_LIMIT
    else created
        S-->>A: 201 deviceId createdAt
    end
    U->>A: Enter PIN twice on in-app keypad
    A->>A: Client policy check, UX only
    A->>S: POST /pin with pin in body, bootstrap token, Idempotency-Key
    alt PIN already set
        S-->>A: 409 PIN_ALREADY_SET, hash unchanged
    else weak PIN
        S-->>A: 422 PIN_WEAK
    else ok
        S->>D: Store Argon2id hash, mark bootstrap used, create session and family
        S-->>A: 201 accessToken refreshToken amr pin deviceId biometricEnabled false
        A->>A: Zero the PIN buffer, refresh token to SecureStore, access token in memory
        A->>U: Offer enable biometrics
    end
    Note over A,S: If account already has a PIN the scope is pin-verify, see diagram 2. A replayed POST /pin returns 409 IDEMPOTENT_REPLAY without tokens.
```
SEC: 001, 002, 004, 015, 016, 034, 048, 052, 053, 060.
