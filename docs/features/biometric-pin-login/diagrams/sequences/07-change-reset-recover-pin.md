# 7. Change PIN, PIN reset and hard-lock recovery with cooling-off

← [6. Step-up send transaction (biometric under BIO_ONLY_MAX, PIN above, server recomputed hash)](./06-step-up-transaction.md) · [Index](./README.md) · [8. Disable biometrics and revoke device](./08-disable-biometrics-revoke-device.md) →

```mermaid
sequenceDiagram
    autonumber
    participant U as User
    participant A as App
    participant K as Secure key
    participant S as API
    participant D as DB
    rect rgb(235, 245, 255)
    Note over U,D: Change PIN while unlocked
    U->>A: Enter old PIN, new PIN, confirm
    A->>S: PUT /pin oldPin newPin, access token, Idempotency-Key
    alt wrong old PIN
        S-->>A: 401 PIN_INVALID or 423 PIN_LOCKED, same counter as unlock
    else new PIN weak
        S-->>A: 422 PIN_WEAK
    else new equals old
        S-->>A: 422 PIN_UNCHANGED
    else ok
        S->>D: Revoke other sessions and biometric keys on other devices
        S->>D: Store new hash, re-issue current session
        S-->>A: 200 new tokens, biometric key on this device stays
        A->>A: Write new refresh token first
    end
    end
    rect rgb(255, 242, 235)
    Note over U,D: Forgot PIN or hard lock recovery
    U->>A: Tap Reset PIN
    A->>S: POST /auth/demo-login username secret intent reset
    S-->>A: 200 bootstrapToken scope pin-reset
    A->>S: POST /devices with bootstrap token, new device id
    Note over S,D: Registration with a pin-reset token is exempt from the 5 device cap
    S-->>A: 201 deviceId
    U->>A: Enter new PIN twice
    A->>S: POST /pin/reset pin, bootstrap token, Idempotency-Key
    alt weak PIN
        S-->>A: 422 PIN_WEAK
    else bootstrap invalid or wrong scope
        S-->>A: 401 AUTH_FAILED
    else ok
        S->>D: New hash, clear counters and hard lock
        S->>D: Revoke all sessions, all biometric keys, all other devices
        S->>D: Start cooling-off, audit PIN_RESET
        S-->>A: 200 session amr pin, coolingOffUntil
        A->>K: deleteKey for old device
        A->>A: Replace deviceId and refresh token, clear hint
        A->>U: Cooling-off banner, re-enable biometrics from Settings
    end
    end
    Note over A,S: During cooling-off tx above COOLING_OFF_MAX get 403 COOLING_OFF and biometric-only approval is off for new keys.
```
SEC: 001, 011, 016, 024, 036, 045, 046, 047, 048.
