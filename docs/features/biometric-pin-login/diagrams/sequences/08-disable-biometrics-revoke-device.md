# 8. Disable biometrics and revoke device

← [7. Change PIN, PIN reset and hard-lock recovery with cooling-off](./07-change-reset-recover-pin.md) · [Index](./README.md) · [9. App launch decision and auto-lock](./09-app-launch-auto-lock.md) →

```mermaid
sequenceDiagram
    autonumber
    participant U as User
    participant A as App
    participant K as Secure key
    participant S as API
    participant D as DB
    rect rgb(235, 245, 255)
    Note over U,D: Disable biometrics, also used after KEY_INVALIDATED
    U->>A: Settings, Disable biometrics
    A->>S: DELETE /devices/id/biometric, access token
    alt last unlock older than 5 min
        S-->>A: 403 STEPUP_REQUIRED
        A->>U: Ask PIN or biometric unlock, then retry once
    else foreign or unknown device
        S-->>A: 404 NOT_FOUND
    else ok
        S->>D: Revoke key and live challenges, audit BIO_DISABLED
        S-->>A: 204
        A->>K: deleteKey
        A->>A: Hint false
    end
    end
    rect rgb(255, 242, 235)
    Note over U,D: Revoke a device
    U->>A: Devices screen, Revoke
    alt revoke current device
        A->>S: DELETE /devices/id, access token only
        S->>D: Revoke sessions, refresh families, keys, challenges
        S-->>A: 204
        A->>K: deleteKey
        A->>A: Wipe SecureStore, go to onboarding
    else revoke another device
        A->>S: POST /stepup/challenge action revoke_device targetDeviceId
        S-->>A: 200 challenge, required pin
        U->>A: Enter PIN
        A->>S: POST /stepup/verify challengeId pin
        S-->>A: 200 stepUpToken
        A->>S: DELETE /devices/id with X-StepUp-Token
        alt token missing
            S-->>A: 403 STEPUP_REQUIRED
        else token bad or wrong target
            S-->>A: 403 STEPUP_INVALID
        else ok
            S->>D: Consume token, revoke target device sessions and keys
            S-->>A: 204
        end
    end
    end
    Note over A,S: Another user's device id always returns 404 NOT_FOUND. A revoked device then gets 401 AUTH_FAILED on refresh and biometric verify.
```
SEC: 023, 024, 036, 038, 048, 049.
