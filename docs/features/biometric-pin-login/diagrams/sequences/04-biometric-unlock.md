# 4. Biometric unlock with PIN fallback

← [3. Enable biometrics (two-step enroll with fresh PIN and proof of possession)](./03-enable-biometrics.md) · [Index](./README.md) · [5. Refresh with rotation and reuse detection](./05-refresh-rotation.md) →

```mermaid
sequenceDiagram
    autonumber
    participant U as User
    participant A as App
    participant K as Secure key
    participant S as API
    participant D as DB
    A->>A: Locked, hint true and local key exists
    A->>S: POST /auth/biometric/challenge deviceId, Authorization is the refresh token
    S->>D: Resolve device credential, look up device and active key
    alt invalid credential or deviceId mismatch
        S-->>A: 401 AUTH_FAILED
    else unknown or revoked or not enrolled or suspended or hard locked
        S-->>A: 200 decoy challenge, random ids and nonce, nothing stored
    else enrolled
        S->>D: Store login challenge, supersede older one
        S-->>A: 200 challengeId purpose login userId deviceId nonce expiresAt
    end
    A->>A: Build message from challenge fields only
    A->>K: sign message
    K->>U: OS biometric prompt
    alt cancel or lockout or hardware unavailable or not enrolled
        K-->>A: error code
        A->>U: Show PIN screen
    else key invalidated
        K-->>A: KEY_INVALIDATED
        A->>K: deleteKey
        A->>A: Clear hint, show PIN screen
        Note over A,S: After PIN unlock the app calls DELETE /devices/id/biometric, see diagram 8
    else signed
        K-->>A: DER signature
        A->>S: POST /auth/biometric/verify challengeId deviceId signature, Authorization is the refresh token
        S->>D: Consume challenge atomically, first attempt
        S->>S: Rebuild message from stored challenge, verify with active key
        alt any failure including replay and expiry and unknown device
            S->>D: Increment device bio failures, suspend biometrics until next PIN unlock at 5
            S-->>A: 401 AUTH_FAILED, identical body for all failures
            A->>U: Show PIN screen
        else hard locked user
            S-->>A: 401 AUTH_FAILED
            A->>U: Show PIN screen with reset option
        else ok including soft PIN lock
            S->>D: New family, last_unlock_at now, reset bio failures
            S-->>A: 200 session amr bio
            A->>U: Home
        end
    end
    Note over A,S: PIN counter is never touched by biometric results. No screen trusts a local boolean.
```
SEC: 019, 023, 025, 026, 027, 028, 029, 030, 037, 054.
