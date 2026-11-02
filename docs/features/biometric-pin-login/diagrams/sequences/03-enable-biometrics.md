# 3. Enable biometrics (two-step enroll with fresh PIN and proof of possession)

← [2. PIN unlock with soft lock and hard lock](./02-pin-unlock-lockout.md) · [Index](./README.md) · [4. Biometric unlock with PIN fallback](./04-biometric-unlock.md) →

```mermaid
sequenceDiagram
    autonumber
    participant U as User
    participant A as App
    participant K as Secure key
    participant S as API
    participant D as DB
    U->>A: Settings, Enable biometrics
    A->>K: isSupported
    U->>A: Confirm PIN
    A->>S: POST /stepup/challenge action enable_biometric targetDeviceId
    S->>D: Store step-up challenge, required pin
    S-->>A: 200 challengeId nonce expiresAt boundHash required pin summary
    A->>S: POST /stepup/verify challengeId pin
    alt wrong PIN
        S-->>A: 401 PIN_INVALID or 423 PIN_LOCKED, same user counter as unlock
    else correct PIN
        S->>D: Consume challenge, mint step-up token hash, 60 s
        S-->>A: 200 stepUpToken expiresIn 60
    end
    A->>S: POST /devices/id/biometric/enroll/challenge with X-StepUp-Token
    alt token missing
        S-->>A: 403 STEPUP_REQUIRED
    else token used or expired or other session
        S-->>A: 403 STEPUP_INVALID
    else ok
        S->>D: Consume step-up token, issue enroll challenge bound to session
        S-->>A: 200 challengeId purpose enroll userId deviceId nonce expiresAt
    end
    A->>K: generateKey, biometryCurrentSet or invalidate on enrollment
    K-->>A: public key SPKI and security level
    A->>K: sign enroll message, built from challenge fields
    K->>U: Biometric prompt
    U->>K: Biometric
    K-->>A: DER signature
    A->>S: POST /devices/id/biometric/enroll challengeId publicKey attestation signature, Idempotency-Key
    S->>D: Consume challenge atomically
    S->>S: Parse SPKI P-256 only, verify proof of possession with submitted key
    alt invalid key
        S-->>A: 422 INVALID_PUBLIC_KEY
        A->>K: deleteKey
    else bad signature or expired or replayed
        S-->>A: 401 AUTH_FAILED
        A->>K: deleteKey
    else ok
        S->>D: Revoke previous key, insert key, start cooling-off
        S-->>A: 201 keyId keyFingerprint biometricEnabled true coolingOffUntil
        A->>A: Set biometricEnabled hint true
        A->>U: Biometrics on, cooling-off notice
    end
    Note over A,S: Biometric alone never enables biometrics. Attestation type is none in the demo and is stored untrusted.
```
SEC: 017, 018, 020, 021, 022, 026, 027, 038, 042, 047, 054.
