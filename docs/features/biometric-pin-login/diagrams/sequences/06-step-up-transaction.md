# 6. Step-up send transaction (biometric under BIO_ONLY_MAX, PIN above, server recomputed hash)

← [5. Refresh with rotation and reuse detection](./05-refresh-rotation.md) · [Index](./README.md) · [7. Change PIN, PIN reset and hard-lock recovery with cooling-off](./07-change-reset-recover-pin.md) →

```mermaid
sequenceDiagram
    autonumber
    participant U as User
    participant A as App
    participant K as Secure key
    participant S as API
    participant D as DB
    U->>A: Fill send form, asset network destination amount fee
    A->>S: POST /stepup/challenge action transaction with full tx fields
    S->>S: Normalise decimals, build canonical bytes, txHash is SHA-256
    S->>D: Store challenge with bound_hash txHash
    alt cooling-off and amount above COOLING_OFF_MAX
        S-->>A: 403 COOLING_OFF with retryAfter
    else ok
        S-->>A: 200 challengeId nonce expiresAt boundHash txHash required summary
    end
    A->>U: Show server summary, not locally formatted fields
    Note over S: required is either when amount is at most BIO_ONLY_MAX and key is out of cooling-off. Otherwise pin.
    alt required either, user picks biometrics
        A->>K: sign message purpose stepup with boundHash
        K->>U: Biometric prompt
        K-->>A: DER signature
        A->>S: POST /stepup/verify challengeId signature
        alt bad signature or expired or replayed
            S-->>A: 401 AUTH_FAILED
        else ok
            S->>D: Consume challenge, mint step-up token bound to session device action hash
            S-->>A: 200 stepUpToken expiresIn 60
        end
    else required pin, or user picks PIN
        U->>A: Enter PIN
        A->>S: POST /stepup/verify challengeId pin
        alt biometric proof sent but pin required
            S-->>A: 403 STEPUP_REQUIRED with required pin
        else wrong PIN
            S-->>A: 401 PIN_INVALID or 423 PIN_LOCKED, same user counter
        else ok
            S->>D: Consume challenge, mint step-up token
            S-->>A: 200 stepUpToken expiresIn 60
        end
    end
    A->>S: POST /transactions same fields, X-StepUp-Token, Idempotency-Key
    S->>S: Recompute txHash from this body
    S->>D: One transaction, check expiry and balance and cooling-off, consume token, insert tx, debit
    alt token missing
        S-->>A: 403 STEPUP_REQUIRED
    else mismatch or reuse or other session or expired
        S-->>A: 403 STEPUP_INVALID
    else cooling-off cap
        S-->>A: 403 COOLING_OFF
    else insufficient balance
        S-->>A: 422 INSUFFICIENT_FUNDS
    else ok
        S-->>A: 202 transactionId status accepted_mock txHash
        A->>U: Sent
    end
    Note over A,S: Same Idempotency-Key and body returns the stored 202. A different body returns 422 IDEMPOTENCY_KEY_REUSED.
```
SEC: 026, 027, 038, 039, 040, 041, 042, 043, 044, 047, 060.
