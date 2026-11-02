# 2. PIN unlock with soft lock and hard lock

← [1. First launch, demo-login, device registration, PIN setup](./01-first-launch-pin-setup.md) · [Index](./README.md) · [3. Enable biometrics (two-step enroll with fresh PIN and proof of possession)](./03-enable-biometrics.md) →

```mermaid
sequenceDiagram
    autonumber
    participant U as User
    participant A as App
    participant K as Secure key
    participant S as API
    participant D as DB
    U->>A: Enter PIN
    A->>S: POST /auth/pin/verify deviceId pin, Authorization is the refresh token
    S->>D: Resolve device credential, no side effects
    alt missing or revoked credential or deviceId mismatch
        S-->>A: 401 AUTH_FAILED, counter untouched
    else credential valid
        S->>D: Reserve attempt, one conditional UPDATE before hashing
        alt zero rows, user is locked
            S-->>A: 423 PIN_LOCKED with lockType hard, or soft with retryAfter
            Note over S,D: No hashing. A correct PIN during a lock is also refused.
        else attempt reserved
            S->>S: Argon2id verify, bounded concurrency
            alt wrong PIN, failures 1 to 4
                S-->>A: 401 PIN_INVALID with attemptsRemaining
            else wrong PIN, failure 5 to 9
                S-->>A: 423 PIN_LOCKED soft, retryAfter, attemptsUntilHardLock
                A->>U: Countdown, UX only, input disabled
            else wrong PIN, failure 10
                S->>D: Set hard_locked
                S-->>A: 423 PIN_LOCKED lockType hard
                A->>U: Show Reset PIN, see diagram 7
            else correct PIN
                S->>D: Clear counters, new family, rotate refresh token, last_unlock_at now
                S-->>A: 200 session amr pin, biometricEnabled, recentFailures
                A->>A: Persist new refresh token first, then use access token
                A->>U: Home, show failed attempts notice if any
            end
        end
    end
    Note over A,S: The 5th wrong attempt itself returns 423. Clearing app storage does not reset the server lock.
```
SEC: 005, 005b, 008, 009, 010, 011, 012, 013, 014, 037.
