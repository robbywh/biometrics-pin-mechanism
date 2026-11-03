# 5. Refresh with rotation and reuse detection

← [4. Biometric unlock with PIN fallback](./04-biometric-unlock.md) · [Index](./README.md) · [6. Step-up send transaction (biometric under BIO_ONLY_MAX, PIN above, server recomputed hash)](./06-step-up-transaction.md) →

```mermaid
sequenceDiagram
    autonumber
    participant U as User
    participant A as App
    participant K as Secure key
    participant S as API
    participant D as DB
    A->>A: Access token near expiry, one in-flight refresh only
    A->>S: POST /auth/refresh, Authorization is the refresh token, no body
    S->>D: Find session by refresh hash
    alt unknown or expired
        S-->>A: 401 AUTH_FAILED
        A->>A: Clear credentials, go to onboarding
    else already used or revoked, token reuse
        S->>D: Revoke whole family, audit REFRESH_REUSE
        S-->>A: 401 AUTH_FAILED
        A->>A: Clear credentials, go to onboarding
    else valid but unlock window elapsed
        Note over S,D: More than 15 min since unlock or more than 5 min idle
        S-->>A: 401 UNLOCK_REQUIRED, token not consumed or rotated
        A->>U: Show lock screen, unlock by PIN or biometrics
    else valid and inside window
        S->>D: Compare and set used_at, insert child session with new hash
        S-->>A: 200 new accessToken and rotated refreshToken
        A->>A: Write new refresh token to SecureStore before using access token
    end
    Note over A,S: Lost response after rotation strands the token, user re-bootstraps through demo-login, see ADR-007.
```
SEC: 014, 031, 032, 033, 034, 035, 036, 037.
