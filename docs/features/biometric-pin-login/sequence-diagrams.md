# Sequence diagrams: biometric-pin-login

Source of truth: [openapi.yaml](./openapi.yaml), [contract-notes.md](./contract-notes.md), [decisions.md](./decisions.md). All paths are under `/v1`. Participants: User, App (Expo), Secure key (Secure Enclave or Keystore), API (Go), DB (Postgres). Tokens travel only in headers. The PIN travels only in JSON bodies.

## 1. First launch, demo-login, device registration, PIN setup

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

## 2. PIN unlock with soft lock and hard lock

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

## 3. Enable biometrics (two-step enroll with fresh PIN and proof of possession)

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

## 4. Biometric unlock with PIN fallback

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

## 5. Refresh with rotation and reuse detection

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

## 6. Step-up send transaction (biometric under BIO_ONLY_MAX, PIN above, server recomputed hash)

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

## 7. Change PIN, PIN reset and hard-lock recovery with cooling-off

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

## 8. Disable biometrics and revoke device

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

## 9. App launch decision and auto-lock

```mermaid
sequenceDiagram
    autonumber
    participant U as User
    participant A as App
    participant K as Secure key
    participant S as API
    participant D as DB
    A->>A: Cold start, state Booting, privacy overlay on
    A->>A: Device passcode set
    alt no device passcode
        A->>U: Blocking screen, set a passcode, fail closed
    else no refresh token in SecureStore
        A->>U: Onboarding, see diagram 1
    else refresh token present
        A->>A: State Locked, never Unlocked from a local flag
        alt hint true and local key exists
            A->>K: biometric unlock, see diagram 4
            Note over A,S: Any failure falls back to PIN, see diagram 2
        else hint false or no key
            A->>U: PIN screen, see diagram 2
        end
    end
    S-->>A: 200 session from pin verify or biometric verify
    A->>A: State Unlocked, protected routes open
    Note over A: Auto-lock timers
    U->>A: App moves to background
    A->>A: Show privacy overlay immediately, start background timer
    alt returns within 30 s default
        A->>A: Stay unlocked
    else returns after timer or 5 min foreground inactivity
        A->>A: Drop access token and step-up tokens, clear sensitive state, state Locked
        A->>U: Lock screen, unlock by PIN or biometrics
    end
    Note over A,S: Offline means stays locked. There is no local PIN check. The client never reopens on refresh alone, and the server refuses refresh after its unlock window (diagram 5).
```
SEC: 013, 019, 033, 034, 050, 051, 054.
