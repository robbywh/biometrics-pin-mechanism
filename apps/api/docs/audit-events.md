# Audit events (SEC-061) and where they are emitted

Events go to the append-only `audit_events` table (the API DB role has INSERT/SELECT only) and to the audit sink (JSON on stdout; operational logs go to stderr).
Fields: `ts`, `user_id`, `device_id`, `event_type`, `result`, `ip`, `user_agent`, `request_id`, `metadata` (allow-listed keys only, see
`internal/audit/audit.go`), optional `prev_hash` chain (`AUDIT_HASH_CHAIN=true`). Never: PIN, tokens, nonces, signatures, public key bytes, hashes
(a key is only ever referred to by its 8-byte fingerprint).

| Event | Emitted where | Test that triggers it |
|---|---|---|
| PIN_SET | `POST /pin` success | `TestSec61_AuditEventCoverageAndChain` |
| PIN_CHANGED | `PUT /pin` success | same |
| PIN_RESET | `POST /pin/reset` success | same |
| PIN_VERIFY_FAIL | every wrong PIN in `lockout.Attempt` (pin/verify, PUT /pin, step-up) | same |
| PIN_LOCKED | the 5th consecutive failure (first lock) | same |
| PIN_HARD_LOCKED | the 10th failure | same |
| PIN_UNLOCKED_AFTER_LOCK | correct PIN after >= 5 failures (SEC-012) | same, `TestSec7_02_CorrectPinAfterExpiryResets` |
| BIO_ENROLLED | `POST .../biometric/enroll` (fingerprint only) | same |
| BIO_DISABLED | `DELETE .../biometric` when a key was active | same |
| BIO_KEY_INVALIDATED | 5th consecutive bad signature revokes the key | same, `TestSec30_FiveBadSignaturesRevokeKey` |
| BIO_VERIFY_FAIL | bad signature on biometric verify / step-up | same |
| LOGIN_OK(method) | demo-login (`demo`), pin/verify (`pin`), pin set (`pin_set`), biometric verify (`bio`); failed demo-login is `result=fail` | same |
| REFRESH_REUSE | refresh with a used/revoked token | same, `TestSec7_08_RefreshReuseRevokesFamily` |
| DEVICE_ADDED | `POST /devices` | same |
| DEVICE_REVOKED | `DELETE /devices/{id}` | same, `TestSec38_*` |
| DEVICE_BLOCKED | per-device PIN failure block (SEC-009) | same, `TestSec9_DeviceBlockDoesNotTouchUserCounter` |
| STEPUP_OK / STEPUP_FAIL | `POST /stepup/verify` | same |
| TX_CREATED | `POST /transactions` | same |
| COOLING_OFF_STARTED | new (non-first) device, biometric enrollment, PIN reset | same |
| RATE_LIMITED | every 429 from the limiter (class only) | same, `TestSec7_13_*` |

`TestSec61_AuditEventCoverageAndChain` fails if any type in `audit.AllTypes` is never emitted, verifies the hash chain, and shows that
tampering with one row is detected. Retention: 30 days (demo); the API role cannot delete audit rows, so purging is done by the owner role:
`cd apps/api && DATABASE_MIGRATE_URL=... go run ./cmd/migrate purge-audit [days]`.
