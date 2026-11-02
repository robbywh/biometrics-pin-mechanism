# Sequence diagrams: biometric-pin-login

Source of truth: [openapi.yaml](../../openapi.yaml), [contract-notes.md](../../contract-notes.md), [decisions.md](../../decisions.md). All paths are under `/v1`. Participants: User, App (Expo), Secure key (Secure Enclave or Keystore), API (Go), DB (Postgres). Tokens travel only in headers. The PIN travels only in JSON bodies.

Diagram numbers below are the ones the flows refer to ("see diagram 2").

| # | Flow | File |
|---|---|---|
| 1 | First launch, demo-login, device registration, PIN setup | [01-first-launch-pin-setup.md](./01-first-launch-pin-setup.md) |
| 2 | PIN unlock with soft lock and hard lock | [02-pin-unlock-lockout.md](./02-pin-unlock-lockout.md) |
| 3 | Enable biometrics (two-step enroll with fresh PIN and proof of possession) | [03-enable-biometrics.md](./03-enable-biometrics.md) |
| 4 | Biometric unlock with PIN fallback | [04-biometric-unlock.md](./04-biometric-unlock.md) |
| 5 | Refresh with rotation and reuse detection | [05-refresh-rotation.md](./05-refresh-rotation.md) |
| 6 | Step-up send transaction (biometric under BIO_ONLY_MAX, PIN above, server recomputed hash) | [06-step-up-transaction.md](./06-step-up-transaction.md) |
| 7 | Change PIN, PIN reset and hard-lock recovery with cooling-off | [07-change-reset-recover-pin.md](./07-change-reset-recover-pin.md) |
| 8 | Disable biometrics and revoke device | [08-disable-biometrics-revoke-device.md](./08-disable-biometrics-revoke-device.md) |
| 9 | App launch decision and auto-lock | [09-app-launch-auto-lock.md](./09-app-launch-auto-lock.md) |
