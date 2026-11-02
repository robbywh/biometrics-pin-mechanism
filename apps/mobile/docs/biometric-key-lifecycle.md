# Biometric key lifecycle (T15/T16, SEC-017..024, SEC-054)

```
            (no key)  ---- Enable: PIN step-up (stepup/challenge+verify) ----> enroll/challenge (consumes step-up token)
                                                                                       |
                                                              generateKey(alias=bio.<deviceId>)  [SE / StrongBox|TEE, biometryCurrentSet]
                                                                                       |
                                              sign(enroll challenge, purpose=enroll) with the NEW key (biometric prompt = proof of possession)
                                                                                       |
                                         POST .../biometric/enroll ----201----> hint=true, cooling-off notice          ACTIVE
                                                     | any failure/4xx/cancel: deleteKey(alias), hint stays false
ACTIVE --unlock--> biometric/challenge -> sign (OS prompt) -> biometric/verify -> session (amr=bio)
ACTIVE --cancel/lockout/not enrolled/hw unavailable--> PIN screen (key kept)
ACTIVE --OS enrollment change--> sign fails KEY_INVALIDATED -> deleteKey, hint=false -> PIN unlock -> DELETE /devices/{id}/biometric -> notice "re-enable in Settings"
ACTIVE --Settings: turn off--> DELETE /devices/{id}/biometric (needs unlock <= 5 min, else PIN re-unlock then retry once) -> deleteKey, hint=false
ACTIVE --revoke device / PIN reset--> server revokes all keys -> client deleteKey + hint=false (+ new deviceId after reset)
```
The key never leaves hardware; the client holds no boolean that grants access. `biometricEnabled` in unlock responses reconciles the hint (see `src/biometric/reconcile.ts`, decision table in `src/flows/flows.node.test.ts`).
