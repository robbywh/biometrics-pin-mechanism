# Biometric

[← API contracts index](./README.md) · Tag: `biometric`

Biometrics never send a boolean to the server. They unlock a hardware-backed P-256 key, and the client signs a server challenge with it.

- Signing message: [contract-notes.md §1](../contract-notes.md).
- Signature: ECDSA P-256 over SHA-256, ASN.1 DER, base64url.

## POST /auth/biometric/challenge

Requests a login challenge. The endpoint is non-oracular: it does not reveal whether biometric login is possible for this device.

- **Auth:** `Authorization: Bearer <refresh-token>` (`deviceCredential`). This was added in v1.1.
- **Rate limits:** 10/min/device and 30/min/IP (decisions D-12).

**Rules**

- The body `deviceId` must equal the credential's device. If it does not, the call returns 401 `AUTH_FAILED`.
- The credential is only looked up. It is not consumed, rotated or reuse-checked here.
- Each device has one live login challenge at a time.

**Decoys.** A valid credential always gets a well-formed 200. In these cases `nonce`, `challengeId` and `userId` are decoys and nothing is stored as live:

- the device has no active key
- biometrics are suspended (SEC-030)
- the user is hard-locked

The decoy `userId` is derived stably per device. The client cannot tell a decoy from a real challenge (SEC-029).

### Request body

| Field | Type | Req | Constraints |
|---|---|---|---|
| `deviceId` | `Uuid` | yes | must match the credential |

```json
{ "deviceId": "<device-id>" }
```

### Responses

**200** Challenge. Header: `Cache-Control: no-store`. Body: [Challenge](./schemas.md#challenge-login--enroll) with `purpose: login`.

```json
{
  "challengeId": "<challenge-id>",
  "purpose": "login",
  "userId": "<user-id>",
  "deviceId": "<device-id>",
  "nonce": "<nonce-base64url>",
  "expiresAt": 1767225660
}
```

| Status | Code | When |
|---|---|---|
| 400 | `VALIDATION_ERROR` | malformed body |
| 401 | `AUTH_FAILED` | credential missing or bad, or device mismatch |
| 429 | `RATE_LIMITED` | |

Plus the shared [default errors](./README.md#errors).

**Sequences:** [4. Biometric unlock with PIN fallback](../diagrams/sequences/04-biometric-unlock.md).

**SEC:** SEC-014, SEC-025, SEC-027, SEC-029, SEC-030.

## POST /auth/biometric/verify

Verifies the signed login challenge and returns a new session with `amr=bio`.

- **Auth:** `Authorization: Bearer <refresh-token>` (`deviceCredential`). This was added in v1.1.
- **Rate limits:** 10/min/device and 30/min/IP (decisions D-12).

**Rules**

- The body `deviceId` must equal the credential's device.
- The credential is looked up without side effects.
- The server rebuilds the signed message from its stored challenge.

**What the server checks**

- The device is not revoked.
- The user is not hard-locked.
- The device has an active key, and biometrics are not suspended.
- The challenge is live and unconsumed.
- The signature is valid.

**On failure.** Every failure returns the identical 401 `AUTH_FAILED`, including a missing or bad credential.

**Locks and suspension**

- Biometric unlock is allowed during a **soft** PIN lock and refused during a **hard** lock.
- After 5 consecutive failures, biometric login is **suspended** for the device until the next successful PIN unlock. The key is not revoked, the PIN counter is not touched, and audit event `BIO_SUSPENDED` is written.

**On success.** A new session family is created. The presented refresh token is replaced by the one in the response.

### Request body

| Field | Type | Req | Constraints |
|---|---|---|---|
| `challengeId` | `Uuid` | yes | from the challenge |
| `deviceId` | `Uuid` | yes | must match the credential |
| `signature` | `Base64Url` | yes | DER ECDSA P-256 |
| `risk` | [`RiskSignals`](./schemas.md#risksignals) | no | advisory |

```json
{ "challengeId": "<challenge-id>", "deviceId": "<device-id>", "signature": "<signature-base64url>" }
```

### Responses

**200** Unlocked. Header: `Cache-Control: no-store`. Body: [SessionResponse](./schemas.md#sessionresponse) with `amr: bio`.

| Status | Code | When |
|---|---|---|
| 400 | `VALIDATION_ERROR` | malformed body |
| 401 | `AUTH_FAILED` | every failure mode (uniform) |
| 429 | `RATE_LIMITED` | |

Plus the shared [default errors](./README.md#errors).

**Sequences:** [4. Biometric unlock with PIN fallback](../diagrams/sequences/04-biometric-unlock.md).

**SEC:** SEC-019, SEC-026, SEC-027, SEC-028, SEC-029, SEC-030, SEC-035.

## POST /devices/{deviceId}/biometric/enroll/challenge

Step 1 of enrollment. It issues an enroll challenge and **consumes** the PIN step-up token.

**Path parameter:** `deviceId` (`Uuid`). It must equal the access token's `did`; otherwise the call returns 404.

**Auth and headers**

| Header | Value |
|---|---|
| `Authorization` | `Bearer <access-token>` |
| `X-StepUp-Token` | `<step-up-token>` |

- Get the step-up token from `/stepup` with action `enable_biometric` and `targetDeviceId` equal to the path id. The proof must be a PIN: a biometric alone never enables biometrics.

**Rules**

- The resulting challenge is bound to the session and the device.
- Each device has one live enroll challenge; a new request replaces the old one.
- **Rate limit:** 5/h/user.

**Request body:** none.

### Responses

**200** Enroll challenge. Header: `Cache-Control: no-store`. Body: [Challenge](./schemas.md#challenge-login--enroll) with `purpose: enroll`.

| Status | Code | When |
|---|---|---|
| 401 | `AUTH_FAILED` | bad access token |
| 403 | `STEPUP_REQUIRED` | header missing |
| 403 | `STEPUP_INVALID` | token bad, used, expired or mismatched |
| 404 | `NOT_FOUND` | path id is not the caller's device |
| 429 | `RATE_LIMITED` | |

Plus the shared [default errors](./README.md#errors).

**Sequences:** [3. Enable biometrics](../diagrams/sequences/03-enable-biometrics.md).

**SEC:** SEC-020, SEC-038.

## POST /devices/{deviceId}/biometric/enroll

Step 2 of enrollment. The client submits the new public key with proof of possession.

**Path parameter:** `deviceId` (`Uuid`).

**Auth and headers**

| Header | Value |
|---|---|
| `Authorization` | `Bearer <access-token>` |
| `Idempotency-Key` | UUIDv4, required |

**What the client does.** After a biometric prompt, it signs the enroll challenge with the **new** key. The message uses purpose `enroll` and an empty `boundHash`.

**What the server checks**

- The signature verifies against the submitted `publicKey`.
- `publicKey` is SPKI DER, P-256 only, ≤ 200 bytes, with a point on the curve.

**Rules**

- The challenge is consumed on the first attempt.
- On success, any previous key is revoked atomically and cooling-off starts.
- In the demo, attestation is stored but not verified (type `none`).

### Request body

| Field | Type | Req | Constraints |
|---|---|---|---|
| `challengeId` | `Uuid` | yes | from enroll challenge |
| `publicKey` | `Base64Url` | yes | SPKI DER, P-256 |
| `attestation` | `Attestation` | yes | see below |
| `signature` | `Base64Url` | yes | DER ECDSA P-256 |

`Attestation`:

| Field | Type | Req | Values |
|---|---|---|---|
| `type` | string | yes | `none`, `android_key`, `app_attest`, `play_integrity` |
| `keySecurityLevel` | string | yes | `secure_enclave`, `strongbox`, `tee`, `software`, `unknown` |
| `data` | `Base64Url` | no | |

- In the demo, `type` must be `none`. `keySecurityLevel` is self-reported and not trusted in the demo.

```json
{
  "challengeId": "<challenge-id>",
  "publicKey": "<spki-public-key-base64url>",
  "attestation": { "type": "none", "keySecurityLevel": "secure_enclave" },
  "signature": "<signature-base64url>"
}
```

### Responses

**201** Key active. **200** Idempotent replay (same key and same body), with the same shape and no secrets.

| Field | Type | Req | Notes |
|---|---|---|---|
| `keyId` | `Uuid` | yes | |
| `keyFingerprint` | string | yes | base64url of the first 8 bytes of SHA-256(SPKI) |
| `biometricEnabled` | boolean | yes | |
| `coolingOffUntil` | `UnixSeconds` | no | |

```json
{ "keyId": "<key-id>", "keyFingerprint": "<key-fingerprint>", "biometricEnabled": true, "coolingOffUntil": 1767312000 }
```

| Status | Code | When |
|---|---|---|
| 400 | `VALIDATION_ERROR` | malformed body or missing header |
| 401 | `AUTH_FAILED` | bad proof of possession, expired or replayed challenge |
| 404 | `NOT_FOUND` | path id not the caller's device |
| 422 | `INVALID_PUBLIC_KEY` | key not valid P-256 SPKI |
| 422 | `IDEMPOTENCY_KEY_REUSED` | same key, different body |
| 422 | `VALIDATION_ERROR` | semantically invalid |
| 429 | `RATE_LIMITED` | |

Plus the shared [default errors](./README.md#errors).

**Sequences:** [3. Enable biometrics](../diagrams/sequences/03-enable-biometrics.md).

**SEC:** SEC-017, SEC-018, SEC-020, SEC-021, SEC-022, SEC-047, SEC-060.

## DELETE /devices/{deviceId}/biometric

Disables biometrics for the device. This revokes the key and its challenges.

**Path parameter:** `deviceId` (`Uuid`).

- **Auth:** `Authorization: Bearer <access-token>`.
- **Request body:** none.

**Rules**

- The call is allowed only when the session's `last_unlock_at` is within 5 minutes. A PIN unlock, a biometric unlock or a step-up sets that value.
- Otherwise it returns 403 `STEPUP_REQUIRED`. The client then re-unlocks and retries.
- Use it right after a PIN unlock when the local key has been invalidated (SEC-023).
- It is idempotent: for an owned device it returns 204 even when nothing is enrolled.

### Responses

**204** Disabled. There is no body.

| Status | Code | When |
|---|---|---|
| 401 | `AUTH_FAILED` | bad access token |
| 403 | `STEPUP_REQUIRED` | last unlock older than 5 min |
| 404 | `NOT_FOUND` | unknown or foreign device |
| 429 | `RATE_LIMITED` | |

Plus the shared [default errors](./README.md#errors).

**Sequences:**

- [4. Biometric unlock (key invalidated)](../diagrams/sequences/04-biometric-unlock.md)
- [8. Disable biometrics and revoke device](../diagrams/sequences/08-disable-biometrics-revoke-device.md)

**SEC:** SEC-023, SEC-024, SEC-038.
