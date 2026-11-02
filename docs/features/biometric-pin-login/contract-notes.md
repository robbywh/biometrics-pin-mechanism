# Contract notes: crypto byte layouts, flows, shared vectors

Authority: this file complements `openapi.yaml`. Where the two disagree, raise it with the tech lead; do not pick one silently.

## 0. Global encodings

- JSON binary fields (nonce, signature, publicKey, boundHash, txHash): **base64url, RFC 4648 section 5, NO padding**. Decoders reject `=`, `+`, `/`, whitespace.
- UUIDs: **lowercase canonical 36-char string** (`xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`). In signed messages the 36 ASCII/UTF-8 bytes of that string are used (not the 16 raw bytes).
- Timestamps in JSON: integer unix **seconds** (`expiresAt`, `authTime`, `coolingOffUntil`). Client clocks are never trusted.
- Public key: **SPKI DER** (`SubjectPublicKeyInfo`, 91 bytes for P-256 uncompressed), base64url. iOS: `SecKeyCopyExternalRepresentation` gives raw X9.63 (0x04||X||Y, 65 bytes), so the native module MUST prepend the fixed P-256 SPKI header `3059301306072a8648ce3d020106082a8648ce3d030107034200` to build SPKI. Android: `PublicKey.getEncoded()` is already SPKI.
- Signature: ECDSA P-256 over **SHA-256(message)**, **ASN.1 DER** `SEQUENCE{INTEGER r, INTEGER s}`. iOS: `SecKeyCreateSignature` with `.ecdsaSignatureMessageX962SHA256` (hashes the message itself, returns DER). Android: `Signature.getInstance("SHA256withECDSA")` (DER). Never pre-hash then sign with the "digest" variant. Server parses strictly: reject trailing bytes, non-minimal INTEGERs, r or s outside [1, n-1]. Low-S is not required (do not reject high-S).
- `lp(x)` = `uint16 big-endian length of x in bytes` followed by `x`. Max 65535. An empty value is `0x0000`.

## 1. Challenge signing message (SEC-027, SEC-043)

```
message = lp("CRYPTOAPP/BIO/v1")
       || lp(purpose)        // ASCII: "login" | "enroll" | "stepup"
       || lp(userId)         // 36-byte lowercase UUID string
       || lp(deviceId)       // 36-byte lowercase UUID string
       || lp(nonce)          // 32 raw bytes (decoded from base64url)
       || lp(expiresAt)      // 8 bytes, uint64 big-endian, unix seconds
       || lp(boundHash)      // 32 raw bytes, or empty (0x0000) when the challenge has no boundHash
signature = ECDSA-P256-SHA256-DER(privateKey, message)
```

- Every field has a length prefix, including fixed-size ones (so the encoding is unambiguous and extensible).
- `purpose` for the step-up flow is `stepup` for ALL actions (transaction, enable_biometric, revoke_device); the action is inside `boundHash` (sections 2 and 3). For `login` and `enroll` `boundHash` is empty. For PoP at enroll the signing key is the NEW key.
- The client builds the message ONLY from the values in the challenge response (never from its own state). The server rebuilds it from its stored challenge; a mismatching field simply fails verification.
- Server decoys (SEC-029) use random userId, challengeId, nonce and `expiresAt = now+60`; the client cannot tell and just signs.

### Worked pre-image (hex, no hashes or signatures included on purpose)

Inputs: purpose `login`, userId `11111111-1111-4111-8111-111111111111`, deviceId `22222222-2222-4222-8222-222222222222`, nonce = bytes `00 01 02 ... 1f`, expiresAt `1700000000` (= `0x6553F100`), boundHash empty. Total 147 bytes. Segments (concatenate in order):

| Segment | Hex |
|---|---|
| lp(tag) | `0010` `43525950544f4150502f42494f2f7631` |
| lp(purpose) | `0005` `6c6f67696e` |
| lp(userId) | `0024` `3131313131313131` `2d` `31313131` `2d` `34313131` `2d` `38313131` `2d` `313131313131313131313131` |
| lp(deviceId) | `0024` `3232323232323232` `2d` `32323232` `2d` `34323232` `2d` `38323232` `2d` `323232323232323232323232` |
| lp(nonce) | `0020` `000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f` |
| lp(expiresAt) | `0008` `000000006553f100` |
| lp(boundHash) | `0000` |

The same segments are in `vectors/vectors.json` (`login-preimage-1`).

## 2. Canonical transaction hash (SEC-039)

```
txPreimage = lp("CRYPTOAPP/TX/v1")
          || lp(asset)          // "BTC" | "ETH" | "USDC", ASCII
          || lp(network)        // "bitcoin" | "ethereum", ASCII
          || lp(destination)    // exact ASCII bytes as submitted; NO case folding, NO trimming
          || lp(amountNorm)     // normalised decimal string, ASCII
          || lp(feeNorm)        // normalised decimal string, ASCII
          || lp(txNonce)        // 36-byte lowercase UUID string
          || lp(expiry)         // base-10 ASCII digits of unix seconds, no leading zeros
txHash = SHA-256(txPreimage)    // 32 bytes; JSON uses base64url (43 chars)
```

Decimal normalisation (`amountNorm`, `feeNorm`): input matches `^(0|[1-9][0-9]{0,17})(\.[0-9]{1,18})?$` (leading zeros such as `01`, a trailing `.`, exponents and signs are rejected 400). Strip trailing zeros from the fraction; if the fraction becomes empty drop the `.`. Examples: `1.50` -> `1.5`, `2.000` -> `2`, `0.10` -> `0.1`, `0` stays `0`. `amount` must be > 0 (422 `VALIDATION_ERROR`); `fee` may be `0`.
Destination: regex `^[A-Za-z0-9]{26,90}$`; case is significant and the server does not fold it (EIP-55 checksums stay intact). Asset/network pairs allowed: BTC/bitcoin, ETH/ethereum, USDC/ethereum. `expiry` must be within (now, now+600 s].
Both `/stepup/challenge` and `/transactions` normalise independently and must produce identical bytes.

Worked tx pre-image (140 bytes) is in `vectors/vectors.json` (`tx-preimage-1`): asset `ETH`, network `ethereum`, destination `0x` + 40 x `a`, amount `1.5` (also test input `1.50`), fee `0.001`, txNonce `33333333-3333-4333-8333-333333333333`, expiry `1700000600`.

## 3. Non-transaction action hash (enable_biometric, revoke_device)

```
actionPreimage = lp("CRYPTOAPP/ACTION/v1") || lp(action) || lp(targetDeviceId)   // action ASCII, id = 36-byte UUID string
boundHash = SHA-256(actionPreimage)
```

## 4. Token and credential semantics (quick reference)

| Token | Format | TTL | Stored (server) | Header |
|---|---|---|---|---|
| bootstrap | opaque 256-bit, base64url | <= 600 s, single purpose, single use for set/reset | SHA-256 hash | `Authorization` |
| access | JWT EdDSA; claims `sub,sid,did,amr,auth_time,scope=session,aud,exp,iat` | 300 s default | not stored (sid checked for revocation) | `Authorization` |
| refresh | opaque 256-bit, base64url | 30 d abs, 7 d idle, rotates | SHA-256 hash + family id | `Authorization` (also used as pin/verify credential) |
| step-up | opaque 256-bit, base64url | 60 s, single use | SHA-256 hash | `X-StepUp-Token` |

Server-enforced unlock window (SEC-033): refresh works only if `now - last_unlock_at <= 900 s` and idle `<= 300 s`. `last_unlock_at` is set by successful pin/verify, biometric verify, successful step-up verify. It is NOT set by refresh.
Refresh failure modes: `AUTH_FAILED` (unknown/used/revoked/expired -> family revoked if reuse), `UNLOCK_REQUIRED` (valid token, window elapsed: token not consumed, nothing revoked). A wrong PIN on pin/verify does not consume the refresh token.

## 5. Key flows (client-visible order)

1. First run: `demo-login(login)` -> `POST /devices` -> `POST /pin` -> session. Store refresh token. Store deviceId (non-secret) in AsyncStorage or SecureStore.
2. PIN unlock: `POST /auth/pin/verify` with `Authorization: Bearer <refresh token>`.
3. Biometric unlock: `/auth/biometric/challenge` -> sign (biometric prompt) -> `/auth/biometric/verify`.
4. Auto-lock return: try `/auth/refresh` (works only inside the unlock window) else unlock via 2 or 3.
5. Enable biometrics: `/stepup/challenge {enable_biometric}` -> `/stepup/verify {pin}` -> `/devices/{id}/biometric/enroll/challenge` (consumes step-up token) -> generate key + sign enroll challenge -> `/devices/{id}/biometric/enroll`.
6. Transaction: `/stepup/challenge {transaction}` -> show `summary` -> `/stepup/verify {signature|pin}` -> `/transactions` with `X-StepUp-Token` + `Idempotency-Key` + same fields.
7. Reset PIN / hard lock: `demo-login(reset)` -> `POST /devices` (new device id) -> `POST /pin/reset`. All old devices are revoked; discard the old deviceId and local key; re-enroll biometrics.
8. Key invalidated: delete local key -> PIN unlock -> `DELETE /devices/{id}/biometric`.

## 6. Shared test vectors (`vectors/vectors.json`)

Owner: tech lead. Neither side edits it. Format:

```json
{
  "version": 1,
  "vectors": [
    { "id": "login-preimage-1", "kind": "challenge-message",
      "input": { "purpose": "...", "userId": "...", "deviceId": "...", "nonceHex": "...", "expiresAt": 1700000000, "boundHashHex": "" },
      "segmentsHex": ["...", "..."] },
    { "id": "tx-preimage-1", "kind": "tx-canonical",
      "input": { "asset": "...", "network": "...", "destination": "...", "amount": "...", "fee": "...", "txNonce": "...", "expiry": 1700000600 },
      "equivalentInputs": [ { "amount": "1.50" } ],
      "segmentsHex": ["..."] }
  ]
}
```

Rules: expected pre-image = hex concatenation of `segmentsHex`. Each side's integration test (a) builds the pre-image from `input` with its production code and asserts byte equality, (b) asserts `txHash == SHA-256(pre-image)` using the platform's standard library (the file deliberately contains NO hash or signature values: they are derived, not stored), (c) asserts every `equivalentInputs` override (merged over `input`) yields the identical pre-image, (d) mutation test: change any one field and assert the pre-image differs. Signature round trip is tested per side with locally generated P-256 keys: Backend verifies a signature it creates over the pre-image; Expo asserts the exact bytes passed to the native signer equal the pre-image (native signer mocked).

## 7. Mock payloads

Examples live inline in `openapi.yaml` (`examples`); the Expo mock server derives happy-path responses from them. Failure scenarios the mock MUST support: PIN_INVALID (attemptsRemaining 3..1), PIN_LOCKED soft (retryAfter 30) and hard, UNLOCK_REQUIRED on refresh, AUTH_FAILED on biometric verify, STEPUP_REQUIRED(required=pin), STEPUP_INVALID, COOLING_OFF, RATE_LIMITED (Retry-After), DEVICE_LIMIT, PIN_WEAK, INVALID_PUBLIC_KEY, IDEMPOTENT_REPLAY, SERVICE_UNAVAILABLE.
