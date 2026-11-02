// T15 enable / T16 disable biometrics. The key lifecycle is documented in docs/biometric-key-lifecycle.md.
import * as BiometricKey from 'biometric-key';
import * as api from '../api/endpoints';
import type { ApiError } from '../api/errors';
import { newIdempotencyKey } from '../api/uuid';
import { base64UrlEncode } from '../crypto/base64url';
import { buildChallengeMessage } from '../crypto/messages';
import type { PinBuffer } from '../pin/buffer';
import { authedCall } from '../auth/session';
import { authState } from '../auth/state';
import { setBiometricHint } from '../storage/hint';
import { memory } from '../storage/secureTokens';
import { biometricAlias } from '../biometric/alias';

export type FlowError =
  | ApiError
  | { code: 'BIO_UNAVAILABLE'; reason: string }
  | { code: 'BIO_KEY_ERROR'; kind: BiometricKey.BiometricKeyErrorKind }
  | { code: 'NO_SESSION' }
  | { code: 'REAUTH_REQUIRED' };
export type FlowResult = { ok: true } | { ok: false; error: FlowError };

const deviceIdOrNull = () => authState.get().session?.deviceId ?? null;

/**
 * Enable biometrics. The only entry is a fresh PIN (never biometric alone). Any failure AFTER key creation deletes the key, and
 * the hint is set only after the server answered 201.
 */
export async function enableBiometrics(pin: PinBuffer): Promise<FlowResult> {
  const deviceId = deviceIdOrNull();
  if (!deviceId) { pin.clear(); return { ok: false, error: { code: 'NO_SESSION' } }; }
  let support: BiometricKey.SupportInfo;
  try { support = await BiometricKey.isSupported(); } catch (e) {
    pin.clear();
    return { ok: false, error: { code: 'BIO_KEY_ERROR', kind: e instanceof BiometricKey.BiometricKeyError ? e.kind : 'UNKNOWN' } };
  }
  if (!support.secureHardware || !support.biometricEnrolled) { pin.clear(); return { ok: false, error: { code: 'BIO_UNAVAILABLE', reason: support.reason } }; }

  // 1) step-up with PIN (60 s TTLs: STEPUP_INVALID surfaces as "try again")
  const ch = await authedCall((t) => api.stepupChallengeTarget(t, 'enable_biometric', deviceId));
  if (!ch.ok) { pin.clear(); return ch; }
  const sv = await authedCall((t) => api.stepupVerifyPin(t, ch.data.challengeId, pin), { retry: false });
  pin.clear();
  if (!sv.ok) return sv;
  memory.setStepUp(sv.data.stepUpToken);

  // 2) enroll challenge (consumes the step-up token server-side)
  const stepUp = memory.takeStepUp()!;
  const ec = await authedCall((t) => api.biometricEnrollChallenge(t, deviceId, stepUp), { retry: false });
  if (!ec.ok) return ec;

  // 3) generate the key and prove possession with it (biometric prompt)
  const alias = biometricAlias(deviceId);
  let generated: BiometricKey.GeneratedKey;
  try {
    generated = await BiometricKey.generateKey(alias, __DEV__);
  } catch (e) {
    await BiometricKey.deleteKey(alias).catch(() => undefined);
    return { ok: false, error: { code: 'BIO_KEY_ERROR', kind: e instanceof BiometricKey.BiometricKeyError ? e.kind : 'UNKNOWN' } };
  }
  try {
    const message = buildChallengeMessage({
      purpose: ec.data.purpose, userId: ec.data.userId, deviceId: ec.data.deviceId, nonce: ec.data.nonce, expiresAt: ec.data.expiresAt, boundHash: ec.data.boundHash,
    });
    const { signature } = await BiometricKey.sign(alias, base64UrlEncode(message), 'Enable biometric unlock');
    const enroll = await authedCall(
      (t) =>
        api.biometricEnroll(t, deviceId, newIdempotencyKey(), {
          challengeId: ec.data.challengeId,
          publicKey: generated.publicKeySpki,
          attestation: { type: 'none', keySecurityLevel: generated.securityLevel },
          signature,
        }),
      { retry: false },
    );
    if (!enroll.ok) {
      await BiometricKey.deleteKey(alias).catch(() => undefined);
      return enroll;
    }
    await setBiometricHint(true); // only after 201/200
    authState.patchSession({ biometricEnabled: true });
    if (enroll.data.coolingOffUntil) authState.setNotice({ kind: 'coolingOff', until: enroll.data.coolingOffUntil });
    return { ok: true };
  } catch (e) {
    await BiometricKey.deleteKey(alias).catch(() => undefined);
    return { ok: false, error: { code: 'BIO_KEY_ERROR', kind: e instanceof BiometricKey.BiometricKeyError ? e.kind : 'UNKNOWN' } };
  }
}

const REAUTH_WINDOW_S = 300;

/** Disable biometrics: server first (needs a recent unlock), then delete the local key and clear the hint. */
export async function disableBiometrics(now = Math.floor(Date.now() / 1000)): Promise<FlowResult> {
  const s = authState.get().session;
  if (!s) return { ok: false, error: { code: 'NO_SESSION' } };
  if (now - s.authTime > REAUTH_WINDOW_S) return { ok: false, error: { code: 'REAUTH_REQUIRED' } };
  const r = await authedCall((t) => api.biometricDisable(t, s.deviceId));
  if (!r.ok) {
    if (r.error.code === 'STEPUP_REQUIRED') return { ok: false, error: { code: 'REAUTH_REQUIRED' } };
    if (r.error.code !== 'NOT_FOUND') return r; // 404 = already gone
  }
  await BiometricKey.deleteKey(biometricAlias(s.deviceId)).catch(() => undefined);
  await setBiometricHint(false);
  authState.patchSession({ biometricEnabled: false });
  return { ok: true };
}
