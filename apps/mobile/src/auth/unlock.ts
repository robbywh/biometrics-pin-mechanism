// Unlock paths. Unlocking happens ONLY via a successful server session response (pin/verify, biometric/verify).
// No function here returns a bare "biometric ok" boolean: biometric unlock returns a tagged outcome and the server decides.
import * as BiometricKey from 'biometric-key';
import * as api from '../api/endpoints';
import type { ApiError } from '../api/errors';
import type { PinBuffer } from '../pin/buffer';
import { buildChallengeMessage } from '../crypto/messages';
import { isValidLoginChallenge } from '../crypto/challengeCheck';
import { base64UrlEncode } from '../crypto/base64url';
import { getDeviceId, getRefreshToken, memory } from '../storage/secureTokens';
import { getBiometricHint, setBiometricHint } from '../storage/hint';
import { biometricAlias } from '../biometric/alias';
import { applyServerSession, noteAuthFailed, wipeCredentials } from './session';
import { authState } from './state';

export type PinUnlockResult = { ok: true; recentFailures: number } | { ok: false; error: ApiError };

/** PIN unlock. Credential = refresh token, or the in-memory device-bound bootstrap token on a fresh install (SEC-014). */
export async function unlockWithPin(pin: PinBuffer): Promise<PinUnlockResult> {
  const boot = memory.getBootstrap();
  const refresh = await getRefreshToken();
  // Fresh install: the device-bound bootstrap token (scope pin-verify) is the credential; otherwise the stored refresh token.
  const useBoot = !!boot?.deviceId && boot.scope === 'pin-verify';
  const credential = useBoot ? boot!.token : refresh;
  const deviceId = useBoot ? boot!.deviceId! : await getDeviceId();
  if (!credential || !deviceId) {
    pin.clear();
    await wipeCredentials();
    return { ok: false, error: { code: 'AUTH_FAILED', status: 401 } };
  }
  const r = await api.verifyPin(credential, deviceId, pin);
  pin.clear();
  if (!r.ok) {
    // Credential missing/revoked -> back to onboarding. Everything else (PIN_INVALID, PIN_LOCKED, ...) is shown as-is.
    // L-12: a single 401 never wipes the identity; only a second consecutive AUTH_FAILED does.
    if (r.error.code === 'AUTH_FAILED' && !useBoot && noteAuthFailed()) await wipeCredentials();
    return r;
  }
  const { recentFailures } = await applyServerSession(r.data);
  memory.setBootstrap(null);
  return { ok: true, recentFailures };
}

export type FallbackReason =
  | 'NO_HINT' | 'NO_KEY' | 'NO_DEVICE' | 'USER_CANCELED' | 'LOCKOUT' | 'NOT_ENROLLED' | 'HARDWARE_UNAVAILABLE' | 'KEY_INVALIDATED'
  | 'SERVER_REJECTED' | 'NETWORK' | 'UNKNOWN';

/** Tagged outcome; there is no boolean. On `fallback` the UI shows the PIN screen with a neutral message. */
export type BiometricOutcome = { status: 'unlocked' } | { status: 'fallback'; reason: FallbackReason };

export async function canOfferBiometric(): Promise<boolean> {
  // Hint AND a local key; both non-authoritative, only used to pick the first screen.
  if (!(await getBiometricHint())) return false;
  const did = await getDeviceId();
  if (!did) return false;
  try { return await BiometricKey.hasKey(biometricAlias(did)); } catch { return false; }
}

export async function unlockWithBiometric(promptTitle = 'Unlock'): Promise<BiometricOutcome> {
  const deviceId = await getDeviceId();
  if (!deviceId) return { status: 'fallback', reason: 'NO_DEVICE' };
  const alias = biometricAlias(deviceId);
  let has = false;
  try { has = await BiometricKey.hasKey(alias); } catch { has = false; }
  if (!has) return { status: 'fallback', reason: 'NO_KEY' };

  // D-18: device credential required. Any 401 here is just a biometric failure: NEVER wipe credentials or the key (L-12).
  const credential = await getRefreshToken();
  if (!credential) return { status: 'fallback', reason: 'NO_KEY' };
  const ch = await api.biometricChallenge(credential, deviceId);
  if (!ch.ok) return { status: 'fallback', reason: ch.error.code === 'NETWORK_ERROR' || ch.error.code === 'TIMEOUT' ? 'NETWORK' : 'SERVER_REJECTED' };

  // M-01: refuse to prompt for (and sign) a challenge that is not a login challenge for THIS device.
  if (!isValidLoginChallenge(ch.data, deviceId)) return { status: 'fallback', reason: 'SERVER_REJECTED' };

  let signature: string;
  try {
    // Built ONLY from the server's challenge values (decoys are signed identically).
    const message = buildChallengeMessage({
      purpose: ch.data.purpose,
      userId: ch.data.userId,
      deviceId: ch.data.deviceId,
      nonce: ch.data.nonce,
      expiresAt: ch.data.expiresAt,
      boundHash: ch.data.boundHash,
    });
    signature = (await BiometricKey.sign(alias, base64UrlEncode(message), promptTitle)).signature;
  } catch (e) {
    const kind = e instanceof BiometricKey.BiometricKeyError ? e.kind : 'UNKNOWN';
    if (kind === 'KEY_INVALIDATED') {
      // SEC-023: delete the key, clear the hint; the server is told after the PIN unlock (see reconcile.ts).
      await BiometricKey.deleteKey(alias).catch(() => undefined);
      await setBiometricHint(false);
      authState.setNotice({ kind: 'biometricInvalidated' });
    }
    return { status: 'fallback', reason: kind };
  }

  const v = await api.biometricVerify(credential, { challengeId: ch.data.challengeId, deviceId, signature });
  if (!v.ok) return { status: 'fallback', reason: v.error.code === 'NETWORK_ERROR' || v.error.code === 'TIMEOUT' ? 'NETWORK' : 'SERVER_REJECTED' };
  try {
    await applyServerSession(v.data);
  } catch {
    return { status: 'fallback', reason: 'UNKNOWN' };
  }
  return { status: 'unlocked' };
}
