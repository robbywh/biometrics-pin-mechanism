// T18: change PIN and device management.
import * as BiometricKey from 'biometric-key';
import * as api from '../api/endpoints';
import { keepIdempotencyKeyAfter, newIdempotencyKey } from '../api/uuid';
import type { PinBuffer } from '../pin/buffer';
import { isWeakPin } from '../pin/policy';
import { applyServerSession, authedCall, wipeCredentials } from '../auth/session';
import { authState } from '../auth/state';
import { biometricAlias } from '../biometric/alias';
import type { FlowResult } from './biometrics';

/** One Idempotency-Key per change attempt; rotated if the server says it saw a different body. */
let changeKey = newIdempotencyKey();

export async function changePin(oldPin: PinBuffer, newPin: PinBuffer, confirm: PinBuffer): Promise<FlowResult | { ok: false; error: { code: 'PIN_MISMATCH' | 'PIN_WEAK_LOCAL' } }> {
  if (!newPin.full || !confirm.full || !oldPin.full || !newPin.equals(confirm)) { oldPin.clear(); newPin.clear(); confirm.clear(); return { ok: false, error: { code: 'PIN_MISMATCH' } }; }
  if (isWeakPin(newPin.digits())) { oldPin.clear(); newPin.clear(); confirm.clear(); return { ok: false, error: { code: 'PIN_WEAK_LOCAL' } }; }
  confirm.clear();
  const r = await authedCall((t) => api.changePin(t, changeKey, oldPin, newPin), { retry: false });
  oldPin.clear(); newPin.clear();
  if (!r.ok) {
    if (!keepIdempotencyKeyAfter(r.error.code)) changeKey = newIdempotencyKey();
    return r;
  }
  changeKey = newIdempotencyKey();
  await applyServerSession(r.data, { unlock: false }); // refresh token written first; hint untouched
  authState.setNotice({ kind: 'pinChanged' });
  return { ok: true };
}

export const loadDevices = () => authedCall((t) => api.listDevices(t));

/** Revoke the CURRENT device: DELETE, then wipe credentials + key and route to onboarding. */
export async function revokeCurrentDevice(): Promise<FlowResult> {
  const s = authState.get().session;
  if (!s) return { ok: false, error: { code: 'NO_SESSION' } };
  const r = await authedCall((t) => api.revokeDevice(t, s.deviceId));
  if (!r.ok && r.error.code !== 'NOT_FOUND') return r;
  await BiometricKey.deleteKey(biometricAlias(s.deviceId)).catch(() => undefined);
  await wipeCredentials();
  return { ok: true };
}

/** Revoke ANOTHER device: PIN step-up (action revoke_device), then DELETE with X-StepUp-Token. */
export async function revokeOtherDevice(targetDeviceId: string, pin: PinBuffer): Promise<FlowResult> {
  const ch = await authedCall((t) => api.stepupChallengeTarget(t, 'revoke_device', targetDeviceId));
  if (!ch.ok) { pin.clear(); return ch; }
  const sv = await authedCall((t) => api.stepupVerifyPin(t, ch.data.challengeId, pin), { retry: false });
  pin.clear();
  if (!sv.ok) return sv;
  const token = sv.data.stepUpToken;
  const r = await authedCall((t) => api.revokeDevice(t, targetDeviceId, token), { retry: false });
  if (!r.ok && r.error.code !== 'NOT_FOUND') return r;
  return { ok: true };
}

/**
 * Sign out of THIS device (M-03): DELETE /devices/{current} revokes sessions, the biometric key and challenges atomically.
 * If that fails (offline etc.) fall back to /auth/logout; either way the local key, hint and credentials are wiped.
 * Returns whether the device record was revoked server-side (false => it stays listed until revoked from another device).
 */
export async function signOut(): Promise<{ deviceRevoked: boolean }> {
  const s = authState.get().session;
  let deviceRevoked = false;
  if (s) {
    const r = await authedCall((t) => api.revokeDevice(t, s.deviceId)).catch(() => null);
    deviceRevoked = !!r && (r.ok || r.error.code === 'NOT_FOUND');
    if (!deviceRevoked) await authedCall((t) => api.logout(t)).catch(() => undefined);
    await BiometricKey.deleteKey(biometricAlias(s.deviceId)).catch(() => undefined);
  }
  await wipeCredentials();
  return { deviceRevoked };
}
