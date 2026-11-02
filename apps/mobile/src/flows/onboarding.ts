// T12 / T17: demo-login -> device registration -> PIN setup (or PIN reset / hard-lock recovery).
// Bootstrap tokens live in memory only (never persisted); restarting the app restarts the flow safely.
import { Platform } from 'react-native';
import * as BiometricKey from 'biometric-key';
import * as api from '../api/endpoints';
import type { ApiError } from '../api/errors';
import { keepIdempotencyKeyAfter, newIdempotencyKey } from '../api/uuid';
import type { PinBuffer } from '../pin/buffer';
import { isWeakPin } from '../pin/policy';
import { getDeviceId, memory } from '../storage/secureTokens';
import { setBiometricHint } from '../storage/hint';
import { biometricAlias } from '../biometric/alias';
import { applyServerSession } from '../auth/session';
import { unlockWithPin, type PinUnlockResult } from '../auth/unlock';

export type Intent = 'login' | 'reset';

/** One object per attempt; Idempotency-Keys live here so a retry of the SAME attempt reuses them (SEC-060). */
interface Attempt {
  intent: Intent;
  scope: 'pin-setup' | 'pin-verify' | 'pin-reset';
  deviceKey: string;
  pinKey: string;
  deviceRegistered: boolean;
}
let attempt: Attempt | null = null;

export type StepResult<T = undefined> = ({ ok: true } & (T extends undefined ? object : { data: T })) | { ok: false; error: ApiError | { code: 'PIN_MISMATCH' | 'PIN_WEAK_LOCAL' | 'NO_FLOW' } };

export function currentScope(): Attempt['scope'] | null {
  return attempt?.scope ?? null;
}

/** Step 1: demo-login. The secret is passed through and never retained. */
export async function startBootstrap(username: string, secret: string, intent: Intent): Promise<StepResult<Attempt['scope']>> {
  const r = await api.demoLogin({ username, secret, intent });
  if (!r.ok) return r;
  memory.setBootstrap({ token: r.data.bootstrapToken, scope: r.data.scope });
  attempt = { intent, scope: r.data.scope, deviceKey: newIdempotencyKey(), pinKey: newIdempotencyKey(), deviceRegistered: false };
  return { ok: true, data: r.data.scope };
}

/** Step 2: register this installation (server generates deviceId). Safe to retry with the same key. */
export async function registerThisDevice(deviceName: string): Promise<StepResult> {
  const boot = memory.getBootstrap();
  if (!attempt || !boot) return { ok: false, error: { code: 'NO_FLOW' } };
  if (attempt.deviceRegistered) return { ok: true };
  const r = await api.registerDevice(boot.token, attempt.deviceKey, { name: deviceName.slice(0, 64), platform: Platform.OS === 'ios' ? 'ios' : 'android' });
  if (!r.ok) {
    if (!keepIdempotencyKeyAfter(r.error.code)) attempt.deviceKey = newIdempotencyKey();
    return r;
  }
  memory.setBootstrap({ ...boot, deviceId: r.data.deviceId });
  attempt.deviceRegistered = true;
  return { ok: true };
}

function checkPins(pin: PinBuffer, confirm: PinBuffer): StepResult | null {
  if (!pin.full || !confirm.full || !pin.equals(confirm)) return { ok: false, error: { code: 'PIN_MISMATCH' } };
  if (isWeakPin(pin.digits())) return { ok: false, error: { code: 'PIN_WEAK_LOCAL' } };
  return null;
}

/** Step 3a (scope pin-setup): POST /pin, then session. Buffers are always cleared. */
export async function setInitialPin(pin: PinBuffer, confirm: PinBuffer): Promise<StepResult> {
  const boot = memory.getBootstrap();
  if (!attempt || !boot) { pin.clear(); confirm.clear(); return { ok: false, error: { code: 'NO_FLOW' } }; }
  const bad = checkPins(pin, confirm);
  confirm.clear();
  if (bad) { pin.clear(); return bad; }
  const r = await api.setPin(boot.token, attempt.pinKey, pin);
  pin.clear();
  if (!r.ok) {
    if (!keepIdempotencyKeyAfter(r.error.code)) attempt.pinKey = newIdempotencyKey();
    if (r.error.code === 'IDEMPOTENT_REPLAY' || r.error.code === 'PIN_ALREADY_SET') endFlow();
    return r;
  }
  await applyServerSession(r.data);
  endFlow();
  return { ok: true };
}

/** Step 3b (scope pin-verify, new install of an account that has a PIN): PIN unlock with the device-bound bootstrap token. */
export async function unlockNewInstall(pin: PinBuffer): Promise<PinUnlockResult> {
  const r = await unlockWithPin(pin);
  if (r.ok) endFlow();
  return r;
}

/** Step 3c (T17, scope pin-reset): POST /pin/reset; old deviceId/key are discarded locally. */
export async function resetPinWithNewDevice(pin: PinBuffer, confirm: PinBuffer): Promise<StepResult> {
  const boot = memory.getBootstrap();
  if (!attempt || !boot) { pin.clear(); confirm.clear(); return { ok: false, error: { code: 'NO_FLOW' } }; }
  const bad = checkPins(pin, confirm);
  confirm.clear();
  if (bad) { pin.clear(); return bad; }
  const oldDeviceId = await getDeviceId();
  const r = await api.resetPin(boot.token, attempt.pinKey, pin);
  pin.clear();
  if (!r.ok) {
    if (!keepIdempotencyKeyAfter(r.error.code)) attempt.pinKey = newIdempotencyKey();
    if (r.error.code === 'IDEMPOTENT_REPLAY') endFlow();
    return r;
  }
  // The server revoked every old device and key: drop the local key and hint before adopting the new identity.
  if (oldDeviceId) await BiometricKey.deleteKey(biometricAlias(oldDeviceId)).catch(() => undefined);
  await setBiometricHint(false);
  await applyServerSession(r.data);
  endFlow();
  return { ok: true };
}

export function endFlow(): void {
  attempt = null;
  memory.setBootstrap(null);
}
