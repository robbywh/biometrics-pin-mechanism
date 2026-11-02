// Typed endpoint functions: the ONLY place that talks to the network. All types come from the generated contract.
// Credentials are passed in by the caller (session layer) and never logged. PINs are taken from PinBuffer at the last moment.
import type { components } from './generated/schema';
import { getApi, TimeoutSignal } from './client';
import { mapError, type ApiError } from './errors';
import type { PinBuffer } from '../pin/buffer';
import { getRiskSignals } from '../risk/signals';

type S = components['schemas'];
export type SessionResponse = S['SessionResponse'];
export type Challenge = S['Challenge'];
export type StepUpChallenge = S['StepUpChallenge'];
export type TransactionFields = S['TransactionFields'];
export type Dashboard = S['Dashboard'];
export type Device = S['Device'];
export type BootstrapResponse = S['BootstrapResponse'];
export type RegisterDeviceResponse = S['RegisterDeviceResponse'];
export type BiometricEnrollResponse = S['BiometricEnrollResponse'];
export type Attestation = S['Attestation'];
export type TransactionResponse = S['TransactionResponse'];

export type ApiResult<T> = { ok: true; status: number; data: T } | { ok: false; error: ApiError };

interface FR<D> {
  data?: D;
  error?: unknown;
  response: Response;
}

async function run<D>(f: () => Promise<FR<D>>): Promise<ApiResult<D>> {
  try {
    const r = await f();
    if (r.response.ok) return { ok: true, status: r.response.status, data: r.data as D };
    return { ok: false, error: mapError(r.response.status, r.error, r.response.headers.get('Retry-After')) };
  } catch (e) {
    return { ok: false, error: e instanceof TimeoutSignal ? { code: 'TIMEOUT' } : { code: 'NETWORK_ERROR' } };
  }
}

const bearer = (token: string) => ({ Authorization: `Bearer ${token}` });
const api = () => getApi().client;

// ---- bootstrap / devices ----
export const demoLogin = (b: S['DemoLoginRequest']) => run(() => api().POST('/auth/demo-login', { body: b }));

export async function registerDevice(token: string, idempotencyKey: string, b: { name: string; platform: 'ios' | 'android' }) {
  const risk = await getRiskSignals();
  return run(() =>
    api().POST('/devices', {
      body: { ...b, risk },
      headers: bearer(token),
      params: { header: { 'Idempotency-Key': idempotencyKey } },
    }),
  );
}
export const listDevices = (token: string) => run(() => api().GET('/devices', { headers: bearer(token) }));
export const revokeDevice = (token: string, deviceId: string, stepUpToken?: string) =>
  run(() =>
    api().DELETE('/devices/{deviceId}', {
      params: { path: { deviceId }, header: { 'X-StepUp-Token': stepUpToken } },
      headers: bearer(token),
    }),
  );

// ---- PIN / session ----
export const setPin = (token: string, idempotencyKey: string, pin: PinBuffer) =>
  run(() => api().POST('/pin', { body: { pin: pin.take() }, headers: bearer(token), params: { header: { 'Idempotency-Key': idempotencyKey } } }));
export const resetPin = (token: string, idempotencyKey: string, pin: PinBuffer) =>
  run(() => api().POST('/pin/reset', { body: { pin: pin.take() }, headers: bearer(token), params: { header: { 'Idempotency-Key': idempotencyKey } } }));
export const changePin = (token: string, idempotencyKey: string, oldPin: PinBuffer, newPin: PinBuffer) =>
  run(() =>
    api().PUT('/pin', {
      body: { oldPin: oldPin.take(), newPin: newPin.take() },
      headers: bearer(token),
      params: { header: { 'Idempotency-Key': idempotencyKey } },
    }),
  );
/** credential = refresh token, or the device-bound bootstrap token on a fresh install (SEC-014). */
export async function verifyPin(credential: string, deviceId: string, pin: PinBuffer) {
  const risk = await getRiskSignals();
  return run(() => api().POST('/auth/pin/verify', { body: { deviceId, pin: pin.take(), risk }, headers: bearer(credential) }));
}
export const refresh = (refreshToken: string) => run(() => api().POST('/auth/refresh', { headers: bearer(refreshToken) }));
export const logout = (token: string) => run(() => api().POST('/auth/logout', { headers: bearer(token) }));

// ---- biometric ----
export const biometricChallenge = (deviceId: string) => run(() => api().POST('/auth/biometric/challenge', { body: { deviceId } }));
export async function biometricVerify(b: { challengeId: string; deviceId: string; signature: string }) {
  const risk = await getRiskSignals();
  return run(() => api().POST('/auth/biometric/verify', { body: { ...b, risk } }));
}
export const biometricEnrollChallenge = (token: string, deviceId: string, stepUpToken: string) =>
  run(() =>
    api().POST('/devices/{deviceId}/biometric/enroll/challenge', {
      params: { path: { deviceId }, header: { 'X-StepUp-Token': stepUpToken } },
      headers: bearer(token),
    }),
  );
export const biometricEnroll = (token: string, deviceId: string, idempotencyKey: string, body: S['BiometricEnrollRequest']) =>
  run(() =>
    api().POST('/devices/{deviceId}/biometric/enroll', {
      params: { path: { deviceId }, header: { 'Idempotency-Key': idempotencyKey } },
      body,
      headers: bearer(token),
    }),
  );
export const biometricDisable = (token: string, deviceId: string) =>
  run(() => api().DELETE('/devices/{deviceId}/biometric', { params: { path: { deviceId } }, headers: bearer(token) }));

// ---- step-up / transactions ----
export const stepupChallengeTx = (token: string, tx: TransactionFields) =>
  run(() => api().POST('/stepup/challenge', { body: { action: 'transaction', tx }, headers: bearer(token) }));
export const stepupChallengeTarget = (token: string, action: 'enable_biometric' | 'revoke_device', targetDeviceId: string) =>
  run(() => api().POST('/stepup/challenge', { body: { action, targetDeviceId }, headers: bearer(token) }));
export const stepupVerifyPin = (token: string, challengeId: string, pin: PinBuffer) =>
  run(() => api().POST('/stepup/verify', { body: { challengeId, pin: pin.take() }, headers: bearer(token) }));
export const stepupVerifySignature = (token: string, challengeId: string, signature: string) =>
  run(() => api().POST('/stepup/verify', { body: { challengeId, signature }, headers: bearer(token) }));
export const createTransaction = (token: string, idempotencyKey: string, stepUpToken: string, tx: TransactionFields) =>
  run(() =>
    api().POST('/transactions', {
      body: tx,
      headers: bearer(token),
      params: { header: { 'Idempotency-Key': idempotencyKey, 'X-StepUp-Token': stepUpToken } },
    }),
  );
export const getDashboard = (token: string) => run(() => api().GET('/dashboard', { headers: bearer(token) }));

export async function healthz(): Promise<boolean> {
  try {
    const r = await fetch(`${getApi().base.origin}/healthz`);
    return r.ok;
  } catch {
    return false;
  }
}
