// Session holder: access token in memory, rotated refresh token in SecureStore, single-flight refresh, error policies.
// T8 / T9. Never logs. Never stores lock state. Every API call in the app goes through `authedCall`.
import * as api from '../api/endpoints';
import type { ApiError } from '../api/errors';
import { clearCredentials, getDeviceId, getRefreshToken, memory, saveDeviceId, saveRefreshToken } from '../storage/secureTokens';
import { authState } from './state';
import { reconcileBiometricHint } from '../biometric/reconcile';
import { biometricAlias } from '../biometric/alias';
import * as BiometricKey from 'biometric-key';
import { setBiometricHint } from '../storage/hint';

let inflightRefresh: Promise<'ok' | 'locked' | 'gone' | 'network'> | null = null;

export class SessionPersistError extends Error {}

/** Locks the app: drops access + step-up tokens from memory; the refresh token stays in SecureStore. */
export function lock(): void {
  memory.clearAll();
  inflightRefresh = null;
  if (authState.get().status === 'unlocked') authState.toLocked();
}

/** Credential is gone/revoked: wipe everything local that identifies this install and go to onboarding. */
export async function wipeCredentials(): Promise<void> {
  const did = await getDeviceId().catch(() => null);
  memory.clearAll();
  await clearCredentials();
  if (did) {
    try { await BiometricKey.deleteKey(biometricAlias(did)); } catch { /* best effort */ }
  }
  await setBiometricHint(false);
  authState.toOnboarding();
}

export interface UnlockResult {
  recentFailures: number;
}

/**
 * Applies a server session response (pin/verify, biometric/verify, pin set/change/reset, refresh).
 * Write-then-use: the rotated refresh token is persisted BEFORE the access token is used. A failed write is a fatal lock.
 * `unlock` = true only for responses that prove a fresh unlock (not refresh).
 */
export async function applyServerSession(resp: api.SessionResponse, opts: { unlock: boolean } = { unlock: true }): Promise<UnlockResult> {
  try {
    await saveRefreshToken(resp.refreshToken);
    await saveDeviceId(resp.deviceId);
  } catch {
    lock();
    throw new SessionPersistError('persist failed');
  }
  memory.setAccess(resp.accessToken, resp.expiresIn);
  const recentFailures = resp.recentFailures ?? 0;
  if (opts.unlock || authState.get().status === 'unlocked') {
    authState.__unlockFromServerSession({
      deviceId: resp.deviceId,
      amr: resp.amr,
      authTime: resp.authTime,
      biometricEnabled: resp.biometricEnabled,
      ...(resp.coolingOffUntil ? { coolingOffUntil: resp.coolingOffUntil } : {}),
    });
    if (opts.unlock) {
      if (recentFailures > 0) authState.setNotice({ kind: 'recentFailures', count: recentFailures });
      else if (resp.coolingOffUntil && resp.coolingOffUntil > Math.floor(Date.now() / 1000)) authState.setNotice({ kind: 'coolingOff', until: resp.coolingOffUntil });
      // SEC-054 reconciliation; failures here must never block the unlock.
      void reconcileBiometricHint(resp.deviceId, resp.biometricEnabled).catch(() => undefined);
    }
  }
  return { recentFailures };
}

async function doRefresh(): Promise<'ok' | 'locked' | 'gone' | 'network'> {
  const token = await getRefreshToken();
  if (!token) { await wipeCredentials(); return 'gone'; }
  const r = await api.refresh(token);
  if (r.ok) {
    try { await applyServerSession(r.data, { unlock: false }); } catch { return 'locked'; }
    return 'ok';
  }
  switch (r.error.code) {
    case 'UNLOCK_REQUIRED': lock(); return 'locked'; // token NOT deleted
    case 'AUTH_FAILED': await wipeCredentials(); return 'gone'; // the ONLY wipe path
    case 'NETWORK_ERROR': case 'TIMEOUT': return 'network';
    default: lock(); return 'locked';
  }
}

/** Single-flight refresh: concurrent callers share one request. */
export function refreshSession(): Promise<'ok' | 'locked' | 'gone' | 'network'> {
  inflightRefresh ??= doRefresh().finally(() => { inflightRefresh = null; });
  return inflightRefresh;
}

const err = (code: 'UNLOCK_REQUIRED' | 'AUTH_FAILED' | 'NETWORK_ERROR'): { ok: false; error: ApiError } =>
  ({ ok: false, error: code === 'NETWORK_ERROR' ? { code } : { code, status: 401 } });

/**
 * Runs an authenticated call. Refreshes when the access token is near expiry; on 401 tries exactly ONE refresh then one retry.
 * Never loops. While locked, no call is made at all.
 */
export async function authedCall<T>(fn: (accessToken: string) => Promise<api.ApiResult<T>>, opts: { retry?: boolean } = {}): Promise<api.ApiResult<T>> {
  if (authState.get().status !== 'unlocked') return err('UNLOCK_REQUIRED');
  let token = memory.getAccess();
  if (!token) {
    const s = await refreshSession();
    if (s !== 'ok') return err(s === 'network' ? 'NETWORK_ERROR' : s === 'gone' ? 'AUTH_FAILED' : 'UNLOCK_REQUIRED');
    token = memory.getAccess(0);
    if (!token) return err('UNLOCK_REQUIRED');
  }
  const first = await fn(token);
  // `retry:false` for calls that consume a one-shot PIN buffer / single-use token (a retry could not re-send them).
  if (first.ok || first.error.code !== 'AUTH_FAILED' || opts.retry === false) return first;
  const s = await refreshSession();
  if (s !== 'ok') return err(s === 'network' ? 'NETWORK_ERROR' : s === 'gone' ? 'AUTH_FAILED' : 'UNLOCK_REQUIRED');
  const t2 = memory.getAccess(0);
  if (!t2) return err('UNLOCK_REQUIRED');
  const second = await fn(t2);
  if (!second.ok && second.error.code === 'AUTH_FAILED') lock();
  return second;
}
