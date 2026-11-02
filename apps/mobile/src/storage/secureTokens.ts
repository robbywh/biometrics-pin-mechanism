// SEC-034 / SEC-067: the ONLY module (with hint.ts / prefs.ts) allowed to import SecureStore / AsyncStorage.
// Refresh token + deviceId: SecureStore, WHEN_PASSCODE_SET_THIS_DEVICE_ONLY (no iCloud sync, needs a device passcode).
// Access / step-up tokens: module-level memory only, never persisted.
import * as SecureStore from 'expo-secure-store';

const REFRESH_KEY = 'auth.refreshToken';
const DEVICE_KEY = 'auth.deviceId';
const opts = (): SecureStore.SecureStoreOptions => ({ keychainAccessible: SecureStore.WHEN_PASSCODE_SET_THIS_DEVICE_ONLY });

export const saveRefreshToken = (t: string) => SecureStore.setItemAsync(REFRESH_KEY, t, opts());
export const getRefreshToken = () => SecureStore.getItemAsync(REFRESH_KEY, opts());
export const saveDeviceId = (id: string) => SecureStore.setItemAsync(DEVICE_KEY, id, opts());
export const getDeviceId = () => SecureStore.getItemAsync(DEVICE_KEY, opts());

/** Wipes every persisted credential. */
export async function clearCredentials(): Promise<void> {
  await Promise.all([SecureStore.deleteItemAsync(REFRESH_KEY, opts()), SecureStore.deleteItemAsync(DEVICE_KEY, opts())]);
}

// ---- in-memory only ----
let access: { token: string; expiresAtMs: number } | null = null;
let stepUp: string | null = null;
let bootstrap: { token: string; scope: string; deviceId?: string } | null = null;

export const memory = {
  setAccess(token: string, expiresInSec: number, nowMs = Date.now()) {
    access = { token, expiresAtMs: nowMs + expiresInSec * 1000 };
  },
  /** Returns the token only if it has more than `skewSec` of validity left. */
  getAccess(skewSec = 30, nowMs = Date.now()): string | null {
    return access && access.expiresAtMs - nowMs > skewSec * 1000 ? access.token : null;
  },
  hasAccess: () => access !== null,
  setStepUp(t: string) { stepUp = t; },
  /** Single use: returns and forgets. */
  takeStepUp(): string | null { const t = stepUp; stepUp = null; return t; },
  setBootstrap(b: { token: string; scope: string; deviceId?: string } | null) { bootstrap = b; },
  getBootstrap: () => bootstrap,
  /** Called by lock(): drops access + step-up tokens (and bootstrap material). */
  clearAll() { access = null; stepUp = null; bootstrap = null; },
};
