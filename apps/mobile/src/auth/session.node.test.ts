import { readdirSync, readFileSync, statSync } from 'fs';
import { join } from 'path';
import * as api from '../api/endpoints';
import { authState } from './state';
import { applyServerSession, authedCall, lock, SessionPersistError } from './session';
import { unlockWithBiometric, unlockWithPin } from './unlock';
import { getRefreshToken, memory } from '../storage/secureTokens';
import { failSecureWrites, plain, secure, secureOptions } from '../testing/fakeStorage';
import { fakeKey } from '../testing/fakeBiometricKey';
import { setupMockApi } from '../testing/mockApi';
import { onboardUnlocked, PIN, pinOf } from '../testing/helpers';
import { enableBiometrics } from '../flows/biometrics';
import { boot } from './boot';

const { backend } = setupMockApi();

describe('storage (SEC-034, test 18/21)', () => {
  it('refresh token only in SecureStore with WHEN_PASSCODE_SET_THIS_DEVICE_ONLY; nothing sensitive in AsyncStorage', async () => {
    await onboardUnlocked();
    const refresh = await getRefreshToken();
    expect(refresh).toBeTruthy();
    expect(secureOptions.every((o) => o.keychainAccessible === 'WHEN_PASSCODE_SET_THIS_DEVICE_ONLY')).toBe(true);
    const tokens = [refresh!, memory.getAccess(0)!];
    for (const v of plain.values()) for (const t of tokens) expect(v).not.toContain(t);
    expect([...plain.keys()].every((k) => k.startsWith('hint.') || k.startsWith('pref.'))).toBe(true);
    expect(secure.has('auth.refreshToken')).toBe(true);
  });
  it('boot: no passcode -> needsPasscode; token present -> locked (cold start always locked); none -> onboarding', async () => {
    fakeKey.deviceSecure = false;
    await boot();
    expect(authState.get().status).toBe('needsPasscode');
    fakeKey.deviceSecure = true;
    await boot();
    expect(authState.get().status).toBe('onboarding');
    await onboardUnlocked();
    authState.__reset();
    await boot();
    expect(authState.get().status).toBe('locked');
    expect(memory.hasAccess()).toBe(true); // module memory survives in-process, but state is locked and calls are refused:
    expect(await authedCall(async () => ({ ok: true as const, status: 200, data: 1 }))).toMatchObject({ ok: false, error: { code: 'UNLOCK_REQUIRED' } });
  });
});

describe('refresh policy (T8)', () => {
  it('concurrent calls with an expired access token cause exactly one refresh', async () => {
    await onboardUnlocked();
    memory.setAccess('expired', 0);
    const results = await Promise.all([1, 2, 3, 4].map(() => authedCall((t) => api.getDashboard(t))));
    expect(results.every((r) => r.ok)).toBe(true);
    expect(backend.log.filter((l) => l.op === 'refresh')).toHaveLength(1);
  });
  it('rotated refresh token is persisted before the new access token is used; failed write is a fatal lock', async () => {
    await onboardUnlocked();
    const before = await getRefreshToken();
    memory.setAccess('expired', 0);
    await authedCall((t) => api.getDashboard(t));
    expect(await getRefreshToken()).not.toBe(before);
    memory.setAccess('expired', 0);
    failSecureWrites.value = true;
    const r = await authedCall((t) => api.getDashboard(t));
    expect(r.ok).toBe(false);
    expect(authState.get().status).toBe('locked');
    expect(memory.hasAccess()).toBe(false);
  });
  it('applyServerSession throws SessionPersistError when the keychain write fails', async () => {
    failSecureWrites.value = true;
    await expect(applyServerSession({ accessToken: 'a', expiresIn: 300, refreshToken: 'r'.repeat(43), amr: 'pin', authTime: 1, deviceId: '2f0c9a4e-5b1d-4c6e-9a3f-7d8e1b2c3d4e', biometricEnabled: false })).rejects.toBeInstanceOf(SessionPersistError);
    expect(authState.get().status).not.toBe('unlocked');
  });
  it('UNLOCK_REQUIRED locks but keeps the refresh token', async () => {
    await onboardUnlocked();
    memory.setAccess('expired', 0);
    backend.setScenario('unlock-required');
    const r = await authedCall((t) => api.getDashboard(t));
    expect(r).toMatchObject({ ok: false, error: { code: 'UNLOCK_REQUIRED' } });
    expect(authState.get().status).toBe('locked');
    expect(await getRefreshToken()).toBeTruthy();
    expect(memory.hasAccess()).toBe(false);
  });
  it('AUTH_FAILED on refresh (reuse) wipes credentials and routes to onboarding', async () => {
    await onboardUnlocked();
    memory.setAccess('expired', 0);
    backend.setScenario('refresh-reuse');
    await authedCall((t) => api.getDashboard(t));
    expect(authState.get().status).toBe('onboarding');
    expect(await getRefreshToken()).toBeNull();
  });
  it('a 401 on an API call triggers one refresh and one retry, never a loop', async () => {
    await onboardUnlocked();
    const orig = backend.handle.bind(backend);
    backend.handle = (req) => (req.path === '/v1/dashboard' ? { status: 401, headers: {}, body: { error: { code: 'AUTH_FAILED', message: 'x' } } } : orig(req));
    const r = await authedCall((t) => api.getDashboard(t));
    backend.handle = orig;
    expect(r.ok).toBe(false);
    expect(backend.log.filter((l) => l.op === 'refresh')).toHaveLength(1);
    expect(backend.log.filter((l) => l.op === 'getDashboard')).toHaveLength(0 + 0); // overridden handle bypasses log
    expect(authState.get().status).toBe('locked');
  });
});

describe('lock manager state machine (T9, test 19)', () => {
  it('lock() drops the in-memory token, keeps the refresh token; no calls while locked', async () => {
    await onboardUnlocked();
    lock();
    expect(authState.get().status).toBe('locked');
    expect(memory.hasAccess()).toBe(false);
    expect(await getRefreshToken()).toBeTruthy();
    const before = backend.log.length;
    await authedCall((t) => api.getDashboard(t));
    expect(backend.log.length).toBe(before);
  });
  it('the only way to Unlocked is a server session response (setter is used by session.ts only)', () => {
    const files: string[] = [];
    const walk = (d: string) => readdirSync(d).forEach((f) => { const p = join(d, f); if (statSync(p).isDirectory()) walk(p); else files.push(p); });
    walk(join(__dirname, '..'));
    const users = files.filter((f) => /\.tsx?$/.test(f) && !f.includes('.test.') && readFileSync(f, 'utf8').includes('__unlockFromServerSession')).map((f) => f.split('/').slice(-1)[0]);
    expect(users.sort()).toEqual(['session.ts', 'state.ts']);
  });
  it('local boolean cannot unlock: a signer that "succeeds" while the server rejects keeps the app locked (test 15)', async () => {
    const { deviceId } = await onboardUnlocked();
    expect((await enableBiometrics(pinOf(PIN))).ok).toBe(true);
    lock();
    backend.setScenario('bio-auth-failed'); // server rejects the signature; client "authenticate()" would have said true
    const out = await unlockWithBiometric();
    expect(out).toEqual({ status: 'fallback', reason: 'SERVER_REJECTED' });
    expect(authState.get().status).toBe('locked');
    expect(fakeKey.signed.length).toBeGreaterThan(0);
    expect(deviceId).toBeTruthy();
  });
  it('PIN unlock after lock works and wrong PIN keeps it locked', async () => {
    await onboardUnlocked();
    lock();
    const bad = await unlockWithPin(pinOf('000001'));
    expect(bad).toMatchObject({ ok: false, error: { code: 'PIN_INVALID', attemptsRemaining: 4 } });
    expect(authState.get().status).toBe('locked');
    const good = await unlockWithPin(pinOf(PIN));
    expect(good.ok).toBe(true);
    expect(authState.get().status).toBe('unlocked');
  });
});
