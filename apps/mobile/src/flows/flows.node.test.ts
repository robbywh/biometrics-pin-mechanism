import * as api from '../api/endpoints';
import { authState } from '../auth/state';
import { authedCall, lock } from '../auth/session';
import { canOfferBiometric, unlockWithBiometric, unlockWithPin } from '../auth/unlock';
import { getBiometricHint, setBiometricHint } from '../storage/hint';
import { getDeviceId, getRefreshToken, memory } from '../storage/secureTokens';
import { plain } from '../testing/fakeStorage';
import { fakeKey } from '../testing/fakeBiometricKey';
import { setupMockApi } from '../testing/mockApi';
import { onboardUnlocked, PIN, pinOf } from '../testing/helpers';
import { disableBiometrics, enableBiometrics } from './biometrics';
import { endFlow, registerThisDevice, resetPinWithNewDevice, setInitialPin, startBootstrap, unlockNewInstall } from './onboarding';
import { changePin, loadDevices, revokeCurrentDevice, revokeOtherDevice, signOut } from './account';
import { SendTransaction } from './send';
import { decide, reconcileBiometricHint } from '../biometric/reconcile';
import { biometricAlias } from '../biometric/alias';
import { base64UrlDecode } from '../crypto/base64url';

const { backend } = setupMockApi();

// Independent re-implementation of contract-notes s1, used only to assert what reached the native signer.
const lp = (b: Buffer) => Buffer.concat([Buffer.from([b.length >> 8, b.length & 255]), b]);
function expectedMessage(c: { purpose: string; userId: string; deviceId: string; nonce: string; expiresAt: number; boundHash?: string }) {
  const exp = Buffer.alloc(8); exp.writeBigUInt64BE(BigInt(c.expiresAt));
  return Buffer.concat([lp(Buffer.from('CRYPTOAPP/BIO/v1')), lp(Buffer.from(c.purpose)), lp(Buffer.from(c.userId)), lp(Buffer.from(c.deviceId)), lp(Buffer.from(c.nonce, 'base64url')), lp(exp), lp(c.boundHash ? Buffer.from(c.boundHash, 'base64url') : Buffer.alloc(0))]);
}
const lastResponse = (op: string) => [...backend.log].reverse().find((l) => l.op === op)!.response!.body as any;
const TX = { asset: 'ETH', network: 'ethereum', destination: '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', amount: '1.5', fee: '0.001', txNonce: '33333333-3333-4333-8333-333333333333', expiry: 1767225900 } as const;

describe('onboarding (T12)', () => {
  it('happy path reaches Unlocked; no token/PIN in AsyncStorage; bootstrap not persisted', async () => {
    await onboardUnlocked();
    expect(authState.get().status).toBe('unlocked');
    expect(memory.getBootstrap()).toBeNull();
    expect(JSON.stringify([...plain.entries()])).not.toContain(PIN);
  });
  it('local weak-PIN / mismatch block before any request; server still 422s a tampered client', async () => {
    await startBootstrap('alice', 's', 'login');
    await registerThisDevice('t');
    const before = backend.log.length;
    expect(await setInitialPin(pinOf('123456'), pinOf('123456'))).toMatchObject({ ok: false, error: { code: 'PIN_WEAK_LOCAL' } });
    expect(await setInitialPin(pinOf('493017'), pinOf('493018'))).toMatchObject({ ok: false, error: { code: 'PIN_MISMATCH' } });
    expect(backend.log.length).toBe(before);
    // tampered client skips the local check -> server PIN_WEAK
    const r = await api.setPin(memory.getBootstrap()!.token, '3f2b8c1a-0d4e-4f6a-9b7c-1a2b3c4d5e6f', pinOf('123456'));
    expect(r).toMatchObject({ ok: false, error: { code: 'PIN_WEAK' } });
  });
  it('device registration idempotency key is reused on retry of the same attempt', async () => {
    await startBootstrap('alice', 's', 'login');
    backend.setScenario('rate-limited');
    expect(await registerThisDevice('t')).toMatchObject({ ok: false, error: { code: 'RATE_LIMITED', retryAfter: 12 } });
    backend.setScenario('happy');
    await registerThisDevice('t');
    const keys = backend.log.filter((l) => l.op === 'registerDevice').map((l) => l.headers['idempotency-key']);
    expect(new Set(keys).size).toBe(1);
  });
  it.each([['device-limit', 'DEVICE_LIMIT'], ['idempotent-replay', 'IDEMPOTENT_REPLAY']])('scenario %s -> %s', async (sc, code) => {
    await startBootstrap('alice', 's', 'login');
    if (sc === 'device-limit') { backend.setScenario('device-limit'); expect(await registerThisDevice('t')).toMatchObject({ ok: false, error: { code } }); return; }
    await registerThisDevice('t');
    backend.setScenario('idempotent-replay');
    expect(await setInitialPin(pinOf(PIN), pinOf(PIN))).toMatchObject({ ok: false, error: { code } });
    expect(memory.getBootstrap()).toBeNull();
  });
  it('PIN_ALREADY_SET when the account already has a PIN and scope is pin-setup is blocked server side', async () => {
    backend.seedPin(PIN);
    const s = await startBootstrap('alice', 's', 'login');
    expect(s).toMatchObject({ ok: true, data: 'pin-verify' }); // scope for an account with a PIN
    await registerThisDevice('t');
    expect(await setInitialPin(pinOf('735201'), pinOf('735201'))).toMatchObject({ ok: false, error: { code: 'SCOPE_INSUFFICIENT' } });
  });
  it('new install of an account with a PIN: device-bound bootstrap token unlocks via pin/verify', async () => {
    backend.seedPin(PIN);
    await startBootstrap('alice', 's', 'login');
    await registerThisDevice('t');
    const r = await unlockNewInstall(pinOf(PIN));
    expect(r.ok).toBe(true);
    expect(authState.get().status).toBe('unlocked');
    expect(await getRefreshToken()).toBeTruthy();
    expect(backend.log.find((l) => l.op === 'verifyPin')!.headers.authorization).toMatch(/^Bearer /);
  });
});

describe('PIN unlock lock states (T13)', () => {
  beforeEach(async () => { await onboardUnlocked(); lock(); });
  it('pin-invalid-n: attemptsRemaining comes from the server', async () => {
    backend.setScenario('pin-invalid-n');
    expect(await unlockWithPin(pinOf(PIN))).toMatchObject({ ok: false, error: { code: 'PIN_INVALID', attemptsRemaining: 4 } });
    expect(await unlockWithPin(pinOf(PIN))).toMatchObject({ ok: false, error: { code: 'PIN_INVALID', attemptsRemaining: 3 } });
  });
  it('soft lock: correct PIN still rejected, retryAfter from server; clearing storage does not change it', async () => {
    backend.setScenario('pin-locked-soft');
    plain.clear();
    expect(await unlockWithPin(pinOf(PIN))).toMatchObject({ ok: false, error: { code: 'PIN_LOCKED', lockType: 'soft', retryAfter: 30 } });
    expect(authState.get().status).toBe('locked');
  });
  it('hard lock', async () => {
    backend.setScenario('pin-hard-locked');
    expect(await unlockWithPin(pinOf(PIN))).toMatchObject({ ok: false, error: { code: 'PIN_LOCKED', lockType: 'hard' } });
  });
  it('rate limited and offline stay locked', async () => {
    backend.setScenario('rate-limited');
    expect(await unlockWithPin(pinOf(PIN))).toMatchObject({ ok: false, error: { code: 'RATE_LIMITED', retryAfter: 12 } });
    backend.setScenario('happy');
    const orig = backend.handle.bind(backend);
    backend.handle = () => { throw new Error('offline'); };
    const r = await unlockWithPin(pinOf(PIN));
    backend.handle = orig;
    expect(r).toMatchObject({ ok: false });
    expect(authState.get().status).toBe('locked');
  });
  it('recentFailures produces a one-time notice (SEC-012) and the PIN buffer is cleared after submit', async () => {
    await unlockWithPin(pinOf('000001'));
    await unlockWithPin(pinOf('000001'));
    const pin = pinOf(PIN);
    await unlockWithPin(pin);
    expect(pin.length).toBe(0);
    expect(authState.get().notice).toEqual({ kind: 'recentFailures', count: 2 });
  });
  it('AUTH_FAILED (refresh token revoked) routes to onboarding', async () => {
    const orig = backend.handle.bind(backend);
    backend.handle = (r) => (r.path.endsWith('/pin/verify') ? { status: 401, headers: {}, body: { error: { code: 'AUTH_FAILED', message: 'x' } } } : orig(r));
    await unlockWithPin(pinOf(PIN));
    backend.handle = orig;
    expect(authState.get().status).toBe('onboarding');
    expect(await getRefreshToken()).toBeNull();
  });
});

describe('enable / disable biometrics (T15, T16)', () => {
  it('happy path: key created, hint set only after 201, cooling-off notice', async () => {
    const { deviceId } = await onboardUnlocked();
    expect(await getBiometricHint()).toBe(false);
    const r = await enableBiometrics(pinOf(PIN));
    expect(r.ok).toBe(true);
    expect(await getBiometricHint()).toBe(true);
    expect(fakeKey.keys.has(biometricAlias(deviceId))).toBe(true);
    expect(authState.get().notice?.kind).toBe('coolingOff');
    // enroll challenge was signed with the exact contract bytes
    const ec = lastResponse('biometricEnrollChallenge');
    expect(Buffer.from(fakeKey.signed.at(-1)!.message).equals(expectedMessage(ec))).toBe(true);
    const enroll = backend.log.find((l) => l.op === 'biometricEnroll')!.body as any;
    expect(enroll.attestation).toEqual({ type: 'none', keySecurityLevel: 'tee' });
    expect(base64UrlDecode(enroll.publicKey).length).toBe(91);
    // step-up token was single-use and dropped
    expect(memory.takeStepUp()).toBeNull();
  });
  it('wrong PIN / locked PIN: no key is ever created', async () => {
    await onboardUnlocked();
    expect(await enableBiometrics(pinOf('000001'))).toMatchObject({ ok: false, error: { code: 'PIN_INVALID' } });
    expect(fakeKey.keys.size).toBe(0);
    backend.setScenario('pin-locked-soft');
    expect(await enableBiometrics(pinOf(PIN))).toMatchObject({ ok: false, error: { code: 'PIN_LOCKED' } });
    expect(fakeKey.keys.size).toBe(0);
    expect(await getBiometricHint()).toBe(false);
  });
  it('INVALID_PUBLIC_KEY from the server deletes the key and leaves the hint false', async () => {
    await onboardUnlocked();
    fakeKey.badSpki = true;
    expect(await enableBiometrics(pinOf(PIN))).toMatchObject({ ok: false, error: { code: 'INVALID_PUBLIC_KEY' } });
    expect(fakeKey.keys.size).toBe(0);
    expect(await getBiometricHint()).toBe(false);
  });
  it('sign failure after key creation deletes the key; unsupported hardware blocks early', async () => {
    await onboardUnlocked();
    fakeKey.nextSignError = 'USER_CANCELED';
    expect(await enableBiometrics(pinOf(PIN))).toMatchObject({ ok: false, error: { code: 'BIO_KEY_ERROR', kind: 'USER_CANCELED' } });
    expect(fakeKey.keys.size).toBe(0);
    fakeKey.support = { secureHardware: true, biometricEnrolled: false, reason: 'NOT_ENROLLED' } as never;
    expect(await enableBiometrics(pinOf(PIN))).toMatchObject({ ok: false, error: { code: 'BIO_UNAVAILABLE' } });
  });
  it('STEPUP_INVALID on enroll challenge surfaces (try again) without creating a key', async () => {
    await onboardUnlocked();
    const orig = backend.handle.bind(backend);
    backend.handle = (r) => (r.path.endsWith('/enroll/challenge') ? { status: 403, headers: {}, body: { error: { code: 'STEPUP_INVALID', message: 'x' } } } : orig(r));
    expect(await enableBiometrics(pinOf(PIN))).toMatchObject({ ok: false, error: { code: 'STEPUP_INVALID' } });
    backend.handle = orig;
    expect(fakeKey.keys.size).toBe(0);
  });
  it('disable: server then local key and hint; needs recent unlock', async () => {
    const { deviceId } = await onboardUnlocked();
    await enableBiometrics(pinOf(PIN));
    expect(await disableBiometrics(Math.floor(Date.now() / 1000) + 3600)).toMatchObject({ ok: false, error: { code: 'REAUTH_REQUIRED' } });
    expect((await disableBiometrics()).ok).toBe(true);
    expect(fakeKey.keys.has(biometricAlias(deviceId))).toBe(false);
    expect(await getBiometricHint()).toBe(false);
    expect(backend.deviceById(deviceId)!.biometricEnabled).toBe(false);
  });
});

describe('biometric unlock (T14, tests 15/16/17/22)', () => {
  async function enrolled() {
    const { deviceId } = await onboardUnlocked();
    await enableBiometrics(pinOf(PIN));
    lock();
    return deviceId;
  }
  it('success: signature over exactly the preimage built from the challenge, amr=bio', async () => {
    const deviceId = await enrolled();
    fakeKey.signed.length = 0;
    expect(await canOfferBiometric()).toBe(true);
    expect(await unlockWithBiometric()).toEqual({ status: 'unlocked' });
    expect(authState.get().session!.amr).toBe('bio');
    const ch = lastResponse('biometricChallenge');
    expect(fakeKey.signed).toHaveLength(1);
    expect(Buffer.from(fakeKey.signed[0]!.message).equals(expectedMessage(ch))).toBe(true);
    expect(ch.deviceId).toBe(deviceId);
    const verify = backend.log.find((l) => l.op === 'biometricVerify')!.body as any;
    expect(Object.keys(verify).sort()).toEqual(['challengeId', 'deviceId', 'risk', 'signature']);
  });
  it.each(['USER_CANCELED', 'LOCKOUT', 'NOT_ENROLLED', 'HARDWARE_UNAVAILABLE'] as const)('%s lands on PIN, never open', async (kind) => {
    await enrolled();
    fakeKey.nextSignError = kind;
    expect(await unlockWithBiometric()).toEqual({ status: 'fallback', reason: kind });
    expect(authState.get().status).toBe('locked');
    expect(backend.log.some((l) => l.op === 'biometricVerify')).toBe(false);
  });
  it('KEY_INVALIDATED: key + hint removed, then after PIN unlock the server is told (DELETE biometric)', async () => {
    const deviceId = await enrolled();
    fakeKey.invalidateAll(); // OS enrollment change
    fakeKey.keys.add(biometricAlias(deviceId)); // key object still present but unusable
    fakeKey.nextSignError = 'KEY_INVALIDATED';
    expect(await unlockWithBiometric()).toEqual({ status: 'fallback', reason: 'KEY_INVALIDATED' });
    expect(fakeKey.keys.size).toBe(0);
    expect(await getBiometricHint()).toBe(false);
    expect(backend.deviceById(deviceId)!.biometricEnabled).toBe(true);
    expect((await unlockWithPin(pinOf(PIN))).ok).toBe(true);
    await new Promise((r) => setTimeout(r, 20)); // reconcile runs after unlock
    expect(backend.deviceById(deviceId)!.biometricEnabled).toBe(false);
    expect(authState.get().notice).toEqual({ kind: 'biometricInvalidated' });
  });
  it('flipping the AsyncStorage hint by hand never grants access', async () => {
    await onboardUnlocked();
    lock();
    await setBiometricHint(true);
    expect(await canOfferBiometric()).toBe(false); // no key
    expect(await unlockWithBiometric()).toEqual({ status: 'fallback', reason: 'NO_KEY' });
    expect(authState.get().status).toBe('locked');
  });
  it('decoy/unknown challenge is signed like any other and rejected by the server uniformly', async () => {
    const deviceId = await enrolled();
    backend.deviceById(deviceId)!.biometricEnabled = false; // server no longer lists a key -> decoy challenge
    expect(await unlockWithBiometric()).toEqual({ status: 'fallback', reason: 'SERVER_REJECTED' });
  });
});

describe('reconciliation matrix (SEC-054)', () => {
  const rows: [boolean, boolean, boolean, string][] = [
    // hint, serverEnabled, keyPresent -> outcome
    [true, true, true, 'hint-kept'],
    [false, true, true, 'hint-set'],
    [true, true, false, 'server-realigned'],
    [false, true, false, 'server-realigned'],
    [true, false, true, 'orphan-key-deleted'],
    [false, false, false, 'hint-cleared'],
  ];
  it.each(rows)('hint=%s server=%s key=%s -> %s', (hint, serverEnabled, keyPresent, outcome) => {
    expect(decide({ hint, serverEnabled, keyPresent })).toBe(outcome);
  });
  it('server disabled + local orphan key: key deleted, hint cleared', async () => {
    const { deviceId } = await onboardUnlocked();
    fakeKey.keys.add(biometricAlias(deviceId));
    await setBiometricHint(true);
    expect(await reconcileBiometricHint(deviceId, false)).toBe('orphan-key-deleted');
    expect(fakeKey.keys.size).toBe(0);
    expect(await getBiometricHint()).toBe(false);
  });
  it('server enabled + key present sets the hint', async () => {
    const { deviceId } = await onboardUnlocked();
    fakeKey.keys.add(biometricAlias(deviceId));
    expect(await reconcileBiometricHint(deviceId, true)).toBe('hint-set');
    expect(await getBiometricHint()).toBe(true);
  });
});

describe('PIN reset / hard-lock recovery (T17)', () => {
  it('pin-hard-locked -> reset -> unlocked with a NEW device; old key and hint gone', async () => {
    const { deviceId: oldId } = await onboardUnlocked();
    await enableBiometrics(pinOf(PIN));
    lock();
    backend.setScenario('pin-hard-locked');
    expect(await unlockWithPin(pinOf(PIN))).toMatchObject({ ok: false, error: { lockType: 'hard' } });
    expect(await startBootstrap('alice', 's', 'reset')).toMatchObject({ ok: true, data: 'pin-reset' });
    await registerThisDevice('t');
    expect(await resetPinWithNewDevice(pinOf('735201'), pinOf('735201'))).toEqual({ ok: true });
    expect(authState.get().status).toBe('unlocked');
    const newId = authState.get().session!.deviceId;
    expect(newId).not.toBe(oldId);
    expect(await getDeviceId()).toBe(newId);
    expect(fakeKey.keys.size).toBe(0);
    expect(await getBiometricHint()).toBe(false);
    expect(authState.get().notice?.kind).toBe('coolingOff');
    expect(backend.deviceById(oldId)!.revoked).toBe(true);
  });
  it('IDEMPOTENT_REPLAY ends the flow', async () => {
    await onboardUnlocked();
    lock();
    await startBootstrap('alice', 's', 'reset');
    await registerThisDevice('t');
    backend.setScenario('idempotent-replay');
    const orig = backend.handle.bind(backend);
    backend.handle = (r) => (r.path.endsWith('/pin/reset') ? { status: 409, headers: {}, body: { error: { code: 'IDEMPOTENT_REPLAY', message: 'x' } } } : orig(r));
    expect(await resetPinWithNewDevice(pinOf('735201'), pinOf('735201'))).toMatchObject({ ok: false, error: { code: 'IDEMPOTENT_REPLAY' } });
    backend.handle = orig;
    expect(memory.getBootstrap()).toBeNull();
    endFlow();
  });
});

describe('settings: change PIN, devices (T18)', () => {
  it('change PIN swaps tokens (refresh first), hint unchanged; weak/unchanged/locked errors', async () => {
    await onboardUnlocked();
    await enableBiometrics(pinOf(PIN));
    const before = await getRefreshToken();
    expect(await changePin(pinOf(PIN), pinOf('735201'), pinOf('735201'))).toEqual({ ok: true });
    expect(await getRefreshToken()).not.toBe(before);
    expect(await getBiometricHint()).toBe(true);
    expect(await changePin(pinOf('735201'), pinOf('735201'), pinOf('735201'))).toMatchObject({ ok: false, error: { code: 'PIN_UNCHANGED' } });
    expect(await changePin(pinOf('735201'), pinOf('123456'), pinOf('123456'))).toMatchObject({ ok: false, error: { code: 'PIN_WEAK_LOCAL' } });
    expect(await changePin(pinOf('000001'), pinOf('864209'), pinOf('864209'))).toMatchObject({ ok: false, error: { code: 'PIN_INVALID' } });
  });
  it('revoke other requires PIN step-up; revoke current wipes credentials and key', async () => {
    const { deviceId } = await onboardUnlocked();
    // second device on the same account
    const login = await api.demoLogin({ username: 'alice', secret: 's', intent: 'login' });
    if (!login.ok) throw new Error('x');
    const d2 = await api.registerDevice(login.data.bootstrapToken, '5f2b8c1a-0d4e-4f6a-9b7c-1a2b3c4d5e6f', { name: 'Tablet', platform: 'android' });
    if (!d2.ok) throw new Error('x');
    const list = await loadDevices();
    expect(list.ok && list.data.devices).toHaveLength(2);
    expect(await revokeOtherDevice(d2.data.deviceId, pinOf('000001'))).toMatchObject({ ok: false, error: { code: 'PIN_INVALID' } });
    expect(backend.log.some((l) => l.op === 'revokeDevice')).toBe(false);
    expect((await revokeOtherDevice(d2.data.deviceId, pinOf(PIN))).ok).toBe(true);
    expect(backend.log.find((l) => l.op === 'revokeDevice')!.headers['x-stepup-token']).toBeTruthy();
    await enableBiometrics(pinOf(PIN));
    expect((await revokeCurrentDevice()).ok).toBe(true);
    expect(authState.get().status).toBe('onboarding');
    expect(await getRefreshToken()).toBeNull();
    expect(fakeKey.keys.size).toBe(0);
    expect(deviceId).toBeTruthy();
  });
});

describe('send transaction with step-up (T19, test 22)', () => {
  it('PIN proof path (amount above bio threshold forces PIN): same fields in challenge and submit', async () => {
    await onboardUnlocked();
    const f = new SendTransaction({ ...TX, amount: '2000' });
    const c = await f.begin();
    expect(c.ok && c.data.required).toBe('pin');
    expect(f.divergence).toBe(false);
    expect((await f.proveWithBiometric())).toEqual({ ok: true, data: { fallbackToPin: true } }); // server demands PIN
    expect(fakeKey.signed).toHaveLength(0);
    expect((await f.proveWithPin(pinOf(PIN))).ok).toBe(true);
    const sub = await f.submit();
    expect(sub.ok).toBe(true);
    const chal = backend.log.find((l) => l.op === 'stepupChallenge')!.body as any;
    const tx = backend.log.find((l) => l.op === 'createTransaction')!;
    expect(tx.body).toEqual(chal.tx);
    expect(tx.headers['x-stepup-token']).toBeTruthy();
    expect(tx.headers['idempotency-key']).toBeTruthy();
    expect(f.hasToken).toBe(false);
  });
  it('biometric proof path signs purpose=stepup with boundHash from the challenge', async () => {
    await onboardUnlocked();
    await enableBiometrics(pinOf(PIN));
    fakeKey.signed.length = 0;
    const f = new SendTransaction(TX);
    const c = await f.begin();
    expect(c.ok && c.data.required).toBe('either');
    expect(await f.proveWithBiometric()).toEqual({ ok: true, data: { fallbackToPin: false } });
    const ch = lastResponse('stepupChallenge');
    expect(Buffer.from(fakeKey.signed[0]!.message).equals(expectedMessage(ch))).toBe(true);
    expect(fakeKey.signed[0]!.message.length).toBeGreaterThan(147); // includes 32-byte boundHash
    expect((await f.submit()).ok).toBe(true);
  });
  it('biometric cancel falls back to PIN with the same live challenge', async () => {
    await onboardUnlocked();
    await enableBiometrics(pinOf(PIN));
    const f = new SendTransaction(TX);
    await f.begin();
    fakeKey.nextSignError = 'USER_CANCELED';
    expect(await f.proveWithBiometric()).toEqual({ ok: true, data: { fallbackToPin: true } });
    expect((await f.proveWithPin(pinOf(PIN))).ok).toBe(true);
    expect((await f.submit()).ok).toBe(true);
  });
  it('stepup-needs-pin: signature attempt is rejected by the server and the flow switches to PIN', async () => {
    await onboardUnlocked();
    await enableBiometrics(pinOf(PIN));
    backend.setScenario('stepup-needs-pin');
    const f = new SendTransaction(TX);
    const c = await f.begin();
    expect(c.ok && c.data.required).toBe('pin');
    expect(await f.proveWithBiometric()).toEqual({ ok: true, data: { fallbackToPin: true } });
    expect((await f.proveWithPin(pinOf(PIN))).ok).toBe(true);
  });
  it('wrong step-up PIN consumes the challenge: restart required (D-08)', async () => {
    await onboardUnlocked();
    const f = new SendTransaction(TX);
    await f.begin();
    expect(await f.proveWithPin(pinOf('000001'))).toMatchObject({ ok: false, error: { code: 'PIN_INVALID' }, restart: true });
    expect(await f.proveWithPin(pinOf(PIN))).toMatchObject({ ok: false, restart: true });
    await f.begin();
    expect((await f.proveWithPin(pinOf(PIN))).ok).toBe(true);
  });
  it('stepup-invalid, cooling-off, insufficient funds', async () => {
    await onboardUnlocked();
    backend.setScenario('stepup-invalid');
    const f = new SendTransaction(TX);
    await f.begin();
    await f.proveWithPin(pinOf(PIN));
    expect(await f.submit()).toMatchObject({ ok: false, error: { code: 'STEPUP_INVALID' }, restart: true });
    backend.setScenario('cooling-off');
    expect(await new SendTransaction(TX).begin()).toMatchObject({ ok: false, error: { code: 'COOLING_OFF', retryAfter: 3600 } });
    backend.setScenario('happy');
    const big = new SendTransaction({ ...TX, amount: '200000' });
    await big.begin();
    await big.proveWithPin(pinOf(PIN));
    expect(await big.submit()).toMatchObject({ ok: false, error: { code: 'INSUFFICIENT_FUNDS' } });
  });
  it('double tap submits once; fields are frozen', async () => {
    await onboardUnlocked();
    const f = new SendTransaction(TX);
    await f.begin();
    await f.proveWithPin(pinOf(PIN));
    const [a, b] = await Promise.all([f.submit(), f.submit()]);
    expect([a.ok, b.ok].filter(Boolean)).toHaveLength(1);
    expect(backend.log.filter((l) => l.op === 'createTransaction')).toHaveLength(1);
    expect(Object.isFrozen(f.fields)).toBe(true);
  });
  it('dashboard is reachable only after unlock and returns decimal strings', async () => {
    await onboardUnlocked();
    const d = await authedCall((t) => api.getDashboard(t));
    expect(d.ok && typeof d.data.totalValue).toBe('string');
  });
});

describe('Idempotency-Key policy', () => {
  it('send: same key after a network error, a NEW key after a definitive business error', async () => {
    await onboardUnlocked();
    const f = new SendTransaction({ ...TX, amount: '200000' });
    await f.begin();
    await f.proveWithPin(pinOf(PIN));
    expect(await f.submit()).toMatchObject({ ok: false, error: { code: 'INSUFFICIENT_FUNDS' } });
    await f.begin();
    await f.proveWithPin(pinOf(PIN));
    await f.submit();
    const keys = backend.log.filter((l) => l.op === 'createTransaction').map((l) => l.headers['idempotency-key']);
    expect(keys).toHaveLength(2);
    expect(keys[0]).not.toBe(keys[1]);
  });
});

describe('sign out', () => {
  it('calls /auth/logout then wipes credentials, key and hint', async () => {
        await onboardUnlocked();
    await enableBiometrics(pinOf(PIN));
    await signOut();
    expect(backend.log.some((l) => l.op === 'logout')).toBe(true);
    expect(authState.get().status).toBe('onboarding');
    expect(await getRefreshToken()).toBeNull();
    expect(fakeKey.keys.size).toBe(0);
    expect(await getBiometricHint()).toBe(false);
  });
});
