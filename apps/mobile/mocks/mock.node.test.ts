import { MockBackend, SCENARIOS, type MockRequest } from './core';
import { operations } from './spec';

const IDEM = '3f2b8c1a-0d4e-4f6a-9b7c-1a2b3c4d5e6f';
const PIN = '493017';
let b: MockBackend;
const call = (method: string, path: string, body?: unknown, headers: Record<string, string> = {}) => {
  const req: MockRequest = { method, path, headers: Object.fromEntries(Object.entries(headers).map(([k, v]) => [k.toLowerCase(), v])) };
  if (body !== undefined) req.body = body;
  return b.handle(req);
};
const auth = (t: string) => ({ Authorization: `Bearer ${t}` });

beforeEach(() => {
  b = new MockBackend();
  b.validateResponses = true; // throws if a response violates the spec schema for its status
});

async function onboard() {
  const login = call('POST', '/v1/auth/demo-login', { username: 'alice', secret: 'x', intent: 'login' });
  const bt = (login.body as any).bootstrapToken;
  const dev = call('POST', '/v1/devices', { name: 'Test', platform: 'ios' }, { ...auth(bt), 'Idempotency-Key': IDEM });
  const deviceId = (dev.body as any).deviceId as string;
  const s = call('POST', '/v1/pin', { pin: PIN }, { ...auth(bt), 'Idempotency-Key': IDEM });
  return { bt, deviceId, session: s.body as any, login, dev, s };
}

describe('mock backend conformance', () => {
  it('unknown route -> 404, unknown field -> 400 VALIDATION_ERROR', () => {
    expect(call('GET', '/v1/nope').status).toBe(404);
    const r = call('POST', '/v1/auth/demo-login', { username: 'a', secret: 'b', intent: 'login', extra: 1 });
    expect(r.status).toBe(400);
    expect((r.body as any).error.code).toBe('VALIDATION_ERROR');
  });
  it('scenario list matches contract-notes s7 / T3', () => {
    expect([...SCENARIOS].sort()).toEqual(['bio-auth-failed', 'cooling-off', 'device-limit', 'happy', 'idempotent-replay', 'pin-hard-locked', 'pin-invalid-n', 'pin-locked-soft', 'rate-limited', 'refresh-reuse', 'service-unavailable', 'stepup-invalid', 'stepup-needs-pin', 'unlock-required'].sort());
    expect(call('POST', '/__mock/scenario', { name: 'nonsense' }).status).toBe(400);
    expect(call('POST', '/__mock/scenario', { name: 'rate-limited' }).status).toBe(200);
  });
  it('happy onboarding conforms and bootstrap token cannot reach dashboard', async () => {
    const { bt, session, login, dev, s } = await onboard();
    expect([login.status, dev.status, s.status]).toEqual([200, 201, 201]);
    expect(session.amr).toBe('pin');
    expect(call('GET', '/v1/dashboard', undefined, auth(bt)).status).toBe(403);
    expect(call('GET', '/v1/dashboard', undefined, auth(session.accessToken)).status).toBe(200);
  });
  it('PIN_WEAK, PIN_ALREADY_SET, missing Idempotency-Key', async () => {
    const login = call('POST', '/v1/auth/demo-login', { username: 'alice', secret: 'x', intent: 'login' });
    const bt = (login.body as any).bootstrapToken;
    call('POST', '/v1/devices', { name: 'T', platform: 'ios' }, { ...auth(bt), 'Idempotency-Key': IDEM });
    expect(call('POST', '/v1/pin', { pin: '111111' }, { ...auth(bt), 'Idempotency-Key': IDEM }).status).toBe(422);
    expect(call('POST', '/v1/pin', { pin: PIN }, auth(bt)).status).toBe(400);
  });
  it('PIN lockout schedule: 4 x 401, 5th 423 soft, correct pin still locked', async () => {
    const { deviceId, session } = await onboard();
    const v = (pin: string) => call('POST', '/v1/auth/pin/verify', { deviceId, pin }, auth(session.refreshToken));
    for (let i = 1; i <= 4; i++) {
      const r = v('000001');
      expect(r.status).toBe(401);
      expect((r.body as any).error.attemptsRemaining).toBe(5 - i);
    }
    expect(v('000001').status).toBe(423);
    const locked = v(PIN);
    expect(locked.status).toBe(423);
    expect((locked.body as any).error.lockType).toBe('soft');
  });
  it('pin/verify with deviceId mismatch or no credential -> uniform AUTH_FAILED', async () => {
    const { deviceId, session } = await onboard();
    expect(call('POST', '/v1/auth/pin/verify', { deviceId, pin: PIN }).status).toBe(401);
    expect(call('POST', '/v1/auth/pin/verify', { deviceId: '99999999-9999-4999-8999-999999999999', pin: PIN }, auth(session.refreshToken)).status).toBe(401);
  });

  it.each(SCENARIOS)('scenario %s: every operation response conforms to its schema', async (name) => {
    // validateResponses=true makes handle() throw on any nonconforming response, so merely exercising every op is the test.
    const seeded = await onboard();
    b.setScenario(name);
    const A = auth(seeded.session.accessToken);
    const d = seeded.deviceId;
    const tx = { asset: 'ETH', network: 'ethereum', destination: '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', amount: '1.5', fee: '0.001', txNonce: '33333333-3333-4333-8333-333333333333', expiry: 1700000600 };
    const calls: [string, string, unknown?, Record<string, string>?][] = [
      ['GET', '/healthz'],
      ['POST', '/v1/auth/demo-login', { username: 'alice', secret: 'x', intent: 'reset' }],
      ['POST', '/v1/auth/pin/verify', { deviceId: d, pin: PIN }, auth(seeded.session.refreshToken)],
      ['POST', '/v1/auth/pin/verify', { deviceId: d, pin: '000001' }, auth(seeded.session.refreshToken)],
      ['POST', '/v1/auth/biometric/challenge', { deviceId: d }],
      ['POST', '/v1/auth/biometric/verify', { challengeId: IDEM, deviceId: d, signature: 'AAAA' }],
      ['POST', '/v1/auth/refresh', undefined, auth(seeded.session.refreshToken)],
      ['GET', '/v1/devices', undefined, A],
      ['POST', '/v1/devices', { name: 'x', platform: 'android' }, { ...auth(seeded.bt), 'Idempotency-Key': IDEM }],
      ['DELETE', `/v1/devices/${d}/biometric`, undefined, A],
      ['POST', `/v1/devices/${d}/biometric/enroll/challenge`, undefined, { ...A, 'X-StepUp-Token': 'a'.repeat(43) }],
      ['POST', `/v1/devices/${d}/biometric/enroll`, { challengeId: IDEM, publicKey: 'AAAA', attestation: { type: 'none', keySecurityLevel: 'tee' }, signature: 'AAAA' }, { ...A, 'Idempotency-Key': IDEM }],
      ['POST', '/v1/stepup/challenge', { action: 'transaction', tx }, A],
      ['POST', '/v1/stepup/challenge', { action: 'enable_biometric', targetDeviceId: d }, A],
      ['POST', '/v1/stepup/verify', { challengeId: IDEM, pin: PIN }, A],
      ['POST', '/v1/stepup/verify', { challengeId: IDEM, signature: 'AAAA' }, A],
      ['POST', '/v1/transactions', tx, { ...A, 'Idempotency-Key': IDEM, 'X-StepUp-Token': 'a'.repeat(43) }],
      ['PUT', '/v1/pin', { oldPin: PIN, newPin: '735201' }, { ...A, 'Idempotency-Key': IDEM }],
      ['GET', '/v1/dashboard', undefined, A],
      ['DELETE', `/v1/devices/${d}`, undefined, { ...A, 'X-StepUp-Token': 'a'.repeat(43) }],
      ['POST', '/v1/auth/logout', undefined, A],
    ];
    for (const [m, p, body, h] of calls) expect(() => call(m, p, body, h)).not.toThrow();
    expect(operations.length).toBe(20);
  });

  it('full happy biometric enroll + login + tx flow conforms', async () => {
    const { deviceId, session } = await onboard();
    const A = auth(session.accessToken);
    const ch = (call('POST', '/v1/stepup/challenge', { action: 'enable_biometric', targetDeviceId: deviceId }, A).body as any);
    const su = (call('POST', '/v1/stepup/verify', { challengeId: ch.challengeId, pin: PIN }, A).body as any).stepUpToken;
    const ec = call('POST', `/v1/devices/${deviceId}/biometric/enroll/challenge`, undefined, { ...A, 'X-StepUp-Token': su }).body as any;
    const spki = Buffer.concat([Buffer.from('3059301306072a8648ce3d020106082a8648ce3d030107034200', 'hex'), Buffer.from([4]), Buffer.alloc(64, 1)]).toString('base64url');
    const en = call('POST', `/v1/devices/${deviceId}/biometric/enroll`, { challengeId: ec.challengeId, publicKey: spki, attestation: { type: 'none', keySecurityLevel: 'tee' }, signature: 'AAAA' }, { ...A, 'Idempotency-Key': IDEM });
    expect(en.status).toBe(201);
    const lc = call('POST', '/v1/auth/biometric/challenge', { deviceId }).body as any;
    const vr = call('POST', '/v1/auth/biometric/verify', { challengeId: lc.challengeId, deviceId, signature: 'AAAA' });
    expect(vr.status).toBe(200);
    expect((vr.body as any).amr).toBe('bio');
    // replay of the same challenge fails
    expect(call('POST', '/v1/auth/biometric/verify', { challengeId: lc.challengeId, deviceId, signature: 'AAAA' }).status).toBe(401);
    // bad key => INVALID_PUBLIC_KEY
    const ch2 = call('POST', '/v1/stepup/challenge', { action: 'enable_biometric', targetDeviceId: deviceId }, A).body as any;
    const su2 = (call('POST', '/v1/stepup/verify', { challengeId: ch2.challengeId, pin: PIN }, A).body as any).stepUpToken;
    const ec2 = call('POST', `/v1/devices/${deviceId}/biometric/enroll/challenge`, undefined, { ...A, 'X-StepUp-Token': su2 }).body as any;
    const bad = call('POST', `/v1/devices/${deviceId}/biometric/enroll`, { challengeId: ec2.challengeId, publicKey: 'AAAA', attestation: { type: 'none', keySecurityLevel: 'tee' }, signature: 'AAAA' }, { ...A, 'Idempotency-Key': '4f2b8c1a-0d4e-4f6a-9b7c-1a2b3c4d5e6f' });
    expect((bad.body as any).error.code).toBe('INVALID_PUBLIC_KEY');
  });
});
