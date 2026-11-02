// Contract-derived mock backend core: pure request -> response function over in-memory state.
// - Request bodies are validated against the spec schemas (additionalProperties:false => 400 VALIDATION_ERROR).
// - No real crypto: any non-empty base64url signature is accepted. No real secrets.
// - Used by msw/node (Jest) and by the host HTTP server (`pnpm mock`).
import { randomBytes, randomUUID } from 'crypto';
import { hasResponse, lastErrors, matchOperation, responseSchema, validatorFor, type Operation } from './spec';
import { computeActionHash, computeTxHash } from '../src/crypto/messages';

export const SCENARIOS = [
  'happy', 'pin-invalid-n', 'pin-locked-soft', 'pin-hard-locked', 'unlock-required', 'refresh-reuse', 'bio-auth-failed',
  'stepup-needs-pin', 'stepup-invalid', 'cooling-off', 'rate-limited', 'device-limit', 'service-unavailable', 'idempotent-replay',
] as const;
export type Scenario = (typeof SCENARIOS)[number];

export interface MockRequest {
  method: string;
  path: string;
  headers: Record<string, string>;
  /** parsed JSON body, or undefined when absent */
  body?: unknown;
  bodyInvalid?: boolean;
}
export interface MockResponse {
  status: number;
  headers: Record<string, string>;
  body?: unknown;
}

const b64u = (n: number) => randomBytes(n).toString('base64url');
const USER_ID = '11111111-1111-4111-8111-111111111111';
const DEMO_SECRET_REJECT = 'wrong-secret'; // the mock only rejects this literal value; it holds no real secret

interface DeviceRec {
  id: string; name: string; platform: 'ios' | 'android'; createdAt: number; lastSeenAt: number;
  biometricEnabled: boolean; revoked: boolean; keyPub?: string;
}
type TokenRec =
  | { kind: 'bootstrap'; scope: 'pin-setup' | 'pin-verify' | 'pin-reset'; deviceId?: string; used: boolean }
  | { kind: 'access'; deviceId: string; unlockAt: number }
  | { kind: 'refresh'; deviceId: string; used: boolean }
  | { kind: 'stepup'; deviceId: string; action: string; boundHash: string; used: boolean };
interface ChallengeRec { id: string; purpose: 'login' | 'enroll' | 'stepup'; deviceId: string; consumed: boolean; action?: string; boundHash?: string; required?: string }

export class MockBackend {
  scenario: Scenario = 'happy';
  validateResponses = false;
  now: () => number = () => Math.floor(Date.now() / 1000);
  pin: string | null = null;
  failures = 0;
  hardLocked = false;
  lockedUntil = 0;
  private devices = new Map<string, DeviceRec>();
  private tokens = new Map<string, TokenRec>();
  private challenges = new Map<string, ChallengeRec>();
  private idem = new Map<string, { hash: string; res: MockResponse }>();
  private scenarioCalls = new Map<string, number>();
  private balances = { BTC: 0.15, ETH: 1.2, USDC: 93.2 };
  /** every request seen: handy for assertions */
  readonly log: { op: string; headers: Record<string, string>; body: unknown; response?: MockResponse }[] = [];

  reset(): void {
    Object.assign(this, { scenario: 'happy', pin: null, failures: 0, hardLocked: false, lockedUntil: 0 });
    this.devices.clear(); this.tokens.clear(); this.challenges.clear(); this.idem.clear(); this.scenarioCalls.clear(); this.log.length = 0;
  }
  setScenario(s: string): boolean {
    if (!(SCENARIOS as readonly string[]).includes(s)) return false;
    this.scenario = s as Scenario;
    this.scenarioCalls.clear();
    if (s === 'pin-hard-locked') this.hardLocked = true;
    return true;
  }
  /** test helper: pre-seed an account that already has a PIN */
  seedPin(pin: string): void { this.pin = pin; }
  deviceById(id: string): DeviceRec | undefined { return this.devices.get(id); }

  // ---------- helpers ----------
  private json(status: number, body: unknown, headers: Record<string, string> = {}): MockResponse {
    return { status, headers: { 'content-type': 'application/json', 'x-request-id': randomUUID(), ...headers }, body };
  }
  private err(status: number, code: string, extra: Record<string, unknown> = {}, headers: Record<string, string> = {}): MockResponse {
    return this.json(status, { error: { code, message: 'Request could not be completed.', ...extra } }, headers);
  }
  private count(key: string): number {
    const n = (this.scenarioCalls.get(key) ?? 0) + 1;
    this.scenarioCalls.set(key, n);
    return n;
  }
  private bearer(req: MockRequest): string | undefined {
    const h = req.headers['authorization'];
    return h && /^Bearer [A-Za-z0-9._-]+$/.test(h) ? h.slice(7) : undefined;
  }
  private access(req: MockRequest): { rec: Extract<TokenRec, { kind: 'access' }>; token: string } | MockResponse {
    const t = this.bearer(req);
    const rec = t ? this.tokens.get(t) : undefined;
    if (!t || !rec) return this.err(401, 'AUTH_FAILED', {}, { 'cache-control': 'no-store' });
    if (rec.kind === 'bootstrap') return this.err(403, 'SCOPE_INSUFFICIENT');
    if (rec.kind !== 'access') return this.err(401, 'AUTH_FAILED');
    return { rec, token: t };
  }
  private bootstrap(req: MockRequest): { rec: Extract<TokenRec, { kind: 'bootstrap' }>; token: string } | MockResponse {
    const t = this.bearer(req);
    const rec = t ? this.tokens.get(t) : undefined;
    if (!t || !rec || rec.kind !== 'bootstrap' || rec.used) return this.err(401, 'AUTH_FAILED');
    return { rec, token: t };
  }
  private isResp(x: unknown): x is MockResponse { return typeof x === 'object' && x !== null && 'status' in x && 'headers' in x; }

  private idempotent(req: MockRequest, scopeKey: string, run: () => MockResponse, replayTokenBearing: boolean): MockResponse {
    const key = req.headers['idempotency-key']!;
    const k = `${scopeKey}:${key}`;
    const hash = JSON.stringify(req.body);
    const prev = this.idem.get(k);
    if (prev) {
      if (prev.hash !== hash) return this.err(422, 'IDEMPOTENCY_KEY_REUSED');
      return replayTokenBearing ? this.err(409, 'IDEMPOTENT_REPLAY', { }) : prev.res;
    }
    const res = run();
    if (res.status < 300) this.idem.set(k, { hash, res });
    return res;
  }

  private session(deviceId: string, amr: 'pin' | 'bio', recentFailures = 0, coolingOffUntil?: number) {
    const dev = this.devices.get(deviceId)!;
    // one live refresh family per device
    for (const [, r] of this.tokens) if (r.kind === 'refresh' && r.deviceId === deviceId) r.used = true;
    const accessToken = `mock.${b64u(24)}.sig`;
    const refreshToken = b64u(32);
    const now = this.now();
    this.tokens.set(accessToken, { kind: 'access', deviceId, unlockAt: now });
    this.tokens.set(refreshToken, { kind: 'refresh', deviceId, used: false });
    dev.lastSeenAt = now;
    return {
      accessToken, expiresIn: 300, refreshToken, amr, authTime: now, deviceId, biometricEnabled: dev.biometricEnabled, recentFailures,
      ...(coolingOffUntil ? { coolingOffUntil } : {}),
    };
  }

  private weak(pin: string): boolean {
    const d = pin.split('').map(Number);
    const df = d.slice(1).map((x, i) => x - d[i]!);
    return /^(\d)\1{5}$/.test(pin) || df.every((x) => x === 1) || df.every((x) => x === -1) || /^(\d\d)\1\1$/.test(pin) || /^(\d\d\d)\1$/.test(pin) || ['123456', '654321', '112233', '000000'].includes(pin);
  }

  /** Shared PIN check with durable-style lockout. Returns null on success. */
  private checkPin(pin: string): MockResponse | null {
    const now = this.now();
    if (this.hardLocked) return this.err(423, 'PIN_LOCKED', { lockType: 'hard' });
    if (this.lockedUntil > now) {
      const ra = this.lockedUntil - now;
      return this.err(423, 'PIN_LOCKED', { lockType: 'soft', retryAfter: ra, attemptsUntilHardLock: Math.max(0, 10 - this.failures) }, { 'retry-after': String(ra) });
    }
    if (pin === this.pin) { this.failures = 0; return null; }
    this.failures++;
    if (this.failures >= 10) { this.hardLocked = true; return this.err(423, 'PIN_LOCKED', { lockType: 'hard' }); }
    if (this.failures >= 5) {
      const ra = [30, 60, 300, 900, 3600][this.failures - 5]!;
      this.lockedUntil = now + ra;
      return this.err(423, 'PIN_LOCKED', { lockType: 'soft', retryAfter: ra, attemptsUntilHardLock: 10 - this.failures }, { 'retry-after': String(ra) });
    }
    return this.err(401, 'PIN_INVALID', { attemptsRemaining: 5 - this.failures });
  }

  private scenarioOverride(op: Operation): MockResponse | null {
    const id = op.operationId;
    switch (this.scenario) {
      case 'service-unavailable':
        return this.err(503, 'SERVICE_UNAVAILABLE');
      case 'rate-limited':
        return this.err(429, 'RATE_LIMITED', { retryAfter: 12 }, { 'retry-after': '12', 'ratelimit-limit': '10', 'ratelimit-remaining': '0', 'ratelimit-reset': '12' });
      case 'pin-invalid-n':
        if (id === 'verifyPin' || id === 'changePin' || id === 'stepupVerify') {
          const n = this.count('pin');
          if (n <= 4) return this.err(401, 'PIN_INVALID', { attemptsRemaining: 5 - n });
          return this.err(423, 'PIN_LOCKED', { lockType: 'soft', retryAfter: 30, attemptsUntilHardLock: 5 }, { 'retry-after': '30' });
        }
        return null;
      case 'pin-locked-soft':
        if (id === 'verifyPin' || id === 'changePin' || id === 'stepupVerify') return this.err(423, 'PIN_LOCKED', { lockType: 'soft', retryAfter: 30, attemptsUntilHardLock: 5 }, { 'retry-after': '30' });
        return null;
      case 'pin-hard-locked':
        if (id === 'verifyPin' || id === 'changePin') return this.err(423, 'PIN_LOCKED', { lockType: 'hard' });
        if (id === 'biometricVerify') return this.err(401, 'AUTH_FAILED');
        return null;
      case 'unlock-required':
        return id === 'refresh' ? this.err(401, 'UNLOCK_REQUIRED') : null;
      case 'refresh-reuse':
        return id === 'refresh' ? this.err(401, 'AUTH_FAILED') : null;
      case 'bio-auth-failed':
        return id === 'biometricVerify' ? this.err(401, 'AUTH_FAILED') : null;
      case 'stepup-invalid':
        return id === 'createTransaction' ? this.err(403, 'STEPUP_INVALID') : null;
      case 'cooling-off': // applied inside stepupChallenge for transaction actions
        return null;
      case 'device-limit':
        return id === 'registerDevice' ? this.err(409, 'DEVICE_LIMIT') : null;
      case 'idempotent-replay':
        return id === 'setPin' || id === 'resetPin' || id === 'changePin' ? this.err(409, 'IDEMPOTENT_REPLAY') : null;
      default:
        return null;
    }
  }

  // ---------- entry ----------
  handle(req: MockRequest): MockResponse {
    const res = this.dispatch(req);
    const last = this.log[this.log.length - 1];
    if (last && !last.response) last.response = res;
    if (this.validateResponses) this.assertConforms(req, res);
    return res;
  }

  private assertConforms(req: MockRequest, res: MockResponse): void {
    if (req.path.startsWith('/__mock')) return;
    const m = matchOperation(req.method, req.path);
    if (!m) return;
    if (!hasResponse(m.op, res.status)) throw new Error(`mock returned undocumented status ${res.status} for ${m.op.operationId}`);
    const schema = responseSchema(m.op, res.status);
    if (schema) {
      const v = validatorFor(schema);
      if (!v(res.body)) throw new Error(`mock response ${m.op.operationId} ${res.status} violates schema: ${lastErrors(v)}`);
    }
  }

  private dispatch(req: MockRequest): MockResponse {
    if (req.path === '/__mock/scenario' && req.method === 'POST') {
      const name = (req.body as { name?: string } | undefined)?.name;
      return name && this.setScenario(name) ? this.json(200, { scenario: name }) : this.json(400, { error: 'unknown scenario' });
    }
    if (req.path === '/__mock/scenario' && req.method === 'GET') return this.json(200, { scenario: this.scenario, scenarios: SCENARIOS });
    const m = matchOperation(req.method, req.path);
    if (!m) return this.err(404, 'NOT_FOUND', {});
    const { op, params } = m;
    this.log.push({ op: op.operationId, headers: { ...req.headers }, body: req.body });

    // validation (strict: unknown fields rejected by additionalProperties:false in the spec)
    for (const h of op.requiredHeaders) if (!req.headers[h]) return this.err(400, 'VALIDATION_ERROR', {}, {});
    if (op.requestSchema) {
      if (req.bodyInvalid || req.body === undefined) return this.err(400, 'VALIDATION_ERROR');
      if (!validatorFor(op.requestSchema)(req.body)) return this.err(400, 'VALIDATION_ERROR');
    }
    if (params.deviceId && !/^[0-9a-f-]{36}$/.test(params.deviceId)) return this.err(400, 'VALIDATION_ERROR');

    const forced = this.scenarioOverride(op);
    // Only scenarios that the contract documents for this operation apply to it.
    if (forced && hasResponse(op, forced.status)) return forced;
    return this.route(op, params, req);
  }

  private route(op: Operation, params: Record<string, string>, req: MockRequest): MockResponse {
    const body = req.body as any;
    const now = this.now();
    switch (op.operationId) {
      case 'healthz':
        return this.json(200, { status: 'ok' });

      case 'demoLogin': {
        if (body.secret === DEMO_SECRET_REJECT) return this.err(401, 'AUTH_FAILED');
        const scope = this.pin === null ? 'pin-setup' : body.intent === 'reset' ? 'pin-reset' : 'pin-verify';
        const token = b64u(32);
        this.tokens.set(token, { kind: 'bootstrap', scope, used: false });
        return this.json(200, { bootstrapToken: token, expiresIn: 600, scope }, { 'cache-control': 'no-store' });
      }

      case 'registerDevice': {
        const b = this.bootstrap(req);
        if (this.isResp(b)) return b;
        return this.idempotent(req, `dev:${b.token}`, () => {
          const active = [...this.devices.values()].filter((d) => !d.revoked).length;
          if (active >= 5 && b.rec.scope !== 'pin-reset') return this.err(409, 'DEVICE_LIMIT');
          const id = randomUUID();
          this.devices.set(id, { id, name: body.name, platform: body.platform, createdAt: now, lastSeenAt: now, biometricEnabled: false, revoked: false });
          b.rec.deviceId = id;
          return this.json(201, { deviceId: id, createdAt: now, ...(active > 0 ? { coolingOffUntil: now + 86400 } : {}) });
        }, false);
      }

      case 'setPin': {
        const b = this.bootstrap(req);
        if (this.isResp(b)) return b;
        if (b.rec.scope !== 'pin-setup' || !b.rec.deviceId) return this.err(403, 'SCOPE_INSUFFICIENT');
        return this.idempotent(req, `pin:${b.token}`, () => {
          if (this.pin !== null) return this.err(409, 'PIN_ALREADY_SET');
          if (this.weak(body.pin)) return this.err(422, 'PIN_WEAK', {}, {});
          this.pin = body.pin; b.rec.used = true;
          return this.json(201, this.session(b.rec.deviceId!, 'pin'), { 'cache-control': 'no-store' });
        }, true);
      }

      case 'resetPin': {
        const b = this.bootstrap(req);
        if (this.isResp(b)) return b;
        if (b.rec.scope !== 'pin-reset' || !b.rec.deviceId) return this.err(403, 'SCOPE_INSUFFICIENT');
        return this.idempotent(req, `reset:${b.token}`, () => {
          if (this.weak(body.pin)) return this.err(422, 'PIN_WEAK');
          const keep = b.rec.deviceId!;
          for (const d of this.devices.values()) if (d.id !== keep) d.revoked = true;
          this.devices.get(keep)!.biometricEnabled = false;
          this.pin = body.pin; this.failures = 0; this.lockedUntil = 0; this.hardLocked = false; b.rec.used = true;
          if (this.scenario === 'pin-hard-locked') this.scenario = 'happy';
          return this.json(200, this.session(keep, 'pin', 0, now + 86400), { 'cache-control': 'no-store' });
        }, true);
      }

      case 'verifyPin': {
        const t = this.bearer(req);
        const rec = t ? this.tokens.get(t) : undefined;
        const okCred = rec && ((rec.kind === 'refresh' && !rec.used && rec.deviceId === body.deviceId) || (rec.kind === 'bootstrap' && rec.scope === 'pin-verify' && rec.deviceId === body.deviceId && !rec.used));
        if (!okCred || !this.devices.get(body.deviceId) || this.devices.get(body.deviceId)!.revoked) return this.err(401, 'AUTH_FAILED', {}, { 'cache-control': 'no-store' });
        const failuresBefore = this.failures;
        const bad = this.checkPin(body.pin);
        if (bad) return bad;
        if (rec!.kind === 'bootstrap') rec!.used = true;
        return this.json(200, this.session(body.deviceId, 'pin', failuresBefore), { 'cache-control': 'no-store' });
      }

      case 'biometricChallenge': {
        const dev = this.devices.get(body.deviceId);
        const live = dev && !dev.revoked && dev.biometricEnabled && !this.hardLocked;
        const id = randomUUID();
        if (live) this.challenges.set(id, { id, purpose: 'login', deviceId: body.deviceId, consumed: false });
        return this.json(200, { challengeId: id, purpose: 'login', userId: live ? USER_ID : randomUUID(), deviceId: body.deviceId, nonce: b64u(32), expiresAt: now + 60 }, { 'cache-control': 'no-store' });
      }

      case 'biometricVerify': {
        const ch = this.challenges.get(body.challengeId);
        const sigOk = /^[A-Za-z0-9_-]+$/.test(body.signature);
        if (!ch || ch.consumed || ch.deviceId !== body.deviceId || ch.purpose !== 'login' || !sigOk || this.hardLocked) {
          if (ch) ch.consumed = true;
          return this.err(401, 'AUTH_FAILED', {}, { 'cache-control': 'no-store' });
        }
        ch.consumed = true;
        return this.json(200, this.session(body.deviceId, 'bio'), { 'cache-control': 'no-store' });
      }

      case 'refresh': {
        const t = this.bearer(req);
        const rec = t ? this.tokens.get(t) : undefined;
        if (!rec || rec.kind !== 'refresh') return this.err(401, 'AUTH_FAILED');
        if (rec.used) { return this.err(401, 'AUTH_FAILED'); }
        // demo window: unlock required after 15 min since last unlock is simulated via scenario only
        const sess = this.session(rec.deviceId, 'pin');
        return this.json(200, sess, { 'cache-control': 'no-store' });
      }

      case 'logout': {
        const a = this.access(req);
        if (this.isResp(a)) return a;
        this.tokens.delete(a.token);
        return { status: 204, headers: {} };
      }

      case 'listDevices': {
        const a = this.access(req);
        if (this.isResp(a)) return a;
        const devices = [...this.devices.values()].filter((d) => !d.revoked).map((d) => ({ id: d.id, name: d.name, platform: d.platform, createdAt: d.createdAt, lastSeenAt: d.lastSeenAt, current: d.id === a.rec.deviceId, biometricEnabled: d.biometricEnabled }));
        return this.json(200, { devices });
      }

      case 'revokeDevice': {
        const a = this.access(req);
        if (this.isResp(a)) return a;
        const dev = this.devices.get(params.deviceId!);
        if (!dev || dev.revoked) return this.err(404, 'NOT_FOUND');
        if (dev.id !== a.rec.deviceId) {
          const su = this.consumeStepUp(req.headers['x-stepup-token'], 'revoke_device', a.rec.deviceId, dev.id);
          if (su) return su;
        }
        dev.revoked = true; dev.biometricEnabled = false;
        return { status: 204, headers: {} };
      }

      case 'changePin': {
        const a = this.access(req);
        if (this.isResp(a)) return a;
        return this.idempotent(req, `chg:${a.token}`, () => {
          const bad = this.checkPin(body.oldPin);
          if (bad) return bad;
          if (body.newPin === body.oldPin) return this.err(422, 'PIN_UNCHANGED');
          if (this.weak(body.newPin)) return this.err(422, 'PIN_WEAK');
          this.pin = body.newPin;
          for (const d of this.devices.values()) if (d.id !== a.rec.deviceId) { d.revoked = true; }
          return this.json(200, this.session(a.rec.deviceId, 'pin'), { 'cache-control': 'no-store' });
        }, true);
      }

      case 'stepupChallenge': {
        const a = this.access(req);
        if (this.isResp(a)) return a;
        const id = randomUUID();
        let boundHash: string; let required: 'bio' | 'pin' | 'either'; let summary: { title: string; lines: string[] }; let txHash: string | undefined;
        if (body.action === 'transaction') {
          if (this.scenario === 'cooling-off') return this.err(403, 'COOLING_OFF', { retryAfter: 3600 });
          const tx = body.tx;
          try { txHash = computeTxHash(tx); } catch { return this.err(422, 'VALIDATION_ERROR'); }
          if (!(tx.asset === 'USDC' || tx.asset === 'BTC' ? tx.network === (tx.asset === 'BTC' ? 'bitcoin' : 'ethereum') : tx.network === 'ethereum')) return this.err(422, 'VALIDATION_ERROR');
          boundHash = txHash;
          required = this.scenario === 'stepup-needs-pin' || Number(tx.amount) > 1000 ? 'pin' : 'either';
          summary = { title: `Send ${tx.amount} ${tx.asset}`, lines: [`To: ${tx.destination}`, `Network: ${tx.network}`, `Fee: ${tx.fee} ${tx.asset}`] };
        } else {
          const target = this.devices.get(body.targetDeviceId);
          if (!target || target.revoked) return this.err(404, 'NOT_FOUND');
          boundHash = computeActionHash(body.action, body.targetDeviceId);
          required = 'pin';
          summary = { title: body.action === 'enable_biometric' ? 'Enable biometrics' : 'Revoke device', lines: [`Device: ${target.name}`] };
        }
        this.challenges.set(id, { id, purpose: 'stepup', deviceId: a.rec.deviceId, consumed: false, action: body.action === 'transaction' ? 'transaction' : `${body.action}:${body.targetDeviceId}`, boundHash, required });
        return this.json(200, { challengeId: id, purpose: 'stepup', action: body.action, userId: USER_ID, deviceId: a.rec.deviceId, nonce: b64u(32), expiresAt: now + 60, boundHash, ...(txHash ? { txHash } : {}), required, summary }, { 'cache-control': 'no-store' });
      }

      case 'stepupVerify': {
        const a = this.access(req);
        if (this.isResp(a)) return a;
        const ch = this.challenges.get(body.challengeId);
        if (!ch || ch.consumed || ch.purpose !== 'stepup' || ch.deviceId !== a.rec.deviceId) return this.err(401, 'AUTH_FAILED');
        ch.consumed = true;
        if ('signature' in body) {
          if (ch.required === 'pin' || this.scenario === 'stepup-needs-pin') return this.err(403, 'STEPUP_REQUIRED', { required: 'pin' });
          if (!/^[A-Za-z0-9_-]+$/.test(body.signature)) return this.err(401, 'AUTH_FAILED');
        } else {
          const bad = this.checkPin(body.pin);
          if (bad) return bad;
          if (ch.required === 'bio') return this.err(403, 'STEPUP_REQUIRED', { required: 'bio' });
        }
        const token = b64u(32);
        this.tokens.set(token, { kind: 'stepup', deviceId: a.rec.deviceId, action: ch.action!, boundHash: ch.boundHash!, used: false });
        return this.json(200, { stepUpToken: token, expiresIn: 60 }, { 'cache-control': 'no-store' });
      }

      case 'biometricEnrollChallenge': {
        const a = this.access(req);
        if (this.isResp(a)) return a;
        if (params.deviceId !== a.rec.deviceId) return this.err(404, 'NOT_FOUND');
        const su = this.consumeStepUp(req.headers['x-stepup-token'], 'enable_biometric', a.rec.deviceId, params.deviceId!);
        if (su) return su;
        const id = randomUUID();
        this.challenges.set(id, { id, purpose: 'enroll', deviceId: a.rec.deviceId, consumed: false });
        return this.json(200, { challengeId: id, purpose: 'enroll', userId: USER_ID, deviceId: a.rec.deviceId, nonce: b64u(32), expiresAt: now + 60 }, { 'cache-control': 'no-store' });
      }

      case 'biometricEnroll': {
        const a = this.access(req);
        if (this.isResp(a)) return a;
        if (params.deviceId !== a.rec.deviceId) return this.err(404, 'NOT_FOUND');
        return this.idempotent(req, `enr:${a.token}`, () => {
          const ch = this.challenges.get(body.challengeId);
          if (!ch || ch.consumed || ch.purpose !== 'enroll' || ch.deviceId !== a.rec.deviceId) return this.err(401, 'AUTH_FAILED');
          ch.consumed = true;
          let pub: Buffer;
          try { pub = Buffer.from(body.publicKey, 'base64url'); } catch { return this.err(422, 'INVALID_PUBLIC_KEY'); }
          if (pub.length !== 91 || pub.subarray(0, 26).toString('hex') !== '3059301306072a8648ce3d020106082a8648ce3d030107034200' || pub[26] !== 4) return this.err(422, 'INVALID_PUBLIC_KEY');
          const dev = this.devices.get(a.rec.deviceId)!;
          dev.biometricEnabled = true; dev.keyPub = body.publicKey;
          return this.json(201, { keyId: randomUUID(), keyFingerprint: b64u(8), biometricEnabled: true, coolingOffUntil: now + 86400 });
        }, false);
      }

      case 'biometricDisable': {
        const a = this.access(req);
        if (this.isResp(a)) return a;
        if (params.deviceId !== a.rec.deviceId) return this.err(404, 'NOT_FOUND');
        if (now - a.rec.unlockAt > 300) return this.err(403, 'STEPUP_REQUIRED', { required: 'pin' });
        const dev = this.devices.get(params.deviceId!)!;
        dev.biometricEnabled = false; dev.keyPub = undefined;
        return { status: 204, headers: {} };
      }

      case 'createTransaction': {
        const a = this.access(req);
        if (this.isResp(a)) return a;
        return this.idempotent(req, `tx:${a.token}`, () => {
          const t = req.headers['x-stepup-token']!;
          const rec = this.tokens.get(t);
          if (!rec || rec.kind !== 'stepup' || rec.used || rec.deviceId !== a.rec.deviceId || rec.action !== 'transaction') return this.err(403, 'STEPUP_INVALID');
          rec.used = true;
          let h: string;
          try { h = computeTxHash(body); } catch { return this.err(422, 'VALIDATION_ERROR'); }
          if (h !== rec.boundHash) return this.err(403, 'STEPUP_INVALID');
          if (Number(body.amount) > 100000) return this.err(422, 'INSUFFICIENT_FUNDS');
          return this.json(202, { transactionId: randomUUID(), status: 'accepted_mock', txHash: h });
        }, false);
      }

      case 'getDashboard': {
        const a = this.access(req);
        if (this.isResp(a)) return a;
        return this.json(200, {
          currency: 'USD', totalValue: '12843.20',
          balances: [{ asset: 'BTC', amount: '0.15', value: '9750.00' }, { asset: 'ETH', amount: '1.2', value: '3000.00' }, { asset: 'USDC', amount: '93.20', value: '93.20' }],
        }, { 'cache-control': 'no-store' });
      }
      default:
        return this.err(404, 'NOT_FOUND');
    }
  }

  private consumeStepUp(token: string | undefined, action: string, deviceId: string, target: string): MockResponse | null {
    if (!token) return this.err(403, 'STEPUP_REQUIRED', { required: 'pin' });
    const rec = this.tokens.get(token);
    if (!rec || rec.kind !== 'stepup' || rec.used || rec.deviceId !== deviceId || rec.action !== `${action}:${target}`) return this.err(403, 'STEPUP_INVALID');
    rec.used = true;
    return null;
  }
}
