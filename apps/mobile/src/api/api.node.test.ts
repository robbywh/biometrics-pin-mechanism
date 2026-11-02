import { resolveBaseUrl } from './baseUrl';
import { ERROR_CODES, describeError, mapError } from './errors';
import * as api from './endpoints';
import { PinBuffer } from '../pin/buffer';
import { setupMockApi } from '../testing/mockApi';

const { backend } = setupMockApi();
const fill = (s: string) => { const b = new PinBuffer(); for (const c of s) b.push(Number(c)); return b; };

describe('base URL guard (SEC-006)', () => {
  it('accepts https in release and dev', () => {
    expect(resolveBaseUrl('https://api.example.com', false).apiBase).toBe('https://api.example.com/v1');
    expect(resolveBaseUrl('https://api.example.com/', true).origin).toBe('https://api.example.com');
  });
  it('rejects http in release builds (fail fast)', () => {
    expect(() => resolveBaseUrl('http://localhost:8080', false)).toThrow();
    expect(() => resolveBaseUrl('http://api.example.com', false)).toThrow();
    expect(() => resolveBaseUrl(undefined, false)).toThrow();
  });
  it('dev http only for local hosts', () => {
    expect(resolveBaseUrl('http://10.0.2.2:8080', true).apiBase).toBe('http://10.0.2.2:8080/v1');
    expect(resolveBaseUrl('http://192.168.1.20:8080', true).origin).toBe('http://192.168.1.20:8080');
    expect(() => resolveBaseUrl('http://evil.example.com', true)).toThrow();
    expect(() => resolveBaseUrl('ftp://localhost', true)).toThrow();
    expect(() => resolveBaseUrl('https://u:p@api.example.com', true)).toThrow();
  });
});

describe('error mapping (SEC-059)', () => {
  it.each(ERROR_CODES)('maps %s to a typed code with generic text', (code) => {
    const e = mapError(400, { error: { code, message: 'SECRET SERVER TEXT' } });
    expect(e.code).toBe(code);
    expect(describeError(e)).not.toContain('SECRET');
    expect(describeError(e).length).toBeGreaterThan(0);
  });
  it('unknown code, junk body and HTML become UNKNOWN_ERROR without leaking text', () => {
    for (const body of [{ error: { code: 'SOMETHING_NEW', message: 'stack trace' } }, '<html>boom</html>', null, 42, { error: 5 }]) {
      const e = mapError(500, body);
      expect(e.code).toBe('UNKNOWN_ERROR');
      expect(JSON.stringify(e)).not.toMatch(/stack|boom/);
    }
  });
  it('carries server-driven numbers and falls back to Retry-After header', () => {
    expect(mapError(401, { error: { code: 'PIN_INVALID', message: 'x', attemptsRemaining: 3 } })).toMatchObject({ attemptsRemaining: 3 });
    expect(mapError(429, { error: { code: 'RATE_LIMITED', message: 'x' } }, '12')).toMatchObject({ retryAfter: 12 });
    expect(mapError(423, { error: { code: 'PIN_LOCKED', message: 'x', lockType: 'hard' } })).toMatchObject({ lockType: 'hard' });
    expect(mapError(403, { error: { code: 'STEPUP_REQUIRED', message: 'x', required: 'pin' } })).toMatchObject({ required: 'pin' });
  });
});

describe('endpoints against the contract mock', () => {
  it('attaches Idempotency-Key, Authorization and consumes the PIN buffer', async () => {
    const login = await api.demoLogin({ username: 'alice', secret: 's', intent: 'login' });
    if (!login.ok) throw new Error('login');
    const dev = await api.registerDevice(login.data.bootstrapToken, '3f2b8c1a-0d4e-4f6a-9b7c-1a2b3c4d5e6f', { name: 'T', platform: 'ios' });
    expect(dev.ok).toBe(true);
    const pin = fill('493017');
    const res = await api.setPin(login.data.bootstrapToken, '4f2b8c1a-0d4e-4f6a-9b7c-1a2b3c4d5e6f', pin);
    expect(res.ok && res.status).toBe(201);
    expect(pin.length).toBe(0); // zeroed by take()
    const call = backend.log.find((l) => l.op === 'setPin')!;
    expect(call.headers['idempotency-key']).toBe('4f2b8c1a-0d4e-4f6a-9b7c-1a2b3c4d5e6f');
    expect(call.headers['authorization']).toBe(`Bearer ${login.data.bootstrapToken}`);
    // advisory risk signals are attached to POST /devices (T20)
    expect((backend.log.find((l) => l.op === 'registerDevice')!.body as any).risk).toEqual({ rooted: false, emulator: false, debugger: true });
  });
  it('maps server failures to typed errors and never throws', async () => {
    backend.setScenario('rate-limited');
    const r = await api.demoLogin({ username: 'alice', secret: 's', intent: 'login' });
    expect(r).toMatchObject({ ok: false, error: { code: 'RATE_LIMITED', retryAfter: 12 } });
  });
  it('unknown error code from server yields UNKNOWN_ERROR', async () => {
    const orig = backend.handle.bind(backend);
    backend.handle = () => ({ status: 500, headers: {}, body: { error: { code: 'BRAND_NEW', message: 'leak' } } });
    const r = await api.getDashboard('whatever');
    backend.handle = orig;
    expect(r).toMatchObject({ ok: false, error: { code: 'UNKNOWN_ERROR', status: 500 } });
  });
  it('PinBuffer.take refuses incomplete PINs', () => {
    expect(() => fill('123').take()).toThrow();
  });
});
