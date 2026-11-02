// T22: static contract conformance between the canonical openapi.yaml, the typed endpoint layer and the mock backend.
import { readFileSync } from 'fs';
import { resolve } from 'path';
import * as endpoints from '../api/endpoints';
import { operations, spec } from '../../mocks/spec';
import { ERROR_CODES } from '../api/errors';
import { SCENARIOS } from '../../mocks/core';

const endpointFns = endpoints as unknown as Record<string, unknown>;

// operationId -> typed function in src/api/endpoints.ts
const ENDPOINT_FOR_OPERATION: Record<string, keyof typeof endpoints> = {
  healthz: 'healthz', demoLogin: 'demoLogin', registerDevice: 'registerDevice', listDevices: 'listDevices', revokeDevice: 'revokeDevice',
  setPin: 'setPin', changePin: 'changePin', resetPin: 'resetPin', verifyPin: 'verifyPin', biometricChallenge: 'biometricChallenge',
  biometricVerify: 'biometricVerify', refresh: 'refresh', logout: 'logout', biometricEnrollChallenge: 'biometricEnrollChallenge',
  biometricEnroll: 'biometricEnroll', biometricDisable: 'biometricDisable',
  stepupChallenge: 'stepupChallengeTx', // + stepupChallengeTarget for the second oneOf branch
  stepupVerify: 'stepupVerifyPin', // + stepupVerifySignature
  createTransaction: 'createTransaction', getDashboard: 'getDashboard',
};

describe('contract <-> client <-> mock (T22 a)', () => {
  it('every operationId in the spec has a typed endpoint function', () => {
    for (const op of operations) {
      const fn = ENDPOINT_FOR_OPERATION[op.operationId];
      expect(fn).toBeDefined();
      expect(typeof endpointFns[fn!]).toBe('function');
    }
    expect(Object.keys(ENDPOINT_FOR_OPERATION).sort()).toEqual(operations.map((o) => o.operationId).sort());
    expect(typeof endpoints.stepupChallengeTarget).toBe('function');
    expect(typeof endpoints.stepupVerifySignature).toBe('function');
  });
  it('every operationId has a handler in the mock backend', () => {
    const src = readFileSync(resolve(__dirname, '../../mocks/core.ts'), 'utf8');
    for (const op of operations) expect(src).toContain(`case '${op.operationId}'`);
  });
  it('client error mapping covers exactly the contract ErrorCode enum', () => {
    const contractCodes = spec.components.schemas.ErrorCode.enum as string[];
    expect([...ERROR_CODES].sort()).toEqual([...contractCodes].sort());
  });
  it('scenario names match the T3 / contract-notes s7 list', () => {
    expect(SCENARIOS).toHaveLength(14);
  });
  it('the client never sends a bare auth boolean or client-asserted approval (schemas have no such field)', () => {
    const text = JSON.stringify(spec.components.schemas);
    for (const forbidden of ['biometricVerified', 'approved', 'limitOk', 'pinHash']) expect(text).not.toContain(forbidden);
  });
});

describe('policy greps (T14 / T7 / T20 / SEC-019)', () => {
  const { readdirSync, statSync } = jest.requireActual('fs') as typeof import('fs');
  const files: string[] = [];
  const walk = (d: string) => readdirSync(d).forEach((f) => { const p = resolve(d, f); if (statSync(p).isDirectory()) walk(p); else files.push(p); });
  walk(resolve(__dirname, '..'));
  const prod = files.filter((f) => /\.tsx?$/.test(f) && !/\.test\./.test(f) && !f.includes('/testing/') && !f.includes('/generated/'));
  const src = (f: string) => readFileSync(f, 'utf8');
  it('expo-local-authentication is not used anywhere in app code', () => {
    for (const f of prod) expect(src(f)).not.toMatch(/from ['"]expo-local-authentication['"]/);
  });
  it('SecureStore / AsyncStorage are imported only inside src/storage', () => {
    for (const f of prod.filter((p) => !p.includes('/storage/'))) expect(src(f)).not.toMatch(/expo-secure-store|@react-native-async-storage/);
  });
  it('no console.* in app code', () => {
    for (const f of prod) expect(src(f)).not.toMatch(/\bconsole\s*\./);
  });
  it('risk signals are imported only from the API layer', () => {
    for (const f of prod.filter((p) => !p.includes('/api/') && !p.includes('/risk/'))) expect(src(f)).not.toMatch(/risk\/signals/);
  });
  it('PIN is never passed in navigation params or query strings', () => {
    for (const f of prod.filter((p) => p.includes('/app/'))) expect(src(f)).not.toMatch(/(router\.(push|replace)\([^)]*(pin|token)=)/i);
  });
});
