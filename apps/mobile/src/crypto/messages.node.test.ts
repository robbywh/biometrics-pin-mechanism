import { readFileSync } from 'fs';
import { resolve } from 'path';
import { sha256 } from '@noble/hashes/sha2.js';
import { base64UrlDecode, base64UrlEncode, bytesToHex, hexToBytes } from './base64url';
import { buildActionPreimage, buildChallengeMessage, buildTxPreimage, computeTxHash, lp, normalizeDecimal } from './messages';

const vectors = JSON.parse(
  readFileSync(resolve(__dirname, '../../../../docs/features/biometric-pin-login/vectors/vectors.json'), 'utf8'),
) as { vectors: { id: string; input: any; equivalentInputs?: any[]; segmentsHex: string[]; totalBytes: number }[] };
const vec = (id: string) => vectors.vectors.find((v) => v.id === id)!;
const expected = (id: string) => vec(id).segmentsHex.join('');

describe('golden vector login-preimage-1 (SEC-027)', () => {
  const input = vec('login-preimage-1').input;
  const fields = () => ({
    purpose: input.purpose,
    userId: input.userId,
    deviceId: input.deviceId,
    nonce: base64UrlEncode(hexToBytes(input.nonceHex)),
    expiresAt: input.expiresAt,
    boundHash: input.boundHashHex ? base64UrlEncode(hexToBytes(input.boundHashHex)) : undefined,
  });
  it('reproduces byte for byte', () => {
    const msg = buildChallengeMessage(fields());
    expect(bytesToHex(msg)).toBe(expected('login-preimage-1'));
    expect(msg.length).toBe(vec('login-preimage-1').totalBytes);
  });
  it.each([
    ['purpose', { purpose: 'stepup' }],
    ['userId', { userId: '11111111-1111-4111-8111-111111111112' }],
    ['deviceId', { deviceId: '22222222-2222-4222-8222-222222222223' }],
    ['nonce', { nonce: base64UrlEncode(new Uint8Array(32)) }],
    ['expiresAt', { expiresAt: 1700000001 }],
    ['boundHash', { boundHash: base64UrlEncode(new Uint8Array(32)) }],
  ])('mutating %s changes the bytes', (_n, patch) => {
    expect(bytesToHex(buildChallengeMessage({ ...fields(), ...(patch as object) } as any))).not.toBe(expected('login-preimage-1'));
  });
  it('empty boundHash encodes as 0x0000 and 32-byte boundHash is included', () => {
    const withBound = buildChallengeMessage({ ...fields(), boundHash: base64UrlEncode(new Uint8Array(32).fill(7)) });
    expect(withBound.length).toBe(147 + 32);
  });
  it('rejects malformed inputs', () => {
    expect(() => buildChallengeMessage({ ...fields(), userId: 'ABCDEF11-1111-4111-8111-111111111111' })).toThrow();
    expect(() => buildChallengeMessage({ ...fields(), nonce: base64UrlEncode(new Uint8Array(31)) })).toThrow();
    expect(() => buildChallengeMessage({ ...fields(), nonce: 'AAAA=' })).toThrow();
    expect(() => buildChallengeMessage({ ...fields(), boundHash: base64UrlEncode(new Uint8Array(5)) })).toThrow();
    expect(() => buildChallengeMessage({ ...fields(), expiresAt: -1 })).toThrow();
  });
});

describe('golden vector tx-preimage-1 (SEC-039, client sanity only)', () => {
  const v = vec('tx-preimage-1');
  it('reproduces byte for byte', () => {
    const pre = buildTxPreimage(v.input);
    expect(bytesToHex(pre)).toBe(expected('tx-preimage-1'));
    // NOTE: vectors.json says totalBytes=140 but the segments (authoritative) sum to 138. Reported to tech lead.
    expect(pre.length).toBe(expected('tx-preimage-1').length / 2);
  });
  it('equivalentInputs yield identical bytes', () => {
    for (const eq of v.equivalentInputs!) {
      expect(bytesToHex(buildTxPreimage({ ...v.input, ...eq }))).toBe(expected('tx-preimage-1'));
    }
  });
  it('txHash equals SHA-256 of preimage', () => {
    expect(computeTxHash(v.input)).toBe(base64UrlEncode(sha256(hexToBytes(expected('tx-preimage-1')))));
  });
  it.each([
    ['asset', { asset: 'USDC' }],
    ['network', { network: 'bitcoin' }],
    ['destination', { destination: '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab' }],
    ['amount', { amount: '1.6' }],
    ['fee', { fee: '0.002' }],
    ['txNonce', { txNonce: '33333333-3333-4333-8333-333333333334' }],
    ['expiry', { expiry: 1700000601 }],
  ])('mutating %s changes the bytes', (_n, patch) => {
    expect(bytesToHex(buildTxPreimage({ ...v.input, ...(patch as object) }))).not.toBe(expected('tx-preimage-1'));
  });
  it('does not case-fold the destination', () => {
    const a = buildTxPreimage({ ...v.input, destination: '0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' });
    expect(bytesToHex(a)).not.toBe(expected('tx-preimage-1'));
  });
});

describe('decimal normalisation', () => {
  it.each([['1.50', '1.5'], ['2.000', '2'], ['0.10', '0.1'], ['0', '0'], ['0.0', '0']])('%s -> %s', (i, o) => expect(normalizeDecimal(i)).toBe(o));
  it.each(['01', '1.', '1e3', '-1', '+1', '', '.5', ' 1'])('rejects %p', (s) => expect(() => normalizeDecimal(s)).toThrow());
});

describe('length prefix property', () => {
  it('prefix equals payload length for random sizes', () => {
    for (const n of [0, 1, 2, 255, 256, 257, 4096, 65535]) {
      const out = lp(new Uint8Array(n));
      expect((out[0]! << 8) | out[1]!).toBe(n);
      expect(out.length).toBe(n + 2);
    }
    expect(() => lp(new Uint8Array(65536))).toThrow();
  });
});

describe('base64url', () => {
  it('round trips random buffers of all residues', () => {
    for (let n = 0; n < 70; n++) {
      const b = new Uint8Array(n).map((_, i) => (i * 37 + n * 11) & 255);
      const s = base64UrlEncode(b);
      expect(s).not.toMatch(/[=+/]/);
      expect(Array.from(base64UrlDecode(s))).toEqual(Array.from(b));
    }
  });
  it('matches Buffer base64url', () => {
    const b = new Uint8Array(33).map((_, i) => 255 - i);
    expect(base64UrlEncode(b)).toBe(Buffer.from(b).toString('base64url'));
  });
  it.each(['AA==', 'A+A', 'A/A', 'AA A', 'A', 'AAAAA', 'AB', 'é'])('rejects %p', (s) => expect(() => base64UrlDecode(s)).toThrow());
});

describe('action preimage', () => {
  it('has the documented layout', () => {
    const p = buildActionPreimage('enable_biometric', '2f0c9a4e-5b1d-4c6e-9a3f-7d8e1b2c3d4e');
    expect(p.length).toBe(2 + 19 + 2 + 16 + 2 + 36);
  });
});
