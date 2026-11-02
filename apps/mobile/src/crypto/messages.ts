// Signing-message and canonical-transaction builders, byte-exact per docs/features/biometric-pin-login/contract-notes.md
// sections 1-3. Pure TS: no React, no native imports (T6).
import { sha256 } from '@noble/hashes/sha2.js';
import { base64UrlDecode, base64UrlEncode } from './base64url';

const enc = new TextEncoder();
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const DECIMAL_RE = /^(0|[1-9][0-9]{0,17})(\.[0-9]{1,18})?$/;

/** lp(x) = uint16 big-endian length || x. */
export function lp(data: Uint8Array): Uint8Array {
  if (data.length > 0xffff) throw new Error('field too long');
  const out = new Uint8Array(2 + data.length);
  out[0] = (data.length >> 8) & 0xff;
  out[1] = data.length & 0xff;
  out.set(data, 2);
  return out;
}

function concat(parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

const ascii = (s: string) => enc.encode(s);

function uuidBytes(label: string, v: string): Uint8Array {
  if (!UUID_RE.test(v)) throw new Error(`${label}: not a lowercase canonical UUID`);
  return ascii(v);
}

function u64be(n: number): Uint8Array {
  if (!Number.isSafeInteger(n) || n < 0) throw new Error('expiresAt out of range');
  const out = new Uint8Array(8);
  let v = BigInt(n);
  for (let i = 7; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

export type ChallengePurpose = 'login' | 'enroll' | 'stepup';

export interface ChallengeFields {
  purpose: ChallengePurpose;
  userId: string;
  deviceId: string;
  /** base64url, 32 bytes */
  nonce: string;
  expiresAt: number;
  /** base64url, 32 bytes, or undefined/'' when the challenge has no boundHash */
  boundHash?: string | undefined;
}

/** Message the biometric key signs. Built ONLY from the server's challenge response values. */
export function buildChallengeMessage(c: ChallengeFields): Uint8Array {
  if (c.purpose !== 'login' && c.purpose !== 'enroll' && c.purpose !== 'stepup') throw new Error('bad purpose');
  const nonce = base64UrlDecode(c.nonce);
  if (nonce.length !== 32) throw new Error('nonce must be 32 bytes');
  const bound = c.boundHash ? base64UrlDecode(c.boundHash) : new Uint8Array(0);
  if (bound.length !== 0 && bound.length !== 32) throw new Error('boundHash must be 32 bytes or empty');
  return concat([
    lp(ascii('CRYPTOAPP/BIO/v1')),
    lp(ascii(c.purpose)),
    lp(uuidBytes('userId', c.userId)),
    lp(uuidBytes('deviceId', c.deviceId)),
    lp(nonce),
    lp(u64be(c.expiresAt)),
    lp(bound),
  ]);
}

export interface TxFields {
  asset: 'BTC' | 'ETH' | 'USDC';
  network: 'bitcoin' | 'ethereum';
  destination: string;
  amount: string;
  fee: string;
  txNonce: string;
  expiry: number;
}

/** Strip trailing fraction zeros ("1.50"->"1.5", "2.000"->"2"). Throws on anything outside the contract regex. */
export function normalizeDecimal(s: string): string {
  if (!DECIMAL_RE.test(s)) throw new Error('invalid decimal');
  if (!s.includes('.')) return s;
  const [i, f] = s.split('.') as [string, string];
  const frac = f.replace(/0+$/, '');
  return frac.length === 0 ? i : `${i}.${frac}`;
}

export function buildTxPreimage(t: TxFields): Uint8Array {
  if (!/^[A-Za-z0-9]{26,90}$/.test(t.destination)) throw new Error('bad destination');
  if (!Number.isSafeInteger(t.expiry) || t.expiry < 0) throw new Error('bad expiry');
  return concat([
    lp(ascii('CRYPTOAPP/TX/v1')),
    lp(ascii(t.asset)),
    lp(ascii(t.network)),
    lp(ascii(t.destination)),
    lp(ascii(normalizeDecimal(t.amount))),
    lp(ascii(normalizeDecimal(t.fee))),
    lp(uuidBytes('txNonce', t.txNonce)),
    lp(ascii(String(t.expiry))),
  ]);
}

/** Local sanity hash only (divergence warning). The server's txHash stays the authority. */
export function computeTxHash(t: TxFields): string {
  return base64UrlEncode(sha256(buildTxPreimage(t)));
}

export function buildActionPreimage(action: 'enable_biometric' | 'revoke_device', targetDeviceId: string): Uint8Array {
  return concat([lp(ascii('CRYPTOAPP/ACTION/v1')), lp(ascii(action)), lp(uuidBytes('targetDeviceId', targetDeviceId))]);
}

export function computeActionHash(action: 'enable_biometric' | 'revoke_device', targetDeviceId: string): string {
  return base64UrlEncode(sha256(buildActionPreimage(action, targetDeviceId)));
}
