// Fake native module for tests: records the EXACT bytes passed to sign() and lets tests inject native errors.
import { BiometricKeyError, type BiometricKeyErrorKind } from '../../modules/biometric-key/src/errors';
import { base64UrlDecode, base64UrlEncode } from '../crypto/base64url';

type SecurityLevel = 'secure_enclave' | 'strongbox' | 'tee' | 'software' | 'unknown';

const SPKI_HEADER = Buffer.from('3059301306072a8648ce3d020106082a8648ce3d030107034200', 'hex');

export const fakeKey = {
  keys: new Set<string>(),
  signed: [] as { alias: string; message: Uint8Array; title: string }[],
  nextSignError: null as BiometricKeyErrorKind | null,
  nextGenerateError: null as BiometricKeyErrorKind | null,
  securityLevel: 'tee' as SecurityLevel,
  deviceSecure: true,
  badSpki: false,
  support: { secureHardware: true, biometricEnrolled: true, reason: 'ok' as const },
  reset() {
    this.keys.clear(); this.signed.length = 0; this.nextSignError = null; this.nextGenerateError = null;
    this.deviceSecure = true; this.badSpki = false; this.support = { secureHardware: true, biometricEnrolled: true, reason: 'ok' };
  },
  /** simulate an OS biometric enrollment change */
  invalidateAll() { this.keys.clear(); },
};

export const biometricKeyFake = {
  BiometricKeyError,
  isDeviceSecure: async () => fakeKey.deviceSecure,
  isSupported: async () => fakeKey.support,
  hasKey: async (a: string) => fakeKey.keys.has(a),
  generateKey: async (a: string) => {
    if (fakeKey.nextGenerateError) { const k = fakeKey.nextGenerateError; fakeKey.nextGenerateError = null; throw new BiometricKeyError(k); }
    fakeKey.keys.add(a);
    if (fakeKey.badSpki) return { publicKeySpki: 'AAAA', securityLevel: fakeKey.securityLevel };
    return { publicKeySpki: base64UrlEncode(new Uint8Array(Buffer.concat([SPKI_HEADER, Buffer.from([4]), Buffer.alloc(64, 7)]))), securityLevel: fakeKey.securityLevel };
  },
  sign: async (alias: string, messageB64: string, title: string) => {
    if (fakeKey.nextSignError) { const k = fakeKey.nextSignError; fakeKey.nextSignError = null; if (k === 'KEY_INVALIDATED') fakeKey.keys.delete(alias); throw new BiometricKeyError(k); }
    if (!fakeKey.keys.has(alias)) throw new BiometricKeyError('KEY_INVALIDATED');
    fakeKey.signed.push({ alias, message: base64UrlDecode(messageB64), title });
    return { signature: base64UrlEncode(new Uint8Array(Buffer.from('fake-der-signature'))) };
  },
  deleteKey: async (a: string) => { fakeKey.keys.delete(a); },
};
