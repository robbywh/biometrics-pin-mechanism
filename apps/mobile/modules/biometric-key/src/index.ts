// JS API of the local `biometric-key` Expo module. Identical types on iOS and Android (T4/T5).
// SEC-019: there is deliberately NO function returning a "biometric ok" boolean. `sign` returns a signature or throws.
import { requireNativeModule } from 'expo-modules-core';
import { BiometricKeyError, type BiometricKeyErrorKind } from './errors';

export { BiometricKeyError, type BiometricKeyErrorKind };

export type SecurityLevel = 'secure_enclave' | 'strongbox' | 'tee' | 'software' | 'unknown';


export interface SupportInfo {
  /** Secure Enclave present (iOS) / Keystore (Android; real check happens in generateKey via KeyInfo). */
  secureHardware: boolean;
  /** A strong biometric is enrolled. */
  biometricEnrolled: boolean;
  reason: 'ok' | 'NOT_ENROLLED' | 'LOCKOUT' | 'HARDWARE_UNAVAILABLE';
}

export interface GeneratedKey {
  /** base64url (no padding) SPKI DER, 91 bytes decoded */
  publicKeySpki: string;
  securityLevel: SecurityLevel;
}

interface NativeApi {
  isDeviceSecure(): Promise<boolean>;
  isSupported(): Promise<SupportInfo>;
  hasKey(alias: string): Promise<boolean>;
  generateKey(alias: string, allowSoftware: boolean): Promise<GeneratedKey>;
  sign(alias: string, messageBase64Url: string, promptTitle: string): Promise<{ signature: string }>;
  deleteKey(alias: string): Promise<void>;
}

let native: NativeApi | undefined;
const mod = (): NativeApi => (native ??= requireNativeModule<NativeApi>('BiometricKey'));

const KINDS: readonly string[] = ['USER_CANCELED', 'LOCKOUT', 'NOT_ENROLLED', 'KEY_INVALIDATED', 'HARDWARE_UNAVAILABLE', 'UNKNOWN'];

/** Maps whatever the native layer threw to a closed error enum. Never forwards native messages. */
export function toKeyError(e: unknown): BiometricKeyError {
  if (e instanceof BiometricKeyError) return e;
  const code = (e as { code?: unknown } | null)?.code;
  return new BiometricKeyError(typeof code === 'string' && KINDS.includes(code) ? (code as BiometricKeyErrorKind) : 'UNKNOWN');
}

async function guard<T>(f: () => Promise<T>): Promise<T> {
  try {
    return await f();
  } catch (e) {
    throw toKeyError(e);
  }
}

/** Device has a passcode / secure lock screen (SEC-034 fail-closed). */
export const isDeviceSecure = (): Promise<boolean> => guard(() => mod().isDeviceSecure());
export const isSupported = (): Promise<SupportInfo> => guard(() => mod().isSupported());
export const hasKey = (alias: string): Promise<boolean> => guard(() => mod().hasKey(alias));
/** `allowSoftware` is honoured only on simulator / debug native builds (SEC-017, SEC-022). */
export const generateKey = (alias: string, allowSoftware = false): Promise<GeneratedKey> => guard(() => mod().generateKey(alias, allowSoftware));
/** Biometric prompt, then ECDSA-P256-SHA256 DER signature (base64url) over the raw message bytes (base64url). */
export const sign = (alias: string, messageBase64Url: string, promptTitle: string): Promise<{ signature: string }> =>
  guard(() => mod().sign(alias, messageBase64Url, promptTitle));
export const deleteKey = (alias: string): Promise<void> => guard(() => mod().deleteKey(alias));
