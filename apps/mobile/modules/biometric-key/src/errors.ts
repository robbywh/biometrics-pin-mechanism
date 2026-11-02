export type BiometricKeyErrorKind =
  | 'USER_CANCELED'
  | 'LOCKOUT'
  | 'NOT_ENROLLED'
  | 'KEY_INVALIDATED'
  | 'HARDWARE_UNAVAILABLE'
  | 'UNKNOWN';

export class BiometricKeyError extends Error {
  readonly kind: BiometricKeyErrorKind;
  constructor(kind: BiometricKeyErrorKind) {
    super(kind); // message is only the kind: never any key material or message bytes
    this.name = 'BiometricKeyError';
    this.kind = kind;
  }
}

