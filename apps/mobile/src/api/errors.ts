import type { components } from './generated/schema';

export type ErrorCode = components['schemas']['ErrorCode'];

interface Extras {
  status: number;
  attemptsRemaining?: number;
  attemptsUntilHardLock?: number;
  /** seconds; from body.retryAfter or the Retry-After header */
  retryAfter?: number;
  lockType?: 'soft' | 'hard';
  required?: 'bio' | 'pin' | 'either';
}

/** Discriminated union on `code`, one member per contract ErrorCode. Server `message` is deliberately dropped. */
export type KnownApiError = { [C in ErrorCode]: { code: C } & Extras }[ErrorCode];
export type ApiError = KnownApiError | ({ code: 'UNKNOWN_ERROR' } & Extras) | { code: 'NETWORK_ERROR' } | { code: 'TIMEOUT' };

export const ERROR_CODES: readonly ErrorCode[] = [
  'VALIDATION_ERROR', 'AUTH_FAILED', 'PIN_INVALID', 'UNLOCK_REQUIRED', 'STEPUP_REQUIRED', 'STEPUP_INVALID', 'COOLING_OFF',
  'SCOPE_INSUFFICIENT', 'NOT_FOUND', 'PIN_ALREADY_SET', 'DEVICE_LIMIT', 'IDEMPOTENT_REPLAY', 'PIN_WEAK', 'PIN_UNCHANGED',
  'IDEMPOTENCY_KEY_REUSED', 'INVALID_PUBLIC_KEY', 'INSUFFICIENT_FUNDS', 'PIN_LOCKED', 'RATE_LIMITED', 'SERVICE_UNAVAILABLE', 'INTERNAL',
];
const CODE_SET = new Set<string>(ERROR_CODES);

function nonNegInt(v: unknown): number | undefined {
  return typeof v === 'number' && Number.isInteger(v) && v >= 0 ? v : undefined;
}

export function mapError(status: number, body: unknown, retryAfterHeader?: string | null): ApiError {
  const err = (body as { error?: Record<string, unknown> } | null | undefined)?.error;
  const code = err && typeof err === 'object' ? err.code : undefined;
  const hdr = retryAfterHeader != null && /^\d+$/.test(retryAfterHeader) ? Number(retryAfterHeader) : undefined;
  const extras: Extras = { status };
  if (err && typeof err === 'object') {
    const ar = nonNegInt(err.attemptsRemaining);
    const au = nonNegInt(err.attemptsUntilHardLock);
    const ra = nonNegInt(err.retryAfter) ?? hdr;
    if (ar !== undefined) extras.attemptsRemaining = ar;
    if (au !== undefined) extras.attemptsUntilHardLock = au;
    if (ra !== undefined) extras.retryAfter = ra;
    if (err.lockType === 'soft' || err.lockType === 'hard') extras.lockType = err.lockType;
    if (err.required === 'bio' || err.required === 'pin' || err.required === 'either') extras.required = err.required;
  } else if (hdr !== undefined) {
    extras.retryAfter = hdr;
  }
  if (typeof code === 'string' && CODE_SET.has(code)) return { code: code as ErrorCode, ...extras } as KnownApiError;
  return { code: 'UNKNOWN_ERROR', ...extras };
}

function assertNever(x: never): never {
  throw new Error(`unhandled error code ${String(x)}`);
}

/** Generic, non-leaky user text per code. Exhaustive: adding a code to the contract breaks typecheck here. */
export function describeError(e: ApiError): string {
  switch (e.code) {
    case 'NETWORK_ERROR': return 'No connection. Check your network and try again.';
    case 'TIMEOUT': return 'The server took too long to respond. Try again.';
    case 'UNKNOWN_ERROR': return 'Something went wrong. Try again.';
    case 'VALIDATION_ERROR': return 'The request was not valid.';
    case 'AUTH_FAILED': return 'Authentication failed.';
    case 'PIN_INVALID': return e.attemptsRemaining !== undefined ? `Incorrect PIN. ${e.attemptsRemaining} attempts remaining before a temporary lock.` : 'Incorrect PIN.';
    case 'UNLOCK_REQUIRED': return 'Unlock required.';
    case 'STEPUP_REQUIRED': return 'Additional verification is required.';
    case 'STEPUP_INVALID': return 'Verification expired or no longer valid. Please start again.';
    case 'COOLING_OFF': return 'This action is temporarily limited on a new or recently reset device.';
    case 'SCOPE_INSUFFICIENT': return 'Not permitted.';
    case 'NOT_FOUND': return 'Not found.';
    case 'PIN_ALREADY_SET': return 'A PIN is already set for this account.';
    case 'DEVICE_LIMIT': return 'This account has reached its device limit. Remove a device first.';
    case 'IDEMPOTENT_REPLAY': return 'That request was already processed.';
    case 'PIN_WEAK': return 'Choose a less predictable PIN.';
    case 'PIN_UNCHANGED': return 'Choose a different PIN.';
    case 'IDEMPOTENCY_KEY_REUSED': return 'Request conflict. Please start again.';
    case 'INVALID_PUBLIC_KEY': return 'Biometrics could not be enabled on this device.';
    case 'INSUFFICIENT_FUNDS': return 'Insufficient funds.';
    case 'PIN_LOCKED': return e.lockType === 'hard' ? 'Too many incorrect PINs. Reset your PIN to continue.' : 'Too many incorrect PINs. Try again later.';
    case 'RATE_LIMITED': return 'Too many requests. Please wait a moment.';
    case 'SERVICE_UNAVAILABLE': return 'The service is temporarily unavailable.';
    case 'INTERNAL': return 'Something went wrong. Try again.';
    default: return assertNever(e);
  }
}
