import { randomUUID } from 'expo-crypto';

/** UUIDv4 (lowercase) for Idempotency-Key. */
export function newIdempotencyKey(): string {
  return randomUUID().toLowerCase();
}

/**
 * Idempotency-Key policy: reuse the key only when the outcome of the request is unknown or transient (network, timeout, 429, 5xx),
 * so a replay cannot double-execute. After a definitive business error (4xx other than 429) the key MUST be rotated, because a
 * server may store and replay that result for the same key.
 */
export function keepIdempotencyKeyAfter(code: string): boolean {
  return code === 'NETWORK_ERROR' || code === 'TIMEOUT' || code === 'RATE_LIMITED' || code === 'SERVICE_UNAVAILABLE' || code === 'INTERNAL' || code === 'UNKNOWN_ERROR';
}
