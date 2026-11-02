// T19: send a transaction with server-driven step-up. The form is frozen once the challenge is issued; the SAME fields go to
// /stepup/challenge and /transactions. The server's `summary` is what the user confirms. No approval flag exists anywhere.
import * as BiometricKey from 'biometric-key';
import * as api from '../api/endpoints';
import { keepIdempotencyKeyAfter, newIdempotencyKey } from '../api/uuid';
import { base64UrlEncode } from '../crypto/base64url';
import { buildChallengeMessage, computeTxHash } from '../crypto/messages';
import { isValidStepUpChallenge } from '../crypto/challengeCheck';
import type { PinBuffer } from '../pin/buffer';
import { authedCall } from '../auth/session';
import { authState } from '../auth/state';
import { biometricAlias } from '../biometric/alias';
import type { FlowError } from './biometrics';

export type SendResult<T = undefined> = ({ ok: true } & (T extends undefined ? object : { data: T })) | { ok: false; error: FlowError; restart?: boolean };

export class SendTransaction {
  private readonly tx: api.TransactionFields;
  private challenge: api.StepUpChallenge | null = null;
  private stepUpToken: string | null = null;
  /** one key per transaction attempt: reused only when retrying the SAME tx */
  private idemKey = newIdempotencyKey();
  private submitting = false;
  /** true when the local sanity hash differs from the server's txHash (warning only, server stays the authority) */
  divergence = false;

  constructor(tx: api.TransactionFields) {
    this.tx = Object.freeze({ ...tx });
  }

  get fields(): Readonly<api.TransactionFields> { return this.tx; }
  get summary() { return this.challenge?.summary ?? null; }
  get required() { return this.challenge?.required ?? null; }
  get hasToken() { return this.stepUpToken !== null; }

  /** (Re)issues the step-up challenge for the frozen fields. */
  async begin(): Promise<SendResult<api.StepUpChallenge>> {
    this.stepUpToken = null;
    const r = await authedCall((t) => api.stepupChallengeTx(t, this.tx));
    if (!r.ok) return r;
    // M-01 / M-02: the server's challenge must be a step-up for THIS device bound to the hash of the fields WE froze.
    let local: string | null = null;
    try { local = computeTxHash(this.tx); } catch { local = null; }
    const s = authState.get().session;
    this.divergence = local === null || !s || r.data.txHash !== local || !isValidStepUpChallenge(r.data, s.deviceId, local);
    if (this.divergence) { this.challenge = null; return { ok: false, error: { code: 'CHALLENGE_MISMATCH' } }; }
    this.challenge = r.data;
    return { ok: true, data: r.data };
  }

  /** Biometric proof (only if the server allows it). Falls back to PIN on any local failure or if the server demands PIN. */
  async proveWithBiometric(): Promise<SendResult<{ fallbackToPin: boolean }>> {
    const c = this.challenge;
    const s = authState.get().session;
    if (this.divergence) return { ok: false, error: { code: 'CHALLENGE_MISMATCH' } };
    if (!c || !s) return { ok: false, error: { code: 'NO_SESSION' } };
    if (c.required === 'pin') return { ok: true, data: { fallbackToPin: true } };
    let signature: string;
    try {
      const message = buildChallengeMessage({ purpose: c.purpose, userId: c.userId, deviceId: c.deviceId, nonce: c.nonce, expiresAt: c.expiresAt, boundHash: c.boundHash });
      signature = (await BiometricKey.sign(biometricAlias(s.deviceId), base64UrlEncode(message), `Confirm: ${c.summary.title}`.slice(0, 80) /* L-11: prompt carries tx context */)).signature;
    } catch {
      return { ok: true, data: { fallbackToPin: true } }; // challenge not consumed server-side yet: PIN can still use it
    }
    const v = await authedCall((t) => api.stepupVerifySignature(t, c.challengeId, signature), { retry: false });
    if (!v.ok) {
      this.challenge = null; // consumed on first attempt: a new challenge is needed
      if (v.error.code === 'STEPUP_REQUIRED') return { ok: true, data: { fallbackToPin: true } };
      return { ok: false, error: v.error, restart: true };
    }
    this.stepUpToken = v.data.stepUpToken;
    return { ok: true, data: { fallbackToPin: false } };
  }

  async proveWithPin(pin: PinBuffer): Promise<SendResult> {
    const c = this.challenge;
    if (this.divergence) { pin.clear(); return { ok: false, error: { code: 'CHALLENGE_MISMATCH' } }; }
    if (!c) { pin.clear(); return { ok: false, error: { code: 'STEPUP_INVALID', status: 403 }, restart: true }; }
    const v = await authedCall((t) => api.stepupVerifyPin(t, c.challengeId, pin), { retry: false });
    pin.clear();
    if (!v.ok) {
      this.challenge = null; // challenge consumed on first attempt (even wrong PIN): caller must begin() again
      return { ok: false, error: v.error, restart: true };
    }
    this.stepUpToken = v.data.stepUpToken;
    return { ok: true };
  }

  /** Submit exactly once. Double taps return the in-flight result guard. */
  async submit(): Promise<SendResult<api.TransactionResponse>> {
    if (this.submitting) return { ok: false, error: { code: 'IDEMPOTENT_REPLAY', status: 409 } };
    const token = this.stepUpToken;
    if (!token) return { ok: false, error: { code: 'STEPUP_REQUIRED', status: 403 }, restart: true };
    this.submitting = true;
    try {
      const r = await authedCall((t) => api.createTransaction(t, this.idemKey, token, this.tx), { retry: false });
      this.stepUpToken = null; // single use: dropped regardless of outcome
      if (!r.ok && !keepIdempotencyKeyAfter(r.error.code)) this.idemKey = newIdempotencyKey();
      if (!r.ok) return { ok: false, error: r.error, restart: r.error.code === 'STEPUP_INVALID' };
      return { ok: true, data: r.data };
    } finally {
      this.submitting = false;
    }
  }
}
