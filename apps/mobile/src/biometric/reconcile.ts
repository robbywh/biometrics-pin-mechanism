// SEC-054 / T16 reconciliation of the non-authoritative hint with server state (`biometricEnabled` from an authenticated
// unlock response) and the local key. The hint only chooses the first screen; it never grants anything.
import * as BiometricKey from 'biometric-key';
import * as api from '../api/endpoints';
import { getBiometricHint, setBiometricHint } from '../storage/hint';
import { authState } from '../auth/state';
import { biometricAlias } from './alias';
import { authedCall } from '../auth/session';

export type ReconcileOutcome =
  | 'hint-set' // server enabled + key present: hint -> true
  | 'hint-kept' // hint already true, server enabled, key present
  | 'hint-cleared' // server disabled or no key
  | 'orphan-key-deleted' // server disabled but a local key existed: removed
  | 'server-realigned'; // server enabled but key gone: server told to disable

/** Pure decision table (mirrors SEC-054). */
export function decide(input: { hint: boolean; serverEnabled: boolean; keyPresent: boolean }): ReconcileOutcome {
  const { hint, serverEnabled, keyPresent } = input;
  if (serverEnabled && keyPresent) return hint ? 'hint-kept' : 'hint-set';
  if (serverEnabled && !keyPresent) return 'server-realigned';
  if (!serverEnabled && keyPresent) return 'orphan-key-deleted';
  return 'hint-cleared';
}

export async function reconcileBiometricHint(deviceId: string, serverEnabled: boolean): Promise<ReconcileOutcome> {
  const alias = biometricAlias(deviceId);
  let keyPresent = false;
  try { keyPresent = await BiometricKey.hasKey(alias); } catch { keyPresent = false; }
  const outcome = decide({ hint: await getBiometricHint(), serverEnabled, keyPresent });
  switch (outcome) {
    case 'hint-set': case 'hint-kept': await setBiometricHint(true); break;
    case 'hint-cleared': await setBiometricHint(false); break;
    case 'orphan-key-deleted':
      await BiometricKey.deleteKey(alias).catch(() => undefined);
      await setBiometricHint(false);
      break;
    case 'server-realigned': {
      // Key lost locally (e.g. enrollment change) while the server still lists it: tell the server (we just PIN-unlocked).
      await setBiometricHint(false);
      const r = await authedCall((t) => api.biometricDisable(t, deviceId));
      if (r.ok || r.error.code === 'NOT_FOUND') authState.setNotice({ kind: 'biometricInvalidated' });
      break;
    }
  }
  return outcome;
}
