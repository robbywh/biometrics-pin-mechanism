// Cold start: always Locked (or Onboarding when there is no refresh token, or NeedsPasscode when the device has no passcode).
import * as BiometricKey from 'biometric-key';
import { getDeviceId, getRefreshToken } from '../storage/secureTokens';
import { authState } from './state';

export async function boot(): Promise<void> {
  let secure = false;
  try { secure = await BiometricKey.isDeviceSecure(); } catch { secure = false; }
  if (!secure) { authState.toNeedsPasscode(); return; } // SEC-034 fail closed
  let token: string | null = null;
  let did: string | null = null;
  try { [token, did] = await Promise.all([getRefreshToken(), getDeviceId()]); } catch { /* keychain unavailable -> onboarding */ }
  if (token && did) authState.toLocked();
  else authState.toOnboarding();
}
