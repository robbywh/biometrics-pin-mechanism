import { PinBuffer } from '../pin/buffer';
import { authState } from '../auth/state';
import { memory } from '../storage/secureTokens';
import { resetFakes } from './fakeStorage';
import { fakeKey } from './fakeBiometricKey';
import { endFlow, registerThisDevice, setInitialPin, startBootstrap } from '../flows/onboarding';

export const pinOf = (s: string): PinBuffer => { const b = new PinBuffer(); for (const c of s) b.push(Number(c)); return b; };

export function resetWorld() {
  resetFakes();
  fakeKey.reset();
  memory.clearAll();
  endFlow();
  authState.__reset();
}

export const PIN = '493017';

/** Full first-run flow against the mock: leaves the app Unlocked with a PIN set. */
export async function onboardUnlocked(pin = PIN) {
  const s = await startBootstrap('alice', 'demo-secret', 'login');
  if (!s.ok) throw new Error('bootstrap');
  const d = await registerThisDevice('Test phone');
  if (!d.ok) throw new Error('device');
  const r = await setInitialPin(pinOf(pin), pinOf(pin));
  if (!r.ok) throw new Error('pin ' + JSON.stringify(r));
  return { deviceId: authState.get().session!.deviceId };
}
