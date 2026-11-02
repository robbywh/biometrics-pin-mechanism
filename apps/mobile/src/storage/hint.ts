// SEC-054: `biometricEnabled` in AsyncStorage is a NON-authoritative UI hint. It may only choose which screen is shown first.
import AsyncStorage from '@react-native-async-storage/async-storage';

const HINT_KEY = 'hint.biometricEnabled';
const DELAY_KEY = 'pref.autoLockDelaySec';

export async function getBiometricHint(): Promise<boolean> {
  return (await AsyncStorage.getItem(HINT_KEY)) === '1';
}
export async function setBiometricHint(v: boolean): Promise<void> {
  if (v) await AsyncStorage.setItem(HINT_KEY, '1');
  else await AsyncStorage.removeItem(HINT_KEY);
}

/** Auto-lock background delay in seconds: 0 (immediate), 30 (default), 60 (max). */
export type AutoLockDelay = 0 | 30 | 60;
export async function getAutoLockDelay(): Promise<AutoLockDelay> {
  const v = await AsyncStorage.getItem(DELAY_KEY);
  return v === '0' ? 0 : v === '60' ? 60 : 30;
}
export async function setAutoLockDelay(v: AutoLockDelay): Promise<void> {
  await AsyncStorage.setItem(DELAY_KEY, String(v));
}
