// Cached auto-lock delay read by the root layout's AutoLock and written by Settings so changes apply immediately.
import { getAutoLockDelay, setAutoLockDelay, type AutoLockDelay } from '../storage/hint';

let current: AutoLockDelay = 30;
export const cachedAutoLockDelay = (): AutoLockDelay => current;
export async function loadAutoLockDelay(): Promise<void> { current = await getAutoLockDelay(); }
export async function changeAutoLockDelay(v: AutoLockDelay): Promise<void> { current = v; await setAutoLockDelay(v); }
