import { useEffect, useRef, useState } from 'react';
import { AppState } from 'react-native';
import type { ApiError } from '../api/errors';
import { describeError } from '../api/errors';
import type { FlowError } from '../flows/biometrics';

/** Counts down from a SERVER-provided number of seconds. UI-only; never persisted; every attempt still hits the server. */
export function useCountdown() {
  const [left, setLeft] = useState(0);
  const timer = useRef<ReturnType<typeof setInterval> | null>(null);
  const stop = () => { if (timer.current) clearInterval(timer.current); timer.current = null; };
  useEffect(() => stop, []);
  const start = (seconds: number) => {
    stop();
    setLeft(seconds);
    if (seconds <= 0) return;
    timer.current = setInterval(() => setLeft((s) => { if (s <= 1) { stop(); return 0; } return s - 1; }), 1000);
  };
  return { left, start };
}

export function flowErrorText(e: FlowError | { code: string }): string {
  switch (e.code) {
    case 'PIN_MISMATCH': return 'The two PINs do not match.';
    case 'PIN_WEAK_LOCAL': return 'Choose a less predictable PIN.';
    case 'NO_FLOW': case 'NO_SESSION': return 'Please start again.';
    case 'CHALLENGE_MISMATCH': return 'The server response did not match your request. Nothing was approved. Please start again.';
    case 'REAUTH_REQUIRED': return 'Please confirm your PIN again.';
    case 'BIO_UNAVAILABLE': return 'Biometrics are not available or not set up on this device.';
    case 'BIO_KEY_ERROR': return 'Biometrics could not be enabled. Try again.';
    default: return describeError(e as ApiError);
  }
}

/** T10 / SEC-053: runs `onBackground` when the app goes inactive/background (used to wipe PIN buffers). */
export function useOnBackground(onBackground: () => void) {
  const cb = useRef(onBackground);
  useEffect(() => { cb.current = onBackground; });
  useEffect(() => {
    const sub = AppState.addEventListener('change', (s) => { if (s === 'inactive' || s === 'background') cb.current(); });
    return () => sub.remove();
  }, []);
}
