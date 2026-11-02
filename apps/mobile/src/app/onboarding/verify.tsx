import React, { useState } from 'react';
import { Banner, Screen, T } from '../../ui/components';
import { PinPad } from '../../ui/PinPad';
import { useCountdown } from '../../ui/hooks';
import { describeError } from '../../api/errors';
import { unlockNewInstall } from '../../flows/onboarding';
import type { PinBuffer } from '../../pin/buffer';

// Account already has a PIN (new install): unlock with the device-bound bootstrap token as credential.
export default function VerifyNewInstall() {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [resetKey, setResetKey] = useState(0);
  const cd = useCountdown();
  const onComplete = async (pin: PinBuffer) => {
    setBusy(true);
    const r = await unlockNewInstall(pin);
    setBusy(false); setResetKey((k) => k + 1);
    if (r.ok) return;
    setError(describeError(r.error));
    if (r.error.code === 'PIN_LOCKED' && r.error.retryAfter) cd.start(r.error.retryAfter);
  };
  return (
    <Screen scroll>
      <T kind="title">Enter your PIN</T>
      {error ? <Banner tone="error" text={error} /> : null}
      {cd.left > 0 ? <T kind="warn">Try again in {cd.left}s</T> : null}
      <PinPad onComplete={onComplete} disabled={busy || cd.left > 0} resetKey={resetKey} />
    </Screen>
  );
}
