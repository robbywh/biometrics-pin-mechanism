import React, { useState } from 'react';
import { useRouter } from 'expo-router';
import { Banner, Screen, T } from '../../ui/components';
import { PinPad } from '../../ui/PinPad';
import { flowErrorText } from '../../ui/hooks';
import { enableBiometrics } from '../../flows/biometrics';
import type { PinBuffer } from '../../pin/buffer';

export default function EnableBiometrics() {
  const router = useRouter();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [resetKey, setResetKey] = useState(0);
  const onComplete = async (pin: PinBuffer) => {
    setBusy(true);
    const r = await enableBiometrics(pin);
    setBusy(false); setResetKey((k) => k + 1);
    if (r.ok) router.back();
    else setError(r.error.code === 'STEPUP_INVALID' ? 'That took too long. Please try again.' : flowErrorText(r.error));
  };
  return (
    <Screen scroll>
      <T kind="title">Enable biometrics</T>
      <T kind="dim">Confirm your PIN, then approve with your fingerprint or face to create a device-protected key.</T>
      {error ? <Banner tone="error" text={error} /> : null}
      <PinPad label="Confirm your PIN" onComplete={onComplete} disabled={busy} resetKey={resetKey} />
    </Screen>
  );
}
