import React, { useEffect, useRef, useState } from 'react';
import { useRouter } from 'expo-router';
import { Banner, Screen, T } from '../../ui/components';
import { PinPad } from '../../ui/PinPad';
import { flowErrorText, useOnBackground } from '../../ui/hooks';
import { changePin } from '../../flows/account';
import { PinBuffer } from '../../pin/buffer';
import { isWeakPin } from '../../pin/policy';

export default function ChangePin() {
  const router = useRouter();
  const old = useRef<PinBuffer | null>(null);
  const next = useRef<PinBuffer | null>(null);
  const [step, setStep] = useState<0 | 1 | 2>(0);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [resetKey, setResetKey] = useState(0);
  useEffect(() => () => { old.current?.clear(); next.current?.clear(); }, []);
  const restart = (m: string) => { old.current?.clear(); next.current?.clear(); old.current = null; next.current = null; setStep(0); setError(m); setResetKey((k) => k + 1); };

  useOnBackground(() => { if (old.current || next.current) restart('For your security, please start again.'); });

  const onComplete = async (pin: PinBuffer) => {
    if (step === 0) { old.current = pin; setError(null); setStep(1); return; }
    if (step === 1) {
      if (isWeakPin(pin.digits())) { pin.clear(); setError('Choose a less predictable PIN.'); setResetKey((k) => k + 1); return; }
      next.current = pin; setStep(2); return;
    }
    const o = old.current, n = next.current;
    old.current = null; next.current = null;
    if (!o || !n) { pin.clear(); restart('Please start again.'); return; }
    setBusy(true);
    const r = await changePin(o, n, pin);
    setBusy(false);
    if (r.ok) router.back();
    else restart(flowErrorText(r.error));
  };

  const labels = ['Enter your current PIN', 'Enter a new PIN', 'Confirm the new PIN'];
  return (
    <Screen scroll>
      <T kind="title">Change PIN</T>
      {error ? <Banner tone="error" text={error} /> : null}
      <PinPad label={labels[step]} onComplete={onComplete} disabled={busy} resetKey={resetKey} />
    </Screen>
  );
}
