import React, { useEffect, useRef, useState } from 'react';
import { useRouter } from 'expo-router';
import { Banner, Screen, T } from '../../ui/components';
import { PinPad } from '../../ui/PinPad';
import { flowErrorText, useOnBackground } from '../../ui/hooks';
import { PinBuffer } from '../../pin/buffer';
import { isWeakPin } from '../../pin/policy';
import { currentScope, endFlow, resetPinWithNewDevice, setInitialPin } from '../../flows/onboarding';

// PIN setup (scope pin-setup) or PIN reset (scope pin-reset): enter + confirm. The first entry is held in a ref'd buffer only.
export default function SetPin() {
  const router = useRouter();
  const first = useRef<PinBuffer | null>(null);
  const [step, setStep] = useState<'enter' | 'confirm'>('enter');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [resetKey, setResetKey] = useState(0);
  const isReset = currentScope() === 'pin-reset';

  useEffect(() => () => first.current?.clear(), []);

  const restart = (msg: string) => { first.current?.clear(); first.current = null; setStep('enter'); setError(msg); setResetKey((k) => k + 1); };

  useOnBackground(() => { if (first.current) restart('For your security, please start again.'); });

  const onComplete = async (pin: PinBuffer) => {
    if (step === 'enter') {
      if (isWeakPin(pin.digits())) { pin.clear(); restart('Choose a less predictable PIN.'); return; }
      first.current = pin; setError(null); setStep('confirm'); return;
    }
    const a = first.current;
    first.current = null;
    if (!a) { pin.clear(); restart('Please start again.'); return; }
    setBusy(true);
    const r = isReset ? await resetPinWithNewDevice(a, pin) : await setInitialPin(a, pin);
    setBusy(false);
    if (r.ok) return; // state machine moves to Unlocked; the route guard navigates
    restart(flowErrorText(r.error));
    if (r.error.code === 'IDEMPOTENT_REPLAY' || r.error.code === 'PIN_ALREADY_SET' || r.error.code === 'NO_FLOW') {
      endFlow();
      router.replace('/onboarding');
    }
  };

  return (
    <Screen scroll>
      <T kind="title">{isReset ? 'Choose a new PIN' : 'Create your PIN'}</T>
      <T kind="dim">6 digits. Avoid repeats and sequences.</T>
      {error ? <Banner tone="error" text={error} /> : null}
      <PinPad label={step === 'enter' ? 'Enter a new PIN' : 'Confirm your PIN'} onComplete={onComplete} disabled={busy} resetKey={resetKey} />
    </Screen>
  );
}
