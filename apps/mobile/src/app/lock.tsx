import React, { useCallback, useEffect, useState } from 'react';
import { AppState, View } from 'react-native';
import { useRouter } from 'expo-router';
import * as Haptics from 'expo-haptics';
import { Banner, Button, Screen, T } from '../ui/components';
import { PinPad } from '../ui/PinPad';
import { useCountdown } from '../ui/hooks';
import { describeError } from '../api/errors';
import { canOfferBiometric, unlockWithBiometric, unlockWithPin } from '../auth/unlock';
import { useAuth } from '../auth/state';
import type { PinBuffer } from '../pin/buffer';

export default function LockScreen() {
  const router = useRouter();
  const notice = useAuth((s) => s.notice);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [hard, setHard] = useState(false);
  const [bio, setBio] = useState(false);
  const [resetKey, setResetKey] = useState(0);
  const cd = useCountdown();

  const tryBiometric = useCallback(async () => {
    setBusy(true);
    const out = await unlockWithBiometric('Unlock CryptoApp');
    setBusy(false);
    // Any failure: neutral message, PIN stays available. Never "open".
    if (out.status === 'fallback' && out.reason !== 'NO_KEY' && out.reason !== 'NO_HINT') setMessage('Use your PIN to unlock.');
  }, []);

  useEffect(() => {
    let live = true;
    // never auto-prompt while the app is backgrounded (the lock timer can fire there)
    void canOfferBiometric().then((ok) => { if (live && ok) { setBio(true); if (AppState.currentState !== 'background' && AppState.currentState !== 'inactive') void tryBiometric(); } });
    return () => { live = false; };
  }, [tryBiometric]);

  const onPin = async (pin: PinBuffer) => {
    setBusy(true);
    const r = await unlockWithPin(pin);
    setBusy(false);
    setResetKey((k) => k + 1); // input cleared after every attempt
    if (r.ok) return;
    Haptics.notificationAsync(Haptics.NotificationFeedbackType.Error).catch(() => undefined);
    setMessage(describeError(r.error));
    if (r.error.code === 'PIN_LOCKED') {
      setHard(r.error.lockType === 'hard');
      if (r.error.lockType !== 'hard' && r.error.retryAfter) cd.start(r.error.retryAfter);
    } else if (r.error.code === 'RATE_LIMITED' && r.error.retryAfter) cd.start(r.error.retryAfter);
  };

  return (
    <Screen scroll>
      <T kind="title">Welcome back</T>
      {notice?.kind === 'biometricInvalidated' ? <Banner text="Biometrics were disabled because your device biometrics changed. Re-enable them in Settings after you unlock." /> : null}
      {message ? <Banner tone="error" text={message} /> : null}
      {cd.left > 0 ? <T kind="warn" accessibilityLiveRegion="polite">Try again in {cd.left}s</T> : null}
      <PinPad label="Enter your PIN" onComplete={onPin} disabled={busy || hard || cd.left > 0} resetKey={resetKey} />
      <View style={{ gap: 12 }}>
        {bio ? <Button title="Use biometrics" kind="secondary" onPress={() => void tryBiometric()} busy={busy} testID="bio-button" /> : null}
        {hard ? <Button title="Reset PIN" kind="danger" onPress={() => router.push('/onboarding?intent=reset')} testID="reset-cta" /> : <Button title="Forgot PIN?" kind="secondary" onPress={() => router.push('/onboarding?intent=reset')} />}
      </View>
    </Screen>
  );
}
