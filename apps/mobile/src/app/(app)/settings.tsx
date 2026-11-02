import React, { useState } from 'react';
import { useRouter } from 'expo-router';
import { Banner, Button, Card, Screen, T } from '../../ui/components';
import { PinPad } from '../../ui/PinPad';
import { flowErrorText } from '../../ui/hooks';
import { useAuth } from '../../auth/state';
import { lock } from '../../auth/session';
import { unlockWithPin } from '../../auth/unlock';
import { disableBiometrics } from '../../flows/biometrics';
import { cachedAutoLockDelay, changeAutoLockDelay } from '../../auth/autoLockSettings';
import type { AutoLockDelay } from '../../storage/hint';
import { signOut } from '../../flows/account';
import { describeError } from '../../api/errors';
import type { PinBuffer } from '../../pin/buffer';

export default function Settings() {
  const router = useRouter();
  const bio = useAuth((s) => s.session?.biometricEnabled ?? false);
  const [delay, setDelay] = useState<AutoLockDelay>(cachedAutoLockDelay());
  const [reauth, setReauth] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [resetKey, setResetKey] = useState(0);

  const disable = async () => {
    const r = await disableBiometrics();
    if (r.ok) { setError(null); return; }
    if (r.error.code === 'REAUTH_REQUIRED') setReauth(true); else setError(flowErrorText(r.error));
  };
  const onPin = async (pin: PinBuffer) => {
    setBusy(true);
    const u = await unlockWithPin(pin); // re-unlock, then retry the disable once
    setResetKey((k) => k + 1);
    if (!u.ok) { setBusy(false); setError(describeError(u.error)); return; }
    const r = await disableBiometrics();
    setBusy(false);
    if (r.ok) { setReauth(false); setError(null); } else setError(flowErrorText(r.error));
  };

  if (reauth) {
    return (
      <Screen scroll>
        {error ? <Banner tone="error" text={error} /> : null}
        <PinPad label="Confirm your PIN" onComplete={onPin} disabled={busy} resetKey={resetKey} />
        <Button title="Cancel" kind="secondary" onPress={() => setReauth(false)} />
      </Screen>
    );
  }
  return (
    <Screen scroll>
      {error ? <Banner tone="error" text={error} /> : null}
      <Card>
        <T kind="h2">Biometric unlock</T>
        <T kind="dim">{bio ? 'On. Your PIN always works as a fallback.' : 'Off.'}</T>
        {bio ? <Button title="Turn off" kind="secondary" onPress={() => void disable()} /> : <Button title="Turn on" onPress={() => router.push('/enable-biometrics')} />}
      </Card>
      <Card>
        <T kind="h2">Auto-lock when in background</T>
        {([[0, 'Immediately'], [30, '30 seconds'], [60, '1 minute']] as [AutoLockDelay, string][]).map(([v, label]) => (
          <Button key={v} title={`${label}${delay === v ? ' (selected)' : ''}`} kind={delay === v ? 'primary' : 'secondary'} onPress={() => { setDelay(v); void changeAutoLockDelay(v); }} />
        ))}
        <T kind="dim">Applies immediately. The app also locks after 5 minutes of inactivity.</T>
      </Card>
      <Button title="Change PIN" kind="secondary" onPress={() => router.push('/change-pin')} />
      <Button title="Devices" kind="secondary" onPress={() => router.push('/devices')} />
      <Button title="Lock now" onPress={lock} />
      <Button title="Sign out" kind="danger" onPress={() => void signOut()} />
    </Screen>
  );
}
