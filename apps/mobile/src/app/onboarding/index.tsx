import React, { useState } from 'react';
import { TextInput } from 'react-native';
import { useLocalSearchParams, useRouter } from 'expo-router';
import * as Device from 'expo-device';
import { Banner, Button, Screen, T } from '../../ui/components';
import { color, radius } from '../../ui/theme';
import { flowErrorText, useCountdown } from '../../ui/hooks';
import { registerThisDevice, startBootstrap, type Intent } from '../../flows/onboarding';
import { devDemoSecret } from '../../config/devDefaults';

const input = { color: color.text, backgroundColor: color.surface, borderRadius: radius.md, padding: 16, fontSize: 16, minHeight: 56 } as const;

export default function Onboarding() {
  const router = useRouter();
  const { intent } = useLocalSearchParams<{ intent?: string }>();
  const mode: Intent = intent === 'reset' ? 'reset' : 'login';
  const [username, setUsername] = useState('alice');
  const [secret, setSecret] = useState(devDemoSecret());
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const cd = useCountdown();

  const go = async () => {
    setBusy(true); setError(null);
    const s = await startBootstrap(username.trim().toLowerCase(), secret, mode);
    if (!s.ok) { fail(s.error); return; }
    const d = await registerThisDevice(Device.modelName ?? 'My phone');
    if (!d.ok) { fail(d.error); return; }
    setBusy(false); setSecret('');
    router.push(s.data === 'pin-verify' ? '/onboarding/verify' : '/onboarding/pin');
  };
  const fail = (e: { code: string; retryAfter?: number }) => {
    setBusy(false);
    setError(flowErrorText(e));
    if (e.code === 'RATE_LIMITED' && e.retryAfter) cd.start(e.retryAfter);
  };

  return (
    <Screen scroll>
      <T kind="title">{mode === 'reset' ? 'Reset your PIN' : 'Sign in'}</T>
      <T kind="dim">Demo sign-in. This stands in for your password and 2FA.</T>
      {error ? <Banner tone="error" text={error} /> : null}
      {cd.left > 0 ? <T kind="warn">Try again in {cd.left}s</T> : null}
      <TextInput accessibilityLabel="Username" style={input} value={username} onChangeText={setUsername} autoCapitalize="none" autoCorrect={false} placeholderTextColor={color.textDim} placeholder="username" />
      <TextInput accessibilityLabel="Demo secret" style={input} value={secret} onChangeText={setSecret} secureTextEntry autoCapitalize="none" autoCorrect={false} autoComplete="off" textContentType="none" importantForAutofill="noExcludeDescendants" contextMenuHidden placeholderTextColor={color.textDim} placeholder="demo secret" />
      <Button title="Continue" onPress={() => void go()} busy={busy} disabled={!username || !secret || cd.left > 0} testID="continue" />
    </Screen>
  );
}
