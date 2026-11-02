import React, { useCallback, useEffect, useState } from 'react';
import { useRouter } from 'expo-router';
import { Banner, Button, Card, Screen, T } from '../../ui/components';
import { authedCall } from '../../auth/session';
import { authState, useAuth } from '../../auth/state';
import * as api from '../../api/endpoints';
import { describeError } from '../../api/errors';

export default function Home() {
  const router = useRouter();
  const notice = useAuth((s) => s.notice);
  const bioEnabled = useAuth((s) => s.session?.biometricEnabled ?? false);
  const [data, setData] = useState<api.Dashboard | null>(null);
  const [error, setError] = useState<string | null>(null);
  const load = useCallback(async () => {
    const r = await authedCall((t) => api.getDashboard(t));
    if (r.ok) { setData(r.data); setError(null); } else setError(describeError(r.error));
  }, []);
  useEffect(() => { void load(); }, [load]);

  const noticeText =
    notice?.kind === 'recentFailures' ? `${notice.count} failed attempt${notice.count === 1 ? '' : 's'} since your last login.`
    : notice?.kind === 'coolingOff' ? 'New device or biometric key: large transfers are limited for a while.'
    : notice?.kind === 'pinChanged' ? 'Your PIN was changed. Other devices were signed out.'
    : notice?.kind === 'biometricInvalidated' ? 'Biometrics were disabled because your device biometrics changed. Re-enable in Settings.'
    : null;

  return (
    <Screen scroll>
      {noticeText ? <Banner text={noticeText} onDismiss={authState.clearNotice} /> : null}
      <T kind="dim">Total balance</T>
      <T kind="title" accessibilityLabel={data ? `Total balance ${data.totalValue} ${data.currency}` : 'Loading balance'}>{data ? `$${data.totalValue}` : '...'}</T>
      {error ? <Banner tone="error" text={error} /> : null}
      {data?.balances.map((b) => (
        <Card key={b.asset}>
          <T kind="h2">{b.asset}</T>
          <T>{b.amount} {b.asset}</T>
          <T kind="dim">${b.value}</T>
        </Card>
      ))}
      {!bioEnabled ? (
        <Card>
          <T kind="h2">Faster unlock</T>
          <T kind="dim">Use Face ID or fingerprint to unlock. Your PIN always stays available.</T>
          <Button title="Enable biometrics" kind="secondary" onPress={() => router.push('/enable-biometrics')} />
        </Card>
      ) : null}
      <Button title="Send" onPress={() => router.push('/send')} testID="send" />
      <Button title="Settings" kind="secondary" onPress={() => router.push('/settings')} />
    </Screen>
  );
}
