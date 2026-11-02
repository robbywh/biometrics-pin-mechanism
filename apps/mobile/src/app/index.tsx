import React from 'react';
import { ActivityIndicator } from 'react-native';
import { Redirect } from 'expo-router';
import { Screen } from '../ui/components';
import { useAuth } from '../auth/state';

// Entry route ('/'): shows a spinner while booting, then redirects according to the auth state machine.
export default function Entry() {
  const status = useAuth((s) => s.status);
  if (status === 'locked') return <Redirect href="/lock" />;
  if (status === 'onboarding') return <Redirect href="/onboarding" />;
  if (status === 'needsPasscode') return <Redirect href="/needs-passcode" />;
  if (status === 'unlocked') return <Redirect href="/home" />;
  return (
    <Screen>
      <ActivityIndicator accessibilityLabel="Loading" />
    </Screen>
  );
}
