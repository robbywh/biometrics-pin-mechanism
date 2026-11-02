import React, { useEffect, useMemo } from 'react';
import { AppState, View } from 'react-native';
import { Stack } from 'expo-router';
import { StatusBar } from 'expo-status-bar';
import { SafeAreaProvider } from 'react-native-safe-area-context';
import { usePreventScreenCapture } from 'expo-screen-capture';
import { getApi } from '../api/client';
import { AutoLock } from '../auth/autoLock';
import { boot } from '../auth/boot';
import { lock } from '../auth/session';
import { authState, useAuth } from '../auth/state';
import { cachedAutoLockDelay, loadAutoLockDelay } from '../auth/autoLockSettings';
import { PrivacyOverlay } from '../ui/PrivacyOverlay';

// Fails fast at startup if a release build is configured with a non-HTTPS API URL (SEC-006).
getApi();

export default function RootLayout() {
  usePreventScreenCapture(); // SEC-051: Android FLAG_SECURE / iOS capture blocking, app-wide
  const status = useAuth((s) => s.status);

  const autoLock = useMemo(
    () =>
      new AutoLock({
        now: () => Date.now(),
        setTimer: (fn, ms) => setTimeout(fn, ms),
        clearTimer: (h) => clearTimeout(h as ReturnType<typeof setTimeout>),
        getDelaySec: () => cachedAutoLockDelay(),
        isUnlocked: () => authState.get().status === 'unlocked',
        lock,
      }),
    [],
  );

  useEffect(() => {
    void boot();
    void loadAutoLockDelay();
    const sub = AppState.addEventListener('change', (s) => autoLock.onAppState(s));
    return () => { sub.remove(); autoLock.dispose(); };
  }, [autoLock]);
  useEffect(() => { autoLock.touch(); }, [status, autoLock]);

  return (
    <SafeAreaProvider>
      <StatusBar style="light" />
      <View style={{ flex: 1 }} onStartShouldSetResponderCapture={() => { autoLock.touch(); return false; }}>
        <Stack screenOptions={{ headerShown: false, contentStyle: { backgroundColor: '#0B1020' } }}>
          <Stack.Screen name="index" />
          <Stack.Protected guard={status === 'needsPasscode'}>
            <Stack.Screen name="needs-passcode" />
          </Stack.Protected>
          <Stack.Protected guard={status === 'locked'}>
            <Stack.Screen name="lock" />
          </Stack.Protected>
          <Stack.Protected guard={status === 'onboarding' || status === 'locked'}>
            <Stack.Screen name="onboarding/index" />
            <Stack.Screen name="onboarding/pin" />
            <Stack.Screen name="onboarding/verify" />
          </Stack.Protected>
          <Stack.Protected guard={status === 'unlocked'}>
            <Stack.Screen name="(app)" />
          </Stack.Protected>
        </Stack>
        <PrivacyOverlay />
      </View>
    </SafeAreaProvider>
  );
}
