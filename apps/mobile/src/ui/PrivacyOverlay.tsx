// SEC-051: opaque cover whenever the app is not fully active, so the app-switcher snapshot never shows balances or PIN entry.
// Rendered synchronously on the `inactive` event (no timer).
import React, { useEffect, useState } from 'react';
import { AppState, StyleSheet, Text, View } from 'react-native';
import { color } from './theme';

export function PrivacyOverlay({ stateOverride }: { stateOverride?: string }) {
  const [state, setState] = useState<string>(AppState.currentState ?? 'active');
  useEffect(() => {
    const sub = AppState.addEventListener('change', setState);
    return () => sub.remove();
  }, []);
  const s = stateOverride ?? state;
  if (s !== 'inactive' && s !== 'background') return null;
  return (
    <View testID="privacy-overlay" pointerEvents="none" style={styles.cover} accessibilityElementsHidden importantForAccessibility="no-hide-descendants">
      <Text style={styles.brand}>CryptoApp</Text>
    </View>
  );
}
const styles = StyleSheet.create({
  cover: { ...StyleSheet.absoluteFill, backgroundColor: color.bg, alignItems: 'center', justifyContent: 'center', zIndex: 9999, elevation: 9999 },
  brand: { color: color.textDim, fontSize: 18 },
});
