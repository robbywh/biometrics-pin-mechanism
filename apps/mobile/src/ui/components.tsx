import React from 'react';
import { ActivityIndicator, Pressable, ScrollView, StyleSheet, Text, View, type TextProps, type ViewStyle } from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';
import { color, font, MIN_TARGET, radius, space } from './theme';

export function Screen({ children, scroll = false }: { children: React.ReactNode; scroll?: boolean }) {
  const body = scroll ? <ScrollView contentContainerStyle={styles.pad}>{children}</ScrollView> : <View style={[styles.pad, { flex: 1 }]}>{children}</View>;
  return <SafeAreaView style={styles.screen}>{body}</SafeAreaView>;
}

export function T({ kind = 'body', style, ...rest }: TextProps & { kind?: 'title' | 'h2' | 'body' | 'dim' | 'error' | 'ok' | 'warn' }) {
  return <Text {...rest} style={[styles.text, kindStyle[kind], style]} />;
}

export function Button({ title, onPress, kind = 'primary', disabled, busy, testID }: {
  title: string; onPress: () => void; kind?: 'primary' | 'secondary' | 'danger'; disabled?: boolean; busy?: boolean; testID?: string;
}) {
  const off = disabled || busy;
  return (
    <Pressable
      testID={testID}
      accessibilityRole="button"
      accessibilityLabel={title}
      accessibilityState={{ disabled: !!off, busy: !!busy }}
      disabled={off}
      onPress={onPress}
      style={({ pressed }) => [styles.btn, btnKind[kind], off && { opacity: 0.5 }, pressed && { opacity: 0.8 }]}
    >
      {busy ? <ActivityIndicator color={kind === 'primary' ? color.primaryText : color.text} /> : <Text style={[styles.btnText, kind === 'primary' && { color: color.primaryText }]}>{title}</Text>}
    </Pressable>
  );
}

export function Card({ children, style }: { children: React.ReactNode; style?: ViewStyle }) {
  return <View style={[styles.card, style]}>{children}</View>;
}

export function Banner({ text, tone = 'warn', onDismiss }: { text: string; tone?: 'warn' | 'ok' | 'error'; onDismiss?: () => void }) {
  const c = tone === 'ok' ? color.ok : tone === 'error' ? color.danger : color.warn;
  return (
    <View accessibilityRole="alert" style={[styles.banner, { borderColor: c }]}>
      <Text style={[styles.text, { flex: 1, color: c }]}>{text}</Text>
      {onDismiss ? <Pressable accessibilityRole="button" accessibilityLabel="Dismiss" onPress={onDismiss} style={styles.dismiss}><Text style={styles.text}>OK</Text></Pressable> : null}
    </View>
  );
}

const styles = StyleSheet.create({
  screen: { flex: 1, backgroundColor: color.bg },
  pad: { padding: space.lg, gap: space.md },
  text: { color: color.text, fontSize: font.body },
  btn: { minHeight: MIN_TARGET, borderRadius: radius.md, alignItems: 'center', justifyContent: 'center', paddingHorizontal: space.lg },
  btnText: { color: color.text, fontSize: font.body, fontWeight: '600' },
  card: { backgroundColor: color.surface, borderRadius: radius.md, padding: space.md, gap: space.sm },
  banner: { borderWidth: 1, borderRadius: radius.md, padding: space.md, flexDirection: 'row', alignItems: 'center', gap: space.sm },
  dismiss: { minHeight: 44, minWidth: 44, alignItems: 'center', justifyContent: 'center' },
});
const kindStyle = StyleSheet.create({
  title: { fontSize: font.title, fontWeight: '700' },
  h2: { fontSize: font.h2, fontWeight: '600' },
  body: {},
  dim: { color: color.textDim, fontSize: font.small },
  error: { color: color.danger },
  ok: { color: color.ok },
  warn: { color: color.warn },
});
const btnKind = StyleSheet.create({
  primary: { backgroundColor: color.primary },
  secondary: { backgroundColor: color.surfaceAlt, borderWidth: 1, borderColor: color.border },
  danger: { backgroundColor: color.danger },
});
