// SEC-002 / SEC-052 / SEC-053: custom in-app numeric keypad. No system keyboard => no autofill, clipboard, or third-party keyboards.
// Digits live in a ref'd PinBuffer; React state holds only the COUNT (for the dots). When 6 digits are entered, ownership of the
// buffer is handed to `onComplete` (which must clear it, or the flow's `take()` does) and the pad starts a fresh buffer.
import React, { useCallback, useEffect, useRef, useState } from 'react';
import { Pressable, StyleSheet, Text, View } from 'react-native';
import * as Haptics from 'expo-haptics';
import { PIN_LENGTH, PinBuffer } from '../pin/buffer';
import { useOnBackground } from './hooks';
import { color, font, MIN_TARGET, radius, space } from './theme';

export interface PinPadProps {
  onComplete: (pin: PinBuffer) => void | Promise<void>;
  /** Disables input while a request is in flight or a server lock countdown runs (UX only; the server stays authoritative). */
  disabled?: boolean;
  label?: string;
  /** Changing this value wipes the entry (e.g. after a failed attempt). */
  resetKey?: number;
}

const ROWS = [[1, 2, 3], [4, 5, 6], [7, 8, 9]];

export function PinPad({ onComplete, disabled, label = 'Enter your PIN', resetKey = 0 }: PinPadProps) {
  const buf = useRef(new PinBuffer());
  const [count, setCount] = useState(0);

  const wipe = useCallback(() => { buf.current.clear(); setCount(0); }, []);
  useEffect(() => { wipe(); }, [resetKey, wipe]);
  useEffect(() => () => buf.current.clear(), []); // unmount mid-entry clears the buffer
  useEffect(() => { if (disabled) wipe(); }, [disabled, wipe]);
  useOnBackground(wipe); // a partial entry never survives backgrounding

  const press = (d: number) => {
    if (disabled) return;
    if (!buf.current.push(d)) return;
    Haptics.selectionAsync().catch(() => undefined);
    setCount(buf.current.length);
    if (buf.current.full) {
      const done = buf.current;
      buf.current = new PinBuffer(); // hand over ownership; the pad never touches `done` again
      setCount(0);
      void onComplete(done);
    }
  };
  const back = () => { if (!disabled) { buf.current.pop(); setCount(buf.current.length); } };

  const Key = ({ d }: { d: number }) => (
    <Pressable testID={`key-${d}`} accessibilityRole="button" accessibilityLabel={`${d}`} disabled={disabled} onPress={() => press(d)} style={({ pressed }) => [styles.key, pressed && styles.pressed, disabled && { opacity: 0.4 }]}>
      <Text style={styles.keyText}>{d}</Text>
    </Pressable>
  );

  return (
    <View style={styles.wrap}>
      <Text accessibilityRole="header" style={styles.label}>{label}</Text>
      <View testID="pin-dots" accessible accessibilityLabel={`${count} of ${PIN_LENGTH} digits entered`} style={styles.dots}>
        {Array.from({ length: PIN_LENGTH }, (_, i) => <View key={i} style={[styles.dot, i < count && styles.dotOn]} />)}
      </View>
      {ROWS.map((r, i) => <View key={i} style={styles.row}>{r.map((d) => <Key key={d} d={d} />)}</View>)}
      <View style={styles.row}>
        <View style={styles.key} />
        <Key d={0} />
        <Pressable testID="key-back" accessibilityRole="button" accessibilityLabel="Delete" disabled={disabled} onPress={back} style={styles.key}>
          <Text style={styles.keyText}>{'<'}</Text>
        </Pressable>
      </View>
    </View>
  );
}

const SIZE = Math.max(MIN_TARGET, 72);
const styles = StyleSheet.create({
  wrap: { alignItems: 'center', gap: space.md },
  label: { color: color.text, fontSize: font.h2, fontWeight: '600' },
  dots: { flexDirection: 'row', gap: space.md, marginVertical: space.md, minHeight: 24 },
  dot: { width: 16, height: 16, borderRadius: radius.pill, borderWidth: 2, borderColor: color.textDim },
  dotOn: { backgroundColor: color.primary, borderColor: color.primary },
  row: { flexDirection: 'row', gap: space.lg },
  key: { width: SIZE, height: SIZE, borderRadius: radius.pill, alignItems: 'center', justifyContent: 'center', backgroundColor: color.surface },
  pressed: { backgroundColor: color.surfaceAlt },
  keyText: { color: color.text, fontSize: 28, fontWeight: '500' },
});
