import React from 'react';
import { StyleSheet } from 'react-native';
import { fireEvent, render, screen, waitFor } from '@testing-library/react-native';
import { PinPad } from './PinPad';
import { PrivacyOverlay } from './PrivacyOverlay';
import { PinBuffer } from '../pin/buffer';

jest.mock('expo-haptics', () => ({ selectionAsync: jest.fn(async () => undefined), notificationAsync: jest.fn(async () => undefined), NotificationFeedbackType: { Error: 'error' } }));

const tap = async (digits: string) => { for (const d of digits) await fireEvent.press(screen.getByTestId(`key-${d}`)); };

describe('PinPad (SEC-002/052/053, test 20)', () => {
  it('hands the buffer over at 6 digits, shows only a count, and never exposes digits in the tree', async () => {
    const received: PinBuffer[] = [];
    await render(<PinPad onComplete={(p) => { received.push(p); }} />);
    await tap('4930');
    expect(screen.getByLabelText('4 of 6 digits entered')).toBeTruthy();
    // no digit of the PIN is rendered anywhere except the static keypad labels; the display holds dots only
    expect(JSON.stringify(screen.toJSON())).not.toContain('4930');
    await tap('17');
    await waitFor(() => expect(received).toHaveLength(1));
    expect(received[0]!.take()).toBe('493017');
    expect(screen.getByLabelText('0 of 6 digits entered')).toBeTruthy(); // display count back to 0
  });
  it('is an in-app keypad: no TextInput exists, hence no system keyboard / autofill / clipboard', async () => {
    await render(<PinPad onComplete={() => undefined} />);
    expect(screen.queryByTestId('pin-input')).toBeNull();
    expect(JSON.stringify(screen.toJSON())).not.toContain('"TextInput"');
  });
  it('ignores input while disabled and wipes on resetKey change', async () => {
    const onComplete = jest.fn();
    const { rerender } = await render(<PinPad onComplete={onComplete} />);
    await tap('123');
    await rerender(<PinPad onComplete={onComplete} resetKey={1} />);
    expect(screen.getByLabelText('0 of 6 digits entered')).toBeTruthy();
    await rerender(<PinPad onComplete={onComplete} disabled resetKey={1} />);
    await tap('123456');
    expect(onComplete).not.toHaveBeenCalled();
  });
  it('unmount mid-entry clears the buffer (no callback, no leftovers)', async () => {
    const onComplete = jest.fn();
    const r = await render(<PinPad onComplete={onComplete} />);
    await tap('12345');
    await r.unmount();
    expect(onComplete).not.toHaveBeenCalled();
  });
  it('touch targets are at least 56dp', async () => {
    await render(<PinPad onComplete={() => undefined} />);
    const style = StyleSheet.flatten(screen.getByTestId('key-5').props.style as never) as { width: number; height: number };
    expect(style.width).toBeGreaterThanOrEqual(56);
    expect(style.height).toBeGreaterThanOrEqual(56);
  });
});

describe('PrivacyOverlay (SEC-051, test 20)', () => {
  it.each(['inactive', 'background'])('is mounted when the app is %s', async (state) => {
    await render(<PrivacyOverlay stateOverride={state} />);
    expect(screen.getByTestId('privacy-overlay', { includeHiddenElements: true })).toBeTruthy();
  });
  it('is absent when active', async () => {
    await render(<PrivacyOverlay />);
    expect(screen.queryByTestId('privacy-overlay', { includeHiddenElements: true })).toBeNull();
  });
});
