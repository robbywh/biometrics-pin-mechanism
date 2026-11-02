import React from 'react';
import { AppState } from 'react-native';
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react-native';
import { setupMockApi } from '../testing/mockApi';
import { onboardUnlocked, PIN, pinOf } from '../testing/helpers';
import { lock } from '../auth/session';
import { authState } from '../auth/state';
import { unlockWithPin } from '../auth/unlock';
import { enableBiometrics } from '../flows/biometrics';
import { fakeKey } from '../testing/fakeBiometricKey';
import LockScreen from '../app/lock';

const mockPush = jest.fn();
const mockReplace = jest.fn();
jest.mock('expo-router', () => ({ useRouter: () => ({ push: mockPush, replace: mockReplace, back: jest.fn() }), useLocalSearchParams: () => ({}) }));
jest.mock('expo-haptics', () => ({ selectionAsync: jest.fn(async () => undefined), notificationAsync: jest.fn(async () => undefined), NotificationFeedbackType: { Error: 'error' } }));

const { backend } = setupMockApi();
const tap = async (d: string) => { for (const c of d) await fireEvent.press(screen.getByTestId(`key-${c}`)); };

beforeEach(async () => { mockPush.mockClear(); mockReplace.mockClear(); await onboardUnlocked(); lock(); });

describe('lock screen (T13)', () => {
  it('wrong PIN: server-driven attemptsRemaining is shown and the entry is cleared', async () => {
    await render(<LockScreen />);
    await tap('000001');
    await waitFor(() => expect(screen.getByText(/4 attempts remaining/)).toBeTruthy());
    expect(screen.getByLabelText('0 of 6 digits entered')).toBeTruthy();
    expect(authState.get().status).toBe('locked');
  });
  it('soft lock shows a countdown from retryAfter and disables the keypad', async () => {
    backend.setScenario('pin-locked-soft');
    await render(<LockScreen />);
    await tap(PIN);
    await waitFor(() => expect(screen.getByText(/Try again in 30s/)).toBeTruthy());
    await tap('1');
    expect(screen.getByLabelText('0 of 6 digits entered')).toBeTruthy(); // input ignored while counting down
  });
  it('hard lock offers Reset PIN; navigation carries no PIN or token', async () => {
    backend.setScenario('pin-hard-locked');
    await render(<LockScreen />);
    await tap(PIN);
    await waitFor(() => expect(screen.getByTestId('reset-cta')).toBeTruthy());
    await fireEvent.press(screen.getByTestId('reset-cta'));
    expect(mockPush).toHaveBeenCalledWith('/onboarding?intent=reset');
    expect(JSON.stringify(mockPush.mock.calls)).not.toContain(PIN);
  });
  it('correct PIN unlocks via the server response', async () => {
    await render(<LockScreen />);
    await tap(PIN);
    await waitFor(() => expect(authState.get().status).toBe('unlocked'));
  });
  it('biometric button is offered only with hint + key; cancel falls back to the PIN pad with a neutral message', async () => {
    await render(<LockScreen />);
    expect(screen.queryByTestId('bio-button')).toBeNull();
    expect((await unlockWithPin(pinOf(PIN))).ok).toBe(true); // real server unlock, no fabricated state
    expect((await enableBiometrics(pinOf(PIN))).ok).toBe(true);
    lock();
    fakeKey.nextSignError = 'USER_CANCELED';
    await render(<LockScreen />);
    await waitFor(() => expect(screen.getByText('Use your PIN to unlock.')).toBeTruthy());
    expect(authState.get().status).toBe('locked');
    expect(screen.getByTestId('bio-button')).toBeTruthy();
  });
});

describe('PIN entry is wiped on background (T10, SEC-053)', () => {
  it('partial entry is cleared when the app goes to background', async () => {
    let listener: ((s: string) => void) | undefined;
    const spy = jest.spyOn(AppState, 'addEventListener').mockImplementation(((_t: string, l: (s: string) => void) => { listener = l; return { remove: jest.fn() }; }) as never);
    await render(<LockScreen />);
    await tap('123');
    expect(screen.getByLabelText('3 of 6 digits entered')).toBeTruthy();
    await act(async () => { listener?.('background'); });
    expect(screen.getByLabelText('0 of 6 digits entered')).toBeTruthy();
    spy.mockRestore();
  });
});
