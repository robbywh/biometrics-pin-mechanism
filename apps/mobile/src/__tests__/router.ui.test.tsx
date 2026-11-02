// Integration: the real src/app tree rendered through expo-router (boot -> lock -> PIN -> Home -> lock -> wipe).
// EXPO_PUBLIC_API_URL is set in jest.setup.ui.ts (the root layout validates it at module scope).
import { join } from 'path';
import { act, screen, fireEvent, waitFor } from '@testing-library/react-native';
import { renderRouter } from 'expo-router/testing-library';
import { setupMockApi } from '../testing/mockApi';
import { onboardUnlocked, PIN } from '../testing/helpers';
import { lock, wipeCredentials } from '../auth/session';
import { authState } from '../auth/state';
import { boot } from '../auth/boot';
import { memory } from '../storage/secureTokens';

jest.mock('expo-haptics', () => ({ selectionAsync: jest.fn(async () => undefined), notificationAsync: jest.fn(async () => undefined), NotificationFeedbackType: { Error: 'error' } }));
jest.mock('expo-screen-capture', () => ({ usePreventScreenCapture: jest.fn() }));
jest.mock('expo-device', () => ({ modelName: 'Test', isDevice: true, isRootedExperimentalAsync: async () => false }));

setupMockApi();
const tap = async (d: string) => { for (const c of d) await fireEvent.press(screen.getByTestId(`key-${c}`)); };

it('boot -> lock screen -> PIN -> Home dashboard -> lock() -> lock screen -> wipe -> onboarding', async () => {
  await onboardUnlocked();
  lock();
  authState.__reset(); // simulate a cold start: refresh token + deviceId remain in SecureStore, state is fresh
  await renderRouter(join(__dirname, '../app'));
  await act(async () => { await boot(); });
  await waitFor(() => expect(screen.getByText('Welcome back')).toBeTruthy());

  await tap(PIN);
  await waitFor(() => expect(screen.getByText('$12843.20')).toBeTruthy());
  expect(screen.queryByText('Welcome back')).toBeNull();

  await act(async () => { lock(); });
  await waitFor(() => expect(screen.getByText('Welcome back')).toBeTruthy());
  expect(screen.queryByText('$12843.20')).toBeNull(); // protected tree unmounted, balances not in the tree
  expect(memory.hasAccess()).toBe(false);

  await act(async () => { await wipeCredentials(); });
  await waitFor(() => expect(screen.getByText('Sign in')).toBeTruthy());
});
