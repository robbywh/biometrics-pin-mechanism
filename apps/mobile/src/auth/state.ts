// Auth state machine: Booting -> NeedsPasscode | Onboarding | Locked -> Unlocked.
// Holds NO secrets: only non-secret session metadata. The ONLY way to reach `unlocked` is `__unlockFromServerSession`, which is
// imported solely by src/auth/session.ts (enforced by a test), and session.ts calls it only after a server session response.
import { createStore } from 'zustand/vanilla';
import { useStore } from 'zustand';

export type AuthStatus = 'booting' | 'needsPasscode' | 'onboarding' | 'locked' | 'unlocked';

export interface SessionInfo {
  deviceId: string;
  amr: 'pin' | 'bio';
  authTime: number;
  biometricEnabled: boolean;
  coolingOffUntil?: number;
}

export type Notice =
  | { kind: 'recentFailures'; count: number }
  | { kind: 'biometricInvalidated' }
  | { kind: 'coolingOff'; until: number }
  | { kind: 'pinChanged' }
  | null;

interface AuthState {
  status: AuthStatus;
  session: SessionInfo | null;
  notice: Notice;
}

export const authStore = createStore<AuthState>(() => ({ status: 'booting', session: null, notice: null }));

export const authState = {
  get: () => authStore.getState(),
  toNeedsPasscode: () => authStore.setState({ status: 'needsPasscode', session: null }),
  toOnboarding: () => authStore.setState({ status: 'onboarding', session: null }),
  toLocked: () => authStore.setState({ status: 'locked', session: null }),
  patchSession: (p: Partial<SessionInfo>) => authStore.setState((st) => (st.session ? { session: { ...st.session, ...p } } : st)),
  setNotice: (notice: Notice) => authStore.setState({ notice }),
  clearNotice: () => authStore.setState({ notice: null }),
  /** @internal call only from session.ts after a server session response */
  __unlockFromServerSession: (session: SessionInfo) => authStore.setState({ status: 'unlocked', session }),
  __reset: () => authStore.setState({ status: 'booting', session: null, notice: null }),
};

export const useAuth = <T,>(selector: (s: AuthState) => T): T => useStore(authStore, selector);
