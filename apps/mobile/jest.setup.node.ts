// Node project setup: globals + native module stubs shared by logic tests.
(globalThis as { __DEV__?: boolean }).__DEV__ = true;

jest.mock('expo-crypto', () => ({
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  randomUUID: () => require('crypto').randomUUID(),
}));
jest.mock('expo-device', () => ({
  isDevice: true,
  isRootedExperimentalAsync: jest.fn(async () => false),
}));

jest.mock('expo-secure-store', () => jest.requireActual('./src/testing/fakeStorage').secureStoreFake);
jest.mock('@react-native-async-storage/async-storage', () => ({
  __esModule: true,
  default: jest.requireActual('./src/testing/fakeStorage').asyncStorageFake,
}));
jest.mock('./modules/biometric-key/src/index', () => jest.requireActual('./src/testing/fakeBiometricKey').biometricKeyFake);

jest.mock('react-native', () => ({ Platform: { OS: 'ios' }, AppState: { addEventListener: jest.fn() } }), { virtual: true });
