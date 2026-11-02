process.env.EXPO_PUBLIC_API_URL = 'https://api.test';
(globalThis as { __DEV__?: boolean }).__DEV__ = true;
jest.mock('expo-crypto', () => ({
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  randomUUID: () => require('crypto').randomUUID(),
}));

jest.mock('expo-secure-store', () => jest.requireActual('./src/testing/fakeStorage').secureStoreFake);
jest.mock('@react-native-async-storage/async-storage', () => ({
  __esModule: true,
  default: jest.requireActual('./src/testing/fakeStorage').asyncStorageFake,
}));
jest.mock('./modules/biometric-key/src/index', () => jest.requireActual('./src/testing/fakeBiometricKey').biometricKeyFake);
