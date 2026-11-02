const { defineConfig } = require('eslint/config');
const expo = require('eslint-config-expo/flat');

const banned = (name, message) => ({ name, message });

module.exports = defineConfig([
  expo,
  { ignores: ['dist/*', 'android/*', 'ios/*', 'src/api/generated/*', '.expo/*', 'coverage/*'] },
  {
    // SEC-055: no console in app code.
    files: ['src/**/*.{ts,tsx}'],
    rules: {
      'no-console': 'error',
      'no-restricted-imports': [
        'error',
        {
          paths: [
            // SEC-019: never use the boolean API for auth decisions; the native module is the only biometric entry point.
            banned('expo-local-authentication', 'SEC-019: biometrics only via the biometric-key native module (signature), never a boolean.'),
            banned('expo-secure-store', 'Use src/storage/* only.'),
            banned('@react-native-async-storage/async-storage', 'Use src/storage/* only.'),
          ],
          patterns: [
            { group: ['**/risk/signals', '@/risk/signals'], message: 'T20: risk signals may only be imported by the API layer (src/api/*).' },
          ],
        },
      ],
    },
  },
  {
    // Storage module is the only place allowed to import SecureStore/AsyncStorage (T7); API layer may import risk signals (T20).
    files: ['src/storage/**/*.{ts,tsx}'],
    rules: { 'no-restricted-imports': ['error', { paths: [banned('expo-local-authentication', 'SEC-019')] }] },
  },
  {
    files: ['src/api/**/*.{ts,tsx}'],
    rules: {
      'no-restricted-imports': ['error', { paths: [banned('expo-local-authentication', 'SEC-019'), banned('expo-secure-store', 'Use src/storage/*'), banned('@react-native-async-storage/async-storage', 'Use src/storage/*')] }],
    },
  },
  {
    // React-Compiler-oriented rules from eslint-plugin-react-hooks v7 are disabled: PIN buffers intentionally live in refs and
    // the screens use imperative effects. Rules-of-hooks / exhaustive-deps stay on.
    files: ['src/**/*.tsx'],
    rules: {
      'react-hooks/refs': 'off',
      'react-hooks/set-state-in-effect': 'off',
      'react-hooks/static-components': 'off',
      'react-hooks/purity': 'off',
      'react-hooks/preserve-manual-memoization': 'off',
      'react-hooks/immutability': 'off',
    },
  },
  {
    files: ['**/*.test.{ts,tsx}', 'jest.setup.*', 'mocks/**', 'scripts/**', '*.config.{js,ts}', 'plugins/**'],
    rules: { 'no-console': 'off', 'no-restricted-imports': 'off' },
  },
]);
