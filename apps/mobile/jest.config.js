// Two projects: `node` for pure logic (crypto, api client, session, MSW, ajv) and `ui` (jest-expo) for components/screens.
// msw / openapi-fetch / @noble/hashes v2 are ESM-only: transform them.
const esm = '(?:msw|cookie|standard-navigation|@msw|until-async|openapi-fetch|@noble|headers-polyfill|@open-draft|outvariant|strict-event-emitter|is-node-process|rettime)';
const transformIgnore = `node_modules/(?!(?:.pnpm/)?(?:(jest-)?react-native|@react-native(-community)?|expo(nent)?|@expo(nent)?/.*|@expo-google-fonts/.*|react-navigation|@react-navigation/.*|@sentry/react-native|native-base|react-native-svg|zustand|${esm}))`;

const common = {
  moduleNameMapper: {
    '^@/(.*)$': '<rootDir>/src/$1',
    '^biometric-key$': '<rootDir>/modules/biometric-key/src/index.ts',
  },
  transformIgnorePatterns: [transformIgnore],
  testPathIgnorePatterns: ['/node_modules/', '/android/', '/ios/'],
};

module.exports = {
  projects: [
    {
      ...common,
      displayName: 'node',
      testEnvironment: 'node',
      transform: { '\\.m?[jt]sx?$': ['babel-jest', { caller: { name: 'metro', platform: 'ios' } }] },
      testMatch: ['<rootDir>/src/**/*.node.test.ts', '<rootDir>/mocks/**/*.test.ts', '<rootDir>/scripts/**/*.test.ts'],
      setupFilesAfterEnv: ['<rootDir>/jest.setup.node.ts'],
    },
    {
      ...common,
      displayName: 'ui',
      preset: 'jest-expo',
      transform: { '\\.mjs$': ['babel-jest', { caller: { name: 'metro', platform: 'ios' } }] },
      testMatch: ['<rootDir>/src/**/*.ui.test.tsx'],
      setupFilesAfterEnv: ['<rootDir>/jest.setup.ui.ts'],
    },
  ],
};
