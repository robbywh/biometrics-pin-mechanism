import type { ExpoConfig } from 'expo/config';

// APP_VARIANT: development | preview | production. Only `development` may talk cleartext to localhost (SEC-006).
const variant = process.env.APP_VARIANT ?? 'development';
const isDev = variant === 'development';

const config: ExpoConfig = {
  name: 'CryptoApp Demo',
  slug: 'cryptoapp-demo',
  version: '1.0.0',
  scheme: 'cryptoapp',
  orientation: 'portrait',
  icon: './assets/icon.png',
  userInterfaceStyle: 'dark',
  // SEC-068: expo-updates is intentionally NOT installed (OTA off).
  ios: {
    bundleIdentifier: 'com.cryptoapp.demo',
    supportsTablet: false,
    infoPlist: {
      NSFaceIDUsageDescription: 'Unlock the app with Face ID.',
      ITSAppUsesNonExemptEncryption: false,
      // ATS stays on. A single Info.plist cannot differ per Xcode configuration, so the localhost/LAN exception is
      // emitted only for the `development` variant (dev client builds) and never for preview/production.
      NSAppTransportSecurity: { NSAllowsArbitraryLoads: false, NSAllowsLocalNetworking: isDev },
    },
  },
  android: {
    package: 'com.cryptoapp.demo',
    allowBackup: false, // SEC-067
    permissions: ['android.permission.USE_BIOMETRIC'],
  },
  plugins: [
    'expo-router',
    'expo-dev-client',
    'expo-secure-store',
    ['expo-build-properties', { android: { minSdkVersion: 30 } }],
    './plugins/withAndroidHardening',
  ],
  extra: { apiUrl: process.env.EXPO_PUBLIC_API_URL ?? '' },
};

export default config;
