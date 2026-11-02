// SEC-016: the demo secret is never in source. In DEV profiles only, it may be prefilled from EXPO_PUBLIC_DEMO_SECRET (a git-ignored
// apps/mobile/.env). The release bundle must not contain it: scripts/check-release-bundle.mjs greps for the marker and the value.
export function devDemoSecret(): string {
  return __DEV__ ? (process.env.EXPO_PUBLIC_DEMO_SECRET ?? '') : '';
}
