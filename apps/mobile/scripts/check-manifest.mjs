#!/usr/bin/env node
// SEC-067 / SEC-006 / SEC-068: assert native config after `expo prebuild`.
//   node scripts/check-manifest.mjs [--variant development|production]
// Run prebuild with the same APP_VARIANT first. Exit code 1 on any violation.
import { readFileSync, existsSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const variant = process.argv.includes('--variant') ? process.argv[process.argv.indexOf('--variant') + 1] : 'production';
const failures = [];
const must = (cond, msg) => { if (!cond) failures.push(msg); };
const read = (p) => (existsSync(resolve(root, p)) ? readFileSync(resolve(root, p), 'utf8') : null);

const main = read('android/app/src/main/AndroidManifest.xml');
must(main, 'android main manifest missing (run expo prebuild)');
if (main) {
  must(/android:allowBackup="false"/.test(main), 'android:allowBackup must be false');
  must(/android:usesCleartextTraffic="false"/.test(main), 'main manifest must set usesCleartextTraffic=false');
  must(/android:dataExtractionRules="@xml\/data_extraction_rules"/.test(main), 'dataExtractionRules missing');
  must(!/expo\.modules\.updates\.ENABLED"\s+android:value="true"/.test(main), 'expo-updates must be disabled');
  must(/USE_BIOMETRIC/.test(main), 'USE_BIOMETRIC permission missing');
  must(/SYSTEM_ALERT_WINDOW"\s+tools:node="remove"/.test(main), 'SYSTEM_ALERT_WINDOW must be removed from release');
}
const rules = read('android/app/src/main/res/xml/data_extraction_rules.xml');
must(rules && /cloud-backup/.test(rules) && /device-transfer/.test(rules) && /exclude domain="sharedpref"/.test(rules), 'data_extraction_rules must exclude sharedpref in cloud-backup and device-transfer');
const dbg = read('android/app/src/debug/AndroidManifest.xml');
must(dbg && /usesCleartextTraffic="true"/.test(dbg), 'cleartext must be enabled in the DEBUG manifest only (dev client -> LAN mock)');

const plist = read('ios/CryptoAppDemo/Info.plist');
must(plist, 'iOS Info.plist missing');
if (plist) {
  must(!/NSAllowsArbitraryLoads<\/key>\s*<true\/>/.test(plist), 'ATS: NSAllowsArbitraryLoads must not be true');
  must(/NSFaceIDUsageDescription/.test(plist), 'NSFaceIDUsageDescription missing');
  if (variant === 'production' || variant === 'preview') must(!/NSAllowsLocalNetworking<\/key>\s*<true\/>/.test(plist), `ATS local-network exception must not ship in ${variant}`);
}
if (failures.length) { console.error('MANIFEST CHECK FAILED:\n - ' + failures.join('\n - ')); process.exit(1); }
console.log(`manifest check OK (variant=${variant})`);
