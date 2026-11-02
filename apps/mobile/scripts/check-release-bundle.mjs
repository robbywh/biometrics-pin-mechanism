#!/usr/bin/env node
// SEC-055 / SEC-016 / SEC-006 release gate.
//   EXPO_PUBLIC_API_URL=https://... DEMO_SECRET_VALUE=<dev secret> node scripts/check-release-bundle.mjs [--dir dist] [--extra-source file.ts ...]
// 1. `console.*` is stripped from every auth-relevant source module when compiled with the PRODUCTION babel config.
// 2. The release bundle contains no dev demo secret (value or the env var name) and no cleartext http:// API URL.
import { readdirSync, readFileSync, statSync, existsSync } from 'node:fs';
import { createRequire } from 'node:module';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const require = createRequire(join(root, 'package.json'));
const babel = require('@babel/core');

const args = process.argv.slice(2);
const opt = (name) => (args.includes(name) ? args[args.indexOf(name) + 1] : undefined);
const dir = resolve(root, opt('--dir') ?? 'dist');
const extra = args.flatMap((a, i) => (args[i - 1] === '--extra-source' ? [resolve(a)] : []));
const failures = [];

// ---- 1. console stripping on auth modules (production babel env) ----
const AUTH_DIRS = ['auth', 'storage', 'api', 'flows', 'pin', 'crypto', 'biometric', 'risk'];
const walk = (d) => readdirSync(d).flatMap((f) => { const p = join(d, f); return statSync(p).isDirectory() ? walk(p) : [p]; });
const sources = [
  ...AUTH_DIRS.flatMap((d) => (existsSync(join(root, 'src', d)) ? walk(join(root, 'src', d)) : [])),
  ...walk(join(root, 'modules/biometric-key/src')),
  ...extra,
].filter((f) => /\.tsx?$/.test(f) && !/\.(test|node\.test|ui\.test)\./.test(f) && !f.includes('/generated/') && !f.includes('/testing/'));

for (const file of sources) {
  const out = babel.transformFileSync(file, { envName: opt('--env') ?? 'production', configFile: join(root, 'babel.config.js'), caller: { name: 'metro', platform: 'android', bundler: 'metro' } });
  if (/\bconsole\s*\.\s*\w+/.test(out.code)) failures.push(`console.* survives production compile in ${file.replace(root + '/', '')}`);
}

// ---- 2. bundle scan ----
if (!existsSync(dir)) failures.push(`bundle dir not found: ${dir} (run: expo export --platform android)`);
else {
  const bundles = walk(dir).filter((f) => /\.(js|hbc|bundle)$/.test(f));
  if (bundles.length === 0) failures.push('no bundle files found');
  const api = process.env.EXPO_PUBLIC_API_URL ?? '';
  const secret = process.env.DEMO_SECRET_VALUE ?? '';
  for (const b of bundles) {
    const text = readFileSync(b).toString('latin1');
    if (secret && text.includes(secret)) failures.push(`dev demo secret found in ${b.replace(root + '/', '')}`);
    if (text.includes('EXPO_PUBLIC_DEMO_SECRET')) failures.push(`EXPO_PUBLIC_DEMO_SECRET referenced in ${b.replace(root + '/', '')}`);
    if (api) {
      if (!api.startsWith('https://')) failures.push(`EXPO_PUBLIC_API_URL is not https: ${api}`);
      if (api.startsWith('http://') && text.includes(api)) failures.push('cleartext API URL baked into the bundle');
    }
    if (/https?:\/\/[^\s"']*:8080/.test(text) && !/^https:/.test(api)) failures.push('dev mock URL baked into the bundle');
  }
}

if (failures.length) { console.error('RELEASE BUNDLE CHECK FAILED:\n - ' + failures.join('\n - ')); process.exit(1); }
console.log(`release bundle check OK (${sources.length} auth-relevant modules compiled for production, bundle scanned)`);
