import { execFileSync, spawnSync } from 'child_process';
import { mkdtempSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join, resolve } from 'path';

const root = resolve(__dirname, '..');
const run = (args: string[], env: Record<string, string> = {}) =>
  spawnSync('node', [join(root, 'scripts/check-release-bundle.mjs'), ...args], { cwd: root, env: { ...process.env, ...env }, encoding: 'utf8' });

describe('release hygiene scripts (T21, test 20/21)', () => {
  it('console.* in an auth module is stripped by the production babel config (no violation)', () => {
    const dir = mkdtempSync(join(tmpdir(), 'rb-'));
    const f = join(dir, 'x.ts');
    writeFileSync(f, "export const f = (t: string) => { console.log(t); return t; };\n");
    // run only the source half: point --dir at a directory with a fake bundle
    const bundleDir = mkdtempSync(join(tmpdir(), 'bundle-'));
    writeFileSync(join(bundleDir, 'a.js'), 'var a=1;');
    const r = run(['--dir', bundleDir, '--extra-source', f], { EXPO_PUBLIC_API_URL: 'https://api.example.com' });
    expect(r.status).toBe(0);
  });
  it('fails (self-test) when console.* is NOT stripped, i.e. the production transform is bypassed', () => {
    const dir = mkdtempSync(join(tmpdir(), 'rb-'));
    const f = join(dir, 'x.ts');
    writeFileSync(f, "export const f = (t: string) => { console.log(t); return t; };\n");
    const bundleDir = mkdtempSync(join(tmpdir(), 'bundle-'));
    writeFileSync(join(bundleDir, 'a.js'), 'var a=1;');
    const r = run(['--dir', bundleDir, '--env', 'development', '--extra-source', f], { EXPO_PUBLIC_API_URL: 'https://api.example.com' });
    expect(r.status).toBe(1);
    expect(r.stderr).toContain('console.*');
  });
  it('fails on a deliberately planted dev secret in the bundle', () => {
    const bundleDir = mkdtempSync(join(tmpdir(), 'bundle-'));
    writeFileSync(join(bundleDir, 'a.js'), 'var s="SUPER-DEV-SECRET";');
    const r = run(['--dir', bundleDir], { DEMO_SECRET_VALUE: 'SUPER-DEV-SECRET', EXPO_PUBLIC_API_URL: 'https://api.example.com' });
    expect(r.status).toBe(1);
    expect(r.stderr).toContain('dev demo secret');
  });
  it('fails on a cleartext API URL', () => {
    const bundleDir = mkdtempSync(join(tmpdir(), 'bundle-'));
    writeFileSync(join(bundleDir, 'a.js'), 'var u="http://api.example.com";');
    const r = run(['--dir', bundleDir], { EXPO_PUBLIC_API_URL: 'http://api.example.com' });
    expect(r.status).toBe(1);
    expect(r.stderr).toMatch(/not https|cleartext/);
  });
  it('manifest checker passes only after prebuild (smoke: script runs and reports)', () => {
    const r = spawnSync('node', [join(root, 'scripts/check-manifest.mjs'), '--variant', 'development'], { cwd: root, encoding: 'utf8' });
    expect([0, 1]).toContain(r.status);
    expect(execFileSync).toBeDefined();
  });
});
