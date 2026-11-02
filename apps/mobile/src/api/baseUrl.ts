// SEC-006: HTTPS only. Cleartext http:// is tolerated only in dev builds and only for loopback / emulator host / private LAN
// addresses (a physical device must reach `pnpm mock` on the dev machine over the LAN).
const DEV_HOSTS = new Set(['localhost', '127.0.0.1', '10.0.2.2', '10.0.3.2']);

function isPrivateLan(host: string): boolean {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(host);
  if (!m) return host.endsWith('.local');
  const a = Number(m[1]);
  const b = Number(m[2]);
  return a === 10 || (a === 192 && b === 168) || (a === 172 && b >= 16 && b <= 31);
}

export interface ResolvedBase {
  /** e.g. https://api.example.com (no trailing slash, no path) */
  origin: string;
  /** origin + /v1 */
  apiBase: string;
}

export function resolveBaseUrl(raw: string | undefined, isDev: boolean): ResolvedBase {
  if (!raw) throw new Error('EXPO_PUBLIC_API_URL is not set');
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    throw new Error('EXPO_PUBLIC_API_URL is not a valid URL');
  }
  if (u.username || u.password || u.search || u.hash) throw new Error('API URL must not carry credentials, query or fragment');
  if (u.protocol === 'https:') {
    // ok
  } else if (u.protocol === 'http:') {
    if (!isDev) throw new Error('Cleartext API URL is not allowed in release builds');
    if (!DEV_HOSTS.has(u.hostname) && !isPrivateLan(u.hostname)) throw new Error('Cleartext API URL only allowed for local development hosts');
  } else {
    throw new Error('Unsupported API URL scheme');
  }
  const origin = `${u.protocol}//${u.host}`;
  return { origin, apiBase: `${origin}/v1` };
}
