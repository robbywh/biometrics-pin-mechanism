import createClient from 'openapi-fetch';
import type { paths } from './generated/schema';
import { resolveBaseUrl, type ResolvedBase } from './baseUrl';

export const REQUEST_TIMEOUT_MS = 10_000;

export class TimeoutSignal extends Error {}

/** fetch with a hard timeout. No retries, no logging. */
export function makeFetch(impl: typeof fetch = (...a) => fetch(...a), timeoutMs = REQUEST_TIMEOUT_MS): typeof fetch {
  return async (input, init) => {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), timeoutMs);
    try {
      return await impl(input, { ...init, signal: ctrl.signal });
    } catch (e) {
      if (ctrl.signal.aborted) throw new TimeoutSignal('timeout');
      throw e;
    } finally {
      clearTimeout(t);
    }
  };
}

export type ApiClient = ReturnType<typeof createClient<paths>>;

export interface ClientBundle {
  client: ApiClient;
  base: ResolvedBase;
}

export function createApiClient(rawUrl: string | undefined, isDev: boolean, fetchImpl?: typeof fetch): ClientBundle {
  const base = resolveBaseUrl(rawUrl, isDev);
  // Request/response bodies are JSON only; credentials are attached per call by endpoints.ts.
  const client = createClient<paths>({ baseUrl: base.apiBase, fetch: makeFetch(fetchImpl), headers: { Accept: 'application/json' } });
  return { client, base };
}

let singleton: ClientBundle | undefined;

/** Fails fast (throws) when a release build is configured with a non-HTTPS URL. */
export function getApi(): ClientBundle {
  singleton ??= createApiClient(process.env.EXPO_PUBLIC_API_URL, __DEV__);
  return singleton;
}

export function __setApiForTests(b: ClientBundle | undefined): void {
  singleton = b;
}
