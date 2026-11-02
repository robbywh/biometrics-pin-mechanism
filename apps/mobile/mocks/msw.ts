// MSW adapter over the framework-agnostic mock core (used by Jest via msw/node).
import { getResponse, http, HttpResponse } from 'msw';
import { MockBackend, type MockRequest } from './core';

export function createMockBackend(): MockBackend {
  const b = new MockBackend();
  b.validateResponses = true;
  return b;
}

export function mswHandlers(backend: MockBackend) {
  return [
    http.all('*', async ({ request }) => {
      const url = new URL(request.url);
      const headers: Record<string, string> = {};
      request.headers.forEach((v, k) => (headers[k.toLowerCase()] = v));
      const req: MockRequest = { method: request.method, path: url.pathname, headers };
      const text = await request.text();
      if (text.length > 0) {
        try { req.body = JSON.parse(text); } catch { req.bodyInvalid = true; }
      }
      const res = backend.handle(req);
      return res.status === 204
        ? new HttpResponse(null, { status: 204, headers: res.headers })
        : HttpResponse.json(res.body as never, { status: res.status, headers: res.headers });
    }),
  ];
}

/**
 * Jest transport: runs the real MSW handlers through msw's `getResponse` (no http interceptors, which are ESM+wasm and do not
 * load under Jest CJS). Returns a fetch implementation to inject into the API client.
 */
export function mswFetch(backend: MockBackend): typeof fetch {
  const handlers = mswHandlers(backend);
  return (async (input: RequestInfo | URL, init?: RequestInit) => {
    const request = new Request(input as RequestInfo, init);
    const res = await getResponse(handlers, request);
    if (!res) throw new TypeError('network request failed (no mock handler)');
    return res;
  }) as typeof fetch;
}
