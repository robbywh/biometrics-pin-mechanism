// `pnpm mock`: host HTTP server (port 8080) over the same mock core.
// Choice recorded in README: a thin node:http adapter instead of @mswjs/http-middleware (not needed, fewer deps).
import { createServer } from 'http';
import { MockBackend, SCENARIOS, type MockRequest } from './core';

const port = Number(process.env.MOCK_PORT ?? 8080);
const backend = new MockBackend();

const server = createServer((incoming, outgoing) => {
  const chunks: Buffer[] = [];
  let size = 0;
  incoming.on('data', (c: Buffer) => {
    size += c.length;
    if (size > 16 * 1024) { outgoing.writeHead(413).end(); incoming.destroy(); return; }
    chunks.push(c);
  });
  incoming.on('end', () => {
    const headers: Record<string, string> = {};
    for (const [k, v] of Object.entries(incoming.headers)) if (typeof v === 'string') headers[k.toLowerCase()] = v;
    const req: MockRequest = { method: incoming.method ?? 'GET', path: new URL(incoming.url ?? '/', 'http://x').pathname, headers };
    const text = Buffer.concat(chunks).toString('utf8');
    if (text) { try { req.body = JSON.parse(text); } catch { req.bodyInvalid = true; } }
    const res = backend.handle(req);
    outgoing.writeHead(res.status, res.headers);
    outgoing.end(res.status === 204 || res.body === undefined ? undefined : JSON.stringify(res.body));
  });
});

server.listen(port, '0.0.0.0', () => {
  console.log(`mock API on :${port}  scenarios: ${SCENARIOS.join(', ')}  switch: POST /__mock/scenario {"name":"..."}`);
});
