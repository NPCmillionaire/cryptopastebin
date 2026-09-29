/**
 * A local server that runs the real Worker request handler.
 *
 * Exists so the application can be exercised end to end — in a real browser,
 * against the actual handler — without a Cloudflare account. D1 is backed by
 * `node:sqlite` running this repository's own migration, and the assets binding
 * serves the built client from disk. The platform is substituted; the logic is not.
 *
 * Usage:
 *   npm run build
 *   node scripts/local-server.mjs [port]
 */
import { createServer } from 'node:http';
import { readFile, stat } from 'node:fs/promises';
import { extname, join, normalize, resolve } from 'node:path';
import worker from '../apps/api/dist/src/index.js';
import { LocalD1, LocalR2 } from '../apps/api/dist/src/dev/sqlite-bindings.js';

const PORT = Number(process.argv[2] ?? 8788);
const ROOT = resolve(import.meta.dirname, '..');
const DIST = join(ROOT, 'apps', 'web', 'dist');

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.map': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.woff2': 'font/woff2',
  '.ico': 'image/x-icon',
};

const assets = {
  async fetch(request) {
    const url = new URL(request.url);
    // normalize() plus a prefix check: a path from the network must not escape
    // the dist directory even in a dev-only server.
    const candidate = resolve(join(DIST, normalize(decodeURIComponent(url.pathname))));
    if (!candidate.startsWith(DIST)) return new Response('forbidden', { status: 403 });

    // Unknown paths fall back to the app shell, matching the Worker's
    // single-page-application asset handling so /p/<id> loads the viewer.
    const target = await stat(candidate)
      .then((s) => (s.isFile() ? candidate : join(DIST, 'index.html')))
      .catch(() => join(DIST, 'index.html'));

    try {
      const body = await readFile(target);
      return new Response(body, {
        headers: { 'Content-Type': MIME[extname(target)] ?? 'application/octet-stream' },
      });
    } catch {
      return new Response('not found', { status: 404 });
    }
  },
};

const schema = await readFile(join(ROOT, 'apps', 'api', 'migrations', '0001_init.sql'), 'utf8');
const env = {
  DB: new LocalD1(schema),
  BLOBS: new LocalR2(),
  ASSETS: assets,
  RATE_LIMIT_KEY: 'local-development-only-not-a-secret',
};
const ctx = { waitUntil: () => undefined, passThroughOnException: () => undefined, props: {} };

const server = createServer((nodeReq, nodeRes) => {
  void (async () => {
    const chunks = [];
    for await (const chunk of nodeReq) chunks.push(chunk);
    const body = Buffer.concat(chunks);

    const headers = new Headers();
    for (const [name, value] of Object.entries(nodeReq.headers)) {
      if (typeof value === 'string') headers.set(name, value);
      else if (Array.isArray(value)) headers.set(name, value.join(', '));
    }
    headers.set('cf-connecting-ip', nodeReq.socket.remoteAddress ?? '127.0.0.1');

    const method = nodeReq.method ?? 'GET';
    const request = new Request(`http://127.0.0.1:${PORT}${nodeReq.url ?? '/'}`, {
      method,
      headers,
      body: method === 'GET' || method === 'HEAD' ? null : new Uint8Array(body),
    });

    const response = await worker.fetch(request, env, ctx);
    nodeRes.statusCode = response.status;
    response.headers.forEach((value, name) => nodeRes.setHeader(name, value));
    const out = Buffer.from(await response.arrayBuffer());
    nodeRes.end(method === 'HEAD' ? undefined : out);
  })().catch((error) => {
    nodeRes.statusCode = 500;
    nodeRes.end(String(error));
  });
});

// Same cadence as the deployed cron trigger.
setInterval(() => void worker.scheduled({}, env, ctx), 60_000).unref();

server.listen(PORT, '127.0.0.1', () => {
  process.stdout.write(`cryptopaste local server on http://127.0.0.1:${PORT}\n`);
});
