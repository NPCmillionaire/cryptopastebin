/**
 * The CryptoPaste Worker.
 *
 * Serves the static client and a three-endpoint API. What it never does is worth
 * enumerating, because the guarantees rest on the absences: it does not log
 * request bodies, does not record client addresses, does not read the URL
 * fragment (it cannot — fragments are not transmitted), does not set a cookie,
 * does not emit a `Set-Cookie`, does not contact a third party, and stores no
 * field describing a paste's contents.
 *
 * @module
 */
import { Hono } from 'hono';
import type { Env } from './env.js';
import { API_HEADERS, applySecurityHeaders } from './headers.js';
import { generateId, isValidId } from './ids.js';
import {
  DEFAULT_EXPIRY,
  EXPIRY_OPTIONS,
  isExpiryOption,
  MAX_ENVELOPE_BYTES,
  RATE_LIMIT,
} from './limits.js';
import { consume } from './ratelimit.js';
import { pasteExists, purgeExpired, putPaste, takePaste } from './store.js';
import { purgeRateBuckets } from './ratelimit.js';

const ENVELOPE_MAGIC = new Uint8Array([0x43, 0x50, 0x42, 0x31]); // "CPB1"

const app = new Hono<{ Bindings: Env }>();

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', ...API_HEADERS },
  });
}

function problem(status: number, message: string, extra: Record<string, unknown> = {}): Response {
  return json({ error: message, ...extra }, status);
}

function clientAddress(request: Request): string {
  // Cloudflare sets this and it cannot be spoofed by the client at the edge. It
  // is used only to derive a rate-limit HMAC and is never written anywhere.
  return request.headers.get('cf-connecting-ip') ?? 'unknown';
}

app.get('/api/config', (c) =>
  json({
    maxEnvelopeBytes: MAX_ENVELOPE_BYTES,
    expiryOptions: EXPIRY_OPTIONS,
    defaultExpiry: DEFAULT_EXPIRY,
    rateLimit: { windowSeconds: RATE_LIMIT.windowSeconds, maxWrites: RATE_LIMIT.maxWrites },
  }),
);

app.post('/api/pastes', async (c) => {
  const now = Math.floor(Date.now() / 1000);
  const rate = await consume(c.env, 'write', clientAddress(c.req.raw), now);
  if (!rate.allowed) {
    return problem(429, 'rate limit exceeded', { retryAfter: rate.resetIn });
  }

  const declared = c.req.header('content-length');
  if (declared !== undefined && Number(declared) > MAX_ENVELOPE_BYTES) {
    return problem(413, `envelope exceeds ${MAX_ENVELOPE_BYTES} bytes`);
  }

  const expiresInRaw = Number(c.req.query('expiresIn') ?? DEFAULT_EXPIRY);
  if (!isExpiryOption(expiresInRaw)) {
    return problem(400, 'expiresIn must be one of the advertised options', { expiryOptions: EXPIRY_OPTIONS });
  }
  const burn = c.req.query('burn') === '1';

  const body = new Uint8Array(await c.req.arrayBuffer());
  // Re-checked after reading: Content-Length is a claim, not a measurement.
  if (body.length > MAX_ENVELOPE_BYTES) {
    return problem(413, `envelope exceeds ${MAX_ENVELOPE_BYTES} bytes`);
  }
  if (body.length < 64) {
    return problem(400, 'envelope is too short to be valid');
  }
  // A magic-byte check, and nothing more. The server deliberately does not parse
  // the envelope: it has no key, so validation beyond "this is plausibly one of
  // ours" would be theatre, and a parser here would be attack surface that
  // processes hostile bytes for no benefit.
  for (let i = 0; i < ENVELOPE_MAGIC.length; i++) {
    if (body[i] !== ENVELOPE_MAGIC[i]) return problem(400, 'not a CryptoPaste envelope');
  }

  const id = generateId();
  await putPaste(c.env, {
    id,
    envelope: body,
    burn,
    createdAt: now,
    expiresAt: now + expiresInRaw,
  });

  return json({ id, burn, expiresAt: now + expiresInRaw, size: body.length }, 201);
});

app.on(['GET', 'HEAD'], '/api/pastes/:id', async (c) => {
  const now = Math.floor(Date.now() / 1000);
  const id = c.req.param('id');
  if (!isValidId(id)) return problem(404, 'not found');

  const rate = await consume(c.env, 'read', clientAddress(c.req.raw), now);
  if (!rate.allowed) return problem(429, 'rate limit exceeded', { retryAfter: rate.resetIn });

  // HEAD must never consume a burn paste. Link unfurlers issue speculative
  // requests, and a preview that destroyed the paste before the recipient opened
  // it would be indistinguishable from an attack.
  if (c.req.method === 'HEAD') {
    const meta = await pasteExists(c.env, id, now);
    if (meta === null) return new Response(null, { status: 404, headers: API_HEADERS });
    return new Response(null, {
      status: 200,
      headers: {
        ...API_HEADERS,
        'Content-Type': 'application/octet-stream',
        'Content-Length': String(meta.size),
        'X-Paste-Burn': meta.burn ? '1' : '0',
      },
    });
  }

  const paste = await takePaste(c.env, id, now);
  if (paste === null) return problem(404, 'not found');

  return new Response(paste.envelope as unknown as BodyInit, {
    status: 200,
    headers: {
      ...API_HEADERS,
      'Content-Type': 'application/octet-stream',
      'Content-Length': String(paste.envelope.length),
      'X-Paste-Burn': paste.burned ? '1' : '0',
      'X-Paste-Expires-At': String(paste.expiresAt),
    },
  });
});

app.all('/api/*', () => problem(405, 'method not allowed'));

// Everything else is the static client, served from the assets binding.
app.all('*', async (c) => {
  if (c.req.method !== 'GET' && c.req.method !== 'HEAD') return problem(405, 'method not allowed');
  return c.env.ASSETS.fetch(c.req.raw);
});

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    let response: Response;
    try {
      response = await app.fetch(request, env, ctx);
    } catch {
      // Deliberately opaque. An exception message can carry a SQL fragment, a
      // binding name, or a stack path, and none of that helps a legitimate user.
      response = problem(500, 'internal error');
    }
    return applySecurityHeaders(new Response(response.body, response));
  },

  /** Scheduled purge of expired pastes, orphaned blobs, and stale rate buckets. */
  async scheduled(_event: ScheduledController, env: Env, _ctx: ExecutionContext): Promise<void> {
    const now = Math.floor(Date.now() / 1000);
    // Bounded loop: a single invocation should not run unbounded, and anything
    // left over is picked up by the next tick a minute later.
    for (let i = 0; i < 20; i++) {
      const { rows } = await purgeExpired(env, now);
      if (rows === 0) break;
    }
    await purgeRateBuckets(env, now);
  },
};

export { app };
