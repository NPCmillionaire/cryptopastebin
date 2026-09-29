import { describe, expect, it } from 'vitest';
import worker from '../src/index.js';
import { createPaste, readPaste } from '@cryptopaste/crypto';
import { ctx, makeEnv, req, type TestEnv } from './harness.js';
import { INLINE_STORAGE_THRESHOLD, MAX_ENVELOPE_BYTES, RATE_LIMIT } from '../src/limits.js';

const fetchApp = (env: TestEnv, request: Request) => worker.fetch(request, env as never, ctx);

async function post(env: TestEnv, envelope: Uint8Array, query = ''): Promise<Response> {
  return fetchApp(
    env,
    req(`/api/pastes${query}`, {
      method: 'POST',
      body: envelope as unknown as BodyInit,
      headers: { 'Content-Type': 'application/octet-stream' },
    }),
  );
}

async function upload(env: TestEnv, body: string, query = ''): Promise<{ id: string; fragment: string }> {
  const created = await createPaste({ body });
  const res = await post(env, created.envelope, query);
  expect(res.status).toBe(201);
  const { id } = (await res.json()) as { id: string };
  return { id, fragment: created.fragment! };
}

describe('round trip through the API', () => {
  it('stores and returns an envelope that still decrypts', async () => {
    const env = makeEnv();
    const body = 'console.log("hello");\n';
    const created = await createPaste({ body, lang: 'javascript', render: 'code' });

    const post1 = await post(env, created.envelope);
    expect(post1.status).toBe(201);
    const meta = (await post1.json()) as { id: string; size: number; burn: boolean };
    expect(meta.size).toBe(created.envelope.length);
    expect(meta.burn).toBe(false);

    const get1 = await fetchApp(env, req(`/api/pastes/${meta.id}`));
    expect(get1.status).toBe(200);
    expect(get1.headers.get('Content-Type')).toBe('application/octet-stream');
    const fetched = new Uint8Array(await get1.arrayBuffer());
    expect(Buffer.from(fetched).equals(Buffer.from(created.envelope))).toBe(true);

    const read = await readPaste(fetched, { kind: 'fragment', fragment: created.fragment! });
    expect(read.content.body).toBe(body);
    expect(read.content.lang).toBe('javascript');
  });

  it('serves the same paste repeatedly when it is not a burn paste', async () => {
    const env = makeEnv();
    const { id } = await upload(env, 'persistent');
    for (let i = 0; i < 3; i++) {
      expect((await fetchApp(env, req(`/api/pastes/${id}`))).status).toBe(200);
    }
  });

  it('returns 404 for a well-formed id that does not exist', async () => {
    const env = makeEnv();
    expect((await fetchApp(env, req('/api/pastes/AAAAAAAAAAAAAAAAAAAAAA'))).status).toBe(404);
  });

  it('rejects an id that does not match the exact expected shape', async () => {
    const env = makeEnv();
    // Wrong length, wrong alphabet, and a SQL-injection attempt all fail the
    // allow-list pattern in ids.ts before any query is prepared.
    for (const id of ['short', 'AAAAAAAAAAAAAAAAAAAAA', 'AAAAAAAAAAAAAAAAAAAAAAA', "' OR 1=1--", 'AAAA%2FAAAA']) {
      const res = await fetchApp(env, req(`/api/pastes/${encodeURIComponent(id)}`));
      expect(res.status, id).toBe(404);
    }
  });

  it('never reaches the paste route with a traversal path', async () => {
    const env = makeEnv();
    // The URL parser normalises `..` segments away before routing, so this is a
    // request for /etc/passwd, which the API does not own. It must be handled by
    // the assets binding and must not query the database.
    const res = await fetchApp(env, req('/api/pastes/../../etc/passwd'));
    expect(env.ASSETS.requests).toContain('/etc/passwd');
    expect(res.headers.get('Content-Type')).toContain('text/html');
  });
});

describe('burn after reading', () => {
  it('serves once and then is gone', async () => {
    const env = makeEnv();
    const { id, fragment } = await upload(env, 'one time only', '?burn=1');

    const first = await fetchApp(env, req(`/api/pastes/${id}`));
    expect(first.status).toBe(200);
    expect(first.headers.get('X-Paste-Burn')).toBe('1');
    const read = await readPaste(new Uint8Array(await first.arrayBuffer()), { kind: 'fragment', fragment });
    expect(read.content.body).toBe('one time only');

    expect((await fetchApp(env, req(`/api/pastes/${id}`))).status).toBe(404);
    expect((await fetchApp(env, req(`/api/pastes/${id}`))).status).toBe(404);
  });

  it('hands the paste to exactly one of many concurrent readers', async () => {
    const env = makeEnv();
    const { id } = await upload(env, 'contested', '?burn=1');

    const responses = await Promise.all(
      Array.from({ length: 12 }, () => fetchApp(env, req(`/api/pastes/${id}`))),
    );
    const winners = responses.filter((r) => r.status === 200);
    const losers = responses.filter((r) => r.status === 404);
    expect(winners).toHaveLength(1);
    expect(losers).toHaveLength(11);
  });

  it('removes the R2 object too when the envelope was stored out of line', async () => {
    const env = makeEnv();
    const big = 'x'.repeat(INLINE_STORAGE_THRESHOLD * 2);
    const created = await createPaste({ body: big, compress: false });
    expect(created.envelope.length).toBeGreaterThan(INLINE_STORAGE_THRESHOLD);

    const res = await post(env, created.envelope, '?burn=1');
    const { id } = (await res.json()) as { id: string };
    expect(env.BLOBS.objects.size).toBe(1);

    const got = await fetchApp(env, req(`/api/pastes/${id}`));
    expect(got.status).toBe(200);
    expect(new Uint8Array(await got.arrayBuffer()).length).toBe(created.envelope.length);
    expect(env.BLOBS.objects.size).toBe(0);
    expect((await fetchApp(env, req(`/api/pastes/${id}`))).status).toBe(404);
  });

  it('is not consumed by a HEAD request, so link previews cannot destroy it', async () => {
    const env = makeEnv();
    const { id, fragment } = await upload(env, 'survives unfurling', '?burn=1');

    for (let i = 0; i < 3; i++) {
      const head = await fetchApp(env, req(`/api/pastes/${id}`, { method: 'HEAD' }));
      expect(head.status).toBe(200);
      expect(head.headers.get('X-Paste-Burn')).toBe('1');
      expect(await head.text()).toBe('');
    }

    const get = await fetchApp(env, req(`/api/pastes/${id}`));
    expect(get.status).toBe(200);
    const read = await readPaste(new Uint8Array(await get.arrayBuffer()), { kind: 'fragment', fragment });
    expect(read.content.body).toBe('survives unfurling');
  });
});

describe('expiry', () => {
  it('refuses an expiry that is not one of the advertised options', async () => {
    const env = makeEnv();
    const created = await createPaste({ body: 'x' });
    for (const bad of ['1', '999999999', 'abc', '-3600', '0']) {
      const res = await post(env, created.envelope, `?expiresIn=${bad}`);
      expect(res.status, bad).toBe(400);
    }
  });

  it('stops serving an expired paste even before the sweep runs', async () => {
    const env = makeEnv();
    const { id } = await upload(env, 'short lived', '?expiresIn=300');
    // Rewind the stored expiry rather than waiting: the read path filters on
    // expires_at, so this proves expiry is enforced by the query and does not
    // depend on the cron having fired.
    env.DB.db.exec(`UPDATE pastes SET expires_at = 1 WHERE id = '${id}'`);
    expect((await fetchApp(env, req(`/api/pastes/${id}`))).status).toBe(404);
    expect((await fetchApp(env, req(`/api/pastes/${id}`, { method: 'HEAD' }))).status).toBe(404);
  });

  it('reclaims expired rows and their R2 objects on the scheduled sweep', async () => {
    const env = makeEnv();
    const big = await createPaste({ body: 'y'.repeat(INLINE_STORAGE_THRESHOLD * 2), compress: false });
    await post(env, big.envelope);
    await upload(env, 'small one');
    expect(env.BLOBS.objects.size).toBe(1);

    env.DB.db.exec('UPDATE pastes SET expires_at = 1');
    await worker.scheduled({} as ScheduledController, env as never, ctx);

    const remaining = env.DB.db.prepare('SELECT COUNT(*) AS n FROM pastes').get() as { n: number };
    expect(remaining.n).toBe(0);
    expect(env.BLOBS.objects.size).toBe(0);
  });

  it('leaves unexpired pastes alone during the sweep', async () => {
    const env = makeEnv();
    const { id } = await upload(env, 'keep me');
    await worker.scheduled({} as ScheduledController, env as never, ctx);
    expect((await fetchApp(env, req(`/api/pastes/${id}`))).status).toBe(200);
  });
});

describe('input validation', () => {
  it('rejects a body that is not a CryptoPaste envelope', async () => {
    const env = makeEnv();
    const notAnEnvelope = new Uint8Array(128).fill(0x41);
    const res = await post(env, notAnEnvelope);
    expect(res.status).toBe(400);
  });

  it('rejects an implausibly short body', async () => {
    const env = makeEnv();
    const res = await post(env, new Uint8Array([0x43, 0x50, 0x42, 0x31]));
    expect(res.status).toBe(400);
  });

  it('rejects an oversized envelope on the declared length alone', async () => {
    const env = makeEnv();
    const res = await fetchApp(
      env,
      req('/api/pastes', {
        method: 'POST',
        body: new Uint8Array(128) as unknown as BodyInit,
        headers: { 'Content-Length': String(MAX_ENVELOPE_BYTES + 1) },
      }),
    );
    expect(res.status).toBe(413);
  });

  it('rejects unsupported methods on the API', async () => {
    const env = makeEnv();
    for (const method of ['PUT', 'DELETE', 'PATCH']) {
      const res = await fetchApp(env, req('/api/pastes/AAAAAAAAAAAAAAAAAAAAAA', { method }));
      expect(res.status, method).toBe(405);
    }
  });
});

describe('rate limiting', () => {
  it('blocks a client past the write limit and lets a different one through', async () => {
    const env = makeEnv();
    const created = await createPaste({ body: 'spam' });

    let blocked = 0;
    for (let i = 0; i < RATE_LIMIT.maxWrites + 5; i++) {
      const res = await fetchApp(
        env,
        req('/api/pastes', { method: 'POST', body: created.envelope as unknown as BodyInit, ip: '198.51.100.1' }),
      );
      if (res.status === 429) blocked++;
    }
    expect(blocked).toBe(5);

    const other = await fetchApp(
      env,
      req('/api/pastes', { method: 'POST', body: created.envelope as unknown as BodyInit, ip: '198.51.100.2' }),
    );
    expect(other.status).toBe(201);
  });

  it('stores no client address, only an opaque counter key', async () => {
    const env = makeEnv();
    await upload(env, 'x');
    const buckets = env.DB.db.prepare('SELECT bucket_key FROM rate_buckets').all() as { bucket_key: string }[];
    expect(buckets.length).toBeGreaterThan(0);
    for (const b of buckets) {
      expect(b.bucket_key).toMatch(/^[0-9a-f]{20}$/);
      expect(b.bucket_key).not.toContain('203.0.113.7');
    }
    // And no column anywhere in the schema is capable of holding one.
    const columns = env.DB.db.prepare(`SELECT name FROM pragma_table_info('pastes')`).all() as { name: string }[];
    expect(columns.map((c) => c.name).sort()).toEqual(
      ['blob', 'burn', 'created_at', 'expires_at', 'id', 'r2_key', 'size'].sort(),
    );
  });

  it('drops stale buckets on the scheduled sweep', async () => {
    const env = makeEnv();
    await upload(env, 'x');
    env.DB.db.exec('UPDATE rate_buckets SET window_start = 0');
    await worker.scheduled({} as ScheduledController, env as never, ctx);
    const left = env.DB.db.prepare('SELECT COUNT(*) AS n FROM rate_buckets').get() as { n: number };
    expect(left.n).toBe(0);
  });
});

describe('response headers', () => {
  it('sets no-referrer and a CSP with no inline or third-party allowance', async () => {
    const env = makeEnv();
    const res = await fetchApp(env, req('/'));
    expect(res.headers.get('Referrer-Policy')).toBe('no-referrer');

    const csp = res.headers.get('Content-Security-Policy')!;
    expect(csp).toContain("default-src 'none'");
    expect(csp).toContain("script-src 'self'");
    expect(csp).toContain("frame-ancestors 'none'");
    expect(csp).not.toContain('unsafe-inline');
    expect(csp).not.toContain('unsafe-eval');
    expect(csp).not.toContain('wasm-unsafe-eval');
    expect(csp).not.toContain('https://');

    expect(res.headers.get('X-Content-Type-Options')).toBe('nosniff');
    expect(res.headers.get('X-Frame-Options')).toBe('DENY');
    expect(res.headers.get('Cross-Origin-Opener-Policy')).toBe('same-origin');
    expect(res.headers.get('Strict-Transport-Security')).toContain('max-age=');
  });

  it('marks API responses no-store so a burned paste cannot be recovered from a cache', async () => {
    const env = makeEnv();
    const { id } = await upload(env, 'x');
    const res = await fetchApp(env, req(`/api/pastes/${id}`));
    expect(res.headers.get('Cache-Control')).toContain('no-store');
    expect(res.headers.get('X-Robots-Tag')).toContain('noindex');
  });

  it('sets no CORS allowance, so no other origin can read the API', async () => {
    const env = makeEnv();
    const res = await fetchApp(env, req('/api/config'));
    expect(res.status).toBe(200);
    expect(res.headers.get('Access-Control-Allow-Origin')).toBeNull();
  });

  it('sets no cookies anywhere', async () => {
    const env = makeEnv();
    const { id } = await upload(env, 'x');
    for (const path of ['/', '/api/config', `/api/pastes/${id}`]) {
      const res = await fetchApp(env, req(path));
      expect(res.headers.get('Set-Cookie'), path).toBeNull();
    }
  });
});

describe('static client', () => {
  it('falls through to the assets binding for non-API paths', async () => {
    const env = makeEnv();
    const res = await fetchApp(env, req('/p/AAAAAAAAAAAAAAAAAAAAAA'));
    expect(res.status).toBe(200);
    expect(env.ASSETS.requests).toContain('/p/AAAAAAAAAAAAAAAAAAAAAA');
    // Security headers apply to the app shell as well as the API.
    expect(res.headers.get('Content-Security-Policy')).toBeTruthy();
  });

  it('advertises its limits so the client does not hard-code them', async () => {
    const env = makeEnv();
    const res = await fetchApp(env, req('/api/config'));
    const config = (await res.json()) as { maxEnvelopeBytes: number; expiryOptions: number[] };
    expect(config.maxEnvelopeBytes).toBe(MAX_ENVELOPE_BYTES);
    expect(config.expiryOptions).toContain(3600);
  });
});
