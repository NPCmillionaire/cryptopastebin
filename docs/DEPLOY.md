# Deploying

Target is Cloudflare Workers with D1 for metadata and R2 for large ciphertexts. The
free tier is enough for personal use.

## Prerequisites

```bash
npm install
npx wrangler login
```

## 1. Create the storage

```bash
npx wrangler d1 create cryptopaste
npx wrangler r2 bucket create cryptopaste-blobs
```

Copy the printed `database_id` into `apps/api/wrangler.toml`, replacing
`REPLACE_WITH_YOUR_D1_ID`.

## 2. Apply the schema

```bash
npm run db:migrate -w @cryptopaste/api
```

## 3. Set the rate-limit secret

```bash
openssl rand -base64 32 | npx wrangler secret put RATE_LIMIT_KEY --config apps/api/wrangler.toml
```

This key derives the HMAC that identifies rate-limit buckets. It exists so client
addresses are never stored: a bucket id is a truncated HMAC, which is enough to
count requests and not enough to recover or confirm an address. Rotating it resets
every bucket and destroys even that correlator — worth doing periodically.

## 4. Build and deploy

```bash
npm run build          # crypto package, then the client bundle
npm run deploy -w @cryptopaste/api
```

The Worker serves both the API and the static client, so there is one deployment and
no CORS configuration. That is deliberate: a separate frontend origin would need
`Access-Control-Allow-Origin`, and every value of that header is a wider blast radius
than same-origin.

## Verifying a deployment

```bash
curl -sI https://your-worker.workers.dev/ | grep -iE 'content-security-policy|referrer-policy'
```

`Referrer-Policy: no-referrer` must be present. It is not hardening — it is
load-bearing. Without it, the paste id in the path reaches any third-party resource
the page loads.

The full browser suite can be pointed at a live deployment:

```bash
E2E_BASE=https://your-worker.workers.dev node scripts/e2e.mjs
```

It asserts, among other things, that the key appears in no request URL, header, or
body.

## Local development

No Cloudflare account needed. A local server runs the real Worker handler with D1
backed by `node:sqlite` and R2 held in memory:

```bash
npm run build
node scripts/local-server.mjs 8788
```

Or with the real runtime, once `wrangler.toml` has a database id:

```bash
npm run dev -w @cryptopaste/api     # workerd + local D1
npm run dev -w @cryptopaste/web     # Vite, proxying /api to it
```

## Self-hosting elsewhere

The client is static files and the API needs only three things: a key-value or SQL
store supporting an atomic delete-and-return, blob storage, and a periodic job. The
one query that genuinely matters is in `apps/api/src/store.ts`:

```sql
DELETE FROM pastes WHERE id = ?1 AND burn = 1 AND expires_at > ?2
  RETURNING blob, r2_key, size, burn, expires_at
```

`DELETE ... RETURNING` in a single statement is what makes burn-after-read
single-use. The naive `SELECT` then `DELETE` has a window in which two concurrent
readers both read before either deletes, and under real concurrency it hands the
paste to both — the one thing a burn paste promises not to do. Any port must preserve
that atomicity.

## Operational notes

- **Expiry** is enforced by the read query (`expires_at > now`), so a paste is
  unreadable the instant it expires regardless of whether the cron has run. The
  sweep only reclaims space.
- **The cron runs every minute** and purges in bounded batches; leftovers are picked
  up on the next tick.
- **Nothing is logged about paste contents.** `[observability] enabled = true` in
  `wrangler.toml` captures Worker errors and request metadata, not bodies. Turn it
  off if even that is unwanted.
- **Storage growth** is bounded by expiry. The longest window is 30 days; shorten
  `EXPIRY_OPTIONS` in `apps/api/src/limits.ts` to cap exposure further.
