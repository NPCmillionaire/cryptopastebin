/**
 * Rate limiting without storing client addresses.
 *
 * The bucket identifier is a truncated HMAC-SHA-256 of the client address under a
 * server secret. That is enough to count requests from one source and not enough
 * to recover an address, or to confirm a guessed one, without the secret. The
 * distinction matters for a tool whose whole promise is that the operator knows
 * as little as possible: a plain `INSERT INTO ... (ip)` turns the rate limiter
 * into an access log, and an access log is exactly the artifact a subpoena asks
 * for. Rotating {@link Env.RATE_LIMIT_KEY} invalidates every stored bucket, so
 * even the truncated correlator is not durable.
 *
 * Buckets are a fixed window rather than a sliding one. A fixed window permits a
 * burst of up to 2× the limit across a boundary, which is fine here — the point
 * is to stop bulk abuse of storage, not to shape traffic precisely — and it costs
 * one row and one statement instead of a per-request timestamp log.
 *
 * @module
 */
import type { Env } from './env.js';
import { RATE_LIMIT, RATE_BUCKET_RETENTION_SECONDS } from './limits.js';

export type Action = 'write' | 'read';

async function bucketKey(env: Env, action: Action, clientAddress: string, windowStart: number): Promise<string> {
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(env.RATE_LIMIT_KEY),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const mac = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(`${action}|${clientAddress}|${windowStart}`));
  // 80 bits is ample for a counter key and leaves no room for a reversal shortcut.
  const bytes = new Uint8Array(mac).slice(0, 10);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

export interface RateDecision {
  readonly allowed: boolean;
  readonly remaining: number;
  /** Seconds until the current window ends. */
  readonly resetIn: number;
}

/** Count one request and decide whether to allow it. */
export async function consume(env: Env, action: Action, clientAddress: string, now: number): Promise<RateDecision> {
  const limit = action === 'write' ? RATE_LIMIT.maxWrites : RATE_LIMIT.maxReads;
  const windowStart = Math.floor(now / RATE_LIMIT.windowSeconds) * RATE_LIMIT.windowSeconds;
  const resetIn = windowStart + RATE_LIMIT.windowSeconds - now;
  const key = await bucketKey(env, action, clientAddress, windowStart);

  // One statement, so two concurrent requests cannot both read the old count and
  // write the same incremented value. The RETURNING clause gives the post-increment
  // total, which is what the decision needs.
  const row = await env.DB.prepare(
    `INSERT INTO rate_buckets (bucket_key, count, window_start)
     VALUES (?1, 1, ?2)
     ON CONFLICT (bucket_key) DO UPDATE SET count = count + 1
     RETURNING count`,
  )
    .bind(key, windowStart)
    .first<{ count: number }>();

  const count = row?.count ?? 1;
  return { allowed: count <= limit, remaining: Math.max(0, limit - count), resetIn };
}

/** Remove buckets from windows that have closed. Driven by the cron trigger. */
export async function purgeRateBuckets(env: Env, now: number): Promise<number> {
  const result = await env.DB.prepare(`DELETE FROM rate_buckets WHERE window_start < ?1`)
    .bind(now - RATE_BUCKET_RETENTION_SECONDS)
    .run();
  return result.meta?.changes ?? 0;
}
