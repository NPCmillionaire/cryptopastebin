/**
 * Server-side policy limits.
 *
 * These are deliberately separate from the crypto package's limits. The client
 * enforces its own ceilings so it can fail fast with a good message, but the
 * server cannot trust a client-side check and re-applies every one of them.
 *
 * @module
 */

/** Largest envelope the server will accept, in bytes. */
export const MAX_ENVELOPE_BYTES = 25 * 1024 * 1024;

/** Envelopes at or below this size are stored inline in D1; larger ones go to R2. */
export const INLINE_STORAGE_THRESHOLD = 96 * 1024;

/** Allowed expiry windows, in seconds. A closed set, so `expiresIn` cannot be abused. */
export const EXPIRY_OPTIONS = [
  300,        // 5 minutes
  3_600,      // 1 hour
  86_400,     // 1 day
  604_800,    // 1 week
  2_592_000,  // 30 days
] as const;

export type ExpiryOption = (typeof EXPIRY_OPTIONS)[number];

export const DEFAULT_EXPIRY: ExpiryOption = 86_400;

/** Requests per window, per client, for paste creation. */
export const RATE_LIMIT = { windowSeconds: 3_600, maxWrites: 120, maxReads: 1_200 } as const;

/** How long a rate-limit bucket is retained before the scheduled purge removes it. */
export const RATE_BUCKET_RETENTION_SECONDS = 2 * RATE_LIMIT.windowSeconds;

export function isExpiryOption(value: unknown): value is ExpiryOption {
  return typeof value === 'number' && (EXPIRY_OPTIONS as readonly number[]).includes(value);
}
