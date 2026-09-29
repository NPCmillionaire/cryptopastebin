/**
 * Worker bindings.
 *
 * @module
 */

export interface Env {
  /** Paste metadata and inline ciphertext. */
  DB: D1Database;
  /** Ciphertext for envelopes above {@link INLINE_STORAGE_THRESHOLD}. */
  BLOBS: R2Bucket;
  /** Static frontend assets. */
  ASSETS: Fetcher;
  /**
   * HMAC key for deriving rate-limit bucket identifiers.
   *
   * Set with `wrangler secret put RATE_LIMIT_KEY`. It exists so that client
   * addresses are never stored: the bucket id is a truncated HMAC, which is
   * enough to count requests and not enough to recover or confirm an address
   * without the key. Rotating the secret simply resets every bucket.
   */
  RATE_LIMIT_KEY: string;
  /** Public origin, used to build absolute paste URLs. */
  PUBLIC_ORIGIN?: string;
}
