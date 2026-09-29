/**
 * Paste storage.
 *
 * The server's entire view of a paste is: an opaque byte string, its length, a
 * burn flag, and two timestamps. No column here can be used to learn anything
 * about the content.
 *
 * @module
 */
import type { Env } from './env.js';
import { INLINE_STORAGE_THRESHOLD } from './limits.js';

export interface StoredPaste {
  readonly envelope: Uint8Array;
  readonly size: number;
  readonly burned: boolean;
  readonly expiresAt: number;
}

export interface CreateRecord {
  readonly id: string;
  readonly envelope: Uint8Array;
  readonly burn: boolean;
  readonly createdAt: number;
  readonly expiresAt: number;
}

function r2KeyFor(id: string): string {
  return `p/${id}`;
}

/** Write a paste. Large envelopes go to R2, small ones stay inline in D1. */
export async function putPaste(env: Env, record: CreateRecord): Promise<void> {
  const inline = record.envelope.length <= INLINE_STORAGE_THRESHOLD;

  if (!inline) {
    // R2 first: an orphaned object costs a little storage until the scheduled
    // sweep removes it, whereas a row pointing at a missing object is a paste
    // that returns 500 forever. Prefer the recoverable failure.
    await env.BLOBS.put(r2KeyFor(record.id), record.envelope, {
      httpMetadata: { contentType: 'application/octet-stream' },
    });
  }

  try {
    await env.DB.prepare(
      `INSERT INTO pastes (id, blob, r2_key, size, burn, created_at, expires_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
    )
      .bind(
        record.id,
        inline ? record.envelope : null,
        inline ? null : r2KeyFor(record.id),
        record.envelope.length,
        record.burn ? 1 : 0,
        record.createdAt,
        record.expiresAt,
      )
      .run();
  } catch (err) {
    if (!inline) await env.BLOBS.delete(r2KeyFor(record.id)).catch(() => undefined);
    throw err;
  }
}

interface Row {
  blob: ArrayBuffer | Uint8Array | null;
  r2_key: string | null;
  size: number;
  burn: number;
  expires_at: number;
}

function toBytes(value: ArrayBuffer | Uint8Array | null): Uint8Array | null {
  if (value === null) return null;
  return value instanceof Uint8Array ? value : new Uint8Array(value);
}

/**
 * Read a paste, destroying it first if it is burn-after-read.
 *
 * ## Why the delete happens before the bytes are sent
 *
 * `DELETE ... RETURNING` is what makes burn-after-read actually single-use. It is
 * one atomic statement, so when two clients race for the same burn paste exactly
 * one of them gets a row back and the other sees nothing — there is no window in
 * which both read before either deletes. The naive `SELECT` then `DELETE` has
 * precisely that window, and under any real concurrency it hands the paste to
 * both parties, which is the one thing a burn paste promises not to do.
 *
 * The cost is honest and unavoidable: the row is gone before the response has
 * been delivered, so a client that loses its connection mid-download loses the
 * paste. That is the correct side of the trade — at-most-once delivery — because
 * the alternative is at-least-once, and "the attacker also got a copy" is a worse
 * outcome than "you need a new link". This is documented in the API response and
 * in the UI, not buried here.
 */
export async function takePaste(env: Env, id: string, now: number): Promise<StoredPaste | null> {
  const burned = await env.DB.prepare(
    `DELETE FROM pastes
      WHERE id = ?1 AND burn = 1 AND expires_at > ?2
      RETURNING blob, r2_key, size, burn, expires_at`,
  )
    .bind(id, now)
    .first<Row>();

  if (burned !== null) {
    const bytes = await loadBytes(env, burned);
    if (burned.r2_key !== null) await env.BLOBS.delete(burned.r2_key).catch(() => undefined);
    if (bytes === null) return null;
    return { envelope: bytes, size: burned.size, burned: true, expiresAt: burned.expires_at };
  }

  const row = await env.DB.prepare(
    `SELECT blob, r2_key, size, burn, expires_at
       FROM pastes
      WHERE id = ?1 AND burn = 0 AND expires_at > ?2`,
  )
    .bind(id, now)
    .first<Row>();

  if (row === null) return null;
  const bytes = await loadBytes(env, row);
  if (bytes === null) return null;
  return { envelope: bytes, size: row.size, burned: false, expiresAt: row.expires_at };
}

async function loadBytes(env: Env, row: Row): Promise<Uint8Array | null> {
  const inline = toBytes(row.blob);
  if (inline !== null) return inline;
  if (row.r2_key === null) return null;
  const object = await env.BLOBS.get(row.r2_key);
  if (object === null) return null;
  return new Uint8Array(await object.arrayBuffer());
}

/**
 * Whether a paste exists, without consuming a burn paste.
 *
 * Used by `HEAD` so a link preview crawler — Slack, iMessage, a corporate mail
 * scanner — cannot silently burn a paste before the recipient ever opens it.
 * Unfurlers issuing a speculative `GET` are the single most common way
 * burn-after-read surprises people, so `HEAD` deliberately reveals only
 * existence and never touches the row.
 */
export async function pasteExists(env: Env, id: string, now: number): Promise<{ burn: boolean; size: number } | null> {
  const row = await env.DB.prepare(`SELECT burn, size FROM pastes WHERE id = ?1 AND expires_at > ?2`)
    .bind(id, now)
    .first<{ burn: number; size: number }>();
  return row === null ? null : { burn: row.burn === 1, size: row.size };
}

/** Delete expired pastes and their R2 objects. Driven by the cron trigger. */
export async function purgeExpired(env: Env, now: number, batchSize = 500): Promise<{ rows: number; objects: number }> {
  const expired = await env.DB.prepare(
    `DELETE FROM pastes WHERE id IN (
       SELECT id FROM pastes WHERE expires_at <= ?1 LIMIT ?2
     ) RETURNING r2_key`,
  )
    .bind(now, batchSize)
    .all<{ r2_key: string | null }>();

  const keys = (expired.results ?? []).map((r) => r.r2_key).filter((k): k is string => k !== null);
  // R2 delete accepts up to 1000 keys per call; the batch size above keeps us under it.
  if (keys.length > 0) await env.BLOBS.delete(keys).catch(() => undefined);

  return { rows: expired.results?.length ?? 0, objects: keys.length };
}
