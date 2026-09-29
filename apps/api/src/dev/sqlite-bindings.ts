/**
 * SQLite- and memory-backed stand-ins for the D1 and R2 bindings.
 *
 * Used by the test suite and by `scripts/local-server.mjs`. Both share one
 * implementation so that what runs in CI and what runs on a developer's machine
 * behave identically.
 *
 * The D1 shim is backed by `node:sqlite` rather than being a hand-written fake,
 * and that choice is what gives the tests their value. The two behaviours the
 * suite is meant to prove — that `DELETE ... RETURNING` makes a burn paste
 * single-use under concurrent reads, and that the rate-limit upsert cannot
 * double-count — are properties of SQLite's statement atomicity, not of this
 * adapter. A mock would implement whatever the author assumed and would pass
 * regardless of whether the real query is correct; here the same SQL text runs
 * against the same engine D1 is built on.
 *
 * @module
 */
import { DatabaseSync } from 'node:sqlite';

type Row = Record<string, unknown>;

class LocalStatement {
  private args: unknown[] = [];
  private readonly db: DatabaseSync;
  private readonly sql: string;

  // Assigned explicitly rather than via constructor parameter properties, so this
  // file also loads under Node's type-stripping loader.
  constructor(db: DatabaseSync, sql: string) {
    this.db = db;
    this.sql = sql;
  }

  bind(...args: unknown[]): this {
    this.args = args;
    return this;
  }

  async first<T>(): Promise<T | null> {
    const rows = this.db.prepare(this.sql).all(...(this.args as never[])) as Row[];
    return (rows[0] as T) ?? null;
  }

  async all<T>(): Promise<{ results: T[]; meta: { changes: number } }> {
    const rows = this.db.prepare(this.sql).all(...(this.args as never[])) as Row[];
    return { results: rows as T[], meta: { changes: rows.length } };
  }

  async run(): Promise<{ meta: { changes: number } }> {
    const info = this.db.prepare(this.sql).run(...(this.args as never[]));
    return { meta: { changes: Number(info.changes) } };
  }
}

/** A D1-shaped database over in-process SQLite. */
export class LocalD1 {
  readonly db: DatabaseSync;

  /**
   * @param schemaSql Contents of the migration to apply. Passed in rather than
   *   read from a path relative to this module, which would break once the file
   *   is compiled into `dist/`.
   * @param path `:memory:` by default; a file path makes local data survive restarts.
   */
  constructor(schemaSql: string, path = ':memory:') {
    this.db = new DatabaseSync(path);
    this.db.exec(schemaSql);
  }

  prepare(sql: string): LocalStatement {
    return new LocalStatement(this.db, sql);
  }
}

/** An R2-shaped object store held in memory. */
export class LocalR2 {
  readonly objects = new Map<string, Uint8Array>();
  putCount = 0;
  deleteCount = 0;

  async put(key: string, value: Uint8Array | ArrayBuffer): Promise<void> {
    this.putCount++;
    this.objects.set(key, value instanceof Uint8Array ? value.slice() : new Uint8Array(value));
  }

  async get(key: string): Promise<{ arrayBuffer(): Promise<ArrayBuffer> } | null> {
    const value = this.objects.get(key);
    if (value === undefined) return null;
    const copy = value.slice();
    return { arrayBuffer: async () => copy.buffer as ArrayBuffer };
  }

  async delete(key: string | string[]): Promise<void> {
    this.deleteCount++;
    for (const k of Array.isArray(key) ? key : [key]) this.objects.delete(k);
  }
}
