/**
 * Test harness. The D1 and R2 stand-ins live in `src/dev/sqlite-bindings.ts` so
 * that the test suite and the local dev server share one implementation.
 */
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { LocalD1, LocalR2 } from '../src/dev/sqlite-bindings.js';

const here = dirname(fileURLToPath(import.meta.url));

export function readSchema(): string {
  return readFileSync(join(here, '..', 'migrations', '0001_init.sql'), 'utf8');
}

export class FakeD1 extends LocalD1 {
  constructor() {
    super(readSchema());
  }
}

export { LocalR2 as FakeR2 };

/** A stub assets binding so requests outside /api can be asserted on. */
export class FakeAssets {
  requests: string[] = [];

  async fetch(request: Request): Promise<Response> {
    this.requests.push(new URL(request.url).pathname);
    return new Response('<!doctype html><title>CryptoPaste</title>', {
      headers: { 'Content-Type': 'text/html; charset=utf-8' },
    });
  }
}

export interface TestEnv {
  DB: FakeD1;
  BLOBS: LocalR2;
  ASSETS: FakeAssets;
  RATE_LIMIT_KEY: string;
}

export function makeEnv(): TestEnv {
  return {
    DB: new FakeD1(),
    BLOBS: new LocalR2(),
    ASSETS: new FakeAssets(),
    RATE_LIMIT_KEY: 'test-secret-key-not-for-production',
  };
}

export const ctx = {
  waitUntil: () => undefined,
  passThroughOnException: () => undefined,
  props: {},
} as unknown as ExecutionContext;

/** Build a request with a plausible client address so the rate limiter has a key. */
export function req(path: string, init: RequestInit & { ip?: string } = {}): Request {
  const headers = new Headers(init.headers);
  headers.set('cf-connecting-ip', init.ip ?? '203.0.113.7');
  return new Request(`https://paste.test${path}`, { ...init, headers });
}
