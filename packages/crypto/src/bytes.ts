/**
 * Byte-level primitives: allocation, comparison, and a bounds-checked
 * reader/writer pair used by every binary codec in this package.
 *
 * The reader exists because hand-rolled offset arithmetic is where binary
 * parsers get their memory-safety and confusion bugs. Every read is
 * length-checked against the remaining buffer and throws {@link FormatError}
 * rather than returning a short or aliased view.
 *
 * @module
 */
import { randomBytes as nobleRandomBytes } from '@noble/hashes/utils.js';
import { FormatError, UsageError } from './errors.js';

/** Cryptographically secure random bytes from the platform CSPRNG. */
export function randomBytes(length: number): Uint8Array {
  if (!Number.isInteger(length) || length < 0) throw new UsageError('length must be a non-negative integer');
  return nobleRandomBytes(length);
}

/** Concatenate byte arrays into a fresh buffer. */
export function concat(...parts: readonly Uint8Array[]): Uint8Array {
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

/**
 * Constant-time equality for byte arrays of equal length.
 *
 * Returns false immediately for differing lengths — length is not secret in any
 * of this package's uses — but compares contents without early exit so the
 * timing of a mismatch does not reveal *where* it occurred.
 */
export function equalCT(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= (a[i] as number) ^ (b[i] as number);
  return diff === 0;
}

/**
 * Best-effort zeroing of a secret buffer.
 *
 * This is a hygiene measure, not a guarantee. A JavaScript runtime may have
 * already copied the bytes during GC, string conversion, or JIT deoptimisation,
 * and there is no portable way to reach those copies. Treat it as reducing the
 * window, never as erasing the secret.
 */
export function wipe(...buffers: readonly Uint8Array[]): void {
  for (const b of buffers) b.fill(0);
}

const TEXT_ENCODER = new TextEncoder();
const TEXT_DECODER = new TextDecoder('utf-8', { fatal: true });

/** UTF-8 encode. */
export function utf8(s: string): Uint8Array {
  return TEXT_ENCODER.encode(s);
}

/** Strict UTF-8 decode; throws {@link FormatError} on invalid sequences. */
export function fromUtf8(b: Uint8Array): string {
  try {
    return TEXT_DECODER.decode(b);
  } catch {
    throw new FormatError('invalid UTF-8');
  }
}

/** Append-only big-endian byte writer. */
export class Writer {
  private chunks: Uint8Array[] = [];
  private len = 0;

  bytes(b: Uint8Array): this {
    this.chunks.push(b);
    this.len += b.length;
    return this;
  }

  u8(n: number): this {
    if (!Number.isInteger(n) || n < 0 || n > 0xff) throw new UsageError(`u8 out of range: ${n}`);
    return this.bytes(new Uint8Array([n]));
  }

  u16(n: number): this {
    if (!Number.isInteger(n) || n < 0 || n > 0xffff) throw new UsageError(`u16 out of range: ${n}`);
    return this.bytes(new Uint8Array([(n >>> 8) & 0xff, n & 0xff]));
  }

  u32(n: number): this {
    if (!Number.isInteger(n) || n < 0 || n > 0xffff_ffff) throw new UsageError(`u32 out of range: ${n}`);
    return this.bytes(new Uint8Array([(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff]));
  }

  /** Length-prefixed byte string with a u16 length. */
  lp16(b: Uint8Array): this {
    return this.u16(b.length).bytes(b);
  }

  /** Length-prefixed byte string with a u32 length. */
  lp32(b: Uint8Array): this {
    return this.u32(b.length).bytes(b);
  }

  get length(): number {
    return this.len;
  }

  finish(): Uint8Array {
    return concat(...this.chunks);
  }
}

/** Bounds-checked big-endian byte reader. */
export class Reader {
  private off = 0;

  constructor(private readonly buf: Uint8Array) {}

  private need(n: number): void {
    if (n < 0) throw new UsageError('negative read length');
    if (this.off + n > this.buf.length) {
      throw new FormatError(`truncated input: need ${n} byte(s) at offset ${this.off}, have ${this.buf.length - this.off}`);
    }
  }

  /** Read `n` bytes as a copy, so the result never aliases the input buffer. */
  bytes(n: number): Uint8Array {
    this.need(n);
    const out = this.buf.slice(this.off, this.off + n);
    this.off += n;
    return out;
  }

  u8(): number {
    this.need(1);
    return this.buf[this.off++] as number;
  }

  u16(): number {
    this.need(2);
    const v = ((this.buf[this.off] as number) << 8) | (this.buf[this.off + 1] as number);
    this.off += 2;
    return v;
  }

  u32(): number {
    this.need(4);
    const v =
      (this.buf[this.off] as number) * 0x100_0000 +
      ((this.buf[this.off + 1] as number) << 16) +
      ((this.buf[this.off + 2] as number) << 8) +
      (this.buf[this.off + 3] as number);
    this.off += 4;
    return v;
  }

  lp16(): Uint8Array {
    return this.bytes(this.u16());
  }

  lp32(): Uint8Array {
    return this.bytes(this.u32());
  }

  /** Bytes consumed so far. Used to slice the exact AAD region of a header. */
  get offset(): number {
    return this.off;
  }

  get remaining(): number {
    return this.buf.length - this.off;
  }

  /** A copy of everything not yet read. */
  rest(): Uint8Array {
    return this.bytes(this.remaining);
  }

  /** A copy of `buf[0..offset)` — the region already parsed. */
  consumed(): Uint8Array {
    return this.buf.slice(0, this.off);
  }

  /** Throws unless the buffer is fully consumed. Rejects trailing-garbage malleability. */
  end(): void {
    if (this.remaining !== 0) {
      throw new FormatError(`${this.remaining} unexpected trailing byte(s)`);
    }
  }
}
