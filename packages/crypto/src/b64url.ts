/**
 * Unpadded base64url (RFC 4648 §5) with strict, canonical-only decoding.
 *
 * Implemented by hand rather than via `btoa`/`Buffer` for two reasons. First,
 * those differ across browser, Worker, and Node, and one of them is always the
 * odd one out. Second, and more importantly, every permissive decoder in the
 * wild accepts *non-canonical* input: trailing bits that are set but discarded,
 * stray padding, whitespace. That makes an encoding malleable — two distinct
 * strings decode to the same bytes — which turns a paste URL, a key, or a
 * content-addressed id into something an attacker can vary at will while
 * pointing at identical plaintext. This decoder rejects all of it.
 *
 * @module
 */
import { FormatError } from './errors.js';

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

const DECODE_TABLE: Int8Array = (() => {
  const t = new Int8Array(128).fill(-1);
  for (let i = 0; i < ALPHABET.length; i++) t[ALPHABET.charCodeAt(i)] = i;
  return t;
})();

/** Encode bytes as unpadded base64url. */
export function b64uEncode(bytes: Uint8Array): string {
  let out = '';
  let i = 0;
  for (; i + 3 <= bytes.length; i += 3) {
    const n = ((bytes[i] as number) << 16) | ((bytes[i + 1] as number) << 8) | (bytes[i + 2] as number);
    out += ALPHABET[(n >>> 18) & 63]! + ALPHABET[(n >>> 12) & 63]! + ALPHABET[(n >>> 6) & 63]! + ALPHABET[n & 63]!;
  }
  const rem = bytes.length - i;
  if (rem === 1) {
    const n = (bytes[i] as number) << 16;
    out += ALPHABET[(n >>> 18) & 63]! + ALPHABET[(n >>> 12) & 63]!;
  } else if (rem === 2) {
    const n = ((bytes[i] as number) << 16) | ((bytes[i + 1] as number) << 8);
    out += ALPHABET[(n >>> 18) & 63]! + ALPHABET[(n >>> 12) & 63]! + ALPHABET[(n >>> 6) & 63]!;
  }
  return out;
}

/**
 * Decode unpadded base64url, rejecting anything non-canonical.
 *
 * Rejects: padding characters, whitespace, any byte outside the alphabet, a
 * length ≡ 1 (mod 4) which cannot encode any byte string, and — the case most
 * decoders miss — a final character whose low-order bits are set but would be
 * discarded, which is what makes two strings decode to the same bytes.
 */
export function b64uDecode(s: string): Uint8Array {
  const n = s.length;
  if (n % 4 === 1) throw new FormatError('invalid base64url length');

  const fullGroups = n >>> 2;
  const rem = n & 3;
  const outLen = fullGroups * 3 + (rem === 2 ? 1 : rem === 3 ? 2 : 0);
  const out = new Uint8Array(outLen);

  const sym = (idx: number): number => {
    const code = s.charCodeAt(idx);
    const v = code < 128 ? (DECODE_TABLE[code] as number) : -1;
    if (v < 0) throw new FormatError('invalid base64url character');
    return v;
  };

  let o = 0;
  let i = 0;
  for (let g = 0; g < fullGroups; g++, i += 4) {
    const v = (sym(i) << 18) | (sym(i + 1) << 12) | (sym(i + 2) << 6) | sym(i + 3);
    out[o++] = (v >>> 16) & 0xff;
    out[o++] = (v >>> 8) & 0xff;
    out[o++] = v & 0xff;
  }

  if (rem === 2) {
    const a = sym(i);
    const b = sym(i + 1);
    // 12 bits decoded, 8 kept: the low 4 bits of `b` must be zero.
    if ((b & 0x0f) !== 0) throw new FormatError('non-canonical base64url: trailing bits set');
    out[o] = ((a << 2) | (b >>> 4)) & 0xff;
  } else if (rem === 3) {
    const a = sym(i);
    const b = sym(i + 1);
    const c = sym(i + 2);
    // 18 bits decoded, 16 kept: the low 2 bits of `c` must be zero.
    if ((c & 0x03) !== 0) throw new FormatError('non-canonical base64url: trailing bits set');
    out[o++] = ((a << 2) | (b >>> 4)) & 0xff;
    out[o] = ((b << 4) | (c >>> 2)) & 0xff;
  }

  return out;
}

/** Decode and require an exact byte length — used for keys and ids. */
export function b64uDecodeExact(s: string, expectedLength: number): Uint8Array {
  const out = b64uDecode(s);
  if (out.length !== expectedLength) {
    throw new FormatError(`expected ${expectedLength} bytes, decoded ${out.length}`);
  }
  return out;
}
