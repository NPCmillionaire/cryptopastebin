/**
 * Optional password layer: Argon2id.
 *
 * ## Why this is an AND layer, not an alternative
 *
 * The obvious design is to let a password *replace* the URL key, so a paste can
 * be opened by anyone who knows the password. That design is much weaker than it
 * looks, and it is what most "password-protected paste" features ship. A paste
 * id is public, so an attacker who scrapes ids can grind passwords offline
 * against the ciphertext at whatever rate their hardware allows, and human
 * passwords do not survive that. Argon2id raises the cost per guess but cannot
 * turn a 30-bit password into a 128-bit key.
 *
 * So here the password is an additional factor combined with the link key (see
 * `mixFactors` in {@link ./kdf.js}), never a substitute for it. Both are
 * required. The password's job is narrow and it does it well: it protects the
 * paste when the *link itself* leaks — pasted into the wrong chat, sitting in a
 * synced clipboard, captured in a screenshot, recovered from browser history.
 * The link supplies the entropy; the password supplies a second channel.
 *
 * ## Parameters
 *
 * Defaults are RFC 9106's second recommended configuration: m=64 MiB, t=3, p=4.
 * They are stored in each envelope rather than compiled in, so the defaults can
 * be raised later without orphaning existing pastes — old envelopes carry the
 * parameters they were created with and keep opening.
 *
 * @module
 */
import { argon2id } from '@noble/hashes/argon2.js';
import { derive, KEY_LEN } from './kdf.js';
import { UsageError } from './errors.js';
import { randomBytes, wipe } from './bytes.js';

/** Salt length for the password KDF. */
export const PASSWORD_SALT_LEN = 16;

/** Argon2id cost parameters, carried inside every password-protected envelope. */
export interface Argon2Params {
  /** Memory cost in KiB. */
  readonly m: number;
  /** Time cost (iterations). */
  readonly t: number;
  /** Parallelism (lanes). */
  readonly p: number;
}

/** RFC 9106 second recommended option: 64 MiB, 3 iterations, 4 lanes. */
export const DEFAULT_ARGON2_PARAMS: Argon2Params = { m: 65_536, t: 3, p: 4 };

/**
 * Bounds on accepted parameters.
 *
 * The lower bounds stop a hostile or buggy envelope from claiming a password
 * layer while pinning the cost to nothing, which would make the layer
 * decorative. The upper bounds stop a hostile envelope from turning a recipient
 * who merely opens a link into a denial-of-service victim by demanding a 4 GiB
 * allocation — a parser must never let attacker-controlled numbers size an
 * allocation without a ceiling.
 */
export const ARGON2_LIMITS = {
  minM: 8_192,
  maxM: 1_048_576,
  minT: 2,
  maxT: 16,
  minP: 1,
  maxP: 16,
} as const;

/** Validate Argon2 parameters against {@link ARGON2_LIMITS}. */
export function validateArgon2Params(params: Argon2Params): void {
  const { m, t, p } = params;
  const L = ARGON2_LIMITS;
  if (!Number.isInteger(m) || m < L.minM || m > L.maxM) {
    throw new UsageError(`argon2 memory must be an integer in [${L.minM}, ${L.maxM}] KiB, got ${m}`);
  }
  if (!Number.isInteger(t) || t < L.minT || t > L.maxT) {
    throw new UsageError(`argon2 iterations must be an integer in [${L.minT}, ${L.maxT}], got ${t}`);
  }
  if (!Number.isInteger(p) || p < L.minP || p > L.maxP) {
    throw new UsageError(`argon2 parallelism must be an integer in [${L.minP}, ${L.maxP}], got ${p}`);
  }
}

/** A fresh password salt. */
export function randomPasswordSalt(): Uint8Array {
  return randomBytes(PASSWORD_SALT_LEN);
}

/**
 * Stretch a password into a 32-byte factor for {@link mixFactors}.
 *
 * Normalises to Unicode NFC first. Without it, the same password typed on macOS
 * and on Linux can produce different byte strings — decomposed versus composed
 * accents — and the paste simply refuses to open with no way for the user to
 * tell why.
 *
 * @param fileSalt The envelope's per-paste salt, mixed in via HKDF after Argon2id
 *   so that the stretched output is additionally bound to this specific paste.
 */
export function passwordFactor(
  password: string,
  passwordSalt: Uint8Array,
  params: Argon2Params,
  fileSalt: Uint8Array,
): Uint8Array {
  if (password.length === 0) throw new UsageError('password must not be empty');
  if (passwordSalt.length !== PASSWORD_SALT_LEN) {
    throw new UsageError(`password salt must be ${PASSWORD_SALT_LEN} bytes, got ${passwordSalt.length}`);
  }
  validateArgon2Params(params);

  const normalised = password.normalize('NFC');
  const hash = argon2id(normalised, passwordSalt, {
    m: params.m,
    t: params.t,
    p: params.p,
    dkLen: KEY_LEN,
  });
  try {
    return derive(hash, 'cpb1/kek/password', fileSalt);
  } finally {
    wipe(hash);
  }
}
