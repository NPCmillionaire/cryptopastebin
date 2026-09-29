/**
 * Key derivation: HKDF-SHA3-256 with mandatory domain separation.
 *
 * Every derived key in CryptoPaste comes out of {@link derive}, and every call
 * site must name its purpose via the {@link Label} union. That is deliberate:
 * the single most common way a layered protocol like this one breaks is key
 * reuse across contexts — the same 32 bytes serving as a content key in one
 * path and a wrapping key in another, so that an oracle in the cheap path
 * unlocks the expensive one. Making the label a closed, exhaustive type means a
 * new call site cannot compile without declaring, and a reviewer reading
 * {@link Label} can enumerate every key the system derives.
 *
 * SHA3-256 rather than SHA-256: the envelope already depends on SHA3/SHAKE via
 * ML-KEM and X-Wing's combiner, so this adds no new primitive, and SHA3's
 * sponge construction is not length-extendable, which removes a whole class of
 * footgun from future changes to the transcript.
 *
 * @module
 */
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha3_256 } from '@noble/hashes/sha3.js';
import { utf8 } from './bytes.js';

/** Length in bytes of every key this module derives. */
export const KEY_LEN = 32;

/**
 * The complete set of derivation contexts. Adding a key to the protocol means
 * adding a member here, which makes the change visible in review.
 */
export type Label =
  /** Wrapping key for the content key, from a link key found in the URL fragment. */
  | 'cpb1/kek/link'
  /** Wrapping key for the content key, from an X-Wing hybrid KEM shared secret. */
  | 'cpb1/kek/xwing'
  /** Additional wrapping factor derived from an Argon2id password hash (AND layer). */
  | 'cpb1/kek/password'
  /** Final wrapping key, mixing a slot's key with the optional password factor. */
  | 'cpb1/kek/final'
  /** X-Wing KEM key-generation seed, expanded from an identity's master seed. */
  | 'cpb1/seed/kem'
  /** ML-DSA-65 signing seed, expanded from an identity's master seed. */
  | 'cpb1/seed/sign';

/**
 * HKDF-SHA3-256 Extract-then-Expand.
 *
 * @param ikm Input keying material — a KEM shared secret, link key, or password hash.
 * @param label Purpose of the derived key. See {@link Label}.
 * @param salt Non-secret salt. Pass the envelope's per-paste salt so that two
 *   pastes sharing an input key still derive unrelated subkeys.
 * @param length Output length in bytes; defaults to {@link KEY_LEN}.
 */
export function derive(ikm: Uint8Array, label: Label, salt: Uint8Array, length: number = KEY_LEN): Uint8Array {
  return hkdf(sha3_256, ikm, salt, utf8(label), length);
}

/**
 * Mix a slot key with the optional password factor into the final wrapping key.
 *
 * Concatenating both inputs as HKDF's IKM gives AND semantics: the result is
 * unpredictable unless *both* factors are known. A leaked link alone does not
 * open a password-protected paste, and a guessed password alone does not open
 * one without the link.
 */
export function mixFactors(slotKey: Uint8Array, passwordFactor: Uint8Array | undefined, salt: Uint8Array): Uint8Array {
  if (passwordFactor === undefined) return derive(slotKey, 'cpb1/kek/final', salt);
  const ikm = new Uint8Array(slotKey.length + passwordFactor.length);
  ikm.set(slotKey, 0);
  ikm.set(passwordFactor, slotKey.length);
  try {
    return derive(ikm, 'cpb1/kek/final', salt);
  } finally {
    ikm.fill(0);
  }
}
