/**
 * Error types for the CryptoPaste crypto core.
 *
 * Every failure path that could be observed by an attacker collapses into
 * {@link DecryptError} with a single opaque message. Callers must not surface a
 * more specific reason to the network: distinguishing "wrong key" from "corrupt
 * ciphertext" from "bad padding" is how padding-oracle and key-confirmation
 * oracles get built.
 *
 * @module
 */

/** Base class so callers can `instanceof CryptoPasteError` in one check. */
export class CryptoPasteError extends Error {
  constructor(message: string) {
    super(message);
    this.name = new.target.name;
  }
}

/**
 * A malformed envelope, container, or key encoding — detected before any secret
 * material is touched. Safe to report in detail, because it depends only on
 * public structure, never on key material.
 */
export class FormatError extends CryptoPasteError {}

/**
 * Authentication or decryption failed. Deliberately uniform: no sub-types, no
 * variable message, no indication of which stage failed. Wrong key, tampered
 * ciphertext, tampered header, and wrong password all produce exactly this.
 */
export class DecryptError extends CryptoPasteError {
  constructor() {
    super('decryption failed: wrong key, wrong password, or the data was modified');
  }
}

/** A caller-side misuse: bad parameters, oversized input, unsupported options. */
export class UsageError extends CryptoPasteError {}
