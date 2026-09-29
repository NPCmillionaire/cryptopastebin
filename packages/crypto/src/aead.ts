/**
 * Authenticated encryption: XChaCha20-Poly1305.
 *
 * XChaCha20 rather than ChaCha20 or AES-GCM specifically for the nonce size. A
 * 192-bit nonce can be drawn at random for every message with a collision
 * probability that stays negligible past any volume this service will ever see,
 * so there is no nonce counter to persist, synchronise, or get wrong. AES-GCM's
 * 96-bit nonce and catastrophic reuse failure mode make it the wrong default for
 * a client-side tool where the same key might be used by two tabs at once;
 * AES-GCM also has no constant-time software implementation on hardware without
 * AES-NI, which describes a good fraction of phones.
 *
 * Both functions take the AAD explicitly and neither has a default, because an
 * omitted AAD is invisible at the call site and silently unbinds a ciphertext
 * from its header.
 *
 * @module
 */
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { DecryptError, UsageError } from './errors.js';
import { KEY_LEN } from './kdf.js';
import { randomBytes } from './bytes.js';

/** XChaCha20-Poly1305 nonce length in bytes. */
export const NONCE_LEN = 24;

/** Poly1305 authentication tag length in bytes. */
export const TAG_LEN = 16;

/** A fresh random 192-bit nonce. */
export function randomNonce(): Uint8Array {
  return randomBytes(NONCE_LEN);
}

function check(key: Uint8Array, nonce: Uint8Array): void {
  if (key.length !== KEY_LEN) throw new UsageError(`key must be ${KEY_LEN} bytes, got ${key.length}`);
  if (nonce.length !== NONCE_LEN) throw new UsageError(`nonce must be ${NONCE_LEN} bytes, got ${nonce.length}`);
}

/**
 * Encrypt and authenticate. Returns `ciphertext || tag`.
 *
 * @param aad Additional authenticated data — always the envelope header region
 *   this ciphertext belongs to, never empty in this codebase.
 */
export function seal(key: Uint8Array, nonce: Uint8Array, aad: Uint8Array, plaintext: Uint8Array): Uint8Array {
  check(key, nonce);
  return xchacha20poly1305(key, nonce, aad).encrypt(plaintext);
}

/**
 * Verify and decrypt.
 *
 * @throws {DecryptError} on any authentication failure, with a message that does
 *   not distinguish a wrong key from modified data. The underlying library error
 *   is swallowed on purpose — it is exactly the kind of detail that becomes an
 *   oracle once it reaches an HTTP response.
 */
export function open(key: Uint8Array, nonce: Uint8Array, aad: Uint8Array, ciphertext: Uint8Array): Uint8Array {
  check(key, nonce);
  if (ciphertext.length < TAG_LEN) throw new DecryptError();
  try {
    return xchacha20poly1305(key, nonce, aad).decrypt(ciphertext);
  } catch {
    throw new DecryptError();
  }
}
