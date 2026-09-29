/**
 * Recipient key validation on the main thread.
 *
 * Decoding a public identity is cheap and involves no secret, so it does not need
 * the worker; doing it inline lets the UI reject a mistyped key the moment it is
 * pasted rather than at upload time.
 *
 * @module
 */
import { decodePublicIdentity, fingerprint } from '@cryptopaste/crypto';

/** Validate an encoded public identity and return its fingerprint. Throws if invalid. */
export function decodeAndFingerprint(encoded: string): string {
  return fingerprint(decodePublicIdentity(encoded));
}
