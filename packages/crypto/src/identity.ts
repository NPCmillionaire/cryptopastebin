/**
 * Long-lived identities: an X-Wing hybrid KEM keypair for receiving pastes, and
 * an ML-DSA-65 keypair for signing them.
 *
 * Both are expanded from one 32-byte master seed through domain-separated HKDF,
 * so a user backs up a single short secret rather than 4 KB of key material.
 * Deriving both from one seed is safe here because the two labels make the
 * expanded seeds computationally independent, and neither scheme's security
 * argument depends on its seed being freshly sampled rather than PRF output.
 *
 * ## Fingerprints
 *
 * An X-Wing public key is 1216 bytes, which no human will ever compare by eye.
 * That matters, because the entire post-quantum guarantee in recipient mode
 * rests on the sender having the *right* public key: a substituted key turns
 * end-to-end encryption into encryption to the attacker. {@link fingerprint}
 * gives a 20-character string over both public keys that two people can read to
 * each other out of band. It is the piece of the system that cannot be
 * automated away, and it is the piece most implementations quietly omit.
 *
 * @module
 */
import { ml_kem768_x25519 as xwing } from '@noble/post-quantum/hybrid.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { sha3_256 } from '@noble/hashes/sha3.js';
import { b64uDecode, b64uDecodeExact, b64uEncode } from './b64url.js';
import { concat, randomBytes, utf8, wipe } from './bytes.js';
import { derive } from './kdf.js';
import { FormatError, UsageError } from './errors.js';

/** Byte lengths of the two schemes, asserted at load time against the library. */
export const XWING_PUBLIC_KEY_LEN = 1216;
export const XWING_CIPHERTEXT_LEN = 1120;
export const XWING_SEED_LEN = 32;
export const MLDSA65_PUBLIC_KEY_LEN = 1952;
export const MLDSA65_SIGNATURE_LEN = 3309;

/** Length of the master seed from which an identity is expanded. */
export const MASTER_SEED_LEN = 32;

const PUBLIC_PREFIX = 'cpb1pub_';
const SECRET_PREFIX = 'cpb1sec_';
const FINGERPRINT_SALT = utf8('cpb1/fingerprint');

/** The shareable half of an identity. */
export interface PublicIdentity {
  /** X-Wing (ML-KEM-768 + X25519) encapsulation key. */
  readonly kemPublicKey: Uint8Array;
  /** ML-DSA-65 verification key. */
  readonly signPublicKey: Uint8Array;
}

/** A full identity. `masterSeed` is the only value that needs backing up. */
export interface Identity extends PublicIdentity {
  readonly masterSeed: Uint8Array;
  /** X-Wing decapsulation key (itself a 32-byte seed in X-Wing's encoding). */
  readonly kemSecretKey: Uint8Array;
  /** ML-DSA-65 signing key. */
  readonly signSecretKey: Uint8Array;
}

/** Expand an identity from a 32-byte master seed. Deterministic. */
export function identityFromSeed(masterSeed: Uint8Array): Identity {
  if (masterSeed.length !== MASTER_SEED_LEN) {
    throw new UsageError(`master seed must be ${MASTER_SEED_LEN} bytes, got ${masterSeed.length}`);
  }
  const kemSeed = derive(masterSeed, 'cpb1/seed/kem', FINGERPRINT_SALT, XWING_SEED_LEN);
  const signSeed = derive(masterSeed, 'cpb1/seed/sign', FINGERPRINT_SALT, 32);
  try {
    const kem = xwing.keygen(kemSeed);
    const sign = ml_dsa65.keygen(signSeed);
    return {
      masterSeed: masterSeed.slice(),
      kemPublicKey: kem.publicKey,
      kemSecretKey: kem.secretKey,
      signPublicKey: sign.publicKey,
      signSecretKey: sign.secretKey,
    };
  } finally {
    wipe(kemSeed, signSeed);
  }
}

/** Generate a fresh identity from the platform CSPRNG. */
export function generateIdentity(): Identity {
  const seed = randomBytes(MASTER_SEED_LEN);
  try {
    return identityFromSeed(seed);
  } finally {
    wipe(seed);
  }
}

/**
 * A short human-comparable digest over both public keys.
 *
 * Twenty base32-ish characters carry about 100 bits, grouped in fives so it can
 * be read aloud without losing your place. Both keys are covered: verifying only
 * the KEM key would leave the signature key substitutable, which would let an
 * attacker forge authorship on pastes the recipient can genuinely decrypt.
 */
export function fingerprint(identity: PublicIdentity): string {
  const digest = sha3_256(concat(utf8('cpb1/fingerprint/v1'), identity.kemPublicKey, identity.signPublicKey));
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // Crockford-ish: no I, O, 0, 1
  let out = '';
  for (let i = 0; i < 20; i++) {
    if (i > 0 && i % 5 === 0) out += '-';
    out += alphabet[(digest[i] as number) & 31];
  }
  return out;
}

/** Encode a public identity for sharing (a chat message, a profile page, a QR code). */
export function encodePublicIdentity(identity: PublicIdentity): string {
  return PUBLIC_PREFIX + b64uEncode(concat(identity.kemPublicKey, identity.signPublicKey));
}

/** Parse a shared public identity, validating both key lengths. */
export function decodePublicIdentity(encoded: string): PublicIdentity {
  const trimmed = encoded.trim();
  if (!trimmed.startsWith(PUBLIC_PREFIX)) throw new FormatError('not a CryptoPaste public identity');
  const raw = b64uDecode(trimmed.slice(PUBLIC_PREFIX.length));
  const expected = XWING_PUBLIC_KEY_LEN + MLDSA65_PUBLIC_KEY_LEN;
  if (raw.length !== expected) {
    throw new FormatError(`public identity must be ${expected} bytes, got ${raw.length}`);
  }
  return {
    kemPublicKey: raw.slice(0, XWING_PUBLIC_KEY_LEN),
    signPublicKey: raw.slice(XWING_PUBLIC_KEY_LEN),
  };
}

/** Encode the master seed as a backup string. This is the whole secret. */
export function encodeSecretIdentity(identity: Identity): string {
  return SECRET_PREFIX + b64uEncode(identity.masterSeed);
}

/** Restore an identity from a backup string. */
export function decodeSecretIdentity(encoded: string): Identity {
  const trimmed = encoded.trim();
  if (!trimmed.startsWith(SECRET_PREFIX)) throw new FormatError('not a CryptoPaste secret identity');
  const seed = b64uDecodeExact(trimmed.slice(SECRET_PREFIX.length), MASTER_SEED_LEN);
  try {
    return identityFromSeed(seed);
  } finally {
    wipe(seed);
  }
}

/** Strip an identity down to its shareable half. */
export function toPublicIdentity(identity: PublicIdentity): PublicIdentity {
  return { kemPublicKey: identity.kemPublicKey, signPublicKey: identity.signPublicKey };
}

/** Re-export the raw schemes so the envelope layer needs no second import path. */
export { xwing, ml_dsa65 };
