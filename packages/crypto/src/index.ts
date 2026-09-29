/**
 * CryptoPaste crypto core.
 *
 * A zero-knowledge paste format: XChaCha20-Poly1305 for content, X-Wing
 * (ML-KEM-768 + X25519) for addressing pastes to a public key, Argon2id for the
 * optional password factor, ML-DSA-65 for optional authorship, and HKDF-SHA3-256
 * binding it all together. Isomorphic — the same bytes on Node, in a browser, and
 * in a Cloudflare Worker.
 *
 * Start with {@link createPaste} and {@link readPaste}.
 *
 * @module
 */
export {
  createPaste,
  readPaste,
  envelopeRequiresPassword,
  buildPasteUrl,
  parsePasteUrl,
  DEFAULT_PASTE_LIMITS,
  type CreatePasteOptions,
  type CreatedPaste,
  type PasteKey,
  type PasteLimits,
  type ReadPasteResult,
} from './paste.js';

export {
  generateIdentity,
  identityFromSeed,
  fingerprint,
  encodePublicIdentity,
  decodePublicIdentity,
  encodeSecretIdentity,
  decodeSecretIdentity,
  toPublicIdentity,
  MASTER_SEED_LEN,
  XWING_PUBLIC_KEY_LEN,
  XWING_CIPHERTEXT_LEN,
  MLDSA65_PUBLIC_KEY_LEN,
  MLDSA65_SIGNATURE_LEN,
  type Identity,
  type PublicIdentity,
} from './identity.js';

export {
  sanitiseFilename,
  DEFAULT_CONTAINER_LIMITS,
  type Attachment,
  type PasteContent,
  type RenderMode,
  type ContainerLimits,
} from './container.js';

export {
  parseEnvelope,
  sealEnvelope,
  openEnvelope,
  randomLinkKey,
  ENVELOPE_VERSION,
  LINK_KEY_LEN,
  MAX_SLOTS,
  SlotKind,
  type ParsedEnvelope,
  type Credential,
  type Recipient,
  type Slot,
  type SlotKindValue,
} from './envelope.js';

export {
  DEFAULT_ARGON2_PARAMS,
  ARGON2_LIMITS,
  PASSWORD_SALT_LEN,
  validateArgon2Params,
  type Argon2Params,
} from './password.js';

export { b64uEncode, b64uDecode, b64uDecodeExact } from './b64url.js';
export { NONCE_LEN, TAG_LEN } from './aead.js';
export { KEY_LEN } from './kdf.js';
export { randomBytes, equalCT, wipe, concat } from './bytes.js';
export { CryptoPasteError, DecryptError, FormatError, UsageError } from './errors.js';
