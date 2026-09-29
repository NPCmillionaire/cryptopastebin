/**
 * The envelope: the only thing the server ever stores.
 *
 * ```text
 * offset size  field
 * 0      4     magic "CPB1"
 * 4      1     version = 1
 * 5      1     flags       bit0 = inner compressed, bit1 = password layer
 * 6      1     slotCount   1..8
 * 7      1     reserved = 0
 * 8      16    fileSalt    per-paste HKDF salt
 * -- if flags.passwordLayer --
 *        16    passwordSalt
 *        4     argon2 m (KiB)
 *        4     argon2 t
 *        1     argon2 p
 * -- slot table, slotCount entries --
 *        1     kind        0x01 link, 0x02 X-Wing
 *        2+n   slotData    length-prefixed (empty for link, 1120-byte ct for X-Wing)
 *        24    wrapNonce
 *        48    wrappedCek  32-byte content key + 16-byte tag
 * -- body --
 *        24    nonce
 *        4     ciphertextLen
 *        n     ciphertext || tag
 * ```
 *
 * ## Key hierarchy
 *
 * One content key (CEK) encrypts the container. That CEK is then wrapped once per
 * *slot*, and any single slot opens the paste — slots are an OR. A link slot's
 * wrapping key comes from the 32 random bytes in the URL fragment; an X-Wing slot's
 * comes from a hybrid KEM encapsulation to a recipient's public key. Because both
 * paths converge on one CEK, a paste can be addressed to three colleagues and still
 * be openable by link, without storing the ciphertext three times.
 *
 * The optional password layer is orthogonal and ANDs with whichever slot is used.
 *
 * ## Where the post-quantum guarantee actually lives
 *
 * Worth stating plainly, because it is the part most easily oversold. A link-mode
 * paste is already quantum-resistant and always was: its security rests on a
 * 256-bit symmetric key and XChaCha20-Poly1305, and Grover's algorithm at best
 * halves that exponent, leaving 128 bits of quantum security. No lattice
 * cryptography improves on it. Adding ML-KEM to link mode would be theatre.
 *
 * The hybrid KEM earns its place in *recipient* mode, where a key agreement has to
 * happen against a long-lived public key. That is precisely where "harvest now,
 * decrypt later" bites: an adversary who records an X25519-only envelope today can
 * decrypt it the day a cryptographically relevant quantum computer exists, and for
 * a paste meant to stay secret for a decade that is a live risk rather than a
 * theoretical one. X-Wing composes ML-KEM-768 with X25519 so the result is no
 * weaker than X25519 alone even if the lattice assumption falls — the reason to
 * choose a hybrid over raw ML-KEM, whose security has had far less time under
 * scrutiny than elliptic curves have.
 *
 * ## Everything structural is authenticated
 *
 * The body AEAD's AAD is every header byte preceding the ciphertext: version,
 * flags, slot count, salt, Argon2 parameters, the whole slot table, nonce, and
 * length. Each slot's wrap has its own AAD binding it to the header prefix and to
 * that slot's kind and data. The consequence is that an attacker cannot flip the
 * compression flag, downgrade the Argon2 cost, delete a slot, swap one slot's
 * ciphertext for another's, or move a wrap between envelopes: all of it breaks
 * authentication before a single plaintext byte is produced.
 *
 * @module
 */
import { NONCE_LEN, open as aeadOpen, randomNonce, seal as aeadSeal, TAG_LEN } from './aead.js';
import { concat, equalCT, randomBytes, Reader, utf8, wipe, Writer } from './bytes.js';
import { DecryptError, FormatError, UsageError } from './errors.js';
import { derive, KEY_LEN, mixFactors } from './kdf.js';
import {
  type Argon2Params,
  DEFAULT_ARGON2_PARAMS,
  PASSWORD_SALT_LEN,
  passwordFactor,
  randomPasswordSalt,
  validateArgon2Params,
} from './password.js';
import { xwing, XWING_CIPHERTEXT_LEN, XWING_PUBLIC_KEY_LEN } from './identity.js';

export const MAGIC = utf8('CPB1');
export const ENVELOPE_VERSION = 1;

export const FILE_SALT_LEN = 16;
export const LINK_KEY_LEN = 32;
export const MAX_SLOTS = 8;

const FLAG_COMPRESSED = 0b0000_0001;
const FLAG_PASSWORD = 0b0000_0010;
const KNOWN_FLAGS = FLAG_COMPRESSED | FLAG_PASSWORD;

const WRAPPED_CEK_LEN = KEY_LEN + TAG_LEN;

/** Slot kind discriminants as they appear on the wire. */
export const SlotKind = {
  Link: 0x01,
  XWing: 0x02,
} as const;
export type SlotKindValue = (typeof SlotKind)[keyof typeof SlotKind];

/** A parsed slot. */
export interface Slot {
  readonly kind: SlotKindValue;
  /** Empty for a link slot; the 1120-byte X-Wing ciphertext for an X-Wing slot. */
  readonly data: Uint8Array;
  readonly wrapNonce: Uint8Array;
  readonly wrappedCek: Uint8Array;
}

/** A parsed envelope header plus body, before any decryption. */
export interface ParsedEnvelope {
  readonly version: number;
  readonly compressed: boolean;
  readonly fileSalt: Uint8Array;
  readonly password: { readonly salt: Uint8Array; readonly params: Argon2Params } | undefined;
  readonly slots: readonly Slot[];
  readonly nonce: Uint8Array;
  readonly ciphertext: Uint8Array;
  /** Exact header bytes used as the body AEAD's AAD. */
  readonly bodyAad: Uint8Array;
  /** Header prefix (through the Argon2 block, if any) used in each slot's AAD. */
  readonly slotAadPrefix: Uint8Array;
}

/** How a recipient is addressed when sealing. */
export type Recipient =
  | { readonly kind: 'link'; readonly linkKey: Uint8Array }
  | { readonly kind: 'xwing'; readonly kemPublicKey: Uint8Array };

/** A fresh 32-byte link key, destined for the URL fragment. */
export function randomLinkKey(): Uint8Array {
  return randomBytes(LINK_KEY_LEN);
}

/** A fresh per-paste salt. */
export function randomFileSalt(): Uint8Array {
  return randomBytes(FILE_SALT_LEN);
}

function buildHeaderPrefix(flags: number, slotCount: number, fileSalt: Uint8Array, pw: { salt: Uint8Array; params: Argon2Params } | undefined): Uint8Array {
  const w = new Writer().bytes(MAGIC).u8(ENVELOPE_VERSION).u8(flags).u8(slotCount).u8(0).bytes(fileSalt);
  if (pw !== undefined) {
    w.bytes(pw.salt).u32(pw.params.m).u32(pw.params.t).u8(pw.params.p);
  }
  return w.finish();
}

function slotAad(prefix: Uint8Array, kind: number, data: Uint8Array): Uint8Array {
  return concat(prefix, new Writer().u8(kind).lp16(data).finish());
}

/** Options for {@link sealEnvelope}. */
export interface SealEnvelopeOptions {
  /** The already-built plaintext container. */
  readonly container: Uint8Array;
  /** True iff `container`'s inner region was DEFLATE-compressed. */
  readonly compressed: boolean;
  /** One or more recipients; each becomes a slot. */
  readonly recipients: readonly Recipient[];
  /** Optional password, ANDed with every slot. */
  readonly password?: { readonly password: string; readonly params?: Argon2Params | undefined } | undefined;
}

/** Encrypt a container into a wire envelope. */
export function sealEnvelope(options: SealEnvelopeOptions): Uint8Array {
  const { recipients } = options;
  if (recipients.length === 0) throw new UsageError('at least one recipient is required');
  if (recipients.length > MAX_SLOTS) throw new UsageError(`at most ${MAX_SLOTS} recipients, got ${recipients.length}`);

  const fileSalt = randomFileSalt();
  let pw: { salt: Uint8Array; params: Argon2Params } | undefined;
  let pwFactor: Uint8Array | undefined;
  if (options.password !== undefined) {
    const params = options.password.params ?? DEFAULT_ARGON2_PARAMS;
    validateArgon2Params(params);
    const salt = randomPasswordSalt();
    pw = { salt, params };
    pwFactor = passwordFactor(options.password.password, salt, params, fileSalt);
  }

  const flags = (options.compressed ? FLAG_COMPRESSED : 0) | (pw !== undefined ? FLAG_PASSWORD : 0);
  const prefix = buildHeaderPrefix(flags, recipients.length, fileSalt, pw);

  const cek = randomBytes(KEY_LEN);
  const slotBytes: Uint8Array[] = [];
  try {
    for (const recipient of recipients) {
      let kind: number;
      let data: Uint8Array;
      let slotKey: Uint8Array;

      if (recipient.kind === 'link') {
        if (recipient.linkKey.length !== LINK_KEY_LEN) {
          throw new UsageError(`link key must be ${LINK_KEY_LEN} bytes, got ${recipient.linkKey.length}`);
        }
        kind = SlotKind.Link;
        data = new Uint8Array(0);
        slotKey = derive(recipient.linkKey, 'cpb1/kek/link', fileSalt);
      } else {
        if (recipient.kemPublicKey.length !== XWING_PUBLIC_KEY_LEN) {
          throw new UsageError(`X-Wing public key must be ${XWING_PUBLIC_KEY_LEN} bytes, got ${recipient.kemPublicKey.length}`);
        }
        const { cipherText, sharedSecret } = xwing.encapsulate(recipient.kemPublicKey);
        kind = SlotKind.XWing;
        data = cipherText;
        try {
          slotKey = derive(sharedSecret, 'cpb1/kek/xwing', fileSalt);
        } finally {
          wipe(sharedSecret);
        }
      }

      const kek = mixFactors(slotKey, pwFactor, fileSalt);
      const wrapNonce = randomNonce();
      try {
        const wrapped = aeadSeal(kek, wrapNonce, slotAad(prefix, kind, data), cek);
        slotBytes.push(new Writer().u8(kind).lp16(data).bytes(wrapNonce).bytes(wrapped).finish());
      } finally {
        wipe(slotKey, kek);
      }
    }

    const nonce = randomNonce();
    const bodyAad = concat(prefix, ...slotBytes, nonce, new Writer().u32(options.container.length + TAG_LEN).finish());
    const ciphertext = aeadSeal(cek, nonce, bodyAad, options.container);
    return concat(prefix, ...slotBytes, nonce, new Writer().u32(ciphertext.length).finish(), ciphertext);
  } finally {
    wipe(cek);
    if (pwFactor !== undefined) wipe(pwFactor);
  }
}

/**
 * Parse an envelope's structure without decrypting anything.
 *
 * Every length and parameter is range-checked here, before any key material is
 * derived, so a hostile envelope cannot cause a large allocation or a multi-second
 * Argon2 grind just by being fetched.
 */
export function parseEnvelope(bytes: Uint8Array, maxCiphertextLength: number): ParsedEnvelope {
  const reader = new Reader(bytes);

  if (!equalCT(reader.bytes(4), MAGIC)) throw new FormatError('not a CryptoPaste envelope');
  const version = reader.u8();
  if (version !== ENVELOPE_VERSION) throw new FormatError(`unsupported envelope version: ${version}`);
  const flags = reader.u8();
  if ((flags & ~KNOWN_FLAGS) !== 0) throw new FormatError(`unknown envelope flags: 0x${flags.toString(16)}`);
  const slotCount = reader.u8();
  if (slotCount < 1 || slotCount > MAX_SLOTS) throw new FormatError(`slot count out of range: ${slotCount}`);
  const reserved = reader.u8();
  if (reserved !== 0) throw new FormatError('reserved byte must be zero');
  const fileSalt = reader.bytes(FILE_SALT_LEN);

  let password: { salt: Uint8Array; params: Argon2Params } | undefined;
  if ((flags & FLAG_PASSWORD) !== 0) {
    const salt = reader.bytes(PASSWORD_SALT_LEN);
    const params: Argon2Params = { m: reader.u32(), t: reader.u32(), p: reader.u8() };
    // Validated before use: these numbers size an allocation and a work factor,
    // and they arrive from whoever created the envelope.
    validateArgon2Params(params);
    password = { salt, params };
  }
  const slotAadPrefix = reader.consumed();

  const slots: Slot[] = [];
  for (let i = 0; i < slotCount; i++) {
    const kind = reader.u8();
    const data = reader.lp16();
    if (kind === SlotKind.Link) {
      if (data.length !== 0) throw new FormatError('link slot must carry no data');
    } else if (kind === SlotKind.XWing) {
      if (data.length !== XWING_CIPHERTEXT_LEN) {
        throw new FormatError(`X-Wing slot data must be ${XWING_CIPHERTEXT_LEN} bytes, got ${data.length}`);
      }
    } else {
      throw new FormatError(`unknown slot kind: 0x${kind.toString(16)}`);
    }
    const wrapNonce = reader.bytes(NONCE_LEN);
    const wrappedCek = reader.bytes(WRAPPED_CEK_LEN);
    slots.push({ kind, data, wrapNonce, wrappedCek });
  }

  const nonce = reader.bytes(NONCE_LEN);
  const ciphertextLen = reader.u32();
  if (ciphertextLen < TAG_LEN) throw new FormatError('ciphertext shorter than its tag');
  if (ciphertextLen > maxCiphertextLength) {
    throw new FormatError(`ciphertext of ${ciphertextLen} bytes exceeds limit of ${maxCiphertextLength}`);
  }
  const bodyAad = reader.consumed();
  const ciphertext = reader.bytes(ciphertextLen);
  reader.end();

  return { version, compressed: (flags & FLAG_COMPRESSED) !== 0, fileSalt, password, slots, nonce, ciphertext, bodyAad, slotAadPrefix };
}

/** The credential a reader presents to open an envelope. */
export type Credential =
  | { readonly kind: 'link'; readonly linkKey: Uint8Array }
  | { readonly kind: 'xwing'; readonly kemSecretKey: Uint8Array };

/**
 * Recover the content key, then decrypt the container.
 *
 * With an X-Wing credential every X-Wing slot is tried in turn, because an
 * envelope does not record which slot belongs to which recipient — recording that
 * would publish the recipient list to the server, which is exactly the metadata
 * this design withholds. The cost is a handful of decapsulations; the benefit is
 * that a stored envelope reveals only *how many* recipients exist, not who.
 */
export function openEnvelope(
  parsed: ParsedEnvelope,
  credential: Credential,
  password: string | undefined,
): Uint8Array {
  if ((parsed.password !== undefined) !== (password !== undefined)) {
    throw parsed.password !== undefined
      ? new UsageError('this paste requires a password')
      : new UsageError('this paste does not take a password');
  }

  let pwFactor: Uint8Array | undefined;
  if (parsed.password !== undefined && password !== undefined) {
    pwFactor = passwordFactor(password, parsed.password.salt, parsed.password.params, parsed.fileSalt);
  }

  try {
    for (const slot of parsed.slots) {
      let slotKey: Uint8Array;
      if (credential.kind === 'link') {
        if (slot.kind !== SlotKind.Link) continue;
        if (credential.linkKey.length !== LINK_KEY_LEN) throw new UsageError('malformed link key');
        slotKey = derive(credential.linkKey, 'cpb1/kek/link', parsed.fileSalt);
      } else {
        if (slot.kind !== SlotKind.XWing) continue;
        let sharedSecret: Uint8Array;
        try {
          sharedSecret = xwing.decapsulate(slot.data, credential.kemSecretKey);
        } catch {
          // ML-KEM's implicit rejection means a wrong key yields a *valid-looking*
          // shared secret rather than an error, so this path is for malformed input
          // only. Either way the wrap below is what actually decides.
          continue;
        }
        try {
          slotKey = derive(sharedSecret, 'cpb1/kek/xwing', parsed.fileSalt);
        } finally {
          wipe(sharedSecret);
        }
      }

      const kek = mixFactors(slotKey, pwFactor, parsed.fileSalt);
      try {
        const cek = aeadOpen(kek, slot.wrapNonce, slotAad(parsed.slotAadPrefix, slot.kind, slot.data), slot.wrappedCek);
        try {
          return aeadOpen(cek, parsed.nonce, parsed.bodyAad, parsed.ciphertext);
        } finally {
          wipe(cek);
        }
      } catch {
        // Wrong slot for this credential, or wrong password. Keep trying; a uniform
        // DecryptError is thrown once every slot is exhausted so the caller cannot
        // learn which slot, if any, was nearly right.
        continue;
      } finally {
        wipe(slotKey, kek);
      }
    }
    throw new DecryptError();
  } finally {
    if (pwFactor !== undefined) wipe(pwFactor);
  }
}
