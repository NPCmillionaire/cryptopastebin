/**
 * The plaintext container: what actually sits inside the AEAD.
 *
 * Layout (all integers big-endian):
 *
 * ```text
 * container:
 *   u8    version = 1
 *   u8    flags          bit0 = signed
 *   u32   innerLen
 *   bytes inner          (DEFLATE-compressed iff the envelope header says so)
 *   if signed:
 *     u16 + bytes        ML-DSA-65 public key
 *     u16 + bytes        ML-DSA-65 signature over the signing transcript
 *
 * inner (after any decompression):
 *   u32   manifestLen
 *   bytes manifest       (UTF-8 JSON)
 *   bytes body           manifest.body.size bytes
 *   bytes attachment[i]  manifest.attachments[i].size bytes, in order
 * ```
 *
 * ## Why the signature lives in here
 *
 * Signing the *ciphertext* from outside would be simpler, and it is what several
 * tools do. It also publishes the author's identity to anyone who fetches the
 * envelope, including the server — the one party this design is built to keep
 * ignorant. Placing the signature inside the encrypted container means only
 * someone who can already decrypt learns who wrote it. Authorship becomes a fact
 * about the plaintext rather than a label on the outside of the box.
 *
 * The signature covers the exact `inner` bytes as stored, prefixed with a domain
 * separator and the framing fields, so there is no canonical-JSON problem: the
 * verifier hashes the same bytes it read off the wire instead of trying to
 * reconstruct a byte-identical re-serialisation of a parsed object. Every
 * signature scheme that has ever been broken by a canonicalisation bug got there
 * by doing the opposite.
 *
 * @module
 */
import { sha3_256 } from '@noble/hashes/sha3.js';
import { ml_dsa65, MLDSA65_PUBLIC_KEY_LEN, MLDSA65_SIGNATURE_LEN } from './identity.js';
import { compress, decompress } from './compress.js';
import { concat, fromUtf8, Reader, utf8, Writer } from './bytes.js';
import { FormatError, UsageError } from './errors.js';

/** Container format version. */
export const CONTAINER_VERSION = 1;

const FLAG_SIGNED = 0b0000_0001;

const SIGN_DOMAIN = utf8('cpb1/container-signature/v1\0');

/** How the viewer should present the body. */
export type RenderMode = 'code' | 'markdown' | 'plain';

const RENDER_MODES: readonly RenderMode[] = ['code', 'markdown', 'plain'];

/** Narrowing predicate so a parsed string reaches {@link RenderMode} only after a real check. */
function isRenderMode(value: string): value is RenderMode {
  return (RENDER_MODES as readonly string[]).includes(value);
}

/** One encrypted attachment. */
export interface Attachment {
  /** Sanitised display name. See {@link sanitiseFilename}. */
  readonly name: string;
  /** Claimed MIME type. Advisory only — never trusted by the viewer. */
  readonly mime: string;
  readonly bytes: Uint8Array;
}

/** The decrypted contents of a paste. */
export interface PasteContent {
  /** The paste text. */
  readonly body: string;
  /** Language hint for syntax highlighting, or null. */
  readonly lang: string | null;
  readonly render: RenderMode;
  readonly attachments: readonly Attachment[];
}

/** Verified authorship, present only when the paste was signed and verifies. */
export interface Authorship {
  readonly signPublicKey: Uint8Array;
  readonly verified: true;
}

/** Result of opening a container. */
export interface OpenedContainer {
  readonly content: PasteContent;
  /**
   * Present only when a signature was found *and* verified. A present-but-invalid
   * signature is a hard error rather than a soft "unverified" flag: silently
   * downgrading a broken signature to "no signature" is how a forged-authorship
   * UI happens.
   */
  readonly author: Authorship | undefined;
}

/** Limits applied while parsing. Attacker-influenced sizes are checked against these. */
export interface ContainerLimits {
  /** Ceiling on the decompressed `inner` region. */
  readonly maxInnerLength: number;
  /** Ceiling on the manifest JSON. */
  readonly maxManifestLength: number;
  /** Ceiling on the number of attachments. */
  readonly maxAttachments: number;
}

export const DEFAULT_CONTAINER_LIMITS: ContainerLimits = {
  maxInnerLength: 32 * 1024 * 1024,
  maxManifestLength: 64 * 1024,
  maxAttachments: 16,
};

interface ManifestJson {
  v: number;
  body: { size: number; lang: string | null; render: RenderMode };
  attachments: { name: string; mime: string; size: number }[];
}

/**
 * Reduce a filename to something safe to show and to hand to a download.
 *
 * Attachment names arrive inside the ciphertext, so they are authentic — they
 * really are what the author wrote — but authentic is not the same as safe. Three
 * separate problems get handled here:
 *
 * - **Path traversal.** `../../.ssh/authorized_keys` matters the moment anyone
 *   saves a batch of attachments with a script instead of a browser.
 * - **Bidirectional overrides.** A U+202E RIGHT-TO-LEFT OVERRIDE turns
 *   `harmlessU+202Egnp.exe` into something that renders as `harmlessexe.png`.
 *   This is the standard disguise for an executable and it defeats eyeballs
 *   completely, so the control characters are stripped rather than escaped.
 * - **Control characters and newlines**, which can rewrite terminal output or
 *   forge extra lines in a log.
 */
const MAX_FILENAME_LEN = 128;

/**
 * The extension to preserve when truncating an over-long name.
 *
 * Takes up to two trailing dot-segments so that `.tar.gz` and `.tar.bz2` survive
 * intact — truncating those to `.gz` changes what the file appears to be, which
 * is the one thing a filename has to get right.
 */
function trailingExtension(name: string): string {
  const match = /(\.[A-Za-z0-9]{1,8}){1,2}$/.exec(name);
  return match !== null && match[0].length <= 16 ? match[0] : '';
}

export function sanitiseFilename(raw: string): string {
  let name = raw.normalize('NFC');
  // Strip C0/C1 controls, Unicode bidi overrides and isolates, and zero-width marks.
  name = name.replace(/[\u0000-\u001f\u007f-\u009f​-‏‪-‮⁦-⁩﻿]/g, '');
  // Collapse any path structure to its last component.
  name = name.replace(/[\\/]+/g, '/');
  const lastSlash = name.lastIndexOf('/');
  if (lastSlash >= 0) name = name.slice(lastSlash + 1);
  // Leading dots would hide the file; a bare '.' or '..' is not a name at all.
  name = name.replace(/^\.+/, '');
  name = name.trim();
  if (name.length > MAX_FILENAME_LEN) {
    const ext = trailingExtension(name);
    name = name.slice(0, MAX_FILENAME_LEN - ext.length) + ext;
  }
  return name.length > 0 ? name : 'attachment';
}

function buildManifest(content: {
  bodyBytes: Uint8Array;
  lang: string | null;
  render: RenderMode;
  attachments: readonly Attachment[];
}): Uint8Array {
  const manifest: ManifestJson = {
    v: CONTAINER_VERSION,
    body: { size: content.bodyBytes.length, lang: content.lang, render: content.render },
    attachments: content.attachments.map((a) => ({
      name: sanitiseFilename(a.name),
      mime: a.mime,
      size: a.bytes.length,
    })),
  };
  return utf8(JSON.stringify(manifest));
}

function parseManifest(bytes: Uint8Array, limits: ContainerLimits): ManifestJson {
  let parsed: unknown;
  try {
    parsed = JSON.parse(fromUtf8(bytes));
  } catch {
    throw new FormatError('manifest is not valid JSON');
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new FormatError('manifest must be a JSON object');
  }
  // Fields are read individually and re-assigned into a fresh literal. Nothing is
  // spread or Object.assign'd from the parsed value, so a "__proto__" or
  // "constructor" key in the JSON stays inert data and never reaches a prototype.
  const src = parsed as Record<string, unknown>;

  if (src['v'] !== CONTAINER_VERSION) throw new FormatError(`unsupported manifest version: ${String(src['v'])}`);

  const body = src['body'];
  if (typeof body !== 'object' || body === null || Array.isArray(body)) throw new FormatError('manifest.body missing');
  const b = body as Record<string, unknown>;
  const bodySize = b['size'];
  if (typeof bodySize !== 'number' || !Number.isInteger(bodySize) || bodySize < 0 || bodySize > limits.maxInnerLength) {
    throw new FormatError('manifest.body.size out of range');
  }
  const lang = b['lang'];
  if (lang !== null && (typeof lang !== 'string' || lang.length > 64)) throw new FormatError('manifest.body.lang invalid');
  const render = b['render'];
  if (typeof render !== 'string' || !isRenderMode(render)) {
    throw new FormatError('manifest.body.render invalid');
  }

  const rawAttachments = src['attachments'];
  if (!Array.isArray(rawAttachments)) throw new FormatError('manifest.attachments must be an array');
  if (rawAttachments.length > limits.maxAttachments) {
    throw new FormatError(`too many attachments: ${rawAttachments.length} > ${limits.maxAttachments}`);
  }
  const attachments = rawAttachments.map((entry, i) => {
    if (typeof entry !== 'object' || entry === null || Array.isArray(entry)) {
      throw new FormatError(`manifest.attachments[${i}] must be an object`);
    }
    const e = entry as Record<string, unknown>;
    const name = e['name'];
    const mime = e['mime'];
    const size = e['size'];
    if (typeof name !== 'string' || name.length > 512) throw new FormatError(`attachments[${i}].name invalid`);
    if (typeof mime !== 'string' || mime.length > 255) throw new FormatError(`attachments[${i}].mime invalid`);
    if (typeof size !== 'number' || !Number.isInteger(size) || size < 0 || size > limits.maxInnerLength) {
      throw new FormatError(`attachments[${i}].size out of range`);
    }
    return { name, mime, size };
  });

  return { v: CONTAINER_VERSION, body: { size: bodySize, lang, render }, attachments };
}

/** Options for {@link buildContainer}. */
export interface BuildContainerOptions {
  readonly body: string;
  readonly lang?: string | null;
  readonly render?: RenderMode;
  readonly attachments?: readonly Attachment[];
  /** Compress the inner region. The caller records this in the envelope header. */
  readonly compressInner: boolean;
  /** ML-DSA-65 keys to sign with, or undefined to leave the paste unsigned. */
  readonly signer?: { readonly signPublicKey: Uint8Array; readonly signSecretKey: Uint8Array } | undefined;
}

/** Serialise, optionally compress, and optionally sign a container. */
export async function buildContainer(options: BuildContainerOptions): Promise<Uint8Array> {
  const bodyBytes = utf8(options.body);
  const attachments = options.attachments ?? [];
  const manifest = buildManifest({
    bodyBytes,
    lang: options.lang ?? null,
    render: options.render ?? 'plain',
    attachments,
  });

  const innerRaw = concat(
    new Writer().u32(manifest.length).finish(),
    manifest,
    bodyBytes,
    ...attachments.map((a) => a.bytes),
  );
  const inner = options.compressInner ? await compress(innerRaw) : innerRaw;

  const signed = options.signer !== undefined;
  const framing = new Writer().u8(CONTAINER_VERSION).u8(signed ? FLAG_SIGNED : 0).u32(inner.length).finish();

  const out = new Writer().bytes(framing).bytes(inner);
  if (options.signer !== undefined) {
    const transcript = sha3_256(concat(SIGN_DOMAIN, framing, inner));
    const signature = ml_dsa65.sign(transcript, options.signer.signSecretKey);
    out.lp16(options.signer.signPublicKey).lp16(signature);
  }
  return out.finish();
}

/** Parse, verify, decompress, and split a container. */
export async function openContainer(
  container: Uint8Array,
  opts: { readonly innerIsCompressed: boolean; readonly limits?: ContainerLimits },
): Promise<OpenedContainer> {
  const limits = opts.limits ?? DEFAULT_CONTAINER_LIMITS;
  const reader = new Reader(container);

  const version = reader.u8();
  if (version !== CONTAINER_VERSION) throw new FormatError(`unsupported container version: ${version}`);
  const flags = reader.u8();
  if ((flags & ~FLAG_SIGNED) !== 0) throw new FormatError(`unknown container flags: 0x${flags.toString(16)}`);
  const innerLen = reader.u32();
  if (innerLen > limits.maxInnerLength) {
    throw new FormatError(`inner region of ${innerLen} bytes exceeds limit of ${limits.maxInnerLength}`);
  }
  const framing = reader.consumed();
  const inner = reader.bytes(innerLen);

  let author: Authorship | undefined;
  if ((flags & FLAG_SIGNED) !== 0) {
    const signPublicKey = reader.lp16();
    const signature = reader.lp16();
    if (signPublicKey.length !== MLDSA65_PUBLIC_KEY_LEN) throw new FormatError('bad ML-DSA-65 public key length');
    if (signature.length !== MLDSA65_SIGNATURE_LEN) throw new FormatError('bad ML-DSA-65 signature length');
    const transcript = sha3_256(concat(SIGN_DOMAIN, framing, inner));
    let ok = false;
    try {
      ok = ml_dsa65.verify(signature, transcript, signPublicKey);
    } catch {
      ok = false;
    }
    // A present signature that does not verify is fatal. Reporting the paste as
    // merely "unsigned" would let an attacker who can modify the container strip
    // authorship without the reader noticing anything changed.
    if (!ok) throw new FormatError('signature verification failed');
    author = { signPublicKey, verified: true };
  }
  reader.end();

  const innerRaw = opts.innerIsCompressed ? await decompress(inner, limits.maxInnerLength) : inner;

  const innerReader = new Reader(innerRaw);
  const manifestLen = innerReader.u32();
  if (manifestLen > limits.maxManifestLength) {
    throw new FormatError(`manifest of ${manifestLen} bytes exceeds limit of ${limits.maxManifestLength}`);
  }
  const manifest = parseManifest(innerReader.bytes(manifestLen), limits);

  // Sizes are cross-checked against the actual remaining bytes before any read,
  // so a manifest that lies about a part's size fails here rather than silently
  // shifting every subsequent part's boundary.
  let declared = manifest.body.size;
  for (const a of manifest.attachments) declared += a.size;
  if (declared !== innerReader.remaining) {
    throw new FormatError(`manifest declares ${declared} byte(s) of parts, container holds ${innerReader.remaining}`);
  }

  const body = fromUtf8(innerReader.bytes(manifest.body.size));
  const attachments: Attachment[] = manifest.attachments.map((a) => ({
    name: sanitiseFilename(a.name),
    mime: a.mime,
    bytes: innerReader.bytes(a.size),
  }));
  innerReader.end();

  return {
    content: { body, lang: manifest.body.lang, render: manifest.body.render, attachments },
    author,
  };
}

/** Guard used by the public API to keep total plaintext under a policy limit. */
export function assertWithinSize(totalBytes: number, maxBytes: number): void {
  if (totalBytes > maxBytes) {
    throw new UsageError(`paste is ${totalBytes} bytes, over the ${maxBytes}-byte limit`);
  }
}
