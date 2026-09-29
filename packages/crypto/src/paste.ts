/**
 * The high-level API. Everything above this line is plumbing; this is what the
 * frontend calls.
 *
 * Two functions matter: {@link createPaste} turns text, attachments, and a
 * recipient list into an opaque blob plus a secret that never leaves the client,
 * and {@link readPaste} reverses it. The server sees only the blob.
 *
 * @module
 */
import {
  type Attachment,
  assertWithinSize,
  buildContainer,
  type ContainerLimits,
  DEFAULT_CONTAINER_LIMITS,
  openContainer,
  type PasteContent,
  type RenderMode,
  sanitiseFilename,
} from './container.js';
import {
  type Credential,
  LINK_KEY_LEN,
  openEnvelope,
  parseEnvelope,
  randomLinkKey,
  type Recipient,
  sealEnvelope,
} from './envelope.js';
import { TAG_LEN } from './aead.js';
import { b64uDecodeExact, b64uEncode } from './b64url.js';
import { type Identity, type PublicIdentity } from './identity.js';
import { type Argon2Params } from './password.js';
import { UsageError } from './errors.js';
import { wipe } from './bytes.js';

/** Policy limits. The API refuses to build or parse anything outside these. */
export interface PasteLimits extends ContainerLimits {
  /** Ceiling on body + attachments before compression. */
  readonly maxPlaintextLength: number;
}

export const DEFAULT_PASTE_LIMITS: PasteLimits = {
  ...DEFAULT_CONTAINER_LIMITS,
  maxPlaintextLength: 24 * 1024 * 1024,
};

/** Input to {@link createPaste}. */
export interface CreatePasteOptions {
  readonly body: string;
  readonly lang?: string | null;
  readonly render?: RenderMode;
  readonly attachments?: readonly Attachment[];
  /**
   * Recipients addressed by public key. Each gets its own X-Wing slot.
   *
   * Independent of the link: a paste with recipients is still openable by link
   * unless {@link CreatePasteOptions.linkAccess} is set to false.
   */
  readonly recipients?: readonly PublicIdentity[];
  /**
   * Whether the returned link key can open the paste. Defaults to true.
   *
   * Set false for a paste addressed only to specific public keys — then there is
   * no secret in the URL at all, and forwarding the link to the wrong person
   * leaks nothing.
   */
  readonly linkAccess?: boolean;
  /** An extra factor ANDed with whichever slot is used. */
  readonly password?: string | undefined;
  readonly argon2Params?: Argon2Params | undefined;
  /** Sign the paste with this identity so readers learn who wrote it. */
  readonly signWith?: Identity | undefined;
  /**
   * Compress before encrypting. Defaults to true for text-only pastes and false
   * when attachments are present. See the caveat in {@link ./compress.js}.
   */
  readonly compress?: boolean;
  readonly limits?: PasteLimits;
}

/** Output of {@link createPaste}. */
export interface CreatedPaste {
  /** The bytes to upload. Opaque to the server. */
  readonly envelope: Uint8Array;
  /**
   * The link key, or undefined when `linkAccess` was false.
   *
   * This belongs in a URL fragment and nowhere else. A fragment is never sent in
   * an HTTP request, never reaches an access log, and is not included in a
   * `Referer` header — which is the entire reason the scheme works.
   */
  readonly linkKey: Uint8Array | undefined;
  /** {@link CreatedPaste.linkKey} as base64url, ready to place after `#`. */
  readonly fragment: string | undefined;
}

/** Encrypt a paste. Nothing here touches the network. */
export async function createPaste(options: CreatePasteOptions): Promise<CreatedPaste> {
  const limits = options.limits ?? DEFAULT_PASTE_LIMITS;
  const attachments = (options.attachments ?? []).map((a) => ({
    name: sanitiseFilename(a.name),
    mime: a.mime,
    bytes: a.bytes,
  }));
  if (attachments.length > limits.maxAttachments) {
    throw new UsageError(`at most ${limits.maxAttachments} attachments, got ${attachments.length}`);
  }

  let total = new TextEncoder().encode(options.body).length;
  for (const a of attachments) total += a.bytes.length;
  assertWithinSize(total, limits.maxPlaintextLength);

  const linkAccess = options.linkAccess ?? true;
  const recipients: Recipient[] = [];
  let linkKey: Uint8Array | undefined;
  if (linkAccess) {
    linkKey = randomLinkKey();
    recipients.push({ kind: 'link', linkKey });
  }
  for (const r of options.recipients ?? []) {
    recipients.push({ kind: 'xwing', kemPublicKey: r.kemPublicKey });
  }
  if (recipients.length === 0) {
    throw new UsageError('a paste needs either link access or at least one recipient');
  }

  const compressInner = options.compress ?? attachments.length === 0;
  const container = await buildContainer({
    body: options.body,
    lang: options.lang ?? null,
    render: options.render ?? 'plain',
    attachments,
    compressInner,
    signer:
      options.signWith !== undefined
        ? { signPublicKey: options.signWith.signPublicKey, signSecretKey: options.signWith.signSecretKey }
        : undefined,
  });

  try {
    const envelope = sealEnvelope({
      container,
      compressed: compressInner,
      recipients,
      password:
        options.password !== undefined
          ? { password: options.password, params: options.argon2Params }
          : undefined,
    });
    return {
      envelope,
      linkKey,
      fragment: linkKey !== undefined ? b64uEncode(linkKey) : undefined,
    };
  } finally {
    wipe(container);
  }
}

/** How a reader authenticates to {@link readPaste}. */
export type PasteKey =
  /** The base64url fragment from the URL. */
  | { readonly kind: 'fragment'; readonly fragment: string }
  /** Raw link key bytes. */
  | { readonly kind: 'linkKey'; readonly linkKey: Uint8Array }
  /** A recipient identity, for a paste addressed to its public key. */
  | { readonly kind: 'identity'; readonly identity: Identity };

/** Output of {@link readPaste}. */
export interface ReadPasteResult {
  readonly content: PasteContent;
  /** Present only when the paste carried a signature that verified. */
  readonly author: { readonly signPublicKey: Uint8Array; readonly verified: true } | undefined;
  /** True when a password was required to open it. */
  readonly passwordProtected: boolean;
}

/** Whether an envelope needs a password, readable without any key. */
export function envelopeRequiresPassword(envelope: Uint8Array, limits: PasteLimits = DEFAULT_PASTE_LIMITS): boolean {
  return parseEnvelope(envelope, limits.maxPlaintextLength + TAG_LEN + 1024).password !== undefined;
}

/** Decrypt a paste. */
export async function readPaste(
  envelope: Uint8Array,
  key: PasteKey,
  options: { readonly password?: string | undefined; readonly limits?: PasteLimits } = {},
): Promise<ReadPasteResult> {
  const limits = options.limits ?? DEFAULT_PASTE_LIMITS;
  const parsed = parseEnvelope(envelope, limits.maxPlaintextLength + TAG_LEN + 1024);

  let credential: Credential;
  let ownedKey: Uint8Array | undefined;
  switch (key.kind) {
    case 'fragment': {
      ownedKey = b64uDecodeExact(key.fragment.trim().replace(/^#/, ''), LINK_KEY_LEN);
      credential = { kind: 'link', linkKey: ownedKey };
      break;
    }
    case 'linkKey':
      credential = { kind: 'link', linkKey: key.linkKey };
      break;
    case 'identity':
      credential = { kind: 'xwing', kemSecretKey: key.identity.kemSecretKey };
      break;
  }

  try {
    const container = openEnvelope(parsed, credential, options.password);
    try {
      const opened = await openContainer(container, {
        innerIsCompressed: parsed.compressed,
        limits,
      });
      return {
        content: opened.content,
        author: opened.author,
        passwordProtected: parsed.password !== undefined,
      };
    } finally {
      wipe(container);
    }
  } finally {
    if (ownedKey !== undefined) wipe(ownedKey);
  }
}

/**
 * Assemble the URL a user shares.
 *
 * The id goes in the path and the key goes in the fragment, and that split is
 * the load-bearing part of the whole design. A fragment is resolved entirely by
 * the browser: it is not placed in the request line, so it cannot appear in the
 * server's access log, a reverse proxy's log, a CDN cache key, or a `Referer`
 * header sent to a third-party resource. The server can therefore serve the
 * ciphertext without ever being in a position to decrypt it, which is what makes
 * "the operator cannot read your pastes" a structural property rather than a
 * promise.
 */
export function buildPasteUrl(baseUrl: string, id: string, fragment: string | undefined): string {
  const base = baseUrl.replace(/\/+$/, '');
  const url = `${base}/p/${encodeURIComponent(id)}`;
  return fragment !== undefined ? `${url}#${fragment}` : url;
}

/** Split a paste URL back into its id and fragment. */
export function parsePasteUrl(url: string): { readonly id: string; readonly fragment: string | undefined } {
  const parsed = new URL(url);
  const match = /\/p\/([^/#?]+)\/?$/.exec(parsed.pathname);
  if (match === null) throw new UsageError('not a paste URL');
  const fragment = parsed.hash.startsWith('#') ? parsed.hash.slice(1) : '';
  return { id: decodeURIComponent(match[1] as string), fragment: fragment.length > 0 ? fragment : undefined };
}
