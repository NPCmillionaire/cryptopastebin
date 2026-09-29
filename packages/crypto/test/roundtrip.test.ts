import { describe, expect, it } from 'vitest';
import {
  createPaste,
  decodePublicIdentity,
  decodeSecretIdentity,
  encodePublicIdentity,
  encodeSecretIdentity,
  envelopeRequiresPassword,
  fingerprint,
  generateIdentity,
  identityFromSeed,
  parseEnvelope,
  parsePasteUrl,
  buildPasteUrl,
  readPaste,
  DecryptError,
  UsageError,
  SlotKind,
  DEFAULT_PASTE_LIMITS,
} from '../src/index.js';
import { FAST_ARGON2 } from './vectors.js';

const BODY = 'const answer = 42;\n// hello from a paste\n';

describe('link mode', () => {
  it('round-trips through the fragment', async () => {
    const created = await createPaste({ body: BODY, lang: 'typescript', render: 'code' });
    expect(created.fragment).toBeDefined();
    const read = await readPaste(created.envelope, { kind: 'fragment', fragment: created.fragment! });
    expect(read.content.body).toBe(BODY);
    expect(read.content.lang).toBe('typescript');
    expect(read.content.render).toBe('code');
    expect(read.author).toBeUndefined();
    expect(read.passwordProtected).toBe(false);
  });

  it('rejects a different link key', async () => {
    const a = await createPaste({ body: BODY });
    const b = await createPaste({ body: BODY });
    await expect(readPaste(a.envelope, { kind: 'fragment', fragment: b.fragment! })).rejects.toThrow(DecryptError);
  });

  it('produces a different envelope every time for identical input', async () => {
    const a = await createPaste({ body: BODY });
    const b = await createPaste({ body: BODY });
    expect(Buffer.from(a.envelope).equals(Buffer.from(b.envelope))).toBe(false);
    expect(Buffer.from(a.linkKey!).equals(Buffer.from(b.linkKey!))).toBe(false);
  });

  it('accepts a fragment with a leading hash', async () => {
    const created = await createPaste({ body: BODY });
    const read = await readPaste(created.envelope, { kind: 'fragment', fragment: `#${created.fragment!}` });
    expect(read.content.body).toBe(BODY);
  });
});

describe('recipient mode (X-Wing hybrid KEM)', () => {
  it('addresses a paste to a public identity', async () => {
    const alice = generateIdentity();
    const created = await createPaste({ body: BODY, recipients: [alice] });
    const read = await readPaste(created.envelope, { kind: 'identity', identity: alice });
    expect(read.content.body).toBe(BODY);
  });

  it('creates one X-Wing slot per recipient, plus the link slot', async () => {
    const people = [generateIdentity(), generateIdentity(), generateIdentity()];
    const created = await createPaste({ body: BODY, recipients: people });
    const parsed = parseEnvelope(created.envelope, DEFAULT_PASTE_LIMITS.maxPlaintextLength);
    expect(parsed.slots).toHaveLength(4);
    expect(parsed.slots.filter((s) => s.kind === SlotKind.XWing)).toHaveLength(3);
    expect(parsed.slots.filter((s) => s.kind === SlotKind.Link)).toHaveLength(1);
    for (const person of people) {
      expect((await readPaste(created.envelope, { kind: 'identity', identity: person })).content.body).toBe(BODY);
    }
    expect((await readPaste(created.envelope, { kind: 'fragment', fragment: created.fragment! })).content.body).toBe(BODY);
  });

  it('refuses a non-recipient identity', async () => {
    const alice = generateIdentity();
    const eve = generateIdentity();
    const created = await createPaste({ body: BODY, recipients: [alice], linkAccess: false });
    await expect(readPaste(created.envelope, { kind: 'identity', identity: eve })).rejects.toThrow(DecryptError);
  });

  it('omits the link key entirely when linkAccess is false', async () => {
    const alice = generateIdentity();
    const created = await createPaste({ body: BODY, recipients: [alice], linkAccess: false });
    expect(created.linkKey).toBeUndefined();
    expect(created.fragment).toBeUndefined();
    const parsed = parseEnvelope(created.envelope, DEFAULT_PASTE_LIMITS.maxPlaintextLength);
    expect(parsed.slots).toHaveLength(1);
    expect(parsed.slots[0]!.kind).toBe(SlotKind.XWing);
  });

  it('needs either a link or a recipient', async () => {
    await expect(createPaste({ body: BODY, linkAccess: false })).rejects.toThrow(UsageError);
  });
});

describe('identities', () => {
  it('expands deterministically from a master seed', () => {
    const seed = new Uint8Array(32).fill(9);
    const a = identityFromSeed(seed);
    const b = identityFromSeed(seed);
    expect(Buffer.from(a.kemPublicKey).equals(Buffer.from(b.kemPublicKey))).toBe(true);
    expect(Buffer.from(a.signPublicKey).equals(Buffer.from(b.signPublicKey))).toBe(true);
    expect(fingerprint(a)).toBe(fingerprint(b));
  });

  it('round-trips public and secret encodings', () => {
    const id = generateIdentity();
    const pub = decodePublicIdentity(encodePublicIdentity(id));
    expect(Buffer.from(pub.kemPublicKey).equals(Buffer.from(id.kemPublicKey))).toBe(true);
    expect(fingerprint(pub)).toBe(fingerprint(id));

    const restored = decodeSecretIdentity(encodeSecretIdentity(id));
    expect(Buffer.from(restored.kemSecretKey).equals(Buffer.from(id.kemSecretKey))).toBe(true);
  });

  it('gives fingerprints that are short, grouped, and distinct', () => {
    const a = fingerprint(generateIdentity());
    const b = fingerprint(generateIdentity());
    expect(a).toMatch(/^[A-Z2-9]{5}-[A-Z2-9]{5}-[A-Z2-9]{5}-[A-Z2-9]{5}$/);
    expect(a).not.toBe(b);
  });

  it('covers both public keys, so a substituted signing key changes the fingerprint', () => {
    const a = generateIdentity();
    const b = generateIdentity();
    const spliced = { kemPublicKey: a.kemPublicKey, signPublicKey: b.signPublicKey };
    expect(fingerprint(spliced)).not.toBe(fingerprint(a));
  });

  it('rejects a truncated or mislabelled identity', () => {
    expect(() => decodePublicIdentity('nope_AAAA')).toThrow();
    expect(() => decodePublicIdentity('cpb1pub_AAAA')).toThrow();
    expect(() => decodeSecretIdentity('cpb1sec_AAAA')).toThrow();
  });
});

describe('password layer', () => {
  it('requires both the link and the password', async () => {
    const created = await createPaste({ body: BODY, password: 'correct horse battery staple', argon2Params: FAST_ARGON2 });
    expect(envelopeRequiresPassword(created.envelope)).toBe(true);

    const read = await readPaste(
      created.envelope,
      { kind: 'fragment', fragment: created.fragment! },
      { password: 'correct horse battery staple' },
    );
    expect(read.content.body).toBe(BODY);
    expect(read.passwordProtected).toBe(true);
  });

  it('rejects a wrong password even with the right link', async () => {
    const created = await createPaste({ body: BODY, password: 'right', argon2Params: FAST_ARGON2 });
    await expect(
      readPaste(created.envelope, { kind: 'fragment', fragment: created.fragment! }, { password: 'wrong' }),
    ).rejects.toThrow(DecryptError);
  });

  it('rejects the right password with a wrong link', async () => {
    const created = await createPaste({ body: BODY, password: 'pw', argon2Params: FAST_ARGON2 });
    const other = await createPaste({ body: BODY });
    await expect(
      readPaste(created.envelope, { kind: 'fragment', fragment: other.fragment! }, { password: 'pw' }),
    ).rejects.toThrow(DecryptError);
  });

  it('will not open a password-protected paste without a password', async () => {
    const created = await createPaste({ body: BODY, password: 'pw', argon2Params: FAST_ARGON2 });
    await expect(readPaste(created.envelope, { kind: 'fragment', fragment: created.fragment! })).rejects.toThrow(UsageError);
  });

  it('will not accept a password for a paste that has no password layer', async () => {
    const created = await createPaste({ body: BODY });
    await expect(
      readPaste(created.envelope, { kind: 'fragment', fragment: created.fragment! }, { password: 'pw' }),
    ).rejects.toThrow(UsageError);
  });

  it('normalises Unicode so the same password typed on different platforms works', async () => {
    const composed = 'café';          // é as one code point
    const decomposed = 'café';       // e + combining acute
    expect(composed).not.toBe(decomposed);
    const created = await createPaste({ body: BODY, password: composed, argon2Params: FAST_ARGON2 });
    const read = await readPaste(
      created.envelope,
      { kind: 'fragment', fragment: created.fragment! },
      { password: decomposed },
    );
    expect(read.content.body).toBe(BODY);
  });

  it('ANDs with recipient slots too', async () => {
    const alice = generateIdentity();
    const created = await createPaste({
      body: BODY,
      recipients: [alice],
      linkAccess: false,
      password: 'pw',
      argon2Params: FAST_ARGON2,
    });
    await expect(readPaste(created.envelope, { kind: 'identity', identity: alice }, { password: 'nope' })).rejects.toThrow(
      DecryptError,
    );
    const ok = await readPaste(created.envelope, { kind: 'identity', identity: alice }, { password: 'pw' });
    expect(ok.content.body).toBe(BODY);
  });
});

describe('signing', () => {
  it('reports verified authorship', async () => {
    const author = generateIdentity();
    const created = await createPaste({ body: BODY, signWith: author });
    const read = await readPaste(created.envelope, { kind: 'fragment', fragment: created.fragment! });
    expect(read.author?.verified).toBe(true);
    expect(Buffer.from(read.author!.signPublicKey).equals(Buffer.from(author.signPublicKey))).toBe(true);
  });

  it('keeps the author hidden from anyone who cannot decrypt', async () => {
    const author = generateIdentity();
    const created = await createPaste({ body: BODY, signWith: author });
    // The signing public key must not appear anywhere in the stored envelope.
    const hay = Buffer.from(created.envelope).toString('hex');
    const needle = Buffer.from(author.signPublicKey).toString('hex');
    expect(hay.includes(needle)).toBe(false);
  });
});

describe('attachments', () => {
  it('carries binary files alongside the text', async () => {
    const png = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 1, 2, 3, 4, 5]);
    const bin = new Uint8Array(4096);
    for (let i = 0; i < bin.length; i++) bin[i] = (i * 7) & 0xff;

    const created = await createPaste({
      body: BODY,
      attachments: [
        { name: 'shot.png', mime: 'image/png', bytes: png },
        { name: 'blob.bin', mime: 'application/octet-stream', bytes: bin },
      ],
    });
    const read = await readPaste(created.envelope, { kind: 'fragment', fragment: created.fragment! });
    expect(read.content.attachments).toHaveLength(2);
    expect(read.content.attachments[0]!.name).toBe('shot.png');
    expect(Buffer.from(read.content.attachments[0]!.bytes).equals(Buffer.from(png))).toBe(true);
    expect(Buffer.from(read.content.attachments[1]!.bytes).equals(Buffer.from(bin))).toBe(true);
  });

  it('handles an empty body and a zero-length attachment', async () => {
    const created = await createPaste({ body: '', attachments: [{ name: 'empty', mime: 'application/octet-stream', bytes: new Uint8Array(0) }] });
    const read = await readPaste(created.envelope, { kind: 'fragment', fragment: created.fragment! });
    expect(read.content.body).toBe('');
    expect(read.content.attachments[0]!.bytes.length).toBe(0);
  });

  it('refuses more attachments than the limit allows', async () => {
    const many = Array.from({ length: 17 }, (_, i) => ({ name: `f${i}`, mime: 'text/plain', bytes: new Uint8Array(1) }));
    await expect(createPaste({ body: '', attachments: many })).rejects.toThrow(UsageError);
  });

  it('refuses a paste over the size limit', async () => {
    const limits = { ...DEFAULT_PASTE_LIMITS, maxPlaintextLength: 1024 };
    await expect(createPaste({ body: 'x'.repeat(2048), limits })).rejects.toThrow(UsageError);
  });
});

describe('compression', () => {
  it('shrinks repetitive text and still round-trips', async () => {
    const repetitive = 'abcabcabc\n'.repeat(500);
    const on = await createPaste({ body: repetitive, compress: true });
    const off = await createPaste({ body: repetitive, compress: false });
    expect(on.envelope.length).toBeLessThan(off.envelope.length / 5);
    expect((await readPaste(on.envelope, { kind: 'fragment', fragment: on.fragment! })).content.body).toBe(repetitive);
    expect((await readPaste(off.envelope, { kind: 'fragment', fragment: off.fragment! })).content.body).toBe(repetitive);
  });

  it('defaults off when attachments are present', async () => {
    const withAttachment = await createPaste({
      body: BODY,
      attachments: [{ name: 'a', mime: 'application/octet-stream', bytes: new Uint8Array(32) }],
    });
    expect(parseEnvelope(withAttachment.envelope, DEFAULT_PASTE_LIMITS.maxPlaintextLength).compressed).toBe(false);
    const textOnly = await createPaste({ body: BODY });
    expect(parseEnvelope(textOnly.envelope, DEFAULT_PASTE_LIMITS.maxPlaintextLength).compressed).toBe(true);
  });

  it('preserves multi-byte UTF-8 exactly', async () => {
    const body = 'emoji 🔐🛰️ · κρυπτός · 日本語 · \u0000\u001f edge';
    const created = await createPaste({ body });
    expect((await readPaste(created.envelope, { kind: 'fragment', fragment: created.fragment! })).content.body).toBe(body);
  });
});

describe('URLs', () => {
  it('keeps the key in the fragment and the id in the path', async () => {
    const created = await createPaste({ body: BODY });
    const url = buildPasteUrl('https://paste.example/', 'abc123', created.fragment);
    expect(url).toBe(`https://paste.example/p/abc123#${created.fragment}`);
    expect(new URL(url).pathname).not.toContain(created.fragment!);
    expect(new URL(url).search).toBe('');

    const back = parsePasteUrl(url);
    expect(back.id).toBe('abc123');
    expect(back.fragment).toBe(created.fragment);
  });

  it('handles a link with no fragment', () => {
    const url = buildPasteUrl('https://paste.example', 'xyz', undefined);
    expect(url).toBe('https://paste.example/p/xyz');
    expect(parsePasteUrl(url).fragment).toBeUndefined();
  });

  it('rejects a URL that is not a paste link', () => {
    expect(() => parsePasteUrl('https://paste.example/about')).toThrow(UsageError);
  });
});
