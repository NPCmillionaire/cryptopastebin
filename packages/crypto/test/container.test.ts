/**
 * Container-layer tests.
 *
 * Everything here concerns data that is *authentic but not trustworthy*. Once the
 * AEAD verifies, the manifest really was written by whoever held the key — but
 * "the author wrote it" does not mean "it is safe to act on". A malicious author
 * can still aim a compression bomb, a lying part size, a prototype-polluting key,
 * or a bidi-disguised filename at whoever opens the link. These are the tests for
 * the layer that has to stay suspicious after decryption succeeds.
 */
import { describe, expect, it } from 'vitest';
import { compress } from '../src/compress.js';
import { openContainer, sanitiseFilename } from '../src/container.js';
import { sealEnvelope } from '../src/envelope.js';
import { createPaste, readPaste, randomLinkKey, b64uEncode, FormatError, DEFAULT_PASTE_LIMITS } from '../src/index.js';
import { concat, utf8, Writer } from '../src/bytes.js';

/**
 * Build a container by hand so a hostile manifest can be injected. The public API
 * cannot produce these, which is exactly why the parser has to be tested directly.
 */
async function craftContainer(manifest: unknown, parts: Uint8Array[], compressInner: boolean): Promise<Uint8Array> {
  const manifestBytes = utf8(JSON.stringify(manifest));
  const innerRaw = concat(new Writer().u32(manifestBytes.length).finish(), manifestBytes, ...parts);
  const inner = compressInner ? await compress(innerRaw) : innerRaw;
  return concat(new Writer().u8(1).u8(0).u32(inner.length).finish(), inner);
}

async function craftPaste(
  manifest: unknown,
  parts: Uint8Array[],
  compressInner = false,
): Promise<{ envelope: Uint8Array; fragment: string }> {
  const container = await craftContainer(manifest, parts, compressInner);
  const linkKey = randomLinkKey();
  const envelope = sealEnvelope({
    container,
    compressed: compressInner,
    recipients: [{ kind: 'link', linkKey }],
  });
  return { envelope, fragment: b64uEncode(linkKey) };
}

const goodManifest = (bodySize: number, attachments: { name: string; mime: string; size: number }[] = []) => ({
  v: 1,
  body: { size: bodySize, lang: null, render: 'plain' },
  attachments,
});

describe('filename sanitisation', () => {
  it('strips path traversal down to the final component', () => {
    expect(sanitiseFilename('../../etc/passwd')).toBe('passwd');
    expect(sanitiseFilename('..\\..\\Windows\\System32\\cmd.exe')).toBe('cmd.exe');
    expect(sanitiseFilename('/absolute/path/report.pdf')).toBe('report.pdf');
    expect(sanitiseFilename('a/b/c/')).toBe('attachment');
  });

  it('removes bidi overrides used to disguise an extension', () => {
    // U+202E makes this render as "harmlessexe.png" in most UIs.
    const disguised = 'harmless‮gnp.exe';
    const cleaned = sanitiseFilename(disguised);
    expect(cleaned).not.toContain('‮');
    expect(cleaned).toBe('harmlessgnp.exe');
  });

  it('removes control characters, newlines, and zero-width marks', () => {
    expect(sanitiseFilename('log\n\rINFO: ok.txt')).toBe('logINFO: ok.txt');
    expect(sanitiseFilename('in​voice﻿.pdf')).toBe('invoice.pdf');
    expect(sanitiseFilename('bell\u0007.txt')).toBe('bell.txt');
  });

  it('refuses to produce a hidden file or a bare dot name', () => {
    expect(sanitiseFilename('.bashrc')).toBe('bashrc');
    expect(sanitiseFilename('.')).toBe('attachment');
    expect(sanitiseFilename('..')).toBe('attachment');
    expect(sanitiseFilename('')).toBe('attachment');
    expect(sanitiseFilename('   ')).toBe('attachment');
  });

  it('caps the length while keeping a short extension', () => {
    const long = 'a'.repeat(400) + '.tar.gz';
    const cleaned = sanitiseFilename(long);
    expect(cleaned.length).toBeLessThanOrEqual(128);
    expect(cleaned.endsWith('.tar.gz')).toBe(true);
  });

  it('is applied on the way out, not just on the way in', async () => {
    const body = utf8('hi');
    const evil = new Uint8Array([1, 2, 3]);
    const { envelope, fragment } = await craftPaste(
      goodManifest(body.length, [{ name: '../../../evil‮gnp.exe', mime: 'application/octet-stream', size: evil.length }]),
      [body, evil],
    );
    const read = await readPaste(envelope, { kind: 'fragment', fragment });
    expect(read.content.attachments[0]!.name).toBe('evilgnp.exe');
  });
});

describe('manifest validation', () => {
  it('rejects a manifest whose declared sizes do not match the bytes present', async () => {
    const body = utf8('twelve chars');
    for (const claimed of [body.length - 1, body.length + 1, 0]) {
      if (claimed === body.length) continue;
      const { envelope, fragment } = await craftPaste(goodManifest(claimed), [body]);
      await expect(readPaste(envelope, { kind: 'fragment', fragment }), `claimed ${claimed}`).rejects.toThrow(FormatError);
    }
  });

  it('rejects a lying attachment size that would shift every later boundary', async () => {
    const body = utf8('x');
    const a = new Uint8Array(10).fill(1);
    const b = new Uint8Array(10).fill(2);
    const { envelope, fragment } = await craftPaste(
      goodManifest(body.length, [
        { name: 'a', mime: 'application/octet-stream', size: 4 },
        { name: 'b', mime: 'application/octet-stream', size: 10 },
      ]),
      [body, a, b],
    );
    await expect(readPaste(envelope, { kind: 'fragment', fragment })).rejects.toThrow(FormatError);
  });

  it('leaves a __proto__ key as inert data instead of polluting the prototype', async () => {
    const body = utf8('hi');
    const hostile = {
      v: 1,
      body: { size: body.length, lang: null, render: 'plain' },
      attachments: [],
      __proto__: { polluted: 'yes' },
      constructor: { prototype: { polluted: 'yes' } },
    };
    // JSON.parse never walks a prototype chain, and the parser reads fields
    // individually rather than spreading, so this must simply succeed and leave
    // Object.prototype untouched.
    const { envelope, fragment } = await craftPaste(JSON.parse(JSON.stringify(hostile)), [body]);
    const read = await readPaste(envelope, { kind: 'fragment', fragment });
    expect(read.content.body).toBe('hi');
    expect(({} as Record<string, unknown>)['polluted']).toBeUndefined();
    expect(Object.prototype.hasOwnProperty.call(Object.prototype, 'polluted')).toBe(false);
  });

  it('rejects a bad version, render mode, or field type', async () => {
    const body = utf8('hi');
    const bad: unknown[] = [
      { v: 2, body: { size: 2, lang: null, render: 'plain' }, attachments: [] },
      { v: 1, body: { size: 2, lang: null, render: 'javascript' }, attachments: [] },
      { v: 1, body: { size: '2', lang: null, render: 'plain' }, attachments: [] },
      { v: 1, body: { size: 2, lang: 42, render: 'plain' }, attachments: [] },
      { v: 1, body: { size: -1, lang: null, render: 'plain' }, attachments: [] },
      { v: 1, body: { size: 2, lang: null, render: 'plain' }, attachments: {} },
      { v: 1, attachments: [] },
      [1, 2, 3],
      'nope',
    ];
    for (const manifest of bad) {
      const { envelope, fragment } = await craftPaste(manifest, [body]);
      await expect(readPaste(envelope, { kind: 'fragment', fragment }), JSON.stringify(manifest)).rejects.toThrow(
        FormatError,
      );
    }
  });

  it('rejects a manifest that is not valid JSON or not valid UTF-8', async () => {
    const linkKey = randomLinkKey();
    const bogus = new Uint8Array([0xff, 0xfe, 0xfd, 0xfc]);
    const inner = concat(new Writer().u32(bogus.length).finish(), bogus);
    const container = concat(new Writer().u8(1).u8(0).u32(inner.length).finish(), inner);
    const envelope = sealEnvelope({ container, compressed: false, recipients: [{ kind: 'link', linkKey }] });
    await expect(readPaste(envelope, { kind: 'fragment', fragment: b64uEncode(linkKey) })).rejects.toThrow(FormatError);
  });

  it('rejects more attachments than the limit permits', async () => {
    const body = utf8('x');
    const many = Array.from({ length: 64 }, (_, i) => ({ name: `f${i}`, mime: 'text/plain', size: 1 }));
    const { envelope, fragment } = await craftPaste(goodManifest(body.length, many), [
      body,
      ...many.map(() => new Uint8Array(1)),
    ]);
    await expect(readPaste(envelope, { kind: 'fragment', fragment })).rejects.toThrow(FormatError);
  });
});

describe('decompression bombs', () => {
  it('aborts once the running output crosses the limit, not after collecting it', async () => {
    // 8 MiB of zeros deflates to a few KB. Opened under a 64 KiB ceiling it must
    // be refused, and refused cheaply.
    const zeros = new Uint8Array(8 * 1024 * 1024);
    const inner = concat(new Writer().u32(2).finish(), utf8('{}'), zeros);
    const compressed = await compress(inner);
    expect(compressed.length).toBeLessThan(64 * 1024);

    const container = concat(new Writer().u8(1).u8(0).u32(compressed.length).finish(), compressed);
    const started = Date.now();
    await expect(
      openContainer(container, {
        innerIsCompressed: true,
        limits: { maxInnerLength: 64 * 1024, maxManifestLength: 4096, maxAttachments: 4 },
      }),
    ).rejects.toThrow(FormatError);
    expect(Date.now() - started).toBeLessThan(5000);
  });

  it('rejects an inner length that exceeds the limit before allocating', async () => {
    const container = concat(new Writer().u8(1).u8(0).u32(0x7fff_ffff).finish());
    await expect(
      openContainer(container, {
        innerIsCompressed: false,
        limits: { maxInnerLength: 1024, maxManifestLength: 256, maxAttachments: 2 },
      }),
    ).rejects.toThrow(FormatError);
  });

  it('rejects a corrupt DEFLATE stream distinctly from a bomb', async () => {
    const garbage = new Uint8Array(64).fill(0xab);
    const container = concat(new Writer().u8(1).u8(0).u32(garbage.length).finish(), garbage);
    await expect(openContainer(container, { innerIsCompressed: true })).rejects.toThrow(FormatError);
  });
});

describe('container framing', () => {
  it('rejects an unknown container version or flag', async () => {
    for (const [ver, flags] of [
      [2, 0],
      [1, 0b1111_1110],
    ] as const) {
      const container = concat(new Writer().u8(ver).u8(flags).u32(0).finish());
      await expect(openContainer(container, { innerIsCompressed: false }), `v${ver} f${flags}`).rejects.toThrow(
        FormatError,
      );
    }
  });

  it('rejects trailing bytes after the container', async () => {
    const created = await createPaste({ body: 'hi', compress: false });
    const parsed = await readPaste(created.envelope, { kind: 'fragment', fragment: created.fragment! });
    expect(parsed.content.body).toBe('hi');

    const body = utf8('hi');
    const manifestBytes = utf8(JSON.stringify(goodManifest(body.length)));
    const inner = concat(new Writer().u32(manifestBytes.length).finish(), manifestBytes, body);
    const container = concat(new Writer().u8(1).u8(0).u32(inner.length).finish(), inner, new Uint8Array([0x00]));
    await expect(openContainer(container, { innerIsCompressed: false })).rejects.toThrow(FormatError);
  });

  it('accepts the documented limits object from the public API', async () => {
    const created = await createPaste({ body: 'hi' });
    const read = await readPaste(created.envelope, { kind: 'fragment', fragment: created.fragment! }, { limits: DEFAULT_PASTE_LIMITS });
    expect(read.content.body).toBe('hi');
  });
});
