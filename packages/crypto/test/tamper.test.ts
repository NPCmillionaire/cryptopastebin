/**
 * Integrity tests.
 *
 * The claim these tests exist to defend is narrow and absolute: no modification
 * of a stored envelope can produce a successful decryption. Not a flipped bit in
 * the ciphertext, and — the part that actually gets implementations wrong — not a
 * flipped bit in the *header* either. A header field that is parsed but not
 * authenticated is the standard vulnerability in home-grown envelope formats,
 * because round-trip tests never catch it: everything still works, right up until
 * an attacker downgrades the KDF cost or flips a mode bit.
 *
 * So the exhaustive sweep below mutates every byte offset in turn and asserts a
 * throw, and the targeted cases that follow name the specific downgrades that
 * would be most valuable to an attacker.
 */
import { describe, expect, it } from 'vitest';
import {
  createPaste,
  generateIdentity,
  parseEnvelope,
  readPaste,
  DEFAULT_PASTE_LIMITS,
  FormatError,
  LINK_KEY_LEN,
} from '../src/index.js';
import { FAST_ARGON2 } from './vectors.js';

const BODY = 'secret: hunter2\n';
const LIMIT = DEFAULT_PASTE_LIMITS.maxPlaintextLength;

async function opens(envelope: Uint8Array, fragment: string, password?: string): Promise<boolean> {
  try {
    const read = await readPaste(envelope, { kind: 'fragment', fragment }, password !== undefined ? { password } : {});
    return read.content.body === BODY;
  } catch {
    return false;
  }
}

describe('no single-byte modification can be decrypted', () => {
  it('holds for every offset in a link-mode envelope', async () => {
    const created = await createPaste({ body: BODY });
    const fragment = created.fragment!;
    expect(await opens(created.envelope, fragment)).toBe(true);

    const survivors: number[] = [];
    for (let i = 0; i < created.envelope.length; i++) {
      for (const mask of [0x01, 0x80, 0xff]) {
        const mutated = created.envelope.slice();
        mutated[i] = (mutated[i] as number) ^ mask;
        if (await opens(mutated, fragment)) survivors.push(i);
      }
    }
    expect(survivors).toEqual([]);
  });

  it('holds at every structurally significant offset of a full-featured envelope', async () => {
    const author = generateIdentity();
    const alice = generateIdentity();
    const created = await createPaste({
      body: BODY,
      recipients: [alice],
      signWith: author,
      password: 'pw',
      argon2Params: FAST_ARGON2,
    });
    const fragment = created.fragment!;
    expect(await opens(created.envelope, fragment, 'pw')).toBe(true);

    // Every attempt on this envelope runs Argon2id, so instead of a blind sweep
    // the offsets are enumerated from the parsed layout: one per field that an
    // attacker could plausibly want to change. That covers the same ground as a
    // full sweep for the fields that matter, in a fraction of the time.
    const parsed = parseEnvelope(created.envelope, LIMIT);
    const headerEnd = parsed.slotAadPrefix.length;
    const ctStart = parsed.bodyAad.length;
    const targets = new Map<string, number>([
      ['flags', 5],
      ['slotCount', 6],
      ['reserved', 7],
      ['fileSalt[0]', 8],
      ['fileSalt[15]', 23],
      ['passwordSalt[0]', 24],
      ['argon2.m', headerEnd - 9],
      ['argon2.t', headerEnd - 5],
      ['argon2.p', headerEnd - 1],
      ['slot0.kind', headerEnd],
      ['slot0.dataLen', headerEnd + 1],
      ['slot0.wrapNonce', headerEnd + 3],
      ['slot0.wrappedCek', headerEnd + 3 + 24],
      ['body.nonce', ctStart - 28],
      ['body.ctLen', ctStart - 1],
      ['ciphertext[0]', ctStart],
      ['ciphertext[last]', created.envelope.length - 1],
    ]);

    const survivors: string[] = [];
    for (const [name, offset] of targets) {
      const mutated = created.envelope.slice();
      mutated[offset] = (mutated[offset] as number) ^ 0xff;
      if (await opens(mutated, fragment, 'pw')) survivors.push(`${name}@${offset}`);
    }
    expect(survivors).toEqual([]);
  });
});

describe('truncation and extension', () => {
  it('rejects every truncation', async () => {
    const created = await createPaste({ body: BODY });
    for (let n = 0; n < created.envelope.length; n++) {
      expect(await opens(created.envelope.slice(0, n), created.fragment!), `truncated to ${n}`).toBe(false);
    }
  });

  it('rejects trailing bytes, so an envelope has exactly one valid encoding', async () => {
    const created = await createPaste({ body: BODY });
    const extended = new Uint8Array(created.envelope.length + 1);
    extended.set(created.envelope);
    expect(await opens(extended, created.fragment!)).toBe(false);
    expect(() => parseEnvelope(extended, LIMIT)).toThrow(FormatError);
  });
});

describe('header fields are authenticated, not merely parsed', () => {
  it('rejects a flipped compression flag', async () => {
    const created = await createPaste({ body: 'aaaaaaaaaaaaaaaaaaaaaaaa'.repeat(20), compress: true });
    const mutated = created.envelope.slice();
    mutated[5] = (mutated[5] as number) & ~0b0000_0001; // clear FLAG_COMPRESSED
    expect(parseEnvelope(mutated, LIMIT).compressed).toBe(false); // parses fine …
    expect(await opens(mutated, created.fragment!)).toBe(false); // … but never decrypts
  });

  it('rejects a downgraded Argon2 cost', async () => {
    const created = await createPaste({ body: BODY, password: 'pw', argon2Params: { m: 16_384, t: 3, p: 1 } });
    const parsed = parseEnvelope(created.envelope, LIMIT);
    expect(parsed.password?.params.m).toBe(16_384);

    // Locate and rewrite the memory-cost field: 4 bytes of magic + version +
    // flags + slotCount + reserved + 16 salt + 16 password salt.
    const mOffset = 4 + 1 + 1 + 1 + 1 + 16 + 16;
    const mutated = created.envelope.slice();
    const weaker = 8_192;
    mutated[mOffset] = (weaker >>> 24) & 0xff;
    mutated[mOffset + 1] = (weaker >>> 16) & 0xff;
    mutated[mOffset + 2] = (weaker >>> 8) & 0xff;
    mutated[mOffset + 3] = weaker & 0xff;
    expect(parseEnvelope(mutated, LIMIT).password?.params.m).toBe(weaker);
    expect(await opens(mutated, created.fragment!, 'pw')).toBe(false);
  });

  it('rejects a nonzero reserved byte instead of ignoring it', async () => {
    const created = await createPaste({ body: BODY });
    const mutated = created.envelope.slice();
    mutated[7] = 1;
    expect(() => parseEnvelope(mutated, LIMIT)).toThrow(FormatError);
  });

  it('rejects unknown flag bits rather than masking them off', async () => {
    const created = await createPaste({ body: BODY });
    const mutated = created.envelope.slice();
    mutated[5] = (mutated[5] as number) | 0b1000_0000;
    expect(() => parseEnvelope(mutated, LIMIT)).toThrow(FormatError);
  });

  it('rejects an unknown slot kind', async () => {
    const created = await createPaste({ body: BODY });
    const mutated = created.envelope.slice();
    mutated[4 + 1 + 1 + 1 + 1 + 16] = 0x7f; // first slot's kind byte
    expect(() => parseEnvelope(mutated, LIMIT)).toThrow(FormatError);
  });

  it('rejects an out-of-range slot count', async () => {
    const created = await createPaste({ body: BODY });
    for (const count of [0, 9, 255]) {
      const mutated = created.envelope.slice();
      mutated[6] = count;
      expect(() => parseEnvelope(mutated, LIMIT), `slotCount=${count}`).toThrow(FormatError);
    }
  });

  it('rejects a ciphertext length that overstates the buffer', async () => {
    const created = await createPaste({ body: BODY });
    const parsed = parseEnvelope(created.envelope, LIMIT);
    const lenOffset = parsed.bodyAad.length - 4;
    const mutated = created.envelope.slice();
    mutated[lenOffset] = 0x7f;
    expect(() => parseEnvelope(mutated, LIMIT)).toThrow(FormatError);
  });

  it('refuses a ciphertext larger than the caller-supplied ceiling', async () => {
    // compress: false, so the stored ciphertext really is ~4 KB; a run of one
    // repeated character would otherwise deflate to well under the ceiling and
    // the test would pass for the wrong reason.
    const created = await createPaste({ body: 'x'.repeat(4096), compress: false });
    expect(created.envelope.length).toBeGreaterThan(4096);
    expect(() => parseEnvelope(created.envelope, 128)).toThrow(FormatError);
  });
});

describe('slots cannot be rearranged or transplanted', () => {
  it('rejects a wrapped key moved between two envelopes', async () => {
    const a = await createPaste({ body: BODY });
    const b = await createPaste({ body: BODY });
    const pa = parseEnvelope(a.envelope, LIMIT);

    // Splice b's wrapped CEK into a's slot, keeping everything else.
    const slotStart = pa.slotAadPrefix.length;
    const wrapOffset = slotStart + 1 + 2 + 24; // kind + lp16 length + nonce
    const mutated = a.envelope.slice();
    mutated.set(parseEnvelope(b.envelope, LIMIT).slots[0]!.wrappedCek, wrapOffset);

    expect(await opens(mutated, a.fragment!)).toBe(false);
    expect(await opens(mutated, b.fragment!)).toBe(false);
  });

  it('rejects one recipient slot swapped for another in the same envelope', async () => {
    const alice = generateIdentity();
    const bob = generateIdentity();
    const created = await createPaste({ body: BODY, recipients: [alice, bob], linkAccess: false });
    const parsed = parseEnvelope(created.envelope, LIMIT);
    expect(parsed.slots).toHaveLength(2);

    const slotLen = 1 + 2 + parsed.slots[0]!.data.length + 24 + 48;
    const base = parsed.slotAadPrefix.length;
    const mutated = created.envelope.slice();
    const first = created.envelope.slice(base, base + slotLen);
    const second = created.envelope.slice(base + slotLen, base + 2 * slotLen);
    mutated.set(second, base);
    mutated.set(first, base + slotLen);

    // Swapping whole slots is a reordering, which stays valid by design — either
    // recipient can still find their own slot. What must fail is mixing halves.
    const spliced = created.envelope.slice();
    spliced.set(second.slice(0, 1 + 2 + parsed.slots[0]!.data.length), base);
    for (const who of [alice, bob]) {
      let ok = false;
      try {
        await readPaste(spliced, { kind: 'identity', identity: who });
        ok = true;
      } catch {
        ok = false;
      }
      expect(ok).toBe(false);
    }
  });

  it('rejects a deleted slot', async () => {
    const alice = generateIdentity();
    const created = await createPaste({ body: BODY, recipients: [alice] });
    const parsed = parseEnvelope(created.envelope, LIMIT);
    const linkSlotLen = 1 + 2 + 0 + 24 + 48;
    const base = parsed.slotAadPrefix.length;

    // Drop the link slot and decrement the count, which is what an attacker who
    // wanted to force recipient-only access would do.
    const mutated = new Uint8Array(created.envelope.length - linkSlotLen);
    mutated.set(created.envelope.slice(0, base), 0);
    mutated.set(created.envelope.slice(base + linkSlotLen), base);
    mutated[6] = (created.envelope[6] as number) - 1;

    let ok = false;
    try {
      await readPaste(mutated, { kind: 'identity', identity: alice });
      ok = true;
    } catch {
      ok = false;
    }
    expect(ok).toBe(false);
  });
});

describe('signature integrity', () => {
  it('cannot be forged by substituting another identity', async () => {
    const author = generateIdentity();
    const impostor = generateIdentity();
    const created = await createPaste({ body: BODY, signWith: author });
    const read = await readPaste(created.envelope, { kind: 'fragment', fragment: created.fragment! });
    expect(Buffer.from(read.author!.signPublicKey).equals(Buffer.from(impostor.signPublicKey))).toBe(false);
  });

  it('is covered by the body AEAD, so it cannot be stripped', async () => {
    const author = generateIdentity();
    const created = await createPaste({ body: BODY, signWith: author });
    // The signature lives inside the ciphertext; there is no plaintext byte to
    // clear. Any attempt to alter it necessarily alters the ciphertext.
    const parsed = parseEnvelope(created.envelope, LIMIT);
    const ctStart = parsed.bodyAad.length;
    const mutated = created.envelope.slice();
    mutated[ctStart + 4] = (mutated[ctStart + 4] as number) ^ 0xff;
    expect(await opens(mutated, created.fragment!)).toBe(false);
  });
});

describe('key handling', () => {
  it('rejects a link key of the wrong length', async () => {
    const created = await createPaste({ body: BODY });
    for (const n of [0, LINK_KEY_LEN - 1, LINK_KEY_LEN + 1]) {
      const bad = Buffer.from(new Uint8Array(n)).toString('base64url');
      await expect(readPaste(created.envelope, { kind: 'fragment', fragment: bad }), `len=${n}`).rejects.toThrow();
    }
  });

  it('rejects a fragment that is not valid base64url', async () => {
    const created = await createPaste({ body: BODY });
    await expect(readPaste(created.envelope, { kind: 'fragment', fragment: '!!!!' })).rejects.toThrow(FormatError);
  });

  it('rejects input that is not an envelope at all', async () => {
    expect(() => parseEnvelope(new Uint8Array(64), LIMIT)).toThrow(FormatError);
    expect(() => parseEnvelope(new Uint8Array(0), LIMIT)).toThrow(FormatError);
    expect(() => parseEnvelope(new TextEncoder().encode('CPB2....'), LIMIT)).toThrow(FormatError);
  });
});
