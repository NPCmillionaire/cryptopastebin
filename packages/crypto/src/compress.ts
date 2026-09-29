/**
 * Optional DEFLATE compression of the plaintext container.
 *
 * ## The honest caveat
 *
 * Compressing before encrypting leaks information: ciphertext length becomes a
 * function of plaintext *content*, not just its size. That is the mechanism
 * behind CRIME and BREACH, and any document claiming compression is free here
 * would be wrong.
 *
 * What makes it acceptable in this specific setting is that those attacks need
 * an adversary who can repeatedly inject chosen plaintext into the same secret
 * and observe the resulting length. A paste is authored once, in full, by one
 * person, and encrypted once; there is no request loop for an attacker to drive
 * and no attacker-controlled fragment sharing a compression window with a
 * secret. What does remain is a coarse signal — highly repetitive content
 * compresses further — so an observer learns a little about the *kind* of
 * content, never its bytes. Padding to a size bucket would blunt even that, and
 * is noted as future work in the threat model rather than pretended away.
 *
 * Compression is therefore on by default for text and off when attachments are
 * present, since already-compressed media gains nothing and costs memory. It can
 * always be disabled per paste, and the choice is recorded in the envelope
 * header, which is authenticated as AAD — so an attacker cannot flip the flag to
 * make a decompressor misinterpret a valid payload.
 *
 * @module
 */
import { FormatError } from './errors.js';

const FORMAT = 'deflate-raw';

/**
 * Drive a stream transform over a single input buffer.
 *
 * `limit` is enforced *inside* the read loop rather than on the finished result.
 * That distinction is the whole defence against a compression bomb: a few
 * kilobytes of crafted DEFLATE can expand to gigabytes, so checking the total
 * after collecting every chunk would mean the process has already died before
 * reaching the check. Here the loop aborts and releases the partial output the
 * moment the running total crosses the ceiling.
 */
async function pump(
  transform: TransformStream<Uint8Array, Uint8Array>,
  input: Uint8Array,
  limit: number,
): Promise<Uint8Array> {
  const writer = transform.writable.getWriter();
  // Kept as a value so a failure here is always awaited; a floating rejection
  // from the write side would surface as an unhandled rejection instead of an
  // error the caller can map to FormatError.
  const writeDone = writer.write(input).then(() => writer.close());
  writeDone.catch(() => {});

  const reader = transform.readable.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.length;
      if (total > limit) {
        for (const c of chunks) c.fill(0);
        value.fill(0);
        throw new LimitExceeded(limit);
      }
      chunks.push(value);
    }
    await writeDone;
  } catch (err) {
    await reader.cancel().catch(() => {});
    await writer.abort().catch(() => {});
    throw err;
  }

  const out = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    out.set(c, off);
    off += c.length;
  }
  return out;
}

/** Internal marker so {@link decompress} can tell a bomb from a corrupt stream. */
class LimitExceeded extends Error {
  constructor(readonly limit: number) {
    super(`output exceeds limit of ${limit} bytes`);
  }
}

/**
 * Raw DEFLATE compress.
 *
 * The ceiling is generous because DEFLATE can expand incompressible input
 * slightly; it exists only to bound the buffer, not to reject anything real.
 */
export async function compress(data: Uint8Array): Promise<Uint8Array> {
  const ceiling = data.length + (data.length >>> 6) + 1024;
  return pump(new CompressionStream(FORMAT) as TransformStream<Uint8Array, Uint8Array>, data, ceiling);
}

/**
 * Raw DEFLATE decompress.
 *
 * @param maxOutputLength Hard ceiling on the decompressed size. A compression
 *   bomb is the classic way to turn "open this link" into an out-of-memory
 *   crash, and the compressed size gives no useful bound on the decompressed
 *   one, so the limit has to be explicit and enforced by the caller's policy.
 * @throws {FormatError} if the stream is invalid or exceeds the ceiling.
 */
export async function decompress(data: Uint8Array, maxOutputLength: number): Promise<Uint8Array> {
  try {
    return await pump(new DecompressionStream(FORMAT) as TransformStream<Uint8Array, Uint8Array>, data, maxOutputLength);
  } catch (err) {
    if (err instanceof LimitExceeded) {
      throw new FormatError(`decompressed payload exceeds limit of ${maxOutputLength} bytes`);
    }
    throw new FormatError('invalid compressed payload');
  }
}
