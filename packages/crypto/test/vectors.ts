/**
 * Pinned test vectors.
 *
 * The X-Wing values are copied verbatim from Appendix C of
 * draft-connolly-cfrg-xwing-kem-10. They are here so that an upgrade to
 * `@noble/post-quantum` that silently changed the hybrid combiner — a different
 * label, a reordered transcript, a switch from the X-Wing preset to the QSF or
 * KitchenSink one — fails this repository's test run instead of quietly making
 * every previously created paste undecryptable. A dependency bump is the most
 * likely way a working crypto stack breaks, and a KAT is the only thing that
 * catches it.
 */
export const XWING_KAT = {
  seed: '7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26',
  /** X-Wing's secret key encoding is the 32-byte seed itself. */
  secretKey: '7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26',
  publicKeyPrefix: 'e2236b35a8c24b39b10aa1323a96a919a2ced88400633a7b07131713fc14b2b5',
  publicKeyLength: 1216,
  encapsulationSeed:
    '3cb1eea988004b93103cfb0aeefd2a686e01fa4a58e8a3639ca8a1e3f9ae57e2' +
    '35b8cc873c23dc62b8d260169afa2f75ab916a58d974918835d25e6a435085b2',
  ciphertextPrefix: 'b83aa828d4d62b9a83ceffe1d3d3bb1ef31264643c070c5798927e41fb07914a',
  ciphertextLength: 1120,
  sharedSecret: 'd2df0522128f09dd8e2c92b1e905c793d8f57a54c3da25861f10bf4ca613e384',
} as const;

export function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) throw new Error('odd hex length');
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

/** Argon2 parameters at the floor of the accepted range, to keep tests quick. */
export const FAST_ARGON2 = { m: 8192, t: 2, p: 1 } as const;
