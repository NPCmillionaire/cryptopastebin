import { describe, expect, it } from 'vitest';
import { ml_kem768_x25519 as xwing } from '@noble/post-quantum/hybrid.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import {
  b64uDecode,
  b64uDecodeExact,
  b64uEncode,
  MLDSA65_PUBLIC_KEY_LEN,
  MLDSA65_SIGNATURE_LEN,
  XWING_CIPHERTEXT_LEN,
  XWING_PUBLIC_KEY_LEN,
  FormatError,
} from '../src/index.js';
import { bytesToHex, hexToBytes, XWING_KAT } from './vectors.js';

describe('X-Wing known-answer test (draft-connolly-cfrg-xwing-kem-10, Appendix C)', () => {
  const kp = xwing.keygen(hexToBytes(XWING_KAT.seed));

  it('derives the specified public key from the seed', () => {
    expect(kp.publicKey.length).toBe(XWING_KAT.publicKeyLength);
    expect(bytesToHex(kp.publicKey).slice(0, 64)).toBe(XWING_KAT.publicKeyPrefix);
  });

  it('uses the seed itself as the secret key encoding', () => {
    expect(bytesToHex(kp.secretKey)).toBe(XWING_KAT.secretKey);
  });

  it('produces the specified ciphertext and shared secret for the given encapsulation seed', () => {
    const { cipherText, sharedSecret } = xwing.encapsulate(kp.publicKey, hexToBytes(XWING_KAT.encapsulationSeed));
    expect(cipherText.length).toBe(XWING_KAT.ciphertextLength);
    expect(bytesToHex(cipherText).slice(0, 64)).toBe(XWING_KAT.ciphertextPrefix);
    expect(bytesToHex(sharedSecret)).toBe(XWING_KAT.sharedSecret);
  });

  it('decapsulates back to the same shared secret', () => {
    const { cipherText, sharedSecret } = xwing.encapsulate(kp.publicKey, hexToBytes(XWING_KAT.encapsulationSeed));
    expect(bytesToHex(xwing.decapsulate(cipherText, kp.secretKey))).toBe(bytesToHex(sharedSecret));
  });

  it('matches the lengths this package compiles against', () => {
    expect(XWING_PUBLIC_KEY_LEN).toBe(xwing.lengths.publicKey);
    expect(XWING_CIPHERTEXT_LEN).toBe(xwing.lengths.cipherText);
    expect(MLDSA65_PUBLIC_KEY_LEN).toBe(ml_dsa65.lengths.publicKey);
    expect(MLDSA65_SIGNATURE_LEN).toBe(ml_dsa65.lengths.signature);
  });
});

describe('base64url is canonical', () => {
  it('round-trips arbitrary lengths', () => {
    for (let n = 0; n <= 64; n++) {
      const bytes = new Uint8Array(n);
      for (let i = 0; i < n; i++) bytes[i] = (i * 37 + 11) & 0xff;
      expect(Array.from(b64uDecode(b64uEncode(bytes)))).toEqual(Array.from(bytes));
    }
  });

  it('rejects padding, whitespace, and out-of-alphabet characters', () => {
    for (const bad of ['QQ==', 'QQ=', 'Q Q', 'QQ\n', 'QQ+/', '****']) {
      expect(() => b64uDecode(bad), bad).toThrow(FormatError);
    }
  });

  it('rejects a length that cannot encode any byte string', () => {
    expect(() => b64uDecode('QQQQQ')).toThrow(FormatError);
  });

  it('rejects non-canonical trailing bits, which would make the encoding malleable', () => {
    // 'QQ' decodes to 0x41. 'QR' sets discarded low bits of the final symbol and
    // a permissive decoder would return the same 0x41 for both.
    expect(Array.from(b64uDecode('QQ'))).toEqual([0x41]);
    expect(() => b64uDecode('QR')).toThrow(FormatError);
    // Same idea for the 3-symbol case: 'QUE' is canonical and 'QUF' is the
    // non-canonical spelling of the very same two bytes.
    expect(Array.from(b64uDecode('QUE'))).toEqual([0x41, 0x41]);
    expect(() => b64uDecode('QUF')).toThrow(FormatError);
  });

  it('enforces exact lengths where a key is expected', () => {
    expect(() => b64uDecodeExact(b64uEncode(new Uint8Array(31)), 32)).toThrow(FormatError);
    expect(b64uDecodeExact(b64uEncode(new Uint8Array(32)), 32).length).toBe(32);
  });
});
