# Wire format

All integers are big-endian. Version 1, magic `CPB1`.

## Envelope

The envelope is the only thing the server stores.

```
offset size  field
0      4     magic "CPB1"
4      1     version = 1
5      1     flags        bit0 = inner compressed, bit1 = password layer
6      1     slotCount    1..8
7      1     reserved     must be 0
8      16    fileSalt     per-paste HKDF salt

-- present iff flags.passwordLayer --
       16    passwordSalt
       4     argon2 m (KiB)   validated to [8192, 1048576]
       4     argon2 t          validated to [2, 16]
       1     argon2 p          validated to [1, 16]

-- slot table, slotCount entries --
       1     kind         0x01 = link, 0x02 = X-Wing
       2     dataLen
       n     data         empty for link; 1120-byte X-Wing ciphertext for X-Wing
       24    wrapNonce
       48    wrappedCek   32-byte content key + 16-byte Poly1305 tag

-- body --
       24    nonce
       4     ciphertextLen
       n     ciphertext || tag
```

**Body AAD** = bytes `[0, ciphertextLen)` — the entire header.
**Slot AAD** = header prefix through the Argon2 block, then `kind ‖ dataLen ‖ data`.

Parsing rules that exist to close specific holes:

- A nonzero `reserved` byte is rejected rather than ignored, so the field stays
  usable for a future version instead of becoming a malleability channel.
- Unknown flag bits are rejected rather than masked off.
- Trailing bytes are rejected, so an envelope has exactly one valid encoding.
- `ciphertextLen` is checked against a caller-supplied ceiling *before* the buffer
  is read, so a hostile length cannot drive an allocation.
- Argon2 parameters are range-checked before use. The lower bounds stop an envelope
  from claiming a password layer at zero cost; the upper bounds stop one from
  demanding a 4 GiB allocation from whoever merely opens the link.

## Container (inside the AEAD)

```
container:
  u8    version = 1
  u8    flags        bit0 = signed
  u32   innerLen
  bytes inner        DEFLATE-raw compressed iff the envelope header says so
  if signed:
    u16 + bytes      ML-DSA-65 public key (1952)
    u16 + bytes      ML-DSA-65 signature (3309)

inner (after decompression):
  u32   manifestLen
  bytes manifest     UTF-8 JSON
  bytes body         manifest.body.size bytes
  bytes attachment[i] manifest.attachments[i].size bytes, in order
```

The signature covers `"cpb1/container-signature/v1\0" ‖ version ‖ flags ‖ innerLen ‖ inner`
— the exact bytes as stored. There is no canonical-JSON step, because the verifier
hashes what it read off the wire rather than trying to reproduce a byte-identical
re-serialisation of a parsed object. Every signature scheme broken by a
canonicalisation bug got there by doing the opposite.

A present signature that does not verify is a **hard error**, never a downgrade to
"unsigned". Silently treating a broken signature as absent is how a forged-authorship
UI happens.

### Manifest

```json
{
  "v": 1,
  "body": { "size": 1234, "lang": "typescript", "render": "code" },
  "attachments": [{ "name": "shot.png", "mime": "image/png", "size": 5678 }]
}
```

`render` is one of `code`, `markdown`, `plain`.

The manifest is authentic once the AEAD verifies — it really was written by whoever
held the key — but authentic is not trustworthy. Anyone can create a paste and send
the link to anyone, so the parser treats it as hostile input:

- Fields are read individually and re-assigned into a fresh object literal.
  Nothing is spread or `Object.assign`'d, so a `__proto__` key stays inert data.
- Declared part sizes are summed and compared to the remaining bytes **before any
  part is read**, so a manifest that lies about one size fails outright instead of
  silently shifting every later boundary.
- Filenames are sanitised on the way out as well as in: path components collapsed,
  leading dots removed, and C0/C1 controls plus Unicode bidi overrides stripped —
  a `U+202E` turns `harmless‮gnp.exe` into something that renders as
  `harmlessexe.png`, which defeats eyeballs completely.
- Decompression enforces its ceiling *inside* the read loop, not on the finished
  buffer: a few kilobytes of crafted DEFLATE expands to gigabytes, so a check after
  collecting every chunk runs after the process has already died.

## Encodings

| Thing | Encoding | Length |
|---|---|---|
| Link key (URL fragment) | unpadded base64url | 43 chars / 32 bytes |
| Paste id (URL path) | unpadded base64url | 22 chars / 16 bytes |
| Public identity | `cpb1pub_` + base64url | 3168 bytes |
| Secret identity | `cpb1sec_` + base64url | 32 bytes |
| Fingerprint | 20 chars, grouped in fives | 100 bits |

base64url decoding is **canonical-only**. It rejects padding, whitespace, any
out-of-alphabet character, a length ≡ 1 (mod 4), and — the case most decoders miss —
a final symbol whose discarded low-order bits are set. Without that last check the
encoding is malleable: `QQ` and `QR` both decode to `0x41` in a permissive decoder,
which means two distinct strings name the same key.
