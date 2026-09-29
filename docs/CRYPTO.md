# Cryptographic design

Every algorithm choice below is followed by the reason it was picked over the
obvious alternative. Where a choice is a compromise, it says so.

## Primitives

| Purpose | Algorithm | Why this one |
|---|---|---|
| Content encryption | XChaCha20-Poly1305 | 192-bit nonce, so every message gets a fresh random nonce with no counter to persist or synchronise. AES-GCM's 96-bit nonce fails catastrophically on reuse and has no constant-time software implementation without AES-NI — which describes a large share of phones. |
| Key agreement to a public key | **X-Wing** (ML-KEM-768 + X25519) | A published hybrid KEM with an IND-CCA proof, pinned to the test vectors in `draft-connolly-cfrg-xwing-kem-10`. Hybrid rather than raw ML-KEM so the result is no weaker than X25519 even if the lattice assumption falls; lattice cryptography has had far less time under attack than elliptic curves. |
| Key derivation | HKDF-SHA3-256 | SHA3 is already a dependency through ML-KEM and X-Wing's combiner, so it adds no new primitive, and the sponge construction is not length-extendable. |
| Password stretching | Argon2id | The PHC winner and RFC 9106's recommendation; memory-hard, so GPU and ASIC advantage is bounded. Parameters default to RFC 9106's second recommended option (64 MiB, t=3, p=4) and are stored per-paste so they can be raised later without orphaning old pastes. |
| Authorship | ML-DSA-65 | Post-quantum signatures at NIST category 3. Placed **inside** the ciphertext, so identity is not published to the server. |
| Identity fingerprints | SHA3-256, truncated to 100 bits | Short enough to read aloud, long enough that finding a collision is infeasible. |

Nothing in the stack uses WebAssembly, which is why the Content-Security-Policy
can omit `wasm-unsafe-eval`.

## Key hierarchy

```
                      content key (CEK, 32 random bytes)
                                    │
                    encrypts the container with XChaCha20-Poly1305
                                    │
              ┌─────────────────────┴─────────────────────┐
              │            wrapped once per slot          │
              ▼                                           ▼
        LINK slot                                   X-WING slot
  HKDF(linkKey, "cpb1/kek/link")            X-Wing.encap(recipientPK)
  linkKey = 32 bytes in the URL #fragment    → HKDF(ss, "cpb1/kek/xwing")
              │                                           │
              └──────────────┬────────────────────────────┘
                             ▼
              optional AND with the password factor
        HKDF(slotKey ‖ Argon2id(password), "cpb1/kek/final")
                             ▼
                      key-wrapping key (KEK)
```

Slots are an **OR**: any one of them opens the paste. That is what lets a single
stored ciphertext be readable by link *and* by three named recipients without
storing it three times. The password layer is an **AND** against whichever slot is
used.

## Where the post-quantum part actually matters

This is the claim most easily oversold, so it is worth stating precisely.

**A link-mode paste was already quantum-resistant.** Its security rests on a
256-bit symmetric key and an AEAD. Grover's algorithm at best halves the exponent,
leaving 128 bits of quantum security, and no lattice scheme improves on that.
Bolting ML-KEM onto link mode would be decoration.

**Recipient mode is where the hybrid KEM earns its place.** There, a key agreement
runs against a long-lived public key, and that is exactly the setting for
"harvest now, decrypt later": an adversary who records an X25519-only envelope
today decrypts it the day a cryptographically relevant quantum computer exists. For
a paste meant to stay secret for a decade, that is a live risk rather than a
theoretical one. X-Wing's combiner binds both shared secrets, both ciphertexts, and
the classical public key into one SHA3-256 call, so the composite is secure if
*either* component is.

## Domain separation

Every derived key comes out of one function, and every call site must name its
purpose from a closed TypeScript union:

```ts
type Label =
  | 'cpb1/kek/link' | 'cpb1/kek/xwing' | 'cpb1/kek/password' | 'cpb1/kek/final'
  | 'cpb1/seed/kem' | 'cpb1/seed/sign';
```

Key reuse across contexts is the standard way a layered protocol like this breaks —
the same 32 bytes serving as a content key in one path and a wrapping key in
another, so an oracle in the cheap path unlocks the expensive one. A closed union
means a new call site cannot compile without declaring itself, and a reviewer can
enumerate every key the system derives by reading six lines.

## What is authenticated

The body AEAD's AAD is **every header byte before the ciphertext**: version, flags,
slot count, salt, Argon2 parameters, the entire slot table, nonce, and length. Each
slot's key wrap has its own AAD binding it to the header prefix and to that slot's
kind and data.

So an attacker cannot flip the compression flag, downgrade the Argon2 cost, delete
a slot, swap one slot's ciphertext for another's, or transplant a wrap between
envelopes. All of it fails authentication before a byte of plaintext exists. The
test suite mutates every byte offset of an envelope in turn and asserts that none
of them decrypts.

## Deliberate compromises

**Compression before encryption.** Ciphertext length becomes a function of
plaintext content — the mechanism behind CRIME and BREACH. Those attacks need an
adversary who can repeatedly inject chosen plaintext into the same secret and
observe the length; a paste is authored once, in full, by one person, with no
request loop to drive. What remains is a coarse signal that highly repetitive
content compresses further. Padding to size buckets would blunt even that and is
listed as future work rather than pretended away. Compression is on by default for
text, off when attachments are present, and always overridable.

**Single-shot AEAD.** The whole payload is one AEAD invocation, capped at 24 MiB.
This rules out chunk reordering and truncation attacks entirely, at the cost of
requiring the payload in memory and precluding streaming. For a pastebin that is
the right side of the trade; a file-transfer tool would need chunked AEAD with
per-chunk sequence binding.

**Identity seeds in `localStorage`.** Readable by any script on the origin, so a
successful XSS yields every paste ever addressed to that identity. The mitigations
are a strict CSP, no third-party script, and a single audited sanitisation point —
but none makes the seed unreachable. WebCrypto's non-extractable keys cannot hold
an X-Wing seed, because WebCrypto has no ML-KEM. Link-mode pastes leave no
long-term secret on the device at all and should be preferred when recipient
addressing is not needed.

**Password entropy.** Argon2id raises the cost per guess; it cannot turn a 30-bit
password into a 128-bit key. That is why a password is an additional factor rather
than an alternative to the link key: its job is to protect the paste when the
*link* leaks, not to be the only secret.
