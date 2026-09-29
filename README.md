# CryptoPaste

A pastebin that encrypts in the browser. The server stores ciphertext and never
receives a key.

```
XChaCha20-Poly1305 · X-Wing (ML-KEM-768 + X25519) · Argon2id · ML-DSA-65 · HKDF-SHA3-256
```

## What it does

- **Zero-knowledge by construction.** The content key lives in the URL fragment.
  Browsers never transmit fragments, so it cannot appear in an access log, a CDN
  cache key, or a `Referer` header.
- **Post-quantum recipient addressing.** Encrypt a paste to someone's public key with
  **X-Wing**, the hybrid KEM from `draft-connolly-cfrg-xwing-kem`, verified here
  against the draft's own test vectors. The link then carries no secret at all.
- **Burn after reading.** The server deletes the row and returns it in one atomic
  statement, so exactly one reader can ever get it — even under a concurrent race.
- **Encrypted attachments**, inside the same authenticated envelope as the text.
- **Markdown and syntax highlighting**, rendered through a single audited
  sanitisation point under a CSP that permits no inline script, no `eval`, no WASM,
  and no third-party origin.
- **Optional password**, stretched with Argon2id and combined *with* the link key
  rather than replacing it.
- **Optional authorship**, signed with ML-DSA-65 *inside* the ciphertext, so the
  server never learns who wrote what.

## A claim this README will not make

The post-quantum cryptography is not what makes link-mode pastes secure. Those rest
on a 256-bit symmetric key and were always quantum-resistant — Grover's algorithm
leaves 128 bits of quantum security, and no lattice scheme improves on that.

The hybrid KEM matters in **recipient mode**, where a key agreement runs against a
long-lived public key. That is where "harvest now, decrypt later" is a real risk: a
recorded envelope can be attacked years after it was sent. [CRYPTO.md](docs/CRYPTO.md)
explains the distinction, and [THREAT-MODEL.md](docs/THREAT-MODEL.md) is explicit
about what none of this protects — starting with the fact that a server which serves
you a modified client defeats all of it.

## Layout

```
packages/crypto/   isomorphic crypto core — envelope format, X-Wing, Argon2id, signing
apps/api/          Cloudflare Worker: three endpoints, D1 + R2, cron purge
apps/web/          static client: Vite, crypto in a Web Worker, no CDN
scripts/           local server, browser end-to-end suite, static leak audit
docs/              crypto design, wire format, threat model, deployment
```

## Quick start

```bash
npm install
npm run build
node scripts/local-server.mjs 8788   # runs the real Worker handler locally
```

Open <http://127.0.0.1:8788>. No Cloudflare account needed — D1 is backed by
`node:sqlite` and R2 by memory. [DEPLOY.md](docs/DEPLOY.md) covers real deployment.

## Verification

```bash
npm test                      # 81 crypto tests
npm run test:api              # 26 Worker tests, real SQLite
npm run typecheck             # strict, all three packages
npm run audit:leaks           # static gate on the mistakes tests can't catch
node scripts/e2e.mjs          # 38 checks in real Chromium (server must be running)
```

Some of these are worth describing, because they test claims rather than code paths:

**The X-Wing KAT** pins the first test vector from
`draft-connolly-cfrg-xwing-kem-10`. A dependency bump that silently changed the
hybrid combiner — a different label, a reordered transcript — would otherwise make
every previously created paste undecryptable without failing a single test.

**Tamper sweep.** Every byte offset of an envelope is mutated in turn, three masks
each, and none may decrypt. Header bytes included: a field that is parsed but not
authenticated is the standard flaw in home-grown envelope formats, and round-trip
tests never catch it. Targeted cases cover the downgrades an attacker would actually
want — clearing the compression flag, weakening the Argon2 cost, deleting a slot,
transplanting a wrapped key between envelopes.

**Burn-after-read concurrency.** Twelve simultaneous reads against real SQLite;
exactly one gets a 200 and eleven get 404.

**The browser suite** intercepts every request the page makes and asserts the key
appears in no URL, header, or body. It also feeds a paste
`<img onerror>`, `<script>`, `javascript:` links, and a `position:fixed` overlay,
then verifies nothing executed and the legitimate content still rendered.

**The leak audit** gates on things a type checker cannot see: a `console.log` in
shipped source, an `innerHTML` outside the sanitising module, a secret in a query
string, `Math.random`, a third-party origin, an `eval`, or a storage/network call
inside the crypto core.

## Honest notes

- `npm audit` reports advisories in `vitest` and `wrangler`. Both are dev-only and
  reach neither the Worker nor the browser bundle.
- Argon2id is pure JavaScript, so unlocking a password-protected paste takes 1–3
  seconds. That is the price of a CSP without `wasm-unsafe-eval`.
- Identity seeds live in `localStorage`, which an XSS could read. WebCrypto has no
  ML-KEM, so a non-extractable key is not an option. Link-mode pastes leave no
  long-term secret on the device.
- Not independently audited. The primitives are `@noble/*`; the composition is this
  repository's own and has had one author's attention, not a review board's.

## Licence

MIT. See [LICENSE](LICENSE).
