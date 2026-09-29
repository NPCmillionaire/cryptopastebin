# Threat model

The point of this document is to be specific about what the system does **not**
protect against. A security tool that only lists its strengths is not describing a
threat model.

## What the design protects

### The server operator

This is the primary adversary the architecture is built around, including the case
where the operator is compelled by legal process.

The key lives in the URL fragment. Fragments are resolved entirely by the browser:
they are not placed in the request line, so they cannot reach an access log, a
reverse proxy's log, a CDN cache key, or a `Referer` header. The server therefore
serves ciphertext without ever being in a position to decrypt it.

What the operator *can* see is listed under "metadata" below, and it is not nothing.

### A network observer

Everything is HTTPS, and the payload is already ciphertext before it is sent, so TLS
termination anywhere in the path — a corporate middlebox, a CDN edge — yields
nothing but the envelope.

### Anyone who later obtains the stored data

A database dump, a stolen backup, or a seized disk contains envelopes and nothing
else. There is no key material anywhere on the server.

### A future quantum adversary

For recipient-addressed pastes, X-Wing means a recording made today is not
retroactively decryptable. For link-mode pastes the symmetric key was always
quantum-safe. See [CRYPTO.md](CRYPTO.md) for why the distinction matters.

### A malicious paste author

Paste content is attacker-controlled by definition: anyone can create a paste and
send the link to anyone. The viewer treats decrypted content as hostile — one
audited sanitisation point, an allow-list CSP, class-name filtering, forced
attachment MIME types, and filename sanitisation against traversal and bidi
disguises.

---

## What the design does not protect

### Metadata the operator still learns

Not nothing, and worth being explicit about:

- **Ciphertext size**, which bounds the plaintext size and — because compression is
  on by default — hints at how repetitive the content is.
- **Creation and expiry times**, and **when each read happened**.
- **Whether a paste is single-use**, and **how many slots it has**, which reveals the
  *number* of recipients. It does not reveal who they are: the envelope records no
  recipient identifiers, which is why opening a recipient paste tries each X-Wing
  slot in turn.
- **Whether a password layer is present**, and its Argon2 parameters.
- **The client's IP address at the TLS layer**, which the platform sees for every
  request. The application never stores it — the rate limiter keys on a truncated
  HMAC under a rotatable server secret, and no table has a column that could hold an
  address — but a platform-level log is outside this code's control. Someone whose
  threat model includes traffic correlation should reach the site over Tor or a VPN.

### A compromised server

The server can serve a modified client. That is the hard limit of browser-delivered
end-to-end encryption and no amount of care inside this repository changes it: an
operator who wants your plaintext can ship a build that exfiltrates it, and the next
page load will run it.

What is done about it: the deployed bundle has source maps and the repository is
public, so a determined user can verify the served code matches. What is *not*
claimed is that anyone routinely does this. If you need a guarantee that survives a
hostile server, use a tool you install and update deliberately — a native client, or
`age`/GPG at the command line. This design's honest claim is narrower: a
*passive or compelled* operator learns nothing, which covers subpoenas, breaches,
and insider reads of stored data, but not an actively malicious operator targeting
you.

### XSS in the client

If an attacker executes script on this origin, they read the plaintext of whatever
paste is open and any identity seed in `localStorage`. The CSP, the absence of
third-party script, and the single sanitisation point are mitigations, not
guarantees.

### The link itself

The key is in the URL. Anything that captures URLs captures the paste: browser
history, a synced clipboard, a screenshot, a chat client that unfurls links, a
corporate mail scanner, someone reading over your shoulder.

Partial mitigations: `HEAD` never consumes a burn paste, so an unfurler cannot
destroy one before the recipient opens it, and the optional password means a leaked
link alone is not enough. Neither helps if the link is leaked to a party who also
has the password.

### Endpoint compromise

Malware, a malicious browser extension, or a shoulder surfer on either end defeats
everything. Extensions in particular can read page content directly and are outside
any web application's control.

### Traffic analysis

Ciphertext size and timing are visible. Someone who can observe both ends can
correlate an upload with a download.

### Denial of service

Rate limiting bounds storage abuse, but a determined attacker with many addresses
can still consume quota. The platform's own DDoS protection is the real defence.
Burn-after-read has an inherent availability weakness: anyone who obtains the link
can consume the single read before the intended recipient, which destroys the paste.
That is a denial of service, not a confidentiality breach — the attacker needed the
key to read it.

### Recovery

There is none, by construction. A lost fragment or a lost identity seed means the
paste is gone. Nobody, including the operator, can help.

---

## Trust required to use this

1. **The server is not actively malicious at the time you load the page.** See
   "compromised server" above — this is the load-bearing assumption.
2. **Your browser and OS are not compromised.**
3. **TLS holds** for the initial page load.
4. **For recipient mode: you verified the fingerprint out of band.** A substituted
   public key turns end-to-end encryption into encryption to the attacker, and no
   amount of lattice cryptography below that step compensates for skipping it. This
   is the one part of the system that cannot be automated, and it is the part most
   implementations quietly omit.

## Known gaps, honestly listed

- **No padding.** Ciphertext length leaks approximate plaintext length. Bucketing to
  fixed sizes is the fix and is not implemented.
- **No forward secrecy for identities.** One long-lived keypair; compromising the
  seed retroactively opens every paste addressed to it. Ratcheting would fix this and
  would require state both sides maintain, which a pastebin does not have.
- **No transparency log for the served bundle.** Verification is manual.
- **No multi-device identity sync.** By design — syncing a seed means putting it
  somewhere else.
- **Argon2id in pure JavaScript** is several times slower than a WASM build. That was
  chosen so the CSP can omit `wasm-unsafe-eval`; the cost is a 1–3 second unlock.
- **`localStorage` for identity seeds.** Discussed at length in
  [CRYPTO.md](CRYPTO.md); the least-bad option given that WebCrypto cannot hold an
  ML-KEM key.
