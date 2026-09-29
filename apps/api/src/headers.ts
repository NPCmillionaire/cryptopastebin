/**
 * Security response headers.
 *
 * ## The two that carry the design
 *
 * `Referrer-Policy: no-referrer` is not hardening here, it is load-bearing. A
 * paste URL contains the decryption key in its fragment. Fragments are stripped
 * from the `Referer` header by every modern browser, but the *path* — and with it
 * the paste id — is not, and a default referrer policy would hand that id to any
 * third-party resource the page loads. Combined with a CSP that permits no
 * third-party origins at all, there is nowhere for a referrer to leak to.
 *
 * The CSP itself allows no inline script, no inline style, no `eval`, and no
 * external origins whatsoever. For a page that holds plaintext in memory, XSS is
 * not one risk among several — it is the only way to reach the plaintext without
 * the key, so the policy is written to leave no gap rather than to be convenient.
 * That is why the frontend ships zero inline handlers and loads no CDN: every
 * such convenience would require punching a hole in exactly the control that
 * matters most. Notably absent is `wasm-unsafe-eval`: the Argon2 and lattice code
 * is pure JavaScript, so WebAssembly never needs to be enabled.
 *
 * @module
 */

const CSP = [
  "default-src 'none'",
  "script-src 'self'",
  "style-src 'self'",
  "img-src 'self' blob: data:",
  "font-src 'self'",
  "connect-src 'self'",
  "worker-src 'self' blob:",
  "manifest-src 'self'",
  "base-uri 'none'",
  "form-action 'none'",
  "frame-ancestors 'none'",
  'upgrade-insecure-requests',
].join('; ');

const COMMON: Readonly<Record<string, string>> = {
  'Content-Security-Policy': CSP,
  'Referrer-Policy': 'no-referrer',
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Cross-Origin-Resource-Policy': 'same-origin',
  'Cross-Origin-Embedder-Policy': 'require-corp',
  'Strict-Transport-Security': 'max-age=63072000; includeSubDomains; preload',
  'Permissions-Policy':
    'accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()',
};

/** Apply the standard header set to a response, in place. */
export function applySecurityHeaders(response: Response): Response {
  for (const [name, value] of Object.entries(COMMON)) response.headers.set(name, value);
  return response;
}

/**
 * Headers for API responses.
 *
 * `no-store` on every one of them. A ciphertext is not secret, but a burn-after-read
 * paste must not be recoverable from a shared cache or a browser's back-forward
 * cache after it has been destroyed server-side, and a paste id sitting in an
 * intermediary's cache key is metadata nobody needs to keep.
 */
export const API_HEADERS: Readonly<Record<string, string>> = {
  'Cache-Control': 'no-store, no-cache, must-revalidate, private',
  Pragma: 'no-cache',
  'X-Robots-Tag': 'noindex, nofollow, noarchive',
};
